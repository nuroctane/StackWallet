/**
 * Fuel adapter. Addresses are `0x` + lowercase hex of
 * sha256(uncompressed SEC1 pubkey without the 0x04 prefix). Reads go over the
 * fuel-core GraphQL API; every endpoint proves its network through
 * `chain { consensusParameters { chainId } }`. History comes from the node's
 * own `transactionsByOwner` index (keyless).
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  secp256k1Uncompressed,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type ChainInfo,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const FUEL_SEPOLIA = 'fuel:0';
export const FUEL_MAINNET = 'fuel:9889';
/** Native ETH asset id on every public Fuel network (9 decimals). */
export const FUEL_BASE_ASSET_ID =
  '0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07';

export const FuelAddress = z.string().regex(/^0x[0-9a-f]{64}$/);
export const B256 = FuelAddress;

/** Live-probed defaults (CORS `*` on both); used until the shared catalog wires fuel. */
export const FUEL_CHAINS: ChainInfo[] = [
  {
    chainId: FUEL_SEPOLIA,
    family: 'fuel',
    name: 'Fuel Sepolia Testnet',
    nativeAsset: { ref: `${FUEL_SEPOLIA}:native`, symbol: 'ETH', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://app-testnet.fuel.network/transaction/{hash}',
    defaultRpcs: ['https://testnet.fuel.network/v1/graphql'],
    extra: { coinType: 1179993420 },
    layer: 'L2',
    parent: 'Ethereum',
  },
  {
    chainId: FUEL_MAINNET,
    family: 'fuel',
    name: 'Fuel Ignition',
    nativeAsset: { ref: `${FUEL_MAINNET}:native`, symbol: 'ETH', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://app.fuel.network/transaction/{hash}',
    defaultRpcs: ['https://mainnet.fuel.network/v1/graphql'],
    extra: { coinType: 1179993420 },
    layer: 'L2',
    parent: 'Ethereum',
    priceId: 'ethereum',
  },
];

export function fuelAddressBytes(addr: string): Uint8Array | undefined {
  if (!FuelAddress.safeParse(addr).success) return undefined;
  const bytes = Uint8Array.from(addr.slice(2).match(/../g)!, (b) => parseInt(b, 16));
  if (bytes.every((b) => b === 0)) return undefined;
  return bytes;
}

export function isValidFuelAddress(addr: string): boolean {
  return fuelAddressBytes(addr) !== undefined;
}

export function fuelAddressFromPublicKey(sec1: Uint8Array): string {
  const full = secp256k1Uncompressed(sec1);
  return `0x${bytesToHex(sha256(full.subarray(1)))}`;
}

/** A GraphQL response with `data` decoded by `schema`; errors raise with the node message. */
const Response = <T>(schema: z.ZodType<T>) =>
  z.object({
    data: schema.nullable(),
    errors: z
      .array(z.object({ message: z.string().max(2048) }))
      .max(16)
      .optional(),
  });

export class FuelGraphQLError extends Error {}

export type FuelAdapterOptions = BaseAdapterOptions;
/** One GraphQL operation against a network-proven endpoint. */
export type FuelCall = <T>(query: string, variables: unknown, schema: z.ZodType<T>) => Promise<T>;

export class FuelAdapter extends BaseAdapter<'fuel'> {
  private readonly knownChains: ChainInfo[];

  constructor(opts: FuelAdapterOptions = {}) {
    const catalog = chainsForFamily('fuel');
    const chains = catalog.length ? catalog : FUEL_CHAINS;
    super('fuel', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(chains) });
    this.knownChains = chains;
  }

  override chains(): ChainInfo[] {
    return this.knownChains;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return fuelAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidFuelAddress(addr);
  }

  private async gql<T>(
    url: string,
    query: string,
    variables: unknown,
    schema: z.ZodType<T>,
  ): Promise<T> {
    const text = await postJsonText(url, { query, variables }, this.fetchOptions());
    let parsed: z.infer<ReturnType<typeof Response<T>>>;
    try {
      parsed = Response(schema).parse(JSON.parse(text));
    } catch (err) {
      throw err instanceof Error && err.name === 'SyntaxError'
        ? new FuelGraphQLError('Fuel endpoint did not answer JSON')
        : err;
    }
    if (parsed.errors?.length)
      throw new FuelGraphQLError(
        parsed.errors
          .map((e) => e.message)
          .join('; ')
          .slice(0, 512),
      );
    if (parsed.data === null) throw new FuelGraphQLError('Fuel endpoint returned no data');
    return parsed.data;
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const expected = Number(chainId.split(':')[1]);
    await this.verifyEndpoint(chainId, url, async () => {
      const { chain } = await this.gql(url, CHAIN_QUERY, {}, ChainInfo_GQL);
      if (Number(chain.consensusParameters.chainId) !== expected)
        throw new Error('Endpoint consensus parameters do not match this Fuel network');
      if (chain.consensusParameters.baseAssetId !== FUEL_BASE_ASSET_ID)
        throw new Error('Endpoint reports an unexpected base asset');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: FuelCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((q, variables, schema) => this.gql(url, q, variables, schema), url);
    });
  }

  /** The chain head a proven endpoint reports; also feeds pool health. */
  async headHeight(chainId: ChainId): Promise<number> {
    return this.withNode(chainId, async (call, url) => {
      const { chain } = await call(HEAD_QUERY, {}, Head);
      const height = Number(chain.latestBlock.header.height);
      this.noteBlock(url, height);
      return height;
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidFuelAddress(addr)) throw new TypeError(`invalid fuel address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const { balance } = await this.gql(
          url,
          BALANCE_QUERY,
          { owner: addr, assetId: FUEL_BASE_ASSET_ID },
          Balance,
        );
        return balance.amount;
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  /**
   * The node's own owner index. Amounts come from decoding the raw payload's
   * coin inputs and outputs of the holder; the fee is the MaxFee policy upper
   * bound because this query does not expose receipts.
   */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidFuelAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[A-Za-z0-9_-]{1,128}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const page = await this.withNode(chainId, async (call) =>
      call(HISTORY_QUERY, { owner: addr, after: cursor ?? null }, HistoryPage),
    );
    const items: TxRecord[] = [];
    for (const node of page.transactionsByOwner.nodes) {
      const record = historyRecord(chain, addr, node);
      if (record) items.push(record);
    }
    return {
      items,
      ...(page.transactionsByOwner.pageInfo.hasNextPage &&
      page.transactionsByOwner.pageInfo.endCursor
        ? { nextCursor: page.transactionsByOwner.pageInfo.endCursor }
        : {}),
      coverage:
        'fuel-core node owner index. Amounts are decoded from coin inputs and outputs; contract calls are listed without balance changes. The fee shown is the MaxFee policy upper bound, not the settled fee.',
    };
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Fuel transaction id');
    const { transaction } = await this.withNode(chainId, (call) =>
      call(TX_QUERY, { id: hash.toLowerCase() }, TxLookup),
    );
    if (!transaction?.status) return { state: 'unknown' };
    const status = transaction.status;
    switch (status.__typename) {
      case 'SuccessStatus':
        return { state: 'confirmed', blockNumber: Number(status.block?.height ?? 0) };
      case 'SubmittedStatus':
        return { state: 'pending' };
      case 'FailureStatus':
        return { state: 'failed', reason: status.reason ?? 'failure' };
      case 'SqueezedOutStatus':
        return { state: 'failed', reason: `squeezed out: ${status.reason ?? 'unknown'}` };
      default:
        return { state: 'unknown' };
    }
  }
}

const CHAIN_QUERY = `{ chain { consensusParameters { chainId baseAssetId } } }`;
const ChainInfo_GQL = z.object({
  chain: z.object({
    consensusParameters: z.object({
      chainId: z.string().regex(/^\d{1,10}$/),
      baseAssetId: FuelAddress,
    }),
  }),
});
const HEAD_QUERY = `{ chain { latestBlock { header { height } } } }`;
const Head = z.object({
  chain: z.object({
    latestBlock: z.object({ header: z.object({ height: z.string().regex(/^\d+$/) }) }),
  }),
});
const BALANCE_QUERY = `query($owner: Address!, $assetId: AssetId!){
  balance(owner: $owner, assetId: $assetId) { amount } }`;
const Balance = z.object({ balance: z.object({ amount: z.string().regex(/^\d{1,30}$/) }) });
const HISTORY_QUERY = `query($owner: Address!, $after: String){
  transactionsByOwner(first: 20, after: $after, owner: $owner) {
    nodes { id rawPayload status { __typename
      ... on SuccessStatus { block { height } }
      ... on FailureStatus { reason } ... on SqueezedOutStatus { reason } } }
    pageInfo { hasNextPage endCursor } } }`;
const HistoryPage = z.object({
  transactionsByOwner: z.object({
    nodes: z
      .array(
        z.object({
          id: FuelAddress,
          rawPayload: z.string().regex(/^0x(?:[0-9a-fA-F]{2}){1,65536}$/),
          status: z.object({
            __typename: z.string().max(32),
            block: z.object({ height: z.string().regex(/^\d+$/) }).nullish(),
            reason: z.string().max(2048).optional(),
          }),
        }),
      )
      .max(50),
    pageInfo: z.object({
      hasNextPage: z.boolean(),
      endCursor: z.string().max(128).nullable(),
    }),
  }),
});
const TX_QUERY = `query($id: TransactionId!){ transaction(id: $id) { status { __typename
  ... on SuccessStatus { block { height } }
  ... on FailureStatus { reason } ... on SqueezedOutStatus { reason } } } }`;
const TxLookup = z.object({
  transaction: z
    .object({
      status: z
        .object({
          __typename: z.string().max(32),
          block: z.object({ height: z.string().regex(/^\d+$/) }).nullish(),
          reason: z.string().max(2048).optional(),
        })
        .nullish(),
    })
    .nullable(),
});

/** Decode the coin inputs/outputs of a Script transaction payload. */
export function decodeTransferBytes(payload: string):
  | {
      inputs: { owner: string; amount: bigint; assetId: string }[];
      outputs: { type: number; to: string; amount: bigint; assetId: string }[];
      maxFee: bigint;
    }
  | undefined {
  try {
    const hex = payload.slice(2).toLowerCase();
    const bytes = Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
    let o = 0;
    const u64 = () => {
      const v = BigInt(`0x${bytesToHex(bytes.subarray(o, o + 8))}`);
      o += 8;
      return v;
    };
    const b32 = () => {
      const v = `0x${bytesToHex(bytes.subarray(o, o + 32))}`;
      o += 32;
      return v;
    };
    if (u64() !== 0n) return undefined; // Script only
    u64(); // scriptGasLimit
    b32(); // receiptsRoot
    const scriptLength = Number(u64());
    const scriptDataLength = Number(u64());
    const policyTypes = Number(u64());
    const inputsCount = Number(u64());
    const outputsCount = Number(u64());
    const witnessesCount = Number(u64());
    if (inputsCount > 255 || outputsCount > 255 || witnessesCount > 255) return undefined;
    o += scriptLength + ((8 - (scriptLength % 8)) % 8);
    o += scriptDataLength + ((8 - (scriptDataLength % 8)) % 8);
    let maxFee = 0n;
    for (const bit of [1, 2, 4, 8, 16, 32]) {
      if (policyTypes & bit) {
        const v = u64();
        if (bit === 8) maxFee = v;
      }
    }
    const inputs: { owner: string; amount: bigint; assetId: string }[] = [];
    for (let i = 0; i < inputsCount; i++) {
      const type = u64();
      if (type === 0n) {
        b32(); // txID
        u64(); // outputIndex
        const owner = b32();
        const amount = u64();
        const assetId = b32();
        u64(); // txPointer blockHeight
        u64(); // txPointer txIndex
        u64(); // witnessIndex
        u64(); // predicateGasUsed
        const predicateLength = Number(u64());
        const predicateDataLength = Number(u64());
        o += predicateLength + ((8 - (predicateLength % 8)) % 8);
        o += predicateDataLength + ((8 - (predicateDataLength % 8)) % 8);
        inputs.push({ owner, amount, assetId });
      } else if (type === 1n) {
        // Contract input: 32 + 8 + 32 + 32 + 8 + 8
        b32();
        u64();
        b32();
        b32();
        u64();
        u64();
      } else if (type === 2n) {
        // Message: sender, recipient, nonce, witnessIndex, predicateGasUsed, data, predicate, predicateData
        b32();
        b32();
        b32();
        u64();
        u64();
        const dataLength = Number(u64());
        const predicateLength = Number(u64());
        const predicateDataLength = Number(u64());
        o += dataLength + ((8 - (dataLength % 8)) % 8);
        o += predicateLength + ((8 - (predicateLength % 8)) % 8);
        o += predicateDataLength + ((8 - (predicateDataLength % 8)) % 8);
      } else return undefined;
    }
    const outputs: { type: number; to: string; amount: bigint; assetId: string }[] = [];
    for (let i = 0; i < outputsCount; i++) {
      const type = Number(u64());
      if (type === 0 || type === 2 || type === 3) {
        const to = b32();
        const amount = u64();
        const assetId = b32();
        outputs.push({ type, to, amount, assetId });
      } else if (type === 1) {
        u64();
        b32();
        b32();
      } else if (type === 4) {
        b32();
        b32();
      } else return undefined;
    }
    if (o > bytes.length) return undefined;
    return { inputs, outputs, maxFee };
  } catch {
    return undefined;
  }
}

function historyRecord(
  chain: ChainInfo,
  holder: string,
  node: z.infer<typeof HistoryPage>['transactionsByOwner']['nodes'][number],
): TxRecord | undefined {
  const decoded = decodeTransferBytes(node.rawPayload);
  const nativeRef = chain.nativeAsset.ref;
  const failed =
    node.status.__typename === 'FailureStatus' || node.status.__typename === 'SqueezedOutStatus';
  let delta = 0n;
  let from = '';
  let to: string | undefined;
  let contractCall = false;
  if (decoded) {
    let touched = false;
    for (const input of decoded.inputs) {
      if (input.owner === holder && input.assetId === FUEL_BASE_ASSET_ID) {
        delta -= input.amount;
        touched = true;
        if (!from) from = input.owner;
      }
    }
    for (const output of decoded.outputs) {
      if (output.type === 1 || output.type === 4) contractCall = true;
      if (output.type === 0 && output.assetId === FUEL_BASE_ASSET_ID) {
        if (output.to === holder) {
          delta += output.amount;
          touched = true;
        } else if (!to) to = output.to;
      }
    }
    if (!touched) return undefined;
  }
  const fee = from === holder && decoded ? decoded.maxFee : 0n;
  return {
    hash: node.id,
    chainId: chain.chainId,
    from,
    ...(to ? { to } : {}),
    ...(node.status.block?.height ? { blockNumber: Number(node.status.block.height) } : {}),
    ...(contractCall ? { description: 'contract call' } : {}),
    assetDeltas: decoded && delta !== 0n ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: String(fee),
    status: failed
      ? 'failed'
      : node.status.__typename === 'SuccessStatus'
        ? 'confirmed'
        : 'pending',
  };
}

export function createFuelAdapter(opts?: FuelAdapterOptions): FuelAdapter {
  return new FuelAdapter(opts);
}
