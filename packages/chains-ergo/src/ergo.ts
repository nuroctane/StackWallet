/**
 * Ergo adapter. A P2PK address is base58 of `head || compressed pubkey ||
 * blake2b256(head||pubkey)[..4]` where head is 0x01 (mainnet) or 0x11
 * (testnet). Reads go over the public explorer API (`/api/v1`, per-network
 * deployment identified by its height-1 block); box truth and broadcast go
 * over node endpoints (`/info` proves the network by its `network` field).
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  fetchJson,
  postJsonText,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
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
import { ChainInfo as ChainInfoSchema, HttpError } from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const ERGO_MAINNET = 'ergo:mainnet';
export const ERGO_TESTNET = 'ergo:testnet';
/** The protocol fee contract every transfer pays (fleet-sdk `FEE_CONTRACT`). */
export const FEE_CONTRACT =
  '1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304';

const HEAD_MAINNET = 0x01;
const HEAD_TESTNET = 0x11;
/** Height-1 block id: the network fingerprint an explorer endpoint must serve. */
const GENESIS_BLOCK: Record<string, string> = {
  [ERGO_MAINNET]: 'b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b',
  [ERGO_TESTNET]: '5b1827ca092b599eafbaf339d2acf2445bc5216ec2e022d9c001a6fff660cad9',
};

export function blake2b256(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 });
}

/** The 34 raw address bytes (`head || compressed key`) or undefined. */
export function ergoAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^[1-9A-HJ-NP-Za-km-z]{51,52}$/.test(addr)) return undefined;
  let full: Uint8Array;
  try {
    full = base58.decode(addr);
  } catch {
    return undefined;
  }
  if (full.length !== 38) return undefined;
  const payload = full.subarray(0, 34);
  if (payload[0] !== HEAD_MAINNET && payload[0] !== HEAD_TESTNET) return undefined;
  const check = blake2b256(payload);
  for (let i = 0; i < 4; i++) if (full[34 + i] !== check[i]) return undefined;
  return payload;
}

export function isValidErgoAddress(addr: string): boolean {
  return ergoAddressBytes(addr) !== undefined;
}

export function ergoAddressFromPublicKey(sec1: Uint8Array, testnet: boolean): string {
  if (sec1.length !== 33 || (sec1[0] !== 2 && sec1[0] !== 3))
    throw new TypeError('public key must be a compressed SEC1 point');
  const payload = new Uint8Array(34);
  payload[0] = testnet ? HEAD_TESTNET : HEAD_MAINNET;
  payload.set(sec1, 1);
  const full = new Uint8Array(38);
  full.set(payload);
  full.set(blake2b256(payload).subarray(0, 4), 34);
  return base58.encode(full);
}

/** `0008cd || compressed pubkey`: the compiled `Dlog` (P2PK) proposition. */
export function ergoP2pkTree(sec1: Uint8Array): string {
  return `0008cd${bytesToHex(sec1)}`;
}

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const BoxId = z.string().regex(/^[0-9a-f]{64}$/);
const Token = z.object({
  tokenId: z.string().regex(/^[0-9a-f]{64}$/),
  amount: z.union([SafeInt, z.string().regex(/^\d{1,20}$/)]),
});
export const NetworkState = z.object({
  lastBlockId: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
  height: SafeInt,
});
const BlocksPage = z.object({
  items: z.array(z.object({ id: z.string().regex(/^[0-9a-f]{64}$/) })).min(1),
});
const NodeInfo = z.object({
  network: z.string().max(32),
  fullHeight: SafeInt.optional().nullable(),
});
export const Balance = z.object({
  nanoErgs: z.union([SafeInt, z.string().regex(/^\d{1,20}$/)]),
  tokens: z.array(Token).max(256),
});
const OutputInfo = z.object({
  boxId: BoxId,
  value: SafeInt,
  ergoTree: z
    .string()
    .regex(/^[0-9a-f]+$/)
    .max(4096),
  creationHeight: SafeInt,
  address: z.string().max(128).optional(),
  assets: z.array(Token).max(256),
  additionalRegisters: z.record(z.string(), z.string().max(4096)),
  spentTransactionId: BoxId.nullable().optional(),
});
export const BoxesPage = z.object({
  items: z.array(OutputInfo).max(1000),
  total: SafeInt,
});
export const BoxInfo = OutputInfo;
const InputInfo = z.object({
  boxId: BoxId,
  value: SafeInt.optional().nullable(),
  address: z.string().max(128).optional().nullable(),
  assets: z.array(Token).max(256).optional(),
});
const HistoryTx = z.object({
  id: BoxId,
  inclusionHeight: SafeInt,
  timestamp: SafeInt.optional(),
  inputs: z.array(InputInfo).max(256),
  outputs: z.array(OutputInfo).max(256),
});
const HistoryPage = z.object({
  items: z.array(HistoryTx).max(100),
  total: SafeInt,
});

/** Catalog fallback until the lead wires Ergo into `catalog-curated.ts`. */
export const ERGO_CHAINS: ChainInfo[] = [
  ChainInfoSchema.parse({
    chainId: ERGO_MAINNET,
    family: 'ergo',
    name: 'Ergo',
    nativeAsset: { ref: `${ERGO_MAINNET}:native`, symbol: 'ERG', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://explorer.ergoplatform.com/en/transactions/{hash}',
    defaultRpcs: [
      'https://api.ergoplatform.com',
      'http://213.239.193.208:9053',
      'http://159.65.11.55:9053',
    ],
    extra: { coinType: 429 },
    priceId: 'ergo',
    layer: 'L1',
  }),
  ChainInfoSchema.parse({
    chainId: ERGO_TESTNET,
    family: 'ergo',
    name: 'Ergo Testnet',
    nativeAsset: { ref: `${ERGO_TESTNET}:native`, symbol: 'ERG', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://testnet.ergoplatform.com/en/transactions/{hash}',
    defaultRpcs: ['https://api-testnet.ergoplatform.com', 'http://213.239.193.208:9052'],
    extra: { coinType: 429 },
  }),
];

type EndpointKind = 'explorer' | 'node';
export type ErgoAdapterOptions = BaseAdapterOptions;
export type ErgoCall = <T>(path: string, schema: z.ZodType<T>) => Promise<T>;

export class ErgoAdapter extends BaseAdapter<'ergo'> {
  private readonly kinds = new Map<string, EndpointKind>();
  private readonly chainList: ChainInfo[];

  constructor(opts: ErgoAdapterOptions = {}) {
    const catalog = chainsForFamily('ergo');
    const chainList = catalog.length > 0 ? catalog : ERGO_CHAINS;
    super(
      'ergo',
      opts.rpc || catalog.length > 0 ? opts : { ...opts, rpc: new MemoryRpcPool(chainList) },
    );
    this.chainList = chainList;
  }

  override chains(): ChainInfo[] {
    return this.chainList;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    const chain = this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return ergoAddressFromPublicKey(publicKeyBytes(pub), chain.testnet);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    const chain = this.requireChain(chainId);
    const bytes = ergoAddressBytes(addr);
    if (!bytes) return false;
    return bytes[0] === (chain.testnet ? HEAD_TESTNET : HEAD_MAINNET);
  }

  private async get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    return schema.parse(await fetchJson(`${url.replace(/\/$/, '')}${path}`, this.fetchOptions()));
  }

  /** Identify an endpoint once: explorer APIs prove their network by the
   * height-1 block they serve; nodes declare it in `/info`. */
  private async identify(url: string, chainId: ChainId): Promise<EndpointKind> {
    const chain = this.requireChain(chainId);
    const known = this.kinds.get(url);
    if (known) return known;
    let kind: EndpointKind;
    let explorerError: unknown;
    try {
      const genesis = await this.get(url, '/api/v1/blocks?offset=0&limit=1', BlocksPage);
      if (genesis.items[0]?.id !== GENESIS_BLOCK[chainId])
        throw new Error('Endpoint serves a different Ergo network');
      kind = 'explorer';
    } catch (err) {
      explorerError = err;
      // Not an explorer (or it failed); try the node API.
      let info: z.infer<typeof NodeInfo>;
      try {
        info = await this.get(url, '/info', NodeInfo);
      } catch {
        throw explorerError;
      }
      const want = chain.testnet ? 'testnet' : 'mainnet';
      if (info.network !== want) throw new Error(`Endpoint serves ${info.network}, not ${want}`);
      if (info.fullHeight !== undefined && info.fullHeight !== null)
        this.noteBlock(url, info.fullHeight);
      kind = 'node';
    }
    this.kinds.set(url, kind);
    return kind;
  }

  /** Run `query` against the first healthy endpoint of the wanted kind. */
  private withKind<T>(
    chainId: ChainId,
    kind: EndpointKind,
    query: (call: ErgoCall, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      if ((await this.identify(url, chainId)) !== kind)
        throw new Error(`Endpoint is not an Ergo ${kind} API`);
      return query((path, schema) => this.get(url, path, schema), url);
    });
  }

  withExplorer<T>(
    chainId: ChainId,
    query: (call: ErgoCall, url: string) => Promise<T>,
  ): Promise<T> {
    return this.withKind(chainId, 'explorer', query);
  }

  /** POST JSON to a node endpoint (tx broadcast); returns the raw response text. */
  async postNode(chainId: ChainId, path: string, body: unknown): Promise<string> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      if ((await this.identify(url, chainId)) !== 'node')
        throw new Error('Endpoint is not an Ergo node API');
      return postJsonText(`${url.replace(/\/$/, '')}${path}`, body, this.fetchOptions());
    });
  }

  withNode<T>(chainId: ChainId, query: (call: ErgoCall, url: string) => Promise<T>): Promise<T> {
    return this.withKind(chainId, 'node', query);
  }

  /** POST JSON to an explorer endpoint (tx submit); returns the raw response text. */
  async postExplorer(chainId: ChainId, path: string, body: unknown): Promise<string> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      if ((await this.identify(url, chainId)) !== 'explorer')
        throw new Error('Endpoint is not an Ergo explorer API');
      return postJsonText(`${url.replace(/\/$/, '')}${path}`, body, this.fetchOptions());
    });
  }

  /** Current height, from whichever endpoint kind answers first. */
  async height(chainId: ChainId): Promise<{ height: number; url: string }> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      const kind = await this.identify(url, chainId);
      if (kind === 'explorer') {
        const state = await this.get(url, '/api/v1/networkState', NetworkState);
        return { height: state.height, url };
      }
      const info = await this.get(url, '/info', NodeInfo);
      if (info.fullHeight === undefined || info.fullHeight === null)
        throw new Error('Node did not report a height');
      return { height: info.fullHeight, url };
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!this.validateAddress(addr, chainId)) throw new TypeError(`invalid ergo address ${addr}`);
    const result = await withFailover(this.rpc, chainId, async (url) => {
      if ((await this.identify(url, chainId)) !== 'explorer')
        throw new Error('Endpoint is not an Ergo explorer API');
      const balance = await this.get(url, `/api/v1/addresses/${addr}/balance/confirmed`, Balance);
      return { balance, url };
    });
    const native = nativeHolding(chain, BigInt(result.balance.nanoErgs).toString(), {
      kind: 'single',
      endpoint: result.url,
    });
    const notice = 'Confirmed balance from the Ergo explorer; mempool deltas are not included.';
    if (result.balance.tokens.length > 0) native.notice = notice;
    const tokens: Holding[] = result.balance.tokens.map((t) => ({
      assetRef: `${chainId}:token:${t.tokenId}`,
      amount: BigInt(t.amount).toString(),
      updatedAtMs: Date.now(),
      provenance: { kind: 'single', endpoint: result.url },
      metadata: { symbol: t.tokenId.slice(0, 8), decimals: 0 },
      notice:
        'Ergo token amount in raw units; token metadata is not served by the explorer balance endpoint.',
    }));
    return [native, ...tokens];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!this.validateAddress(addr, chainId)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,10}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const offset = cursor === undefined ? 0 : Number(cursor);
    const limit = 20;
    return this.withExplorer(chainId, async (call, url) => {
      const page = await call(
        `/api/v1/addresses/${addr}/transactions?limit=${limit}&offset=${offset}`,
        HistoryPage,
      );
      const nextOffset = offset + page.items.length;
      return {
        items: page.items.map((t) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t)),
        ...(nextOffset < page.total ? { nextCursor: String(nextOffset) } : {}),
        coverage:
          'Ergo explorer address transactions. Deltas are net ERG movement; tokens are not tracked. Fees attribute the whole input-minus-output difference to this address when it funded any input.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('Invalid Ergo transaction id');
    this.requireChain(chainId);
    // A confirmed transaction is in the explorer; the mempool is only visible
    // to node endpoints.
    const confirmed = await withFailover(this.rpc, chainId, async (url) => {
      if ((await this.identify(url, chainId)) !== 'explorer')
        throw new Error('Endpoint is not an Ergo explorer API');
      try {
        const tx = await this.get(url, `/api/v1/transactions/${hash}`, HistoryTx);
        return {
          state: 'confirmed',
          blockNumber: tx.inclusionHeight,
          ...(tx.timestamp !== undefined ? { timestampMs: tx.timestamp } : {}),
        } as TxStatus;
      } catch (err) {
        if (err instanceof HttpError && err.status === 404) return null;
        throw err;
      }
    });
    if (confirmed) return confirmed;
    // Browser bundles usually have only explorer endpoints (nodes are
    // HTTP-only); without a node the mempool is invisible, not an error.
    try {
      const pending = await withFailover(this.rpc, chainId, async (url) => {
        if ((await this.identify(url, chainId)) !== 'node')
          throw new Error('Endpoint is not an Ergo node API');
        try {
          await this.get(url, `/transactions/unconfirmed/byTransactionId/${hash}`, z.unknown());
          return true;
        } catch (err) {
          if (err instanceof HttpError && err.status === 404) return false;
          throw err;
        }
      });
      return pending ? { state: 'pending' } : { state: 'unknown' };
    } catch {
      return { state: 'unknown' };
    }
  }
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof HistoryTx>,
): TxRecord {
  let delta = 0n;
  let funded = false;
  for (const input of t.inputs) {
    if (input.address === holder && input.value !== undefined && input.value !== null) {
      delta -= BigInt(input.value);
      funded = true;
    }
  }
  let outSum = 0n;
  for (const output of t.outputs) {
    outSum += BigInt(output.value);
    if (output.address === holder) delta += BigInt(output.value);
  }
  let inSum = 0n;
  for (const input of t.inputs)
    if (input.value !== undefined && input.value !== null) inSum += BigInt(input.value);
  const firstOut = t.outputs.find((o) => o.address && o.address !== holder) ?? t.outputs[0];
  return {
    hash: t.id,
    chainId,
    from: t.inputs[0]?.address ?? '',
    ...(firstOut?.address ? { to: firstOut.address } : {}),
    blockNumber: t.inclusionHeight,
    ...(t.timestamp !== undefined ? { timestampMs: t.timestamp } : {}),
    assetDeltas: delta !== 0n ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: funded ? String(inSum - outSum) : null,
    status: 'confirmed',
  };
}

export function createErgoAdapter(opts?: ErgoAdapterOptions): ErgoAdapter {
  return new ErgoAdapter(opts);
}
