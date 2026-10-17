/**
 * Sui adapter, with read-only IOTA Rebased networks. Addresses are 0x + 64 hex
 * digits: blake2b-256(0x00 || key) on Sui, blake2b-256(key) on IOTA. Public Sui
 * fullnodes retired JSON-RPC, so Sui reads and broadcasts go over the Mysten
 * GraphQL service; IOTA still serves JSON-RPC (`iotax_*`). Every endpoint
 * proves its chain identifier before it is trusted.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  JsonRpcError,
  MalformedResponseError,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
  type AssetDelta,
  type BaseAdapterOptions,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const SUI_MAINNET = 'sui:mainnet';
export const SUI_TESTNET = 'sui:testnet';
export const SUI_DEVNET = 'sui:devnet';
export const IOTA_MAINNET = 'iota:mainnet';
export const IOTA_TESTNET = 'iota:testnet';

/** GraphQL `chainIdentifier`: base58 of the genesis checkpoint digest. Devnet resets, so it is not pinned. */
export const SUI_CHAIN_IDENTIFIERS: Record<string, string> = {
  [SUI_MAINNET]: '4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S',
  [SUI_TESTNET]: '69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD',
};
/** JSON-RPC `iota_getChainIdentifier`: the first four genesis checkpoint digest bytes. */
export const IOTA_CHAIN_IDENTIFIERS: Record<string, string> = {
  [IOTA_MAINNET]: '6364aad5',
  [IOTA_TESTNET]: '2304aa97',
};

export const SUI_COIN_TYPE = '0x2::sui::SUI';
export const IOTA_COIN_TYPE = '0x2::iota::IOTA';
const SUI_COIN_TYPE_LONG = `0x${'0'.repeat(63)}2::sui::SUI`;
const IOTA_COIN_TYPE_LONG = `0x${'0'.repeat(63)}2::iota::IOTA`;
export const SUI_GAS_COIN_OBJECT_TYPE = '0x2::coin::Coin<0x2::sui::SUI>';
/** Circle's native USDC on Sui mainnet (6 decimals). */
export const SUI_USDC_TYPE =
  '0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC';

export const isIotaChain = (chainId: string): boolean => chainId.startsWith('iota:');

export function suiAddressFromPublicKey(key: Uint8Array): string {
  if (key.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  const pre = new Uint8Array(33);
  pre.set(key, 1);
  return `0x${bytesToHex(blake2b(pre, { dkLen: 32 }))}`;
}

/** IOTA Rebased keeps its Stardust-era rule: Ed25519 addresses hash the key without a flag. */
export function iotaAddressFromPublicKey(key: Uint8Array): string {
  if (key.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  return `0x${bytesToHex(blake2b(key, { dkLen: 32 }))}`;
}

/** Full-length `0x` + 64 hex only; short forms like `0x2` name system objects, not accounts. */
export function isValidSuiAddress(addr: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(addr);
}

export function normalizeSuiAddress(addr: string): string {
  if (!isValidSuiAddress(addr)) throw new TypeError(`invalid Sui address ${addr}`);
  return addr.toLowerCase();
}

export function suiAddressBytes(addr: string): Uint8Array {
  return hexToBytes(normalizeSuiAddress(addr).slice(2));
}

/** A transaction or object digest: base58 of exactly 32 bytes. */
export function isSuiDigest(value: string): boolean {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) return false;
  try {
    return base58.decode(value).length === 32;
  } catch {
    return false;
  }
}

export function suiAssetRef(chainId: string, coinType: string): string {
  return `${chainId}:coin:${coinType}`;
}

const U64 = z.string().regex(/^\d{1,20}$/);
const I64 = z.string().regex(/^-?\d{1,20}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const HexAddress = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const Digest = z.string().refine(isSuiDigest, 'not a 32-byte base58 digest');
const Cursor = z.string().regex(/^[A-Za-z0-9+/=_-]{1,256}$/);

export class SuiGraphQLError extends Error {
  override readonly name = 'SuiGraphQLError';
  constructor(
    readonly url: string,
    readonly messages: string[],
    readonly code: string | undefined,
  ) {
    super(`GraphQL error from ${url}: ${messages.join('; ').slice(0, 512)}`);
  }
}

const GqlEnvelope = z.object({
  data: z.unknown().optional(),
  errors: z
    .array(
      z
        .object({
          message: z.string().transform((m) => m.slice(0, 512)),
          extensions: z
            .object({ code: z.string().max(64).optional() })
            .loose()
            .optional(),
        })
        .loose(),
    )
    .max(50)
    .optional(),
});

const BalanceField = z.object({ totalBalance: U64.nullable() }).nullable();
const BalancesQuery = z.object({
  address: z.object({ native: BalanceField, usdc: BalanceField.optional() }).nullable(),
});

export const GasCoin = z.object({
  address: HexAddress,
  version: SafeInt,
  digest: Digest,
  contents: z.object({ json: z.object({ balance: U64 }).loose() }),
});
const CoinsQuery = z.object({
  address: z
    .object({
      native: BalanceField,
      objects: z.object({ nodes: z.array(GasCoin).max(50) }),
    })
    .nullable(),
  epoch: z.object({ referenceGasPrice: U64 }).nullable(),
});
export interface SuiCoin {
  objectId: string;
  version: number;
  digest: string;
  balance: bigint;
}
export interface SuiCoins {
  coins: SuiCoin[];
  /** Coin objects plus any address (accumulator) balance. */
  totalBalance: bigint;
  referenceGasPrice: bigint;
}

const ObjectsQuery = z.object({
  multiGetObjects: z
    .array(
      z
        .object({
          address: HexAddress,
          version: SafeInt,
          digest: Digest,
          owner: z
            .object({
              __typename: z.string().max(64),
              address: z.object({ address: HexAddress }).nullable().optional(),
            })
            .nullable(),
        })
        .nullable(),
    )
    .max(50),
  epoch: z.object({ referenceGasPrice: U64 }).nullable(),
});
export interface SuiObjectState {
  objectId: string;
  version: number;
  digest: string;
  /** The owning address when the object is address-owned; undefined otherwise. */
  owner: string | undefined;
}

const GasSummary = z.object({
  computationCost: SafeInt,
  storageCost: SafeInt,
  storageRebate: SafeInt,
  nonRefundableStorageFee: SafeInt.optional(),
});
const BalanceChanges = z.object({
  nodes: z
    .array(
      z.object({
        owner: z.object({ address: HexAddress }).nullable(),
        coinType: z.object({ repr: z.string().max(512) }).nullable(),
        amount: I64.nullable(),
      }),
    )
    .max(50),
});
const Effects = z.object({
  digest: Digest.optional(),
  status: z.enum(['SUCCESS', 'FAILURE']).nullable(),
  timestamp: z.string().max(64).nullable().optional(),
  checkpoint: z.object({ sequenceNumber: SafeInt }).nullable().optional(),
  executionError: z
    .object({ message: z.string().transform((m) => m.slice(0, 512)) })
    .nullable()
    .optional(),
  gasEffects: z.object({ gasSummary: GasSummary.nullable() }).nullable().optional(),
  balanceChanges: BalanceChanges.nullable().optional(),
});
export type SuiEffects = z.infer<typeof Effects>;
const StatusQuery = z.object({
  transaction: z.object({ digest: Digest, effects: Effects.nullable() }).nullable(),
});
const HistoryTx = z.object({
  digest: Digest,
  sender: z.object({ address: HexAddress }).nullable(),
  gasInput: z.object({ gasSponsor: z.object({ address: HexAddress }).nullable() }).nullable(),
  effects: Effects.nullable(),
});
const HistoryQuery = z.object({
  address: z
    .object({
      transactions: z.object({
        pageInfo: z.object({ hasPreviousPage: z.boolean(), startCursor: Cursor.nullable() }),
        nodes: z.array(HistoryTx).max(50),
      }),
    })
    .nullable(),
});
const SimulateQuery = z.object({ simulateTransaction: z.object({ effects: Effects.nullable() }) });
const ExecuteMutation = z.object({ executeTransaction: z.object({ effects: Effects.nullable() }) });

const IotaBalance = z.object({ coinType: z.string().max(512), totalBalance: U64 });
const IotaTxBlock = z.object({
  digest: Digest,
  transaction: z
    .object({
      data: z
        .object({ sender: HexAddress, gasData: z.object({ owner: HexAddress }).loose() })
        .loose(),
    })
    .loose()
    .optional(),
  effects: z
    .object({
      status: z.object({
        status: z.enum(['success', 'failure']),
        error: z.string().max(512).optional(),
      }),
      gasUsed: z.object({ computationCost: U64, storageCost: U64, storageRebate: U64 }).loose(),
    })
    .loose()
    .optional(),
  balanceChanges: z
    .array(
      z.object({
        owner: z.union([z.object({ AddressOwner: HexAddress }).loose(), z.unknown()]),
        coinType: z.string().max(512),
        amount: I64,
      }),
    )
    .max(100)
    .optional(),
  timestampMs: U64.optional(),
  checkpoint: U64.optional(),
});
const IotaTxPage = z.object({
  data: z.array(IotaTxBlock).max(50),
  nextCursor: Digest.nullable().optional(),
  hasNextPage: z.boolean(),
});

const BALANCES_QUERY = `query($a: SuiAddress!, $usdc: String!, $withUsdc: Boolean!) {
  address(address: $a) {
    native: balance(coinType: "${SUI_COIN_TYPE}") { totalBalance }
    usdc: balance(coinType: $usdc) @include(if: $withUsdc) { totalBalance }
  }
}`;
const COINS_QUERY = `query($a: SuiAddress!) {
  address(address: $a) {
    native: balance(coinType: "${SUI_COIN_TYPE}") { totalBalance }
    objects(first: 50, filter: { type: "${SUI_GAS_COIN_OBJECT_TYPE}" }) { nodes { address version digest contents { json } } }
  }
  epoch { referenceGasPrice }
}`;
const OBJECTS_QUERY = `query($k: [ObjectKey!]!) {
  multiGetObjects(keys: $k) { address version digest owner { __typename ... on AddressOwner { address { address } } } }
  epoch { referenceGasPrice }
}`;
const EFFECTS_FIELDS = `digest status timestamp checkpoint { sequenceNumber } executionError { message }
  gasEffects { gasSummary { computationCost storageCost storageRebate nonRefundableStorageFee } }
  balanceChanges(first: 50) { nodes { owner { address } coinType { repr } amount } }`;
const STATUS_QUERY = `query($d: String!) { transaction(digest: $d) { digest effects { ${EFFECTS_FIELDS} } } }`;
const HISTORY_QUERY = `query($a: SuiAddress!, $before: String) {
  address(address: $a) {
    transactions(last: 20, before: $before, relation: AFFECTED) {
      pageInfo { hasPreviousPage startCursor }
      nodes { digest sender { address } gasInput { gasSponsor { address } } effects { ${EFFECTS_FIELDS} } }
    }
  }
}`;
const SIMULATE_QUERY = `query($t: JSON!) { simulateTransaction(transaction: $t) { effects { ${EFFECTS_FIELDS} } } }`;
const EXECUTE_MUTATION = `mutation($b: Base64!, $s: [Base64!]!) {
  executeTransaction(transactionDataBcs: $b, signatures: $s) { effects { ${EFFECTS_FIELDS} } }
}`;

/** Net gas: computation plus storage minus the storage rebate (can be negative). */
export function netGas(summary: z.infer<typeof GasSummary>): bigint {
  return (
    BigInt(summary.computationCost) + BigInt(summary.storageCost) - BigInt(summary.storageRebate)
  );
}

export type SuiAdapterOptions = BaseAdapterOptions;
export type SuiGql = <T>(
  query: string,
  variables: Record<string, unknown>,
  schema: z.ZodType<T>,
) => Promise<T>;

export class SuiAdapter extends BaseAdapter<'sui'> {
  constructor(opts: SuiAdapterOptions = {}) {
    super('sui', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    const key = publicKeyBytes(pub);
    return isIotaChain(chainId) ? iotaAddressFromPublicKey(key) : suiAddressFromPublicKey(key);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidSuiAddress(addr);
  }

  private async gqlAt<T>(
    url: string,
    query: string,
    variables: Record<string, unknown>,
    schema: z.ZodType<T>,
  ): Promise<T> {
    const text = await postJsonText(url, { query, variables }, this.fetchOptions());
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      throw new MalformedResponseError(url, 'body is not JSON');
    }
    const env = GqlEnvelope.safeParse(raw);
    if (!env.success) throw new MalformedResponseError(url, 'not a GraphQL response');
    if (env.data.errors?.length)
      throw new SuiGraphQLError(
        url,
        env.data.errors.map((e) => e.message),
        env.data.errors[0]?.extensions?.code,
      );
    return schema.parse(env.data.data);
  }

  private async checkSui(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const { chainIdentifier } = await this.gqlAt(
        url,
        '{ chainIdentifier }',
        {},
        z.object({ chainIdentifier: z.string().max(64) }),
      );
      const expected = SUI_CHAIN_IDENTIFIERS[chainId];
      const known = Object.values(SUI_CHAIN_IDENTIFIERS);
      if (expected ? chainIdentifier !== expected : known.includes(chainIdentifier))
        throw new Error('Endpoint chain identifier does not match this Sui network');
    });
  }

  private async checkIota(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const id = await this.jsonRpc('iota_getChainIdentifier', [], z.string().max(64))(url);
      if (id !== IOTA_CHAIN_IDENTIFIERS[chainId])
        throw new Error('Endpoint chain identifier does not match this IOTA network');
    });
  }

  /** Keep dependent GraphQL observations on one Sui endpoint that proved its network. */
  withGraphql<T>(chainId: ChainId, query: (gql: SuiGql, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    if (isIotaChain(chainId)) throw new Error('IOTA networks are read over JSON-RPC');
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkSui(chainId, url);
      return query((q, v, s) => this.gqlAt(url, q, v, s), url);
    });
  }

  private withIota<T>(chainId: ChainId, query: (url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkIota(chainId, url);
      return query(url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const owner = normalizeSuiAddress(addr);
    if (isIotaChain(chainId)) {
      const { value, provenance } = await withCrossCheck(
        this.rpc,
        chainId,
        async (url) => {
          await this.checkIota(chainId, url);
          const b = await this.jsonRpc(
            'iotax_getBalance',
            [owner, IOTA_COIN_TYPE],
            IotaBalance,
          )(url);
          return b.totalBalance;
        },
        { equal: (a, b) => a === b },
      );
      return [nativeHolding(chain, value, provenance)];
    }
    const withUsdc = chainId === SUI_MAINNET;
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkSui(chainId, url);
        const r = await this.gqlAt(
          url,
          BALANCES_QUERY,
          { a: owner, usdc: SUI_USDC_TYPE, withUsdc },
          BalancesQuery,
        );
        return JSON.stringify([
          r.address?.native?.totalBalance ?? '0',
          r.address?.usdc?.totalBalance ?? '0',
        ]);
      },
      { equal: (a, b) => a === b },
    );
    const [native, usdc] = JSON.parse(value) as [string, string];
    const holdings = [nativeHolding(chain, native, provenance)];
    if (withUsdc)
      holdings.push({
        assetRef: suiAssetRef(chainId, SUI_USDC_TYPE),
        amount: usdc,
        provenance,
        metadata: { symbol: 'USDC', decimals: 6 },
        notice: 'Coin balance from Sui GraphQL; token transfers are not enabled.',
        updatedAtMs: Date.now(),
      });
    return holdings;
  }

  /** The sender's SUI coin objects (largest first, at most 50) and the epoch's reference gas price. */
  async coins(addr: Address, chainId: ChainId): Promise<SuiCoins> {
    const owner = normalizeSuiAddress(addr);
    return this.withGraphql(chainId, async (gql) => {
      const r = await gql(COINS_QUERY, { a: owner }, CoinsQuery);
      if (!r.epoch) throw new Error('Sui GraphQL did not report the reference gas price');
      const coins = (r.address?.objects.nodes ?? [])
        .map((c) => ({
          objectId: c.address.toLowerCase(),
          version: c.version,
          digest: c.digest,
          balance: BigInt(c.contents.json.balance),
        }))
        .sort((a, b) => (a.balance === b.balance ? 0 : a.balance > b.balance ? -1 : 1));
      return {
        coins,
        totalBalance: BigInt(r.address?.native?.totalBalance ?? '0'),
        referenceGasPrice: BigInt(r.epoch.referenceGasPrice),
      };
    });
  }

  /** Current versions and owners of objects (null where the object no longer exists). */
  async objects(
    ids: string[],
    chainId: ChainId,
  ): Promise<{ objects: (SuiObjectState | null)[]; referenceGasPrice: bigint }> {
    if (ids.length === 0 || ids.length > 50) throw new Error('Ask for 1 to 50 objects');
    const keys = ids.map((id) => ({ address: normalizeSuiAddress(id) }));
    return this.withGraphql(chainId, async (gql) => {
      const r = await gql(OBJECTS_QUERY, { k: keys }, ObjectsQuery);
      if (!r.epoch) throw new Error('Sui GraphQL did not report the reference gas price');
      if (r.multiGetObjects.length !== ids.length)
        throw new Error('Object lookup returned a different count');
      return {
        objects: r.multiGetObjects.map((o) =>
          o
            ? {
                objectId: o.address.toLowerCase(),
                version: o.version,
                digest: o.digest,
                owner:
                  o.owner?.__typename === 'AddressOwner' && o.owner.address
                    ? o.owner.address.address.toLowerCase()
                    : undefined,
              }
            : null,
        ),
        referenceGasPrice: BigInt(r.epoch.referenceGasPrice),
      };
    });
  }

  /** Dry-run unsigned transaction bytes; returns the effects the network predicts. */
  async dryRun(txBcsBase64: string, chainId: ChainId): Promise<SuiEffects> {
    return this.withGraphql(chainId, async (gql) => {
      const r = await gql(SIMULATE_QUERY, { t: { bcs: { value: txBcsBase64 } } }, SimulateQuery);
      if (!r.simulateTransaction.effects) throw new Error('Simulation returned no effects');
      return r.simulateTransaction.effects;
    });
  }

  /**
   * Submit signed bytes. A GraphQL error with BAD_USER_INPUT is the network
   * refusing the transaction and is returned, not retried on another endpoint.
   */
  async execute(
    chainId: ChainId,
    txBcsBase64: string,
    signatureBase64: string,
  ): Promise<{ effects: SuiEffects | null } | { rejected: string }> {
    return this.withGraphql(chainId, async (gql) => {
      try {
        const r = await gql(
          EXECUTE_MUTATION,
          { b: txBcsBase64, s: [signatureBase64] },
          ExecuteMutation,
        );
        return { effects: r.executeTransaction.effects };
      } catch (err) {
        if (err instanceof SuiGraphQLError && err.code === 'BAD_USER_INPUT')
          return { rejected: err.messages.join('; ').slice(0, 512) };
        throw err;
      }
    });
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidSuiAddress(addr)) throw new Error('Invalid history address');
    const holder = addr.toLowerCase();
    if (isIotaChain(chainId))
      return this.iotaHistory(holder, chainId, chain.nativeAsset.ref, cursor);
    if (cursor !== undefined && !Cursor.safeParse(cursor).success)
      throw new Error('Invalid history cursor');
    if (options?.signal?.aborted) throw options.signal.reason ?? new Error('aborted');
    return this.withGraphql(chainId, async (gql, url) => {
      const r = await gql(HISTORY_QUERY, { a: holder, before: cursor ?? null }, HistoryQuery);
      const page = r.address?.transactions;
      if (!page) return { items: [], source: url };
      const items = page.nodes
        .map((t) => suiRecord(chainId, chain.nativeAsset.ref, holder, t))
        .reverse();
      return {
        items,
        ...(page.pageInfo.hasPreviousPage && page.pageInfo.startCursor
          ? { nextCursor: page.pageInfo.startCursor }
          : {}),
        coverage:
          'Sui GraphQL transactions that affected this address, newest first. Amounts are SUI balance changes net of gas.',
        source: url,
      };
    });
  }

  /**
   * IOTA nodes cannot filter "from or to" in one query, so a page merges a
   * FromAddress and a ToAddress page; the cursor carries both positions.
   */
  private async iotaHistory(
    holder: string,
    chainId: ChainId,
    nativeRef: string,
    cursor?: string,
  ): Promise<Page<TxRecord>> {
    let pos: { f: string | null; t: string | null } = { f: null, t: null };
    if (cursor !== undefined) {
      const m = /^([1-9A-HJ-NP-Za-km-z]{0,44})\.([1-9A-HJ-NP-Za-km-z]{0,44})$/.exec(cursor);
      if (!m) throw new Error('Invalid history cursor');
      pos = { f: m[1] || null, t: m[2] || null };
      if ((pos.f && !isSuiDigest(pos.f)) || (pos.t && !isSuiDigest(pos.t)) || (!pos.f && !pos.t))
        throw new Error('Invalid history cursor');
    }
    const options = { showInput: true, showEffects: true, showBalanceChanges: true };
    const limit = 10;
    return this.withIota(chainId, async (url) => {
      const fetchSide = (filter: Record<string, string>, after: string | null, done: boolean) =>
        done
          ? Promise.resolve({ data: [], hasNextPage: false, nextCursor: null })
          : this.jsonRpc(
              'iotax_queryTransactionBlocks',
              [{ filter, options }, after, limit, true],
              IotaTxPage,
            )(url);
      const first = cursor === undefined;
      const [sent, received] = await Promise.all([
        fetchSide({ FromAddress: holder }, pos.f, !first && !pos.f),
        fetchSide({ ToAddress: holder }, pos.t, !first && !pos.t),
      ]);
      const seen = new Set<string>();
      const items = [...sent.data, ...received.data]
        .filter((t) => (seen.has(t.digest) ? false : (seen.add(t.digest), true)))
        .map((t) => iotaRecord(chainId, nativeRef, holder, t))
        .sort((a, b) => (b.timestampMs ?? 0) - (a.timestampMs ?? 0));
      const f = sent.hasNextPage && sent.nextCursor ? sent.nextCursor : '';
      const t = received.hasNextPage && received.nextCursor ? received.nextCursor : '';
      return {
        items,
        ...(f || t ? { nextCursor: `${f}.${t}` } : {}),
        coverage:
          'IOTA JSON-RPC transactions sent from or received by this address. Page boundaries of the two lists can interleave.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!isSuiDigest(hash)) throw new Error('Invalid Sui transaction digest');
    if (isIotaChain(chainId)) {
      return this.withIota(chainId, async (url) => {
        let tx: z.infer<typeof IotaTxBlock>;
        try {
          tx = await this.jsonRpc(
            'iota_getTransactionBlock',
            [hash, { showEffects: true }],
            IotaTxBlock,
          )(url);
        } catch (err) {
          // -32003: the node does not know the digest.
          if (err instanceof JsonRpcError && err.code === -32003) return { state: 'unknown' };
          throw err;
        }
        if (!tx.effects || !tx.checkpoint) return { state: 'pending' };
        if (tx.effects.status.status === 'failure')
          return { state: 'failed', reason: tx.effects.status.error ?? 'execution failed' };
        return {
          state: 'confirmed',
          blockNumber: Number(tx.checkpoint),
          ...(tx.timestampMs ? { timestampMs: Number(tx.timestampMs) } : {}),
        };
      });
    }
    return this.withGraphql(chainId, async (gql) => {
      const r = await gql(STATUS_QUERY, { d: hash }, StatusQuery);
      return effectsStatus(r.transaction?.effects ?? null, r.transaction !== null);
    });
  }
}

/** Map effects to a status; a known digest without a checkpoint is still pending. */
export function effectsStatus(effects: SuiEffects | null, known: boolean): TxStatus {
  if (!known) return { state: 'unknown' };
  if (!effects || !effects.status || !effects.checkpoint) return { state: 'pending' };
  if (effects.status === 'FAILURE')
    return { state: 'failed', reason: effects.executionError?.message ?? 'execution failed' };
  const ts = effects.timestamp ? Date.parse(effects.timestamp) : NaN;
  return {
    state: 'confirmed',
    blockNumber: effects.checkpoint.sequenceNumber,
    ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
  };
}

function suiRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof HistoryTx>,
): TxRecord {
  const effects = t.effects;
  const from = t.sender?.address.toLowerCase() ?? '';
  const payer = (t.gasInput?.gasSponsor?.address ?? from).toLowerCase();
  const summary = effects?.gasEffects?.gasSummary ?? null;
  const gas = summary ? netGas(summary) : null;
  const changes = (effects?.balanceChanges?.nodes ?? []).filter(
    (c) => c.owner && c.coinType && c.amount,
  );
  let native = 0n;
  const tokens = new Map<string, bigint>();
  const others: string[] = [];
  for (const c of changes) {
    const owner = c.owner!.address.toLowerCase();
    const type = c.coinType!.repr;
    const amount = BigInt(c.amount!);
    if (owner !== holder) {
      if (type === SUI_COIN_TYPE_LONG && amount > 0n) others.push(owner);
      continue;
    }
    if (type === SUI_COIN_TYPE_LONG) native += amount;
    else tokens.set(type, (tokens.get(type) ?? 0n) + amount);
  }
  // Balance changes already include the gas the payer was charged; the fee is listed separately.
  // A net storage rebate is not a negative fee: it stays in the native delta.
  const fee = paidFee(payer, holder, gas);
  if (fee !== null) native += fee;
  const deltas: AssetDelta[] = [];
  if (native !== 0n) deltas.push({ assetRef: nativeRef, amount: native.toString() });
  for (const [type, amount] of tokens) {
    if (amount === 0n) continue;
    const usdc = chainId === SUI_MAINNET && type === longCoinType(SUI_USDC_TYPE);
    deltas.push({
      assetRef: suiAssetRef(chainId, type),
      amount: amount.toString(),
      ...(usdc ? { symbol: 'USDC', decimals: 6 } : {}),
    });
  }
  const status = effectsStatus(effects ?? null, true);
  const to = from === holder ? (others.length === 1 ? others[0] : undefined) : holder;
  return {
    hash: t.digest,
    chainId,
    from,
    ...(to ? { to } : {}),
    ...(status.state === 'confirmed'
      ? {
          blockNumber: status.blockNumber,
          ...(status.timestampMs ? { timestampMs: status.timestampMs } : {}),
        }
      : {}),
    assetDeltas: deltas,
    feeAssetRef: nativeRef,
    fee: fee === null ? null : fee.toString(),
    status:
      status.state === 'failed' ? 'failed' : status.state === 'confirmed' ? 'confirmed' : 'pending',
  };
}

function paidFee(payer: string, holder: string, gas: bigint | null): bigint | null {
  if (payer !== holder || gas === null) return null;
  return gas > 0n ? gas : 0n;
}

function iotaRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof IotaTxBlock>,
): TxRecord {
  const from = t.transaction?.data.sender.toLowerCase() ?? '';
  const payer = t.transaction?.data.gasData.owner.toLowerCase() ?? from;
  const used = t.effects?.gasUsed;
  const gas = used
    ? BigInt(used.computationCost) + BigInt(used.storageCost) - BigInt(used.storageRebate)
    : null;
  let native = 0n;
  const others: string[] = [];
  for (const c of t.balanceChanges ?? []) {
    const owner =
      typeof c.owner === 'object' && c.owner !== null && 'AddressOwner' in c.owner
        ? String((c.owner as { AddressOwner: string }).AddressOwner).toLowerCase()
        : undefined;
    const native_ = c.coinType === IOTA_COIN_TYPE || c.coinType === IOTA_COIN_TYPE_LONG;
    if (!owner || !native_) continue;
    if (owner === holder) native += BigInt(c.amount);
    else if (BigInt(c.amount) > 0n) others.push(owner);
  }
  const fee = paidFee(payer, holder, gas);
  if (fee !== null) native += fee;
  const failed = t.effects?.status.status === 'failure';
  const to = from === holder ? (others.length === 1 ? others[0] : undefined) : holder;
  return {
    hash: t.digest,
    chainId,
    from,
    ...(to ? { to } : {}),
    ...(t.checkpoint ? { blockNumber: Number(t.checkpoint) } : {}),
    ...(t.timestampMs ? { timestampMs: Number(t.timestampMs) } : {}),
    assetDeltas: native !== 0n ? [{ assetRef: nativeRef, amount: native.toString() }] : [],
    feeAssetRef: nativeRef,
    fee: fee === null ? null : fee.toString(),
    status: failed ? 'failed' : t.checkpoint ? 'confirmed' : 'pending',
  };
}

/** `0x2::sui::SUI` -> the zero-padded address form GraphQL reports in `repr`. */
export function longCoinType(type: string): string {
  const m = /^0x([0-9a-fA-F]{1,64})(::.+)$/.exec(type);
  if (!m) return type;
  return `0x${m[1]!.toLowerCase().padStart(64, '0')}${m[2]}`;
}

export function createSuiAdapter(opts?: SuiAdapterOptions): SuiAdapter {
  return new SuiAdapter(opts);
}
