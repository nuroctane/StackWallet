/**
 * Tezos adapter. Implicit addresses are base58check of a curve-tagged
 * blake2b-160 key hash; reads go over the Octez node RPC, whose
 * `/chains/main/chain_id` is the CAIP-2 reference, so every endpoint proves
 * which network it serves. History and operation lookup come from TzKT, which
 * reports the same chain id from `/v1/head`.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { createBase58check } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  MemoryRpcPool,
  fetchJson,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type ChainInfo,
  type Holding,
  type HistoryOptions,
  type Page,
  type RpcPool,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const TEZOS_MAINNET = 'tezos:NetXdQprcVkpaWU';
/** Shadownet, the long-running application testnet that replaced Ghostnet. */
export const TEZOS_SHADOWNET = 'tezos:NetXsqzbfFenSTS';

export interface TezosNetwork {
  /** TzKT API base urls, in priority order. */
  indexers: string[];
}

export const NETWORKS: Record<string, TezosNetwork> = {
  [TEZOS_MAINNET]: { indexers: ['https://api.tzkt.io'] },
  [TEZOS_SHADOWNET]: { indexers: ['https://api.shadownet.tzkt.io'] },
};

const b58 = createBase58check(sha256);

export const PREFIX = {
  tz1: Uint8Array.of(6, 161, 159),
  tz2: Uint8Array.of(6, 161, 161),
  tz3: Uint8Array.of(6, 161, 164),
  tz4: Uint8Array.of(6, 161, 166),
  block: Uint8Array.of(1, 52),
  operation: Uint8Array.of(5, 116),
  edpk: Uint8Array.of(13, 15, 37, 217),
  edsig: Uint8Array.of(9, 245, 205, 134, 18),
} as const;
const IMPLICIT = ['tz1', 'tz2', 'tz3', 'tz4'] as const;

export function b58checkEncode(prefix: Uint8Array, payload: Uint8Array): string {
  const full = new Uint8Array(prefix.length + payload.length);
  full.set(prefix);
  full.set(payload, prefix.length);
  return b58.encode(full);
}

export function b58checkDecode(
  value: string,
  prefix: Uint8Array,
  length: number,
): Uint8Array | undefined {
  if (value.length > 64 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(value)) return undefined;
  try {
    const bytes = b58.decode(value);
    if (bytes.length !== prefix.length + length) return undefined;
    if (!prefix.every((b, i) => bytes[i] === b)) return undefined;
    const payload = bytes.slice(prefix.length);
    return b58checkEncode(prefix, payload) === value ? payload : undefined;
  } catch {
    return undefined;
  }
}

/** The binary `public_key_hash`: a curve tag (tz1 0, tz2 1, tz3 2, tz4 3) and 20 bytes. */
export function tezosAddressBytes(addr: string): Uint8Array | undefined {
  const tag = IMPLICIT.indexOf(addr.slice(0, 3) as (typeof IMPLICIT)[number]);
  if (tag < 0) return undefined;
  const hash = b58checkDecode(addr, PREFIX[IMPLICIT[tag]!], 20);
  if (!hash || hash.every((b) => b === 0)) return undefined;
  const out = new Uint8Array(21);
  out[0] = tag;
  out.set(hash, 1);
  return out;
}

/** Implicit accounts only; KT1 contracts and rollups are not transfer destinations here. */
export function isValidTezosAddress(addr: string): boolean {
  return tezosAddressBytes(addr) !== undefined;
}

export function tezosAddressFromPublicKey(ed25519: Uint8Array): string {
  if (ed25519.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  return b58checkEncode(PREFIX.tz1, blake2b(ed25519, { dkLen: 20 }));
}

export const OpHash = z.string().regex(/^o[1-9A-HJ-NP-Za-km-z]{50}$/);
export const BlockHash = z.string().regex(/^B[1-9A-HJ-NP-Za-km-z]{50}$/);
const Mutez = z.string().regex(/^\d{1,19}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const NetChainId = z.string().regex(/^Net[1-9A-HJ-NP-Za-km-z]{12}$/);
export const Header = z.object({
  hash: BlockHash,
  level: SafeInt,
  chain_id: NetChainId,
  timestamp: z.string().max(64).optional(),
});
export const Contract = z.object({
  balance: Mutez,
  counter: z
    .string()
    .regex(/^\d{1,16}$/)
    .optional(),
  revealed: z.boolean().optional(),
});
export const ManagerKey = z.union([
  z.null(),
  z.string().regex(/^(edpk|sppk|p2pk|BLpk)[1-9A-HJ-NP-Za-km-z]{40,100}$/),
]);
const TzktHead = z.object({ chainId: NetChainId, level: SafeInt });

export type TezosAdapterOptions = BaseAdapterOptions & {
  /** TzKT endpoints per chain; defaults to `NETWORKS[chainId].indexers`. */
  indexers?: RpcPool;
};
export type TezosGet = <T>(path: string, schema: z.ZodType<T>) => Promise<T>;
export type TezosPost = <T>(path: string, body: unknown, schema: z.ZodType<T>) => Promise<T>;

function indexerPool(): MemoryRpcPool {
  return new MemoryRpcPool(
    Object.entries(NETWORKS).map(
      ([chainId, n]): ChainInfo => ({
        chainId,
        family: 'tezos',
        name: chainId,
        nativeAsset: { ref: `${chainId}:native`, symbol: 'XTZ', decimals: 6 },
        testnet: chainId !== TEZOS_MAINNET,
        defaultRpcs: n.indexers,
      }),
    ),
  );
}

function base(url: string): string {
  return url.replace(/\/$/, '');
}

export class TezosAdapter extends BaseAdapter<'tezos'> {
  readonly indexers: RpcPool;

  constructor(opts: TezosAdapterOptions = {}) {
    super('tezos', opts);
    this.indexers = opts.indexers ?? indexerPool();
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return tezosAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidTezosAddress(addr);
  }

  private get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    return fetchJson(`${base(url)}${path}`, this.fetchOptions()).then((v) => schema.parse(v));
  }

  private post<T>(url: string, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    return postJsonText(`${base(url)}${path}`, body, this.fetchOptions()).then((text) =>
      schema.parse(JSON.parse(text)),
    );
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const id = await this.get(url, '/chains/main/chain_id', NetChainId);
      if (`tezos:${id}` !== chainId)
        throw new Error('Endpoint chain id does not match this Tezos network');
    });
  }

  private async checkIndexer(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, `tzkt:${url}`, async () => {
      const head = await this.get(url, '/v1/head', TzktHead);
      if (`tezos:${head.chainId}` !== chainId)
        throw new Error('Indexer chain id does not match this Tezos network');
    });
  }

  /** Keep dependent observations on one node that proved its network. */
  withNode<T>(
    chainId: ChainId,
    query: (get: TezosGet, post: TezosPost, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(
        (path, schema) => this.get(url, path, schema),
        (path, body, schema) => this.post(url, path, body, schema),
        url,
      );
    });
  }

  withIndexer<T>(chainId: ChainId, query: (get: TezosGet, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.indexers, chainId, async (url) => {
      await this.checkIndexer(chainId, url);
      return query((path, schema) => this.get(url, path, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidTezosAddress(addr)) throw new TypeError(`invalid tezos address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        // An implicit account that never received tez reads as balance "0".
        const balance = await this.get(
          url,
          `/chains/main/blocks/head/context/contracts/${addr}/balance`,
          Mutez,
        );
        return BigInt(balance).toString();
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidTezosAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,20}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    return withFailover(this.indexers, chainId, async (url) => {
      await this.checkIndexer(chainId, url);
      const query = new URLSearchParams({ limit: '20', 'sort.desc': 'id' });
      if (cursor) query.set('lastId', cursor);
      const items = TzktOperations.parse(
        await fetchJson(`${base(url)}/v1/accounts/${addr}/operations?${query.toString()}`, opts),
      );
      const last = items.at(-1);
      return {
        items: items.map((op) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, op)),
        ...(items.length === 20 && last ? { nextCursor: String(last.id) } : {}),
        coverage:
          'TzKT account operations. Tez transactions carry net changes; other operations (reveal, delegation, staking, contract calls) are listed without balance changes. Fees are baker fees plus storage and allocation burns paid by the sender.',
        source: url,
      };
    });
  }

  /** Operation lookup by hash through TzKT; a hash it has not indexed is `unknown`. */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!OpHash.safeParse(hash).success) throw new Error('Invalid Tezos operation hash');
    return this.withIndexer(chainId, async (get) => {
      const ops = await get(`/v1/operations/${hash}`, TzktOperations);
      const own = ops.filter((op) => op.hash === hash);
      if (own.length === 0) return { state: 'unknown' };
      const bad = own.find((op) => op.status !== 'applied');
      if (bad) return { state: 'failed', reason: failure(bad) };
      const first = own[0]!;
      const ts = first.timestamp ? Date.parse(first.timestamp) : NaN;
      return {
        state: 'confirmed',
        blockNumber: first.level,
        ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
      };
    });
  }
}

const TzktAccount = z
  .object({ address: z.string().max(64).optional(), alias: z.string().max(256).nullish() })
  .loose();
const TzktOperation = z
  .object({
    type: z.string().max(64),
    id: SafeInt,
    level: SafeInt,
    timestamp: z.string().max(64).optional(),
    hash: OpHash,
    sender: TzktAccount.optional(),
    target: TzktAccount.nullish(),
    amount: SafeInt.optional(),
    bakerFee: SafeInt.optional(),
    storageFee: SafeInt.optional(),
    allocationFee: SafeInt.optional(),
    status: z.string().max(32).optional(),
    errors: z
      .array(z.object({ type: z.string().max(256) }).loose())
      .max(16)
      .nullish(),
  })
  .loose();
export const TzktOperations = z.array(TzktOperation).max(200);
type TzktOperation = z.infer<typeof TzktOperation>;

function failure(op: TzktOperation): string {
  const reason = op.errors?.[0]?.type ?? op.status ?? 'failed';
  return reason.replace(/[^\x20-\x7e]/g, '').slice(0, 256);
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  op: TzktOperation,
): TxRecord {
  const from = op.sender?.address && isValidAddressLike(op.sender.address) ? op.sender.address : '';
  const to = op.target?.address && isValidAddressLike(op.target.address) ? op.target.address : '';
  const applied = op.status === undefined || op.status === 'applied';
  const isTransfer = op.type === 'transaction';
  let delta = 0n;
  if (isTransfer && applied && op.amount !== undefined) {
    if (to === holder) delta += BigInt(op.amount);
    if (from === holder) delta -= BigInt(op.amount);
  }
  // Baker fees are charged even for failed operations; burns only when applied.
  const fee =
    from === holder
      ? BigInt(op.bakerFee ?? 0) +
        (applied ? BigInt(op.storageFee ?? 0) + BigInt(op.allocationFee ?? 0) : 0n)
      : 0n;
  const ts = op.timestamp ? Date.parse(op.timestamp) : NaN;
  return {
    entryId: String(op.id),
    hash: op.hash,
    chainId,
    from,
    ...(to ? { to } : {}),
    blockNumber: op.level,
    ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
    ...(isTransfer ? {} : { description: op.type }),
    assetDeltas: isTransfer ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: String(fee),
    status: applied ? 'confirmed' : 'failed',
  };
}

function isValidAddressLike(addr: string): boolean {
  return /^(tz[1-4]|KT1|sr1)[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr);
}

/** The node answers 404 for blocks it does not know; that is an answer, not an outage. */
export function isNotFound(err: unknown): boolean {
  return err instanceof HttpError && err.status === 404;
}

export function createTezosAdapter(opts?: TezosAdapterOptions): TezosAdapter {
  return new TezosAdapter(opts);
}
