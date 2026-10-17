/**
 * Algorand adapter (Algorand mainnet and testnet, Voi read-only). Addresses
 * are base32(pubkey || last 4 bytes of sha512/256(pubkey)), 58 characters.
 * Balances and status come from algod, whose `/v2/transactions/params` names
 * the genesis id and hash, so every endpoint proves its network before it is
 * trusted. History comes from the indexer; every transaction it returns
 * carries the genesis hash and is checked the same way.
 */
import { sha512_256 } from '@noble/hashes/sha2.js';
import { base32nopad, base64, base64urlnopad } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  MemoryRpcPool,
  fetchJson,
  nativeHolding,
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

export const ALGORAND_MAINNET = 'algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k';
export const ALGORAND_TESTNET = 'algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe';
export const VOI_MAINNET = 'algorand:r20fSQI8gWe_kFZziNonSPCXLwcQmH_n';
/** Circle USDC on Algorand mainnet. */
export const USDC_ASA = 31566704;

export interface AlgorandNetwork {
  genesisId: string;
  /** Standard base64, as algod reports it. */
  genesisHash: string;
  symbol: string;
  indexers: string[];
  assets: { id: number; symbol: string; decimals: number }[];
}

export const NETWORKS: Record<string, AlgorandNetwork> = {
  [ALGORAND_MAINNET]: {
    genesisId: 'mainnet-v1.0',
    genesisHash: 'wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=',
    symbol: 'ALGO',
    indexers: ['https://mainnet-idx.algonode.cloud', 'https://mainnet-idx.4160.nodely.dev'],
    assets: [{ id: USDC_ASA, symbol: 'USDC', decimals: 6 }],
  },
  [ALGORAND_TESTNET]: {
    genesisId: 'testnet-v1.0',
    genesisHash: 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=',
    symbol: 'ALGO',
    indexers: ['https://testnet-idx.algonode.cloud', 'https://testnet-idx.4160.nodely.dev'],
    assets: [],
  },
  [VOI_MAINNET]: {
    genesisId: 'voimain-v1.0',
    genesisHash: 'r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=',
    symbol: 'VOI',
    indexers: ['https://mainnet-idx.voi.nodely.dev'],
    assets: [],
  },
};

/** CAIP-2 for an Algorand-protocol network: the first 32 base64url characters of its genesis hash. */
export function caip2FromGenesisHash(genesisHash: string): string {
  const bytes = base64.decode(genesisHash);
  if (bytes.length !== 32) throw new Error('Genesis hash must be 32 bytes');
  return `algorand:${base64urlnopad.encode(bytes).slice(0, 32)}`;
}

function checksum(key: Uint8Array): Uint8Array {
  return sha512_256(key).subarray(28);
}

export function algorandAddressFromPublicKey(key: Uint8Array): string {
  if (key.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  const raw = new Uint8Array(36);
  raw.set(key);
  raw.set(checksum(key), 32);
  return base32nopad.encode(raw);
}

/** The Ed25519 key behind a canonical 58-character address. */
export function algorandAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^[A-Z2-7]{58}$/.test(addr)) return undefined;
  try {
    const raw = base32nopad.decode(addr);
    if (raw.length !== 36) return undefined;
    const key = raw.slice(0, 32);
    // 36 bytes leave two spare base32 bits; only the canonical spelling is accepted.
    return algorandAddressFromPublicKey(key) === addr ? key : undefined;
  } catch {
    return undefined;
  }
}

export function isValidAlgorandAddress(addr: string): boolean {
  return algorandAddressBytes(addr) !== undefined;
}

export function asaAssetRef(chainId: string, assetId: number): string {
  return `${chainId}:asa:${assetId}`;
}

/** Algorand transaction ids: base32 of a 32-byte digest, unpadded. */
export const TxId = z.string().regex(/^[A-Z2-7]{52}$/);
const Addr = z.string().regex(/^[A-Z2-7]{58}$/);
// JSON numbers above 2^53 would already be rounded; such answers are refused, not trusted.
const Uint = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

export const TxParams = z.object({
  'genesis-id': z.string().max(64),
  'genesis-hash': z.string().max(64),
  'last-round': Uint,
  'min-fee': Uint,
  fee: Uint,
});
export type TxParams = z.infer<typeof TxParams>;

export const AlgodAccount = z.object({
  address: Addr,
  amount: Uint,
  'min-balance': Uint,
  round: Uint,
  'auth-addr': Addr.optional(),
  status: z.string().max(32).optional(),
});
export type AlgodAccount = z.infer<typeof AlgodAccount>;

const AssetHolding = z.object({
  'asset-holding': z.object({ amount: Uint, 'asset-id': Uint, 'is-frozen': z.boolean() }),
});

export const PendingTx = z.object({
  'confirmed-round': Uint.optional(),
  'pool-error': z.string().max(4096),
});

const IndexedTx = z
  .object({
    id: TxId,
    'tx-type': z.string().max(16),
    sender: Addr,
    fee: Uint,
    'confirmed-round': Uint.optional(),
    'round-time': Uint.optional(),
    'genesis-hash': z.string().max(64),
    'payment-transaction': z
      .object({
        amount: Uint,
        receiver: Addr,
        'close-amount': Uint.optional(),
        'close-remainder-to': Addr.optional(),
      })
      .optional(),
    'asset-transfer-transaction': z
      .object({
        amount: Uint,
        'asset-id': Uint,
        receiver: Addr,
        'close-amount': Uint.optional(),
        'close-to': Addr.optional(),
      })
      .optional(),
  })
  .loose();
type IndexedTx = z.infer<typeof IndexedTx>;
const IndexedTxPage = z.object({
  transactions: z.array(IndexedTx).max(1000),
  'next-token': z.string().max(128).optional(),
});
const IndexedTxLookup = z.object({ transaction: IndexedTx });

const SimulateResult = z.object({
  'txn-groups': z
    .array(
      z
        .object({
          'failure-message': z.string().max(8192).optional(),
          'failed-at': z.array(Uint).max(16).optional(),
        })
        .loose(),
    )
    .min(1)
    .max(16),
});

export interface AlgorandAdapterOptions extends BaseAdapterOptions {
  /** Indexer endpoints per chain; defaults to `NETWORKS[chainId].indexers`. */
  indexers?: RpcPool;
}

export type AlgodGet = <T>(path: string, schema: z.ZodType<T>) => Promise<T | null>;

function indexerPool(): MemoryRpcPool {
  return new MemoryRpcPool(
    Object.entries(NETWORKS).map(
      ([chainId, n]): ChainInfo => ({
        chainId,
        family: 'algorand',
        name: chainId,
        nativeAsset: { ref: `${chainId}:native`, symbol: n.symbol, decimals: 6 },
        testnet: chainId === ALGORAND_TESTNET,
        defaultRpcs: n.indexers,
      }),
    ),
  );
}

function network(chainId: ChainId): AlgorandNetwork {
  const n = NETWORKS[chainId];
  if (!n) throw new Error(`Unknown Algorand network ${chainId}`);
  return n;
}

const trim = (url: string): string => url.replace(/\/$/, '');

export class AlgorandAdapter extends BaseAdapter<'algorand'> {
  readonly indexers: RpcPool;

  constructor(opts: AlgorandAdapterOptions = {}) {
    super('algorand', opts);
    this.indexers = opts.indexers ?? indexerPool();
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return algorandAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidAlgorandAddress(addr);
  }

  /** GET under a base url; a 404 is an answer (unknown tx, asset not opted in) and yields null. */
  private get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T | null> {
    return this.rest(path, schema, [404])(url);
  }

  private async checkAlgod(chainId: ChainId, url: string): Promise<void> {
    const n = network(chainId);
    await this.verifyEndpoint(chainId, url, async () => {
      const p = await this.get(url, '/v2/transactions/params', TxParams);
      if (!p || p['genesis-hash'] !== n.genesisHash || p['genesis-id'] !== n.genesisId)
        throw new Error('Endpoint genesis does not match this Algorand network');
    });
  }

  /** Keep dependent observations on one algod endpoint that proved its network. */
  withAlgod<T>(chainId: ChainId, query: (get: AlgodGet, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkAlgod(chainId, url);
      return query((path, schema) => this.get(url, path, schema), url);
    });
  }

  async params(chainId: ChainId): Promise<TxParams> {
    return this.withAlgod(chainId, async (get) => {
      const p = await get('/v2/transactions/params', TxParams);
      if (!p) throw new Error('algod did not report transaction parameters');
      return p;
    });
  }

  async account(addr: Address, chainId: ChainId): Promise<AlgodAccount> {
    if (!isValidAlgorandAddress(addr)) throw new TypeError(`invalid algorand address ${addr}`);
    return this.withAlgod(chainId, async (get) => {
      const a = await get(`/v2/accounts/${addr}?exclude=all`, AlgodAccount);
      if (!a || a.address !== addr) throw new Error('algod returned a different account');
      return a;
    });
  }

  private async post(
    chainId: ChainId,
    path: string,
    contentType: string,
    body: Uint8Array,
  ): Promise<{ status: number; body: unknown }> {
    return this.withAlgod(chainId, async (_get, url) => {
      const doFetch = this.fetchImpl ?? globalThis.fetch;
      const res = await doFetch(`${trim(url)}${path}`, {
        method: 'POST',
        headers: { 'content-type': contentType, accept: 'application/json' },
        body: body as BodyInit,
        signal: AbortSignal.timeout(this.timeoutMs ?? 30_000),
      });
      const text = (await res.text()).slice(0, 1 << 16);
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = undefined;
      }
      // Gateway errors and rate limits are a failed endpoint, not a verdict on the transaction.
      if (res.status >= 500 || res.status === 429)
        throw new HttpError(url, res.status, text.slice(0, 512));
      return { status: res.status, body: parsed };
    });
  }

  /** POST a signed transaction as raw msgpack. */
  submit(chainId: ChainId, signed: Uint8Array): Promise<{ status: number; body: unknown }> {
    return this.post(chainId, '/v2/transactions', 'application/x-binary', signed);
  }

  /**
   * Dry-run one unsigned transaction (`allow-empty-signatures`). Returns the
   * failure message, or undefined when the network would accept it.
   */
  async simulateTxn(chainId: ChainId, txn: Uint8Array): Promise<string | undefined> {
    const res = await this.post(
      chainId,
      '/v2/transactions/simulate?format=json',
      'application/msgpack',
      simulateRequest(txn),
    );
    if (res.status !== 200) throw new Error(`simulate answered HTTP ${res.status}`);
    const group = SimulateResult.parse(res.body)['txn-groups'][0]!;
    return group['failure-message'] || undefined;
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidAlgorandAddress(addr)) throw new TypeError(`invalid algorand address ${addr}`);
    const assets = network(chainId).assets;
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkAlgod(chainId, url);
        const account = await this.get(url, `/v2/accounts/${addr}?exclude=all`, AlgodAccount);
        if (!account || account.address !== addr)
          throw new Error('algod returned a different account');
        const tokens = await Promise.all(
          assets.map(async (a) => {
            const h = await this.get(url, `/v2/accounts/${addr}/assets/${a.id}`, AssetHolding);
            // 404: the account has not opted in to the asset, so it holds none.
            if (h && h['asset-holding']['asset-id'] !== a.id)
              throw new Error('algod returned a different asset');
            return String(h?.['asset-holding'].amount ?? 0);
          }),
        );
        return JSON.stringify([String(account.amount), String(account['min-balance']), ...tokens]);
      },
      { equal: (a, b) => a === b },
    );
    const [native, minBalance, ...tokenAmounts] = JSON.parse(value) as string[];
    return [
      {
        ...nativeHolding(chain, native!, provenance),
        ...(native !== '0'
          ? { notice: `${minBalance} base units are the account's locked minimum balance.` }
          : {}),
      },
      ...assets.map((a, i) => ({
        assetRef: asaAssetRef(chainId, a.id),
        amount: tokenAmounts[i] ?? '0',
        provenance,
        metadata: { symbol: a.symbol, decimals: a.decimals },
        notice: 'ASA balance from algod; token transfers are not enabled.',
        updatedAtMs: Date.now(),
      })),
    ];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    const n = network(chainId);
    if (!isValidAlgorandAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[A-Za-z0-9+/=_-]{1,128}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const limit = 20;
    const query = new URLSearchParams({ limit: String(limit) });
    if (cursor) query.set('next', cursor);
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    return withFailover(this.indexers, chainId, async (url) => {
      let raw: unknown;
      try {
        raw = await fetchJson(`${trim(url)}/v2/accounts/${addr}/transactions?${query}`, opts);
      } catch (err) {
        if (err instanceof HttpError && err.status === 404) return { items: [], source: url };
        throw err;
      }
      const page = IndexedTxPage.parse(raw);
      if (page.transactions.some((t) => t['genesis-hash'] !== n.genesisHash))
        throw new Error('Indexer returned transactions from another network');
      return {
        items: page.transactions.map((t) =>
          indexedRecord(chainId, chain.nativeAsset.ref, n, addr, t),
        ),
        ...(page.transactions.length === limit && page['next-token']
          ? { nextCursor: page['next-token'] }
          : {}),
        coverage:
          'Indexer top-level transactions. Effects of inner (application) transactions are not counted.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!TxId.safeParse(hash).success) throw new Error('Invalid Algorand transaction id');
    const n = network(chainId);
    const pending = await this.withAlgod(chainId, (get) =>
      get(`/v2/transactions/pending/${hash}`, PendingTx),
    );
    if (pending) {
      const round = pending['confirmed-round'] ?? 0;
      if (round > 0) return { state: 'confirmed', blockNumber: round };
      if (pending['pool-error'])
        return { state: 'failed', reason: pending['pool-error'].slice(0, 512) };
      return { state: 'pending' };
    }
    // algod forgets confirmed transactions after 1000 rounds; the indexer keeps them.
    const indexed = await withFailover(this.indexers, chainId, (url) =>
      this.get(url, `/v2/transactions/${hash}`, IndexedTxLookup),
    );
    if (!indexed) return { state: 'unknown' };
    const t = indexed.transaction;
    if (t.id !== hash || t['genesis-hash'] !== n.genesisHash)
      throw new Error('Indexer returned a different transaction');
    const round = t['confirmed-round'];
    if (!round) return { state: 'pending' };
    return {
      state: 'confirmed',
      blockNumber: round,
      ...(t['round-time'] ? { timestampMs: t['round-time'] * 1000 } : {}),
    };
  }
}

function msgpackKey(s: string): number[] {
  const b = new TextEncoder().encode(s);
  return [0xa0 | b.length, ...b];
}

/** `{"allow-empty-signatures": true, "txn-groups": [{"txns": [{"txn": <txn>}]}]}` in msgpack. */
export function simulateRequest(txn: Uint8Array): Uint8Array {
  return Uint8Array.from([
    0x82,
    ...msgpackKey('allow-empty-signatures'),
    0xc3,
    ...msgpackKey('txn-groups'),
    0x91,
    0x81,
    ...msgpackKey('txns'),
    0x91,
    0x81,
    ...msgpackKey('txn'),
    ...txn,
  ]);
}

function indexedRecord(
  chainId: string,
  nativeRef: string,
  n: AlgorandNetwork,
  holder: string,
  t: IndexedTx,
): TxRecord {
  const sent = t.sender === holder;
  let to: string | undefined;
  const deltas: TxRecord['assetDeltas'] = [];
  const pay = t['payment-transaction'];
  const axfer = t['asset-transfer-transaction'];
  if (t['tx-type'] === 'pay' && pay) {
    to = pay.receiver;
    let delta = 0n;
    if (pay.receiver === holder) delta += BigInt(pay.amount);
    if (sent) delta -= BigInt(pay.amount);
    const closed = BigInt(pay['close-amount'] ?? 0);
    if (pay['close-remainder-to'] === holder) delta += closed;
    if (sent) delta -= closed;
    deltas.push({ assetRef: nativeRef, amount: String(delta) });
  } else if (t['tx-type'] === 'axfer' && axfer) {
    to = axfer.receiver;
    const known = n.assets.find((a) => a.id === axfer['asset-id']);
    let delta = 0n;
    if (axfer.receiver === holder) delta += BigInt(axfer.amount);
    if (sent) delta -= BigInt(axfer.amount);
    const closed = BigInt(axfer['close-amount'] ?? 0);
    if (axfer['close-to'] === holder) delta += closed;
    if (sent) delta -= closed;
    deltas.push({
      assetRef: asaAssetRef(chainId, axfer['asset-id']),
      amount: String(delta),
      ...(known ? { symbol: known.symbol, decimals: known.decimals } : {}),
    });
  }
  return {
    hash: t.id,
    chainId,
    from: t.sender,
    ...(to ? { to } : {}),
    ...(t['confirmed-round'] ? { blockNumber: t['confirmed-round'] } : {}),
    ...(t['round-time'] ? { timestampMs: t['round-time'] * 1000 } : {}),
    ...(t['tx-type'] !== 'pay' ? { description: t['tx-type'] } : {}),
    assetDeltas: deltas,
    feeAssetRef: nativeRef,
    fee: String(t.fee),
    status: 'confirmed',
  };
}

export function createAlgorandAdapter(opts?: AlgorandAdapterOptions): AlgorandAdapter {
  return new AlgorandAdapter(opts);
}
