/**
 * Bitcoin-fork adapter: Bitcoin Cash, Dash, Zcash (transparent t-addresses
 * only), DefiChain and Verus (transparent t-addresses only). All five share
 * Bitcoin's P2PKH wire model; the per-network table carries the address
 * prefixes, the CashAddr human-readable part where one exists, and which
 * public API driver can serve the network. Addresses are base58check of
 * hash160(compressed secp256k1 key) with the network prefix, or CashAddr on
 * BCH. Signing lives in the Rust core (`btcfork.rs`, feature `fam-btcfork`)
 * and is enabled on the five testnets only; mainnet entries are read-only.
 */
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { createBase58check } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  JsonRpcError,
  MemoryRpcPool,
  fetchJson,
  fetchJsonRpc,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
  secp256k1Compressed,
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

export const BCH_MAINNET = 'btcfork:bch-mainnet';
export const BCH_TESTNET = 'btcfork:bch-testnet';
export const DASH_MAINNET = 'btcfork:dash-mainnet';
export const DASH_TESTNET = 'btcfork:dash-testnet';
export const ZCASH_MAINNET = 'btcfork:zcash-mainnet';
export const ZCASH_TESTNET = 'btcfork:zcash-testnet';
export const DEFICHAIN_MAINNET = 'btcfork:defichain-mainnet';
export const DEFICHAIN_TESTNET = 'btcfork:defichain-testnet';
export const VERUS_MAINNET = 'btcfork:verus-mainnet';
export const VERUS_TESTNET = 'btcfork:verus-testnet';

/** The five chains the Rust core signs for; everything else is read-only. */
export const SIGNING_CHAINS = [
  BCH_TESTNET,
  DASH_TESTNET,
  ZCASH_TESTNET,
  DEFICHAIN_TESTNET,
  VERUS_TESTNET,
] as const;
export type SigningChainId = (typeof SIGNING_CHAINS)[number];

/** Which public API shape serves a network; null when none is reachable. */
export type ForkDriver = 'blockchair' | 'insight' | 'ocean' | 'verus-rpc' | null;

export interface ForkParams {
  chainId: string;
  name: string;
  symbol: string;
  testnet: boolean;
  coinType: number;
  /** base58check version bytes for P2PKH / P2SH (1 or 2 bytes). */
  p2pkh: readonly number[];
  p2sh: readonly number[];
  /** CashAddr human-readable part (BCH only). */
  cashaddrHrp?: string;
  driver: ForkDriver;
  /** Sats per 1000 bytes for the flat fee estimate. */
  feePerKb: number;
  /** Zcash-style v4 framing with an expiry height (Zcash, Verus). */
  v4: boolean;
  explorerTxUrl?: string;
  priceId?: string;
}

export const FORKS: Record<string, ForkParams> = {
  [BCH_MAINNET]: {
    chainId: BCH_MAINNET,
    name: 'Bitcoin Cash',
    symbol: 'BCH',
    testnet: false,
    coinType: 145,
    p2pkh: [0x00],
    p2sh: [0x05],
    cashaddrHrp: 'bitcoincash',
    driver: 'blockchair',
    feePerKb: 1000,
    v4: false,
    explorerTxUrl: 'https://blockchair.com/bitcoin-cash/transaction/{hash}',
    priceId: 'bitcoin-cash',
  },
  [BCH_TESTNET]: {
    chainId: BCH_TESTNET,
    name: 'Bitcoin Cash Testnet',
    symbol: 'tBCH',
    testnet: true,
    coinType: 145,
    p2pkh: [0x6f],
    p2sh: [0xc4],
    cashaddrHrp: 'bchtest',
    driver: null,
    feePerKb: 1000,
    v4: false,
  },
  [DASH_MAINNET]: {
    chainId: DASH_MAINNET,
    name: 'Dash',
    symbol: 'DASH',
    testnet: false,
    coinType: 5,
    p2pkh: [0x4c],
    p2sh: [0x10],
    driver: 'blockchair',
    feePerKb: 1000,
    v4: false,
    explorerTxUrl: 'https://blockchair.com/dash/transaction/{hash}',
    priceId: 'dash',
  },
  [DASH_TESTNET]: {
    chainId: DASH_TESTNET,
    name: 'Dash Testnet',
    symbol: 'tDASH',
    testnet: true,
    coinType: 5,
    p2pkh: [0x8c],
    p2sh: [0x13],
    driver: 'insight',
    feePerKb: 1000,
    v4: false,
    explorerTxUrl: 'https://testnet-insight.dashevo.org/insight/tx/{hash}',
  },
  [ZCASH_MAINNET]: {
    chainId: ZCASH_MAINNET,
    name: 'Zcash',
    symbol: 'ZEC',
    testnet: false,
    coinType: 133,
    p2pkh: [0x1c, 0xb8],
    p2sh: [0x1c, 0xbd],
    driver: 'blockchair',
    feePerKb: 2500,
    v4: true,
    explorerTxUrl: 'https://blockchair.com/zcash/transaction/{hash}',
    priceId: 'zcash',
  },
  [ZCASH_TESTNET]: {
    chainId: ZCASH_TESTNET,
    name: 'Zcash Testnet',
    symbol: 'tZEC',
    testnet: true,
    coinType: 133,
    p2pkh: [0x1d, 0x25],
    p2sh: [0x1c, 0xba],
    driver: null,
    feePerKb: 2500,
    v4: true,
  },
  [DEFICHAIN_MAINNET]: {
    chainId: DEFICHAIN_MAINNET,
    name: 'DefiChain',
    symbol: 'DFI',
    testnet: false,
    coinType: 1129,
    p2pkh: [0x12],
    p2sh: [0x5a],
    driver: 'ocean',
    feePerKb: 1000,
    v4: false,
    explorerTxUrl: 'https://defiscan.live/transactions/{hash}',
    priceId: 'defichain',
  },
  [DEFICHAIN_TESTNET]: {
    chainId: DEFICHAIN_TESTNET,
    name: 'DefiChain Testnet',
    symbol: 'tDFI',
    testnet: true,
    coinType: 1129,
    p2pkh: [0x0f],
    p2sh: [0x80],
    driver: null,
    feePerKb: 1000,
    v4: false,
  },
  [VERUS_MAINNET]: {
    chainId: VERUS_MAINNET,
    name: 'Verus',
    symbol: 'VRSC',
    testnet: false,
    coinType: 141,
    p2pkh: [0x3c],
    p2sh: [0x55],
    driver: 'verus-rpc',
    feePerKb: 1000,
    v4: true,
    explorerTxUrl: 'https://explorer.verus.io/tx/{hash}',
    priceId: 'verus-coin',
  },
  [VERUS_TESTNET]: {
    chainId: VERUS_TESTNET,
    name: 'Verus Testnet',
    symbol: 'tVRSC',
    testnet: true,
    coinType: 141,
    p2pkh: [0x3c],
    p2sh: [0x55],
    driver: null,
    feePerKb: 1000,
    v4: true,
  },
};

function chains(): ChainInfo[] {
  return Object.values(FORKS).map((f) => {
    const base = {
      chainId: f.chainId,
      family: 'btcfork' as const,
      name: f.name,
      nativeAsset: { ref: `${f.chainId}:native`, symbol: f.symbol, decimals: 8 },
      testnet: f.testnet,
      extra: { coinType: f.coinType, segwit: false },
      layer: 'L1' as const,
      defaultRpcs: DEFAULT_RPCS[f.chainId] ?? [],
    };
    return {
      ...base,
      ...(f.explorerTxUrl ? { explorerTxUrl: f.explorerTxUrl } : {}),
      ...(f.priceId ? { priceId: f.priceId } : {}),
    };
  });
}

/** One working public endpoint per network, each probed for CORS `*`. */
const DEFAULT_RPCS: Record<string, string[]> = {
  [BCH_MAINNET]: ['https://api.blockchair.com/bitcoin-cash'],
  [DASH_MAINNET]: ['https://api.blockchair.com/dash'],
  [DASH_TESTNET]: ['https://insight.testnet.networks.dash.org/insight-api'],
  [ZCASH_MAINNET]: ['https://api.blockchair.com/zcash'],
  [DEFICHAIN_MAINNET]: ['https://ocean.defichain.com/v0/main'],
  [VERUS_MAINNET]: ['https://api.verus.services/vrsc'],
};

export const BTCSFORK_CHAINS: ChainInfo[] = chains();

export function forkParams(chainId: string): ForkParams {
  const f = FORKS[chainId];
  if (!f) throw new Error(`unknown Bitcoin-fork chain ${chainId}`);
  return f;
}

// ---------------------------------------------------------------- addresses

const base58check = createBase58check(sha256);

export function base58checkEncode(prefix: readonly number[], hash: Uint8Array): string {
  return base58check.encode(Uint8Array.from([...prefix, ...hash]));
}

/** Returns (version bytes, 20-byte hash) or undefined for malformed input. */
export function base58checkDecode(
  addr: string,
): { prefix: number[]; hash: Uint8Array } | undefined {
  if (!/^[1-9A-HJ-NP-Za-km-z]{20,40}$/.test(addr)) return undefined;
  let payload: Uint8Array;
  try {
    payload = base58check.decode(addr);
  } catch {
    return undefined;
  }
  if (payload.length < 21 || payload.length > 22) return undefined;
  const hash = payload.subarray(payload.length - 20);
  if (hash.every((b) => b === 0)) return undefined;
  return { prefix: [...payload.subarray(0, payload.length - 20)], hash };
}

const CASHADDR_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function cashaddrPolymod(values: Iterable<number>): bigint {
  const GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let c = 1n;
  for (const v of values) {
    const top = c >> 35n;
    c = ((c & 0x07ffff_ffffn) << 5n) ^ BigInt(v);
    for (const [i, g] of GENERATORS.entries()) {
      if (((top >> BigInt(i)) & 1n) === 1n) c ^= g!;
    }
  }
  return c ^ 1n;
}

function cashaddrExpand(hrp: string): number[] {
  return [...hrp].map((ch) => ch.charCodeAt(0) & 0x1f).concat(0);
}

function convertBits(
  data: readonly number[],
  from: number,
  to: number,
  pad: boolean,
): number[] | undefined {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  const maxv = (1 << to) - 1;
  for (const b of data) {
    if (b >> from !== 0) return undefined;
    acc = (acc << from) | b;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    return undefined;
  }
  return out;
}

/** CashAddr (BCH): version byte 0x00 P2PKH / 0x08 P2SH, 20-byte hash. */
export function cashaddrEncode(hrp: string, p2sh: boolean, hash: Uint8Array): string {
  if (hash.length !== 20 || !/^[a-z0-9]{1,32}$/.test(hrp))
    throw new Error('Invalid CashAddr payload');
  const version = p2sh ? 0x08 : 0x00;
  const five = convertBits([version, ...hash], 8, 5, true);
  if (!five) throw new Error('Invalid CashAddr payload');
  const modulo = cashaddrPolymod([
    ...cashaddrExpand(hrp),
    ...five,
    ...new Array<number>(8).fill(0),
  ]);
  for (let i = 0; i < 8; i++) five.push(Number((modulo >> BigInt(5 * (7 - i))) & 0x1fn));
  return `${hrp}:${five.map((v) => CASHADDR_ALPHABET[v]).join('')}`;
}

/** Returns the hrp, P2SH flag and 20-byte hash, or undefined for malformed input. */
export function cashaddrDecode(
  addr: string,
): { hrp: string; p2sh: boolean; hash: Uint8Array } | undefined {
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) return undefined;
  const lower = addr.toLowerCase();
  const split = lower.lastIndexOf(':');
  if (split <= 0) return undefined;
  const hrp = lower.slice(0, split);
  const body = lower.slice(split + 1);
  if (hrp.length === 0 || body.length < 8) return undefined;
  const values: number[] = [];
  for (const c of body) {
    const v = CASHADDR_ALPHABET.indexOf(c);
    if (v < 0) return undefined;
    values.push(v);
  }
  if (cashaddrPolymod([...cashaddrExpand(hrp), ...values]) !== 0n) return undefined;
  const payload = convertBits(values.slice(0, values.length - 8), 5, 8, false);
  if (!payload || payload.length !== 21) return undefined;
  const version = payload[0]!;
  const p2sh = version === 0x00 ? false : version === 0x08 ? true : undefined;
  if (p2sh === undefined) return undefined;
  const hash = Uint8Array.from(payload.slice(1));
  if (hash.every((b) => b === 0)) return undefined;
  return { hrp, p2sh, hash };
}

export type ForkScript = { kind: 'p2pkh' | 'p2sh'; hash: Uint8Array };

/** Decodes an address for the network, checking the version bytes / hrp. */
export function decodeForkAddress(chainId: string, addr: string): ForkScript | undefined {
  const f = forkParams(chainId);
  if (f.cashaddrHrp !== undefined) {
    const cash = cashaddrDecode(addr);
    if (cash && cash.hrp === f.cashaddrHrp)
      return { kind: cash.p2sh ? 'p2sh' : 'p2pkh', hash: cash.hash };
    // Legacy base58 stays accepted so BCH copies from any source still work.
  }
  const legacy = base58checkDecode(addr);
  if (!legacy) return undefined;
  if (legacy.prefix.length === f.p2pkh.length && legacy.prefix.every((b, i) => b === f.p2pkh[i]))
    return { kind: 'p2pkh', hash: legacy.hash };
  if (legacy.prefix.length === f.p2sh.length && legacy.prefix.every((b, i) => b === f.p2sh[i]))
    return { kind: 'p2sh', hash: legacy.hash };
  return undefined;
}

export function isValidForkAddress(addr: string, chainId: string): boolean {
  try {
    return decodeForkAddress(chainId, addr) !== undefined;
  } catch {
    return false;
  }
}

/** P2PKH address for the network from a compressed SEC1 key; CashAddr on BCH. */
export function btcforkAddressFromPublicKey(sec1: Uint8Array, chainId: string): string {
  const f = forkParams(chainId);
  const hash = ripemd160(sha256(secp256k1Compressed(sec1)));
  if (f.cashaddrHrp !== undefined) return cashaddrEncode(f.cashaddrHrp, false, hash);
  return base58checkEncode(f.p2pkh, hash);
}

// --------------------------------------------------------------- networking

const SafeUint = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Hash = z.string().regex(/^[0-9a-f]{64}$/);

export const InsightStatus = z.object({
  info: z.object({ testnet: z.boolean(), blocks: SafeUint }),
});
export const BlockchairStats = z.object({ data: z.object({ blocks: SafeUint }) });
export const OceanStats = z.looseObject({ data: z.looseObject({}) });
export const VerusInfo = z.object({
  blocks: SafeUint,
  name: z.string().max(32).optional(),
});
export const BlockchairDashboard = z.object({
  data: z.record(z.string(), z.looseObject({ address: z.looseObject({ balance: SafeUint }) })),
});
export const InsightBalance = SafeUint;
export const OceanBalance = z.object({
  data: z.string().regex(/^\d{1,20}(\.\d{1,8})?@[0-9A-Z]{1,8}$/),
});
export const VerusBalance = z.object({ balance: SafeUint, received: SafeUint });
export const InsightTx = z.looseObject({
  txid: Hash,
  confirmations: z.number().int().nonnegative().optional(),
  blockheight: z.number().int().optional(),
});
export const VerusTx = z.looseObject({
  confirmations: z.number().int().nonnegative().optional(),
  time: SafeUint.optional(),
});
export const BlockchairTx = z.object({
  data: z.record(
    z.string(),
    z.looseObject({ transaction: z.looseObject({ block_id: z.number().int().nullable() }) }),
  ),
});

/** A verified endpoint of a network, typed by driver. */
export interface ForkClient {
  readonly url: string;
  /** REST GET under the endpoint base; a 404 is a real "not indexed" answer. */
  get<T>(path: string, schema: z.ZodType<T>): Promise<T | null>;
  /** JSON-RPC POST (verus-rpc driver). */
  rpc<T>(method: string, params: unknown[], schema: z.ZodType<T>): Promise<T>;
  /** POST a raw body and parse the JSON response (broadcast endpoints). */
  post<T>(path: string, body: string, contentType: string, schema: z.ZodType<T>): Promise<T>;
}

export type BtcForkAdapterOptions = BaseAdapterOptions;

export class BtcForkAdapter extends BaseAdapter<'btcfork'> {
  constructor(opts: BtcForkAdapterOptions = {}) {
    super('btcfork', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(BTCSFORK_CHAINS) });
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return btcforkAddressFromPublicKey(publicKeyBytes(pub), chainId);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidForkAddress(addr, chainId);
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const f = forkParams(chainId);
    await this.verifyEndpoint(chainId, url, async () => {
      switch (f.driver) {
        case 'insight': {
          const status = InsightStatus.parse(
            await fetchJson(`${url}/status?q=getInfo`, this.fetchOptions()),
          );
          if (status.info.testnet !== f.testnet)
            throw new Error('Endpoint serves another Dash network');
          return;
        }
        case 'blockchair': {
          // The URL path selects the chain; a sane stats payload is the proof of life.
          const stats = BlockchairStats.parse(await fetchJson(`${url}/stats`, this.fetchOptions()));
          if (stats.data.blocks === 0) throw new Error('Blockchair endpoint reports no blocks');
          return;
        }
        case 'ocean': {
          await fetchJson(`${url}/stats`, this.fetchOptions()).then((r) => OceanStats.parse(r));
          return;
        }
        case 'verus-rpc': {
          const info = VerusInfo.parse(await fetchJsonRpc(url, 'getinfo', [], this.fetchOptions()));
          if (info.blocks === 0 || (info.name !== undefined && info.name !== 'VRSC'))
            throw new Error('Endpoint serves another Verus network');
          return;
        }
        case null:
          throw new Error(`No public endpoint is known for ${f.name}`);
      }
    });
  }

  private client(url: string): ForkClient {
    const opts = this.fetchOptions();
    const f = this.fetchImpl ?? fetch;
    return {
      url,
      get: async (path, schema) => {
        try {
          return schema.parse(await fetchJson(`${url.replace(/\/$/, '')}${path}`, opts));
        } catch (error) {
          if (error instanceof HttpError && error.status === 404) return null;
          throw error;
        }
      },
      rpc: async (method, params, schema) =>
        schema.parse(await fetchJsonRpc(url, method, params, opts)),
      post: async (path, body, contentType, schema) => {
        const res = await f(`${url.replace(/\/$/, '')}${path}`, {
          method: 'POST',
          headers: { 'content-type': contentType, accept: 'application/json' },
          body,
          signal: AbortSignal.timeout(this.timeoutMs ?? 30_000),
        });
        const text = await res.text();
        if (!res.ok) throw new HttpError(url, res.status, text.slice(0, 1024));
        return schema.parse(JSON.parse(text));
      },
    };
  }

  /** All dependent reads run on one endpoint that proved its network. */
  async withNode<T>(
    chainId: ChainId,
    query: (client: ForkClient, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(this.client(url), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!this.validateAddress(addr, chainId)) throw new TypeError(`invalid address ${addr}`);
    const f = forkParams(chainId);
    if (f.driver === null)
      throw new Error(`No public ${f.name} endpoint is known; balance unavailable`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const client = this.client(url);
        switch (f.driver) {
          case 'insight': {
            const balance = await client.get(`/addr/${addr}/balance`, InsightBalance);
            if (balance === null) throw new Error('Balance endpoint unavailable');
            return balance.toString();
          }
          case 'blockchair': {
            const dash = await client.get(`/dashboards/address/${addr}`, BlockchairDashboard);
            const balance = dash?.data[addr]?.address.balance;
            if (balance === undefined) throw new Error('Balance endpoint unavailable');
            return balance.toString();
          }
          case 'ocean': {
            const res = await client.get(`/address/${addr}/balance`, OceanBalance);
            if (res === null) throw new Error('Balance endpoint unavailable');
            const [whole, frac = ''] = res.data.split('@')[0]!.split('.') as [string, string?];
            const sats = BigInt(whole) * 100_000_000n + BigInt((frac + '00000000').slice(0, 8));
            return sats.toString();
          }
          case 'verus-rpc': {
            const res = await client.rpc(
              'getaddressbalance',
              [{ addresses: [addr] }],
              VerusBalance,
            );
            return res.balance.toString();
          }
          case null:
            throw new Error('unreachable');
        }
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!this.validateAddress(addr, chainId)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'No keyless per-address history indexer is wired for the Bitcoin forks yet (Blockchair dashboard transactions and the Verus getaddresstxids index are candidates); history is unavailable.',
    };
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    Hash.parse(hash);
    const f = forkParams(chainId);
    if (f.driver === null) return { state: 'unknown' };
    return this.withNode(chainId, async (client) => {
      switch (f.driver) {
        case 'insight': {
          const tx = await client.get(`/tx/${hash}`, InsightTx);
          if (!tx || tx.txid !== hash) return { state: 'unknown' };
          if ((tx.confirmations ?? 0) >= 1)
            return { state: 'confirmed', blockNumber: tx.blockheight ?? 0 };
          return { state: 'pending' };
        }
        case 'verus-rpc': {
          try {
            const tx = await client.rpc('getrawtransaction', [hash, 1], VerusTx);
            if ((tx.confirmations ?? 0) >= 1) return { state: 'confirmed', blockNumber: 0 };
            return { state: 'pending' };
          } catch (err) {
            if (err instanceof JsonRpcError) return { state: 'unknown' };
            throw err;
          }
        }
        case 'blockchair': {
          const tx = await client.get(`/dashboards/transaction/${hash}`, BlockchairTx);
          const record = tx?.data[hash];
          if (!record) return { state: 'unknown' };
          const block = record.transaction.block_id;
          return block === null || block === undefined || block < 0
            ? { state: 'pending' }
            : { state: 'confirmed', blockNumber: block };
        }
        case 'ocean':
          return { state: 'unknown' };
        case null:
          return { state: 'unknown' };
      }
    });
  }
}

export function createBtcForkAdapter(opts?: BtcForkAdapterOptions): BtcForkAdapter {
  return new BtcForkAdapter(opts);
}
