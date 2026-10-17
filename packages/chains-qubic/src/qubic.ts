/**
 * Qubic adapter. Qubic signs with SchnorrQ over the FourQ curve and hashes
 * with KangarooTwelve; the Rust core (`crates/stackwallet-core/src/qubic.rs`)
 * hand-rolls both, and this package carries the matching K12 and identity
 * codec in TypeScript so address validation and broadcast verification do not
 * trust the node. Every byte is pinned against the official
 * `@qubic-lib/qubic-ts-library` (run in `.nur/qubic-oracle`) and the Rust
 * module pins the same vectors.
 *
 * Network: Qubic runs a single mainnet (no public testnet exists, probed
 * 2026-10-17), so `qubic:mainnet` is the signing network. There is exactly
 * one keyless public RPC (`https://rpc.qubic.org`, CORS `*`), so provenance
 * is always `single`.
 *
 * Wiring shim: `qubic` is not yet in the `ChainFamily` enum or chain catalog
 * (the lead wires shared files from `.nur/wiring/qubic.md`). Until then this
 * package carries its own `ChainInfo` (cast to the shared type) and overrides
 * `chains()`; once the catalog entry lands the shim can be deleted.
 */
import { base64 } from '@scure/base';
import {
  BaseAdapter,
  MemoryRpcPool,
  UnsupportedKeyError,
  nativeHolding,
  postJsonText,
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

export const QUBIC_MAINNET = 'qubic:mainnet';
export const QUBIC_RPC = 'https://rpc.qubic.org';
/** Qubic transfers carry no fee; the network charges nothing. */
export const QUBIC_FEE = '0';
/** QU is indivisible: amounts are whole units. */
export const QUBIC_DECIMALS = 0;
export const IDENTITY_LENGTH = 60;
/** Ticks are bounded well below u32 by the network's epoch schedule. */
export const MAX_TICK = 4_000_000_000;
/** Prepared transfers target this many ticks after the latest tick. */
export const DEFAULT_TICK_OFFSET = 20;
/** Approval is refused once fewer than this many ticks remain. */
export const MIN_REMAINING_TICKS = 5;

// ---------------------------------------------------------------------------
// KangarooTwelve over Keccak-p[1600,12], empty customization. Mirrors the
// Rust module; the empty-input official vector is pinned in the tests.
// ---------------------------------------------------------------------------

const RC: bigint[] = [
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];
const RHO = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const MASK64 = (1n << 64n) - 1n;

function keccakP1600x12(s: BigUint64Array): void {
  const at = (i: number) => s[i]!;
  const rotl = (x: bigint, n: number) => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
  const b = new BigUint64Array(25);
  for (const rc of RC) {
    const c = [0n, 0n, 0n, 0n, 0n];
    for (let x = 0; x < 5; x++) c[x] = at(x) ^ at(x + 5) ^ at(x + 10) ^ at(x + 15) ^ at(x + 20);
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5]! ^ rotl(c[(x + 1) % 5]!, 1);
      for (let y = 0; y < 5; y++) s[x + 5 * y] = at(x + 5 * y) ^ d;
    }
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(at(x + 5 * y), RHO[x + 5 * y]!);
    for (let y = 0; y < 5; y++)
      for (let x = 0; x < 5; x++)
        s[x + 5 * y] =
          b[x + 5 * y]! ^ (~b[((x + 1) % 5) + 5 * y]! & b[((x + 2) % 5) + 5 * y]! & MASK64);
    s[0] = at(0) ^ rc;
  }
}

const K12_RATE = 168;

/** KangarooTwelve with an empty customization string; up to 8191 input bytes. */
export function k12(input: Uint8Array, outLength = 32): Uint8Array {
  if (input.length >= 8192 || outLength > K12_RATE)
    throw new RangeError('outside the K12 single-node profile Qubic uses');
  const state = new BigUint64Array(25);
  const block = new Uint8Array(K12_RATE);
  let offset = 0;
  const xorBlock = () => {
    for (let i = 0; i < K12_RATE / 8; i++) {
      let v = 0n;
      for (let j = 7; j >= 0; j--) v = (v << 8n) | BigInt(block[8 * i + j]!);
      state[i] = state[i]! ^ v;
    }
  };
  const flush = () => {
    xorBlock();
    keccakP1600x12(state);
    block.fill(0);
    offset = 0;
  };
  // Sakura single-node framing: input || 0x00 (right_encode of empty
  // customization), delimited suffix 0x07, pad10*1.
  for (const byte of [...input, 0x00]) {
    block[offset] = byte;
    if (++offset === K12_RATE) flush();
  }
  block[offset]! ^= 0x07;
  block[K12_RATE - 1]! ^= 0x80;
  xorBlock();
  keccakP1600x12(state);
  const out = new Uint8Array(outLength);
  for (let i = 0; i < outLength; i++)
    out[i] = Number((state[(i / 8) | 0]! >> BigInt(8 * (i % 8))) & 0xffn);
  return out;
}

// ---------------------------------------------------------------------------
// Identity codec: 4 little-endian u64 limbs, each as 14 base-26 uppercase
// letters (least significant first), plus 4 checksum letters from the low
// 18 bits of K12(public key) read as a little-endian u24.
// ---------------------------------------------------------------------------

/** The 60-character uppercase identity for a 32-byte FourQ public key. */
export function qubicIdentityFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('Qubic public key must be 32 bytes');
  let id = '';
  const view = new DataView(publicKey.buffer, publicKey.byteOffset, publicKey.byteLength);
  for (let i = 0; i < 4; i++) {
    let n = view.getBigUint64(8 * i, true);
    for (let d = 0; d < 14; d++) {
      id += String.fromCharCode(65 + Number(n % 26n));
      n /= 26n;
    }
    // 26^14 > 2^64, so 14 digits always consume a u64 exactly
  }
  const digest = k12(publicKey);
  let checksum = (digest[0]! | (digest[1]! << 8) | (digest[2]! << 16)) & 0x3ffff;
  for (let d = 0; d < 4; d++) {
    id += String.fromCharCode(65 + (checksum % 26));
    checksum = Math.floor(checksum / 26);
  }
  return id;
}

/**
 * Validates an identity and returns its 32-byte public key, or undefined.
 * Non-canonical base-26 limbs (value >= 2^64) are rejected so an identity
 * has exactly one spelling.
 */
export function qubicIdentityBytes(identity: string): Uint8Array | undefined {
  if (identity.length !== IDENTITY_LENGTH || !/^[A-Z]{60}$/.test(identity)) return undefined;
  const publicKey = new Uint8Array(32);
  const view = new DataView(publicKey.buffer);
  for (let i = 0; i < 4; i++) {
    let n = 0n;
    for (let d = 13; d >= 0; d--) n = n * 26n + BigInt(identity.charCodeAt(i * 14 + d) - 65);
    if (n > MASK64) return undefined;
    view.setBigUint64(8 * i, n, true);
  }
  return qubicIdentityFromPublicKey(publicKey) === identity ? publicKey : undefined;
}

export function isValidQubicIdentity(identity: string): boolean {
  return qubicIdentityBytes(identity) !== undefined;
}

/** The lowercase identity-style transaction id explorers show: K12(package). */
export function qubicTxId(packageBytes: Uint8Array): string {
  return qubicIdentityFromPublicKey(k12(packageBytes)).toLowerCase();
}

// ---------------------------------------------------------------------------
// Adapter.
// ---------------------------------------------------------------------------

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Identity = z.string().regex(/^[A-Z]{60}$/);

const TickInfo = z.object({
  tickInfo: z.object({
    tick: SafeInt,
    epoch: SafeInt,
    initialTick: SafeInt,
  }),
});
const Balance = z.object({
  balance: z.object({
    id: Identity,
    balance: z.string().regex(/^\d{1,20}$/),
    validForTick: SafeInt,
  }),
});
const Transaction = z.object({
  transaction: z
    .object({
      sourceId: Identity,
      destId: Identity,
      amount: z.string().regex(/^\d{1,20}$/),
      tickNumber: SafeInt,
    })
    .loose(),
});
const TxStatusResponse = z.object({
  transactionStatus: z.object({ txId: z.string().max(64), moneyFlew: z.boolean() }).loose(),
});
export const BroadcastResult = z
  .object({
    peersBroadcasted: z.number().int().nonnegative().optional(),
    transactionId: z.string().max(64).optional(),
    message: z.string().max(4096).optional(),
  })
  .loose();
export type BroadcastResult = z.infer<typeof BroadcastResult>;

/**
 * Local catalog entry used until the lead wires `qubic` into the shared
 * `ChainFamily` enum and catalog (see `.nur/wiring/qubic.md`).
 */
export const QUBIC_CHAINS: ChainInfo[] = [
  {
    chainId: QUBIC_MAINNET,
    family: 'qubic' as ChainInfo['family'],
    name: 'Qubic',
    nativeAsset: { ref: `${QUBIC_MAINNET}:native`, symbol: 'QU', decimals: QUBIC_DECIMALS },
    testnet: false,
    explorerTxUrl: 'https://explorer.qubic.org/tx/{hash}',
    defaultRpcs: [QUBIC_RPC],
    extra: { coinType: 83293 },
    priceId: 'qubic-network',
  },
];

export type QubicAdapterOptions = BaseAdapterOptions;

export class QubicAdapter extends BaseAdapter {
  constructor(opts: QubicAdapterOptions = {}) {
    // 'qubic' enters ChainFamily with the lead's wiring; the catalog shim
    // above keeps the pool honest in the meantime.
    super('qubic' as never, {
      ...opts,
      rpc: opts.rpc ?? new MemoryRpcPool(QUBIC_CHAINS),
    });
  }

  override chains(): ChainInfo[] {
    const wired = super.chains();
    return wired.length > 0 ? wired : QUBIC_CHAINS;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    const bytes = Uint8Array.from(pub.hex.match(/../g) ?? [], (b) => parseInt(b, 16));
    // The core derives FourQ public keys for Qubic; any 32-byte key is one.
    if (bytes.length !== 32)
      throw new UnsupportedKeyError(`Qubic needs a 32-byte FourQ public key (curve ${pub.curve})`);
    return qubicIdentityFromPublicKey(bytes);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidQubicIdentity(addr);
  }

  /**
   * Qubic exposes no chain magic over RPC; the honest check is that the
   * endpoint serves the Qubic RPC shape with a sane tick schedule. The
   * single public endpoint makes cross-checking impossible anyway.
   */
  async tickInfo(chainId: ChainId): Promise<{ tick: number; epoch: number; initialTick: number }> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.verifyEndpoint(chainId, url, async () => {
        const info = await this.rest('/v1/tick-info', TickInfo, [])(url);
        const t = info?.tickInfo;
        if (!t || t.tick < t.initialTick || t.epoch === 0)
          throw new Error('Endpoint does not serve the Qubic tick schedule');
      });
      const info = await this.rest('/v1/tick-info', TickInfo, [])(url);
      if (info === null) throw new Error('tick-info vanished');
      this.noteBlock(url, info.tickInfo.tick);
      return info.tickInfo;
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidQubicIdentity(addr)) throw new TypeError(`invalid qubic identity ${addr}`);
    let endpoint = '';
    const value = await withFailover(this.rpc, chainId, async (url) => {
      await this.verifyEndpoint(chainId, url, () => this.tickInfo(chainId).then(() => undefined));
      const res = await this.rest(`/v1/balances/${addr}`, Balance, [404])(url);
      if (res === null) throw new Error('balance endpoint not found');
      endpoint = url;
      return res.balance.balance;
    });
    const provenance = { kind: 'single' as const, endpoint };
    return [
      {
        ...nativeHolding(chain, value, provenance),
        notice:
          'Balance observed at a single public endpoint (rpc.qubic.org is the only keyless API); Qubic has no second source to cross-check against.',
      },
    ];
  }

  /**
   * The v1 RPC has no per-address history and the v2 archiver
   * (api.qubic.org / archiver.qubic.org) was unreachable in live probes
   * (2026-10-17), so transfer history reports its gap.
   */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidQubicIdentity(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'No keyless public Qubic history indexer is reachable (the v2 archiver does not answer), so transfer history is unavailable.',
    };
  }

  /**
   * Qubic has no mempool view: a transaction is either executed at its tick
   * (`/v1/transactions/{id}` answers) or invisible. `moneyFlew` false means
   * the tick executed it but the balance did not move (insufficient funds).
   */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    const value = hash.toLowerCase();
    if (!/^[a-z]{60}$/.test(value)) throw new Error('Invalid Qubic transaction id');
    return withFailover(this.rpc, chainId, async (url) => {
      await this.verifyEndpoint(chainId, url, () => this.tickInfo(chainId).then(() => undefined));
      const tx = await this.rest(`/v1/transactions/${value}`, Transaction, [400, 404])(url);
      if (tx === null) return { state: 'unknown' };
      const st = await this.rest(`/v1/tx-status/${value}`, TxStatusResponse, [400, 404])(url);
      if (st !== null && st.transactionStatus.moneyFlew === false)
        return {
          state: 'failed',
          reason: 'the tick executed it but no funds moved (moneyFlew false)',
        };
      return { state: 'confirmed', blockNumber: tx.transaction.tickNumber };
    });
  }

  /** POST a base64 package to `/v1/broadcast-transaction`; schema-checked. */
  async broadcastRaw(chainId: ChainId, encodedTransaction: string): Promise<BroadcastResult> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.verifyEndpoint(chainId, url, () => this.tickInfo(chainId).then(() => undefined));
      const text = await postJsonText(
        `${url.replace(/\/$/, '')}/v1/broadcast-transaction`,
        { encodedTransaction },
        this.fetchOptions(),
      );
      return BroadcastResult.parse(JSON.parse(text));
    });
  }
}

export function createQubicAdapter(opts?: QubicAdapterOptions): QubicAdapter {
  return new QubicAdapter(opts);
}
