/**
 * Aeternity adapter. Accounts are ed25519 keys shown as `ak_` base58check
 * strings; reads go over the node HTTP API (v3) plus the middleware (`/mdw`)
 * for history, and `/v3/status` proves which network an endpoint serves.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { base58, base64 } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  fetchJson,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
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

export function checksum(payload: Uint8Array): Uint8Array {
  return sha256(sha256(payload)).subarray(0, 4);
}

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

/** `ak_`/`th_` are base58check; `tx_` is base64check (same double-sha256 checksum). */
export function encodeChecked(prefix: string, payload: Uint8Array): string {
  const full = concat(payload, checksum(payload));
  return `${prefix}_${prefix === 'tx' ? base64.encode(full) : base58.encode(full)}`;
}

export function decodeChecked(text: string, prefix: string): Uint8Array | undefined {
  if (!text.startsWith(`${prefix}_`) || text.split('_').length !== 2) return undefined;
  try {
    const raw = text.slice(prefix.length + 1);
    const full = prefix === 'tx' ? base64.decode(raw) : base58.decode(raw);
    if (full.length < 5) return undefined;
    const payload = full.subarray(0, -4);
    const check = checksum(payload);
    if (!check.every((b, i) => b === full[payload.length + i])) return undefined;
    return payload;
  } catch {
    return undefined;
  }
}

export function aeternityAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^ak_[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(addr)) return undefined;
  const payload = decodeChecked(addr, 'ak');
  if (!payload || payload.length !== 32 || payload.every((b) => b === 0)) return undefined;
  return payload;
}

export function isValidAeternityAddress(addr: string): boolean {
  return aeternityAddressBytes(addr) !== undefined;
}

export function aeternityAddressFromPublicKey(pub: Uint8Array): string {
  if (pub.length !== 32) throw new Error('Aeternity public keys are 32 bytes');
  return encodeChecked('ak', pub);
}

/** blake2b-256, the chain's one hash function. */
export function aeternityHash(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 });
}

/** `th_` transaction hash of a signed `tx_` string. */
export function aeternityTxHash(signedTx: string): string | undefined {
  const rlp = decodeChecked(signedTx, 'tx');
  return rlp ? encodeChecked('th', aeternityHash(rlp)) : undefined;
}

/**
 * The node emits balances as bare JSON numbers that can exceed 2^53; quote
 * long integer literals so they survive parsing as exact decimal strings.
 */
export function parseAeJson(text: string): unknown {
  return JSON.parse(text.replace(/([:[,]\s*)(-?\d{16,})(?=\s*[,}\]])/g, '$1"$2"'));
}

// --- aeser RLP decoding (read side only; the core owns encoding for signing) ---

export type RlpItem = Uint8Array | RlpItem[];

/** Strict decoder: refuses trailing bytes, non-minimal lengths and huge input. */
export function rlpDecode(bytes: Uint8Array): RlpItem {
  const [item, rest] = rlpRead(bytes);
  if (rest.length !== 0) throw new Error('RLP has trailing bytes');
  return item;
}

function rlpRead(bytes: Uint8Array): [RlpItem, Uint8Array] {
  const first = bytes[0];
  if (first === undefined) throw new Error('empty RLP');
  if (first < 0x80) return [bytes.subarray(0, 1), bytes.subarray(1)];
  if (first < 0xb8) return take(bytes, 1, first - 0x80, false);
  if (first < 0xc0) {
    const lenLen = first - 0xb7;
    const len = lenOf(bytes, 1, lenLen);
    if (len <= 55) throw new Error('non-minimal RLP string');
    return take(bytes, 1 + lenLen, len, false);
  }
  if (first < 0xf8) return take(bytes, 1, first - 0xc0, true);
  const lenLen = first - 0xf7;
  const len = lenOf(bytes, 1, lenLen);
  if (len <= 55) throw new Error('non-minimal RLP list');
  return take(bytes, 1 + lenLen, len, true);
}

function lenOf(bytes: Uint8Array, offset: number, lenLen: number): number {
  if (lenLen === 0 || bytes.length < offset + lenLen || bytes[offset] === 0)
    throw new Error('bad RLP length');
  let len = 0;
  for (let i = 0; i < lenLen; i++) len = len * 256 + bytes[offset + i]!;
  if (len > 1_000_000) throw new Error('RLP item too large');
  return len;
}

function take(
  bytes: Uint8Array,
  offset: number,
  len: number,
  list: boolean,
): [RlpItem, Uint8Array] {
  if (bytes.length < offset + len) throw new Error('truncated RLP');
  const payload = bytes.subarray(offset, offset + len);
  const rest = bytes.subarray(offset + len);
  if (!list) return [payload, rest];
  const items: RlpItem[] = [];
  let remaining = payload;
  while (remaining.length > 0) {
    const [item, r] = rlpRead(remaining);
    items.push(item);
    remaining = r;
  }
  return [items, rest];
}

export function rlpInt(item: RlpItem): bigint {
  if (item instanceof Uint8Array) {
    if (item.length > 16) throw new Error('RLP integer too large');
    return item.reduce((n, b) => n * 256n + BigInt(b), 0n);
  }
  throw new Error('expected an RLP integer');
}

/** Decoded SpendTx (tag 12); anything else returns undefined. */
export function decodeSpendTx(encodedTx: string):
  | {
      senderId: string;
      recipientId: string;
      amount: string;
      fee: string;
      nonce: string;
      signatures: number;
    }
  | undefined {
  const outer = decodeChecked(encodedTx, 'tx');
  if (!outer) return undefined;
  try {
    let top = rlpDecode(outer);
    let signatures = 0;
    if (Array.isArray(top) && rlpInt(top[0]!) === 11n) {
      // SignedTx: [11, 1, [signatures], inner RLP string]
      const sigs = top[2];
      signatures = Array.isArray(sigs) ? sigs.length : 0;
      const inner = top[3];
      if (!(inner instanceof Uint8Array)) return undefined;
      top = rlpDecode(inner);
    }
    if (!Array.isArray(top) || top.length !== 9 || rlpInt(top[0]!) !== 12n) return undefined;
    const id = (item: RlpItem) =>
      item instanceof Uint8Array && item.length === 33 && item[0] === 1
        ? encodeChecked('ak', item.subarray(1))
        : undefined;
    const senderId = id(top[2]!);
    const recipientId = id(top[3]!);
    if (!senderId || !recipientId) return undefined;
    return {
      senderId,
      recipientId,
      amount: rlpInt(top[4]!).toString(),
      fee: rlpInt(top[5]!).toString(),
      nonce: rlpInt(top[7]!).toString(),
      signatures,
    };
  } catch {
    return undefined;
  }
}

const BigBalance = z.union([
  z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  z.string().regex(/^\d{1,40}$/),
]);
const Status = z.object({
  network_id: z.string().max(64),
  top_block_height: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
const Account = z.object({
  balance: BigBalance,
  nonce: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
});
const NextNonce = z.object({
  next_nonce: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
const TxObject = z.object({
  block_height: z.number().int().min(-1).max(Number.MAX_SAFE_INTEGER).optional(),
  block_hash: z.string().max(80).optional(),
  signatures: z.array(z.string().max(200)).max(16).optional(),
});

export type AeternityAdapterOptions = BaseAdapterOptions;
export type AeternityCall = <T>(path: string, schema: z.ZodType<T>) => Promise<T>;

export class AeternityAdapter extends BaseAdapter<'aeternity'> {
  constructor(opts: AeternityAdapterOptions = {}) {
    super('aeternity', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return aeternityAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidAeternityAddress(addr);
  }

  private async get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    const full = `${url.replace(/\/$/, '')}${path}`;
    const opts = this.fetchOptions();
    const doFetch = opts.fetch ?? globalThis.fetch;
    const timeoutMs = opts.timeoutMs ?? 15_000;
    const res = await doFetch(full, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    if (!res.ok) throw new HttpError(full, res.status, text.slice(0, 512));
    return schema.parse(parseAeJson(text));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const status = await this.get(url, '/v3/status', Status);
      if (`aet:${status.network_id}` !== chainId)
        throw new Error('Endpoint network_id does not match this Aeternity network');
    });
  }

  /** POST the signed `tx_` string to a node, returning the raw response text. */
  postTransaction(url: string, signedTx: string): Promise<string> {
    return postJsonText(
      `${url.replace(/\/$/, '')}/v3/transactions`,
      { tx: signedTx },
      this.fetchOptions(),
    );
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(
    chainId: ChainId,
    query: (call: AeternityCall, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, schema) => this.get(url, path, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidAeternityAddress(addr)) throw new TypeError(`invalid aeternity address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        try {
          const account = await this.get(url, `/v3/accounts/${addr}`, Account);
          return BigInt(account.balance).toString();
        } catch (error) {
          // An address that never received AE is not an account yet: zero, not an error.
          if (error instanceof HttpError && error.status === 404) return '0';
          throw error;
        }
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  /** Middleware activities for the account; only SpendTx rows carry amounts. */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidAeternityAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[A-Za-z0-9?&=_-]{1,256}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    let lastError: unknown;
    for (const { url } of this.rpc.endpoints(chainId)) {
      try {
        await this.checkNetwork(chainId, url);
        const res = Activities.parse(
          await fetchJson(
            `${url.replace(/\/$/, '')}/mdw/v3/accounts/${addr}/activities?${cursor ?? 'limit=20'}`,
            opts,
          ),
        );
        const items = res.data
          .filter((a) => a.type.length <= 64)
          .map((a) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, a));
        const next = res.next?.match(/\?(.+)$/)?.[1];
        return {
          items,
          ...(next ? { nextCursor: next } : {}),
          coverage:
            'Middleware account activities. SpendTx rows carry exact aettos amounts and fees; other contract and name events are listed without balance changes.',
          source: url,
        };
      } catch (err) {
        if (options?.signal?.aborted) throw err;
        lastError = err;
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Aeternity history is unavailable');
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^th_[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(hash))
      throw new Error('Invalid Aeternity transaction hash');
    return this.withNode(chainId, async (call) => {
      try {
        const tx = await call(`/v3/transactions/${hash}`, TxObject);
        if (tx.block_height !== undefined && tx.block_height > 0)
          return { state: 'confirmed', blockNumber: tx.block_height };
        return { state: 'pending' };
      } catch (error) {
        if (error instanceof HttpError && error.status === 404) return { state: 'unknown' };
        throw error;
      }
    });
  }
}

const Activities = z.object({
  data: z
    .array(
      z.object({
        type: z.string().max(64),
        height: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
        block_hash: z.string().max(80).optional(),
        payload: z
          .object({
            block_height: z.number().int().max(Number.MAX_SAFE_INTEGER).optional(),
            encoded_tx: z.string().max(4000).optional(),
            tx_hash: z.string().max(80).optional(),
          })
          .loose(),
      }),
    )
    .max(200),
  next: z.string().max(512).nullable().optional(),
});

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  a: z.infer<typeof Activities>['data'][number],
): TxRecord {
  const spend = a.payload.encoded_tx ? decodeSpendTx(a.payload.encoded_tx) : undefined;
  const hash = a.payload.tx_hash ?? a.payload.encoded_tx ?? '';
  let delta = 0n;
  let fee = 0n;
  if (spend) {
    const amount = BigInt(spend.amount);
    if (spend.recipientId === holder) delta += amount;
    if (spend.senderId === holder) {
      delta -= amount;
      fee = BigInt(spend.fee);
    }
  }
  return {
    hash: hash.startsWith('th_') ? hash : '',
    chainId,
    from: spend?.senderId ?? '',
    ...(spend?.recipientId ? { to: spend.recipientId } : {}),
    ...(a.height !== undefined ? { blockNumber: a.height } : {}),
    ...(a.type !== 'SpendTxEvent' ? { description: a.type } : {}),
    assetDeltas: spend ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: String(fee),
    status: 'confirmed',
  };
}

export function createAeternityAdapter(opts?: AeternityAdapterOptions): AeternityAdapter {
  return new AeternityAdapter(opts);
}
