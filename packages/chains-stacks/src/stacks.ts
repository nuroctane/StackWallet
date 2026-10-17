/**
 * Stacks adapter. Addresses are c32check of hash160(compressed pubkey) with a
 * network version byte; reads go over the Hiro API, whose `/v2/info`
 * `network_id` is the CAIP-2 reference, so every endpoint proves which network
 * it serves.
 */
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  BaseAdapter,
  HttpError,
  fetchJson,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
  secp256k1Compressed,
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

export const STACKS_MAINNET = 'stacks:1';
export const STACKS_TESTNET = 'stacks:2147483648';
export const VERSION = {
  mainnetP2pkh: 22,
  mainnetP2sh: 20,
  testnetP2pkh: 26,
  testnetP2sh: 21,
} as const;
const NETWORK_VERSIONS: Record<string, readonly number[]> = {
  [STACKS_MAINNET]: [VERSION.mainnetP2pkh, VERSION.mainnetP2sh],
  [STACKS_TESTNET]: [VERSION.testnetP2pkh, VERSION.testnetP2sh],
};
const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function c32Encode(data: Uint8Array): string {
  let num = 0n;
  for (const b of data) num = (num << 8n) | BigInt(b);
  let out = '';
  while (num > 0n) {
    out = C32[Number(num % 32n)]! + out;
    num /= 32n;
  }
  let zeros = 0;
  while (zeros < data.length && data[zeros] === 0) zeros++;
  return '0'.repeat(zeros) + out;
}

function c32Decode(text: string): Uint8Array | undefined {
  let zeros = 0;
  while (zeros < text.length && text[zeros] === '0') zeros++;
  let num = 0n;
  for (const c of text.slice(zeros)) {
    const v = C32.indexOf(c);
    if (v < 0) return undefined;
    num = num * 32n + BigInt(v);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes]);
}

function checksum(version: number, hash: Uint8Array): Uint8Array {
  return sha256(sha256(Uint8Array.from([version, ...hash]))).subarray(0, 4);
}

export function encodeStacksAddress(version: number, hash: Uint8Array): string {
  if (hash.length !== 20 || !Number.isInteger(version) || version < 0 || version > 31)
    throw new Error('Invalid Stacks address payload');
  return `S${C32[version]}${c32Encode(Uint8Array.from([...hash, ...checksum(version, hash)]))}`;
}

/** Version and hash160 of a canonical standard principal; contract principals are refused. */
export function stacksAddressBytes(
  addr: string,
): { version: number; hash: Uint8Array } | undefined {
  if (!/^S[0-9A-HJKMNP-TV-Z]{1,40}$/.test(addr)) return undefined;
  const version = C32.indexOf(addr[1]!);
  const data = c32Decode(addr.slice(2));
  if (!data || data.length !== 24) return undefined;
  const hash = data.subarray(0, 20);
  if (hash.every((b) => b === 0)) return undefined;
  if (encodeStacksAddress(version, hash) !== addr) return undefined;
  return { version, hash };
}

/** Syntactic and checksum validation; with a chain id the version must belong to that network. */
export function isValidStacksAddress(addr: string, chainId?: string): boolean {
  const parsed = stacksAddressBytes(addr);
  if (!parsed) return false;
  const allowed = chainId === undefined ? Object.values(VERSION) : NETWORK_VERSIONS[chainId];
  return (allowed ?? []).includes(parsed.version as never);
}

export function stacksAddressFromPublicKey(sec1: Uint8Array, chainId = STACKS_TESTNET): string {
  const version = chainId === STACKS_MAINNET ? VERSION.mainnetP2pkh : VERSION.testnetP2pkh;
  return encodeStacksAddress(version, ripemd160(sha256(secp256k1Compressed(sec1))));
}

const MicroStx = z.string().regex(/^\d{1,39}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const TxId = z.string().regex(/^0x[0-9a-f]{64}$/);
const Info = z.object({ network_id: SafeInt });
export const StxBalance = z.object({ balance: MicroStx, locked: MicroStx });
export const Nonces = z.object({
  last_executed_tx_nonce: SafeInt.nullable(),
  last_mempool_tx_nonce: SafeInt.nullable(),
  possible_next_nonce: SafeInt,
  detected_missing_nonces: z.array(SafeInt).max(1024),
});
const PrincipalText = z.string().max(160);
const ApiTx = z.object({
  tx_id: TxId,
  tx_type: z.string().max(64),
  tx_status: z.string().max(64),
  sender_address: PrincipalText,
  nonce: SafeInt.optional(),
  /** Despite the name, the total fee in microSTX. */
  fee_rate: MicroStx.optional(),
  sponsored: z.boolean().optional(),
  block_height: SafeInt.optional(),
  block_time: SafeInt.optional(),
  burn_block_time: SafeInt.optional(),
  replaced_by_tx_id: TxId.nullable().optional(),
  token_transfer: z
    .object({ recipient_address: PrincipalText, amount: MicroStx })
    .loose()
    .optional(),
});
const HistoryPage = z.object({
  limit: SafeInt,
  offset: SafeInt,
  total: SafeInt,
  results: z.array(ApiTx.loose()).max(200),
});

export type StacksAdapterOptions = BaseAdapterOptions;
export type StacksGet = <T>(path: string, schema: z.ZodType<T>) => Promise<T | null>;
export type StacksPost = (
  path: string,
  body: unknown,
) => Promise<{ status: number; body: unknown }>;

const PAGE = 20;

export class StacksAdapter extends BaseAdapter<'stacks'> {
  constructor(opts: StacksAdapterOptions = {}) {
    super('stacks', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return stacksAddressFromPublicKey(publicKeyBytes(pub), chainId);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidStacksAddress(addr, chainId);
  }

  private get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T | null> {
    return this.rest(path, schema, [404])(url);
  }

  private async post(
    url: string,
    path: string,
    body: unknown,
  ): Promise<{ status: number; body: unknown }> {
    const doFetch = this.fetchImpl ?? globalThis.fetch;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs ?? 8000);
    try {
      const res = await doFetch(`${url.replace(/\/$/, '')}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await res.text();
      if (text.length > 65_536) throw new Error('Stacks node response too large');
      if (res.status >= 500) throw new HttpError(url, res.status, text.slice(0, 512));
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error('Stacks node response is not JSON');
      }
      return { status: res.status, body: parsed };
    } finally {
      clearTimeout(timer);
    }
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const info = await this.get(url, '/v2/info', Info);
      if (!info || `stacks:${info.network_id}` !== chainId)
        throw new Error('Endpoint network id does not match this Stacks network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(
    chainId: ChainId,
    query: (get: StacksGet, post: StacksPost, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(
        (path, schema) => this.get(url, path, schema),
        (path, body) => this.post(url, path, body),
        url,
      );
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidStacksAddress(addr, chainId)) throw new TypeError(`invalid stacks address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const res = await this.get(url, `/extended/v1/address/${addr}/stx`, StxBalance);
        return JSON.stringify({ balance: res?.balance ?? '0', locked: res?.locked ?? '0' });
      },
      { equal: (a, b) => a === b },
    );
    const { balance, locked } = JSON.parse(value) as { balance: string; locked: string };
    const holding = nativeHolding(chain, BigInt(balance).toString(), provenance);
    if (BigInt(locked) > 0n)
      holding.notice = `${locked} microSTX of this balance is locked in stacking and cannot be sent.`;
    return [holding];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidStacksAddress(addr, chainId)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,9}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const offset = Number(cursor ?? 0);
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    return withFailover(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const res = HistoryPage.parse(
          await fetchJson(
            `${url.replace(/\/$/, '')}/extended/v1/address/${addr}/transactions?limit=${PAGE}&offset=${offset}`,
            opts,
          ),
        );
        const next = res.offset + res.results.length;
        return {
          items: res.results.map((t) =>
            historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t),
          ),
          ...(res.results.length > 0 && next < res.total ? { nextCursor: String(next) } : {}),
          coverage:
            'Hiro account transactions. STX token transfers carry net changes; contract calls, deploys and stacking are listed without balance changes. Fees are paid by the sender.',
          source: url,
        };
      },
      options?.signal ? { signal: options.signal } : {},
    );
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Stacks transaction id');
    const id = `0x${hash.replace(/^0x/, '').toLowerCase()}`;
    return this.withNode(chainId, async (get) => {
      const tx = await get(`/extended/v1/tx/${id}`, ApiTx.loose());
      if (!tx) return { state: 'unknown' };
      return txStatus(tx);
    });
  }
}

export function txStatus(tx: z.infer<typeof ApiTx>): TxStatus {
  const s = tx.tx_status;
  if (s === 'pending') return { state: 'pending' };
  if (s === 'success') {
    if (tx.block_height === undefined) return { state: 'pending' };
    const t = tx.block_time ?? tx.burn_block_time;
    return {
      state: 'confirmed',
      blockNumber: tx.block_height,
      ...(t !== undefined ? { timestampMs: t * 1000 } : {}),
    };
  }
  if (s.startsWith('abort_')) return { state: 'failed', reason: s };
  if (s.startsWith('dropped_')) {
    if (tx.replaced_by_tx_id) return { state: 'replaced', byHash: tx.replaced_by_tx_id };
    return { state: 'dropped' };
  }
  return { state: 'unknown' };
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof ApiTx>,
): TxRecord {
  const transfer = t.tx_type === 'token_transfer' ? t.token_transfer : undefined;
  const failed = t.tx_status !== 'success' && t.tx_status !== 'pending';
  let delta = 0n;
  if (transfer && t.tx_status === 'success') {
    const amount = BigInt(transfer.amount);
    if (transfer.recipient_address === holder) delta += amount;
    if (t.sender_address === holder) delta -= amount;
  }
  // A sponsor pays a sponsored transaction's fee, and the API does not name the sponsor here.
  const fee = t.sender_address !== holder ? '0' : t.sponsored ? null : (t.fee_rate ?? null);
  return {
    hash: t.tx_id,
    chainId,
    from: t.sender_address,
    ...(transfer ? { to: transfer.recipient_address } : {}),
    ...(t.block_height !== undefined ? { blockNumber: t.block_height } : {}),
    ...((t.block_time ?? t.burn_block_time) !== undefined
      ? { timestampMs: (t.block_time ?? t.burn_block_time)! * 1000 }
      : {}),
    ...(t.tx_type !== 'token_transfer' ? { description: t.tx_type.slice(0, 64) } : {}),
    assetDeltas: transfer ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee,
    status: failed ? 'failed' : t.tx_status === 'pending' ? 'pending' : 'confirmed',
  };
}

export function createStacksAdapter(opts?: StacksAdapterOptions): StacksAdapter {
  return new StacksAdapter(opts);
}
