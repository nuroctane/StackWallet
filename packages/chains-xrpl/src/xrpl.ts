/**
 * XRP Ledger adapter. Classic addresses are base58check (Ripple alphabet) of
 * version 0x00 and ripemd160(sha256(compressed secp256k1 key)). Reads go over
 * rippled's JSON-RPC (`{ method, params: [{…}] }`, not JSON-RPC 2.0), or its
 * WebSocket API for Ripple's own ports (see `webSocketUrl`); every endpoint
 * proves its `network_id` before it is trusted.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base58xrp } from '@scure/base';
import {
  BaseAdapter,
  DEFAULT_TIMEOUT_MS,
  MAX_BODY_BYTES,
  MalformedResponseError,
  RpcTimeoutError,
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

export const XRPL_MAINNET = 'xrpl:0';
export const XRPL_TESTNET = 'xrpl:1';
export const XRPL_DEVNET = 'xrpl:2';
/** `network_id` each endpoint must report in `server_state`. */
export const NETWORK_IDS: Record<string, number> = {
  [XRPL_MAINNET]: 0,
  [XRPL_TESTNET]: 1,
  [XRPL_DEVNET]: 2,
};
const ACCOUNT_VERSION = 0;
/** Account root flags that change whether a plain payment can land. */
export const LSF_REQUIRE_DEST_TAG = 0x0002_0000;
export const LSF_DISALLOW_XRP = 0x0008_0000;
export const LSF_DEPOSIT_AUTH = 0x0100_0000;

function checksum(payload: Uint8Array): Uint8Array {
  return sha256(sha256(payload)).subarray(0, 4);
}

export function encodeXrplAddress(account: Uint8Array): string {
  if (account.length !== 20) throw new TypeError('AccountID must be 20 bytes');
  const raw = new Uint8Array(25);
  raw[0] = ACCOUNT_VERSION;
  raw.set(account, 1);
  raw.set(checksum(raw.subarray(0, 21)), 21);
  return base58xrp.encode(raw);
}

export function xrplAddressFromPublicKey(key: Uint8Array): string {
  const compressed = secp256k1.Point.fromBytes(key).toBytes(true);
  return encodeXrplAddress(ripemd160(sha256(compressed)));
}

/**
 * The AccountID behind a classic `r…` address. X-addresses, seeds and the
 * black-hole accounts zero and one are refused.
 */
export function xrplAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(addr)) return undefined;
  try {
    const raw = base58xrp.decode(addr);
    if (raw.length !== 25 || raw[0] !== ACCOUNT_VERSION) return undefined;
    const sum = checksum(raw.subarray(0, 21));
    if (!sum.every((b, i) => raw[21 + i] === b)) return undefined;
    const account = raw.slice(1, 21);
    const special = account.slice(0, 19).every((b) => b === 0) && account[19]! <= 1;
    if (special || encodeXrplAddress(account) !== addr) return undefined;
    return account;
  } catch {
    return undefined;
  }
}

export function isValidXrplAddress(addr: string): boolean {
  return xrplAddressBytes(addr) !== undefined;
}

const Drops = z.string().regex(/^\d{1,18}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const U32 = z.number().int().nonnegative().max(0xffff_ffff);
const Hash = z.string().regex(/^[0-9A-Fa-f]{64}$/);
const Account = z.string().regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
const ErrorCode = z.string().max(64);

const Envelope = z.object({ result: z.object({}).loose() });
const RpcFailure = z
  .object({
    status: z.literal('error'),
    error: ErrorCode,
    error_message: z.string().max(512).optional(),
  })
  .loose();

const ServerState = z.object({
  state: z
    .object({
      network_id: SafeInt.optional(),
      validated_ledger: z
        .object({
          seq: SafeInt,
          base_fee: SafeInt,
          reserve_base: SafeInt,
          reserve_inc: SafeInt,
        })
        .optional(),
    })
    .loose(),
});
export type ServerState = z.infer<typeof ServerState>;

export const AccountInfo = z.object({
  account_data: z
    .object({
      Account: Account,
      Balance: Drops,
      Flags: U32,
      OwnerCount: SafeInt,
      Sequence: U32,
    })
    .loose(),
  ledger_current_index: SafeInt.optional(),
  ledger_index: SafeInt.optional(),
});
export type AccountInfo = z.infer<typeof AccountInfo>;

export const FeeInfo = z.object({
  ledger_current_index: SafeInt,
  drops: z
    .object({
      base_fee: Drops,
      minimum_fee: Drops,
      open_ledger_fee: Drops,
    })
    .loose(),
});
export type FeeInfo = z.infer<typeof FeeInfo>;

const TxResult = z
  .object({
    hash: Hash,
    validated: z.boolean().optional(),
    ledger_index: SafeInt.optional(),
    close_time_iso: z.string().max(64).optional(),
    meta: z.object({ TransactionResult: ErrorCode }).loose().optional(),
  })
  .loose();

export const SubmitResult = z
  .object({
    engine_result: ErrorCode,
    engine_result_message: z.string().max(512).optional(),
    tx_json: z.object({ hash: Hash.optional() }).loose().optional(),
  })
  .loose();
export type SubmitResult = z.infer<typeof SubmitResult>;

const DeliveredAmount = z.union([
  Drops,
  z.literal('unavailable'),
  z.object({ currency: z.string().max(40), issuer: Account, value: z.string().max(64) }).loose(),
]);
const AccountTx = z.object({
  marker: z.object({ ledger: SafeInt, seq: SafeInt }).loose().optional(),
  transactions: z
    .array(
      z
        .object({
          hash: Hash,
          ledger_index: SafeInt.optional(),
          close_time_iso: z.string().max(64).optional(),
          validated: z.boolean().optional(),
          tx_json: z
            .object({
              TransactionType: z.string().max(64),
              Account: Account,
              Destination: Account.optional(),
              Fee: Drops.optional(),
            })
            .loose(),
          meta: z
            .object({
              TransactionResult: ErrorCode,
              delivered_amount: DeliveredAmount.optional(),
            })
            .loose(),
        })
        .loose(),
    )
    .max(400),
});
type AccountTxEntry = z.infer<typeof AccountTx>['transactions'][number];

/** rippled answered with an error object; `code` is its error token (`actNotFound`, …). */
export class XrplRpcError extends Error {
  override readonly name = 'XrplRpcError';
  constructor(
    readonly url: string,
    readonly code: string,
    message?: string,
  ) {
    super(`rippled ${code} from ${url}${message ? `: ${message}` : ''}`.slice(0, 512));
  }
}

/** One bound call on one endpoint; `null` when rippled answered with an error listed in `absent`. */
export type XrplCall = <T>(
  method: string,
  params: Record<string, unknown>,
  schema: z.ZodType<T>,
  absent?: readonly string[],
) => Promise<T | null>;

export type WebSocketCtor = new (url: string) => WebSocket;

export interface XrplAdapterOptions extends BaseAdapterOptions {
  /** WebSocket implementation for rippled's public ports; `null` keeps every call on HTTP. */
  webSocket?: WebSocketCtor | null;
}

/**
 * rippled serves JSON-RPC without CORS headers, so a browser cannot read
 * Ripple's public `https://host:51234` ports. The same servers answer the same
 * commands over WebSocket, which CORS does not govern, so those endpoints are
 * reached at their WebSocket port instead. Other urls (proxies such as
 * xrplcluster.com that send CORS headers) stay on HTTP.
 */
export function webSocketUrl(url: string): string | undefined {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return undefined;
  }
  if (u.protocol !== 'https:' || u.port !== '51234' || u.username || u.password) return undefined;
  const host = u.hostname.toLowerCase();
  if (host === 's1.ripple.com' || host === 's2.ripple.com') return `wss://${host}/`;
  return `wss://${host}:51233/`;
}

export class XrplAdapter extends BaseAdapter<'xrpl'> {
  private readonly webSocket: WebSocketCtor | undefined;

  constructor(opts: XrplAdapterOptions = {}) {
    super('xrpl', opts);
    this.webSocket =
      opts.webSocket === null ? undefined : (opts.webSocket ?? globalThis.WebSocket ?? undefined);
  }

  /** One request on a fresh socket; rippled answers with the same `id`. */
  private wsRequest(url: string, payload: Record<string, unknown>): Promise<unknown> {
    const Ctor = this.webSocket!;
    const timeoutMs = this.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    return new Promise((resolve, reject) => {
      let done = false;
      let sock: WebSocket | undefined;
      const finish = (error: Error | undefined, value?: unknown) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try {
          sock?.close();
        } catch {
          // Already closing.
        }
        if (error) reject(error);
        else resolve(value);
      };
      const timer = setTimeout(() => finish(new RpcTimeoutError(url, timeoutMs)), timeoutMs);
      try {
        sock = new Ctor(url);
      } catch (e) {
        finish(e instanceof Error ? e : new Error(String(e)));
        return;
      }
      sock.onopen = () => sock!.send(JSON.stringify({ ...payload, id: 1 }));
      sock.onmessage = (ev: MessageEvent) => {
        if (typeof ev.data !== 'string' || ev.data.length > MAX_BODY_BYTES) {
          finish(new MalformedResponseError(url, 'unexpected websocket frame'));
          return;
        }
        let msg: unknown;
        try {
          msg = JSON.parse(ev.data);
        } catch {
          finish(new MalformedResponseError(url, 'body is not JSON'));
          return;
        }
        if ((msg as { id?: unknown } | null)?.id === 1) finish(undefined, msg);
      };
      sock.onerror = () => finish(new Error(`websocket error from ${url}`));
      sock.onclose = () => finish(new Error(`websocket to ${url} closed before answering`));
    });
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return xrplAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidXrplAddress(addr);
  }

  private async call<T>(
    url: string,
    method: string,
    params: Record<string, unknown>,
    schema: z.ZodType<T>,
    absent: readonly string[] = [],
  ): Promise<T | null> {
    const ws = this.webSocket ? webSocketUrl(url) : undefined;
    let raw: unknown;
    if (ws) {
      const msg = await this.wsRequest(ws, { ...params, command: method });
      // WebSocket errors sit beside `result` rather than inside it.
      const failure = RpcFailure.safeParse(msg);
      raw = failure.success ? { result: failure.data } : msg;
    } else {
      const text = await postJsonText(url, { method, params: [params] }, this.fetchOptions());
      try {
        raw = JSON.parse(text);
      } catch {
        throw new MalformedResponseError(url, 'body is not JSON');
      }
    }
    const envelope = Envelope.safeParse(raw);
    if (!envelope.success) throw new MalformedResponseError(url, 'not a rippled response');
    const failure = RpcFailure.safeParse(envelope.data.result);
    if (failure.success) {
      if (absent.includes(failure.data.error)) return null;
      throw new XrplRpcError(url, failure.data.error, failure.data.error_message);
    }
    return schema.parse(envelope.data.result);
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const state = await this.call(url, 'server_state', {}, ServerState);
      if (state?.state.network_id !== NETWORK_IDS[chainId])
        throw new Error('Endpoint network_id does not match this XRPL network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: XrplCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(
        (method, params, schema, absent) => this.call(url, method, params, schema, absent),
        url,
      );
    });
  }

  /** The validated ledger's index, base fee and reserves, all in drops. */
  async ledgerState(
    chainId: ChainId,
  ): Promise<{ seq: number; baseFee: number; reserveBase: number; reserveInc: number }> {
    return this.withNode(chainId, async (call) => {
      const v = (await call('server_state', {}, ServerState))?.state.validated_ledger;
      if (!v) throw new Error('Endpoint has no validated ledger');
      return {
        seq: v.seq,
        baseFee: v.base_fee,
        reserveBase: v.reserve_base,
        reserveInc: v.reserve_inc,
      };
    });
  }

  /** `null` for an account that was never funded. */
  async account(
    addr: Address,
    chainId: ChainId,
    ledger: 'validated' | 'current' = 'validated',
  ): Promise<AccountInfo | null> {
    if (!isValidXrplAddress(addr)) throw new TypeError(`invalid XRPL address ${addr}`);
    return this.withNode(chainId, (call) => accountInfo(call, addr, ledger));
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidXrplAddress(addr)) throw new TypeError(`invalid XRPL address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const info = await accountInfo(
          (m, p, s, a) => this.call(url, m, p, s, a),
          addr,
          'validated',
        );
        // An account that was never funded does not exist on the ledger: zero, not an error.
        return info ? BigInt(info.account_data.Balance).toString() : '0';
      },
      { equal: (a, b) => a === b },
    );
    return [
      {
        ...nativeHolding(chain, value, provenance),
        notice:
          'Includes the reserve the ledger locks (base reserve plus one increment per owned object).',
      },
    ];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidXrplAddress(addr)) throw new Error('Invalid history address');
    let marker: { ledger: number; seq: number } | undefined;
    if (cursor !== undefined) {
      const m = /^(\d{1,10}):(\d{1,10})$/.exec(cursor);
      if (!m) throw new Error('Invalid history cursor');
      marker = { ledger: Number(m[1]), seq: Number(m[2]) };
    }
    const limit = 20;
    return this.withNode(chainId, async (call, url) => {
      const page = await call(
        'account_tx',
        {
          account: addr,
          limit,
          forward: false,
          api_version: 2,
          ...(marker ? { marker } : {}),
        },
        AccountTx,
        ['actNotFound'],
      );
      if (!page) return { items: [], source: url };
      return {
        items: page.transactions.map((t) =>
          historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t),
        ),
        ...(page.marker ? { nextCursor: `${page.marker.ledger}:${page.marker.seq}` } : {}),
        coverage:
          'rippled account_tx over the ledgers this node keeps. XRP deltas use delivered_amount; issued-currency movements are listed without deltas.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid XRPL transaction hash');
    return this.withNode(chainId, async (call) => {
      const tx = await call(
        'tx',
        { transaction: hash.toUpperCase(), binary: false, api_version: 2 },
        TxResult,
        ['txnNotFound'],
      );
      if (!tx) return { state: 'unknown' };
      // Results are provisional until the ledger holding them is validated.
      if (!tx.validated || tx.ledger_index === undefined) return { state: 'pending' };
      const result = tx.meta?.TransactionResult;
      if (result !== 'tesSUCCESS') return { state: 'failed', reason: result ?? 'no result' };
      const ts = tx.close_time_iso ? Date.parse(tx.close_time_iso) : NaN;
      return {
        state: 'confirmed',
        blockNumber: tx.ledger_index,
        ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
      };
    });
  }

  /** Submits a signed blob (hex) and returns rippled's preliminary verdict. */
  async submit(chainId: ChainId, blobHex: string): Promise<SubmitResult> {
    if (!/^[0-9A-F]+$/.test(blobHex)) throw new Error('Blob must be uppercase hex');
    return this.withNode(chainId, async (call) => {
      const res = await call('submit', { tx_blob: blobHex, fail_hard: false }, SubmitResult);
      if (!res) throw new Error('rippled returned no submit result');
      return res;
    });
  }
}

export function accountInfo(
  call: XrplCall,
  addr: string,
  ledger: 'validated' | 'current',
): Promise<AccountInfo | null> {
  return call('account_info', { account: addr, ledger_index: ledger, strict: true }, AccountInfo, [
    'actNotFound',
  ]);
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: AccountTxEntry,
): TxRecord {
  const tx = t.tx_json;
  const result = t.meta.TransactionResult;
  const ok = result === 'tesSUCCESS';
  const delivered = t.meta.delivered_amount;
  let delta = 0n;
  let xrp = false;
  if (ok && tx.TransactionType === 'Payment' && typeof delivered === 'string') {
    if (delivered !== 'unavailable') {
      xrp = true;
      const amount = BigInt(delivered);
      if (tx.Destination === holder) delta += amount;
      if (tx.Account === holder) delta -= amount;
    }
  }
  const ts = t.close_time_iso ? Date.parse(t.close_time_iso) : NaN;
  return {
    hash: t.hash.toUpperCase(),
    chainId,
    ...(t.ledger_index !== undefined ? { blockNumber: t.ledger_index } : {}),
    ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
    from: tx.Account,
    ...(tx.Destination ? { to: tx.Destination } : {}),
    ...(tx.TransactionType !== 'Payment' || !xrp
      ? { description: ok ? tx.TransactionType : `${tx.TransactionType} ${result}` }
      : {}),
    assetDeltas: xrp ? [{ assetRef: nativeRef, amount: delta.toString() }] : [],
    feeAssetRef: nativeRef,
    // The sender pays the fee even when a tec result leaves the payment undone.
    fee: tx.Account === holder && tx.Fee ? tx.Fee : null,
    status: t.validated === false ? 'pending' : ok ? 'confirmed' : 'failed',
  };
}

export function createXrplAdapter(opts?: XrplAdapterOptions): XrplAdapter {
  return new XrplAdapter(opts);
}
