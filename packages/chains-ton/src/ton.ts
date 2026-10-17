/**
 * TON adapter for wallet v4r2 accounts on the basechain. The account id is
 * the hash of the wallet's StateInit (v4r2 code + seqno 0, subwallet
 * 698983191, the Ed25519 key, no plugins), shown in the user-friendly
 * base64url form. Two keyless API dialects are spoken: toncenter (v2, plus v3
 * for message lookups) and tonapi. Each endpoint proves its network by the
 * masterchain zerostate root hash before it is trusted.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64, base64urlnopad } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  fetchJson,
  fetchText,
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

import { Builder, Cell, crc16, parseBoc } from './cell.js';

export const TON_TESTNET = 'tvm:-3';
export const TON_MAINNET = 'tvm:-239';
/** Masterchain zerostate root hashes (hex): the identity of each network. */
export const ZEROSTATE_ROOT_HASH: Record<string, string> = {
  [TON_MAINNET]: bytesToHex(base64.decode('F6OpKZKqvqeFp6CQmFomXNMfMj2EnaUSOXN+Mh+wVWk=')),
  [TON_TESTNET]: bytesToHex(base64.decode('gj+B8wb/AmlPk1z1AhVI484rhrUpgSr2oSFIh56VoSg=')),
};
/** The v4r2 default `wallet_id` for workchain 0, on both networks. */
export const SUBWALLET_ID = 698_983_191;
/** Wallet v4r2 code as `@ton/ton` ships it; its hash is `feb5ff68…bd5c0`. */
const WALLET_V4R2_CODE =
  'te6ccgECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVA==';
const TAG_BOUNCEABLE = 0x11;
const TAG_NON_BOUNCEABLE = 0x51;
const TAG_TEST_ONLY = 0x80;

let code: Cell | undefined;
export function walletCode(): Cell {
  code ??= parseBoc(base64.decode(WALLET_V4R2_CODE));
  return code;
}

export function walletStateInit(publicKey: Uint8Array): Cell {
  if (publicKey.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  const data = new Builder().uint(0, 32).uint(SUBWALLET_ID, 32).bytes(publicKey).bit(false).build();
  // split_depth:none special:none code:just data:just library:empty
  return new Builder()
    .bit(false)
    .bit(false)
    .bit(true)
    .ref(walletCode())
    .bit(true)
    .ref(data)
    .bit(false)
    .build();
}

export function tonWalletHash(publicKey: Uint8Array): Uint8Array {
  return walletStateInit(publicKey).hash;
}

export function friendlyAddress(
  hash: Uint8Array,
  opts: { bounceable: boolean; testOnly: boolean },
): string {
  const raw = new Uint8Array(36);
  const tag = opts.bounceable ? TAG_BOUNCEABLE : TAG_NON_BOUNCEABLE;
  raw[0] = opts.testOnly ? tag | TAG_TEST_ONLY : tag;
  raw[1] = 0;
  raw.set(hash, 2);
  const crc = crc16(raw.subarray(0, 34));
  raw[34] = crc >> 8;
  raw[35] = crc & 0xff;
  return base64urlnopad.encode(raw);
}

/** Non-bounceable (`0Q…` on testnet, `UQ…` on mainnet), as wallets show a wallet. */
export function tonAddressFromPublicKey(publicKey: Uint8Array, testOnly = true): string {
  return friendlyAddress(tonWalletHash(publicKey), { bounceable: false, testOnly });
}

export interface ParsedTonAddress {
  hash: Uint8Array;
  /** Absent for the raw `0:<hex>` form, which carries no flags. */
  bounceable?: boolean;
  testOnly?: boolean;
}

/** A basechain address in any user-friendly spelling (url-safe or standard base64) or `0:<hex>`. */
export function parseTonAddress(addr: string): ParsedTonAddress | undefined {
  const raw = /^0:([0-9a-fA-F]{64})$/.exec(addr);
  if (raw) return { hash: hexToBytes(raw[1]!.toLowerCase()) };
  if (!/^[A-Za-z0-9_\-+/]{48}$/.test(addr)) return undefined;
  if (/[-_]/.test(addr) && /[+/]/.test(addr)) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = base64urlnopad.decode(addr.replace(/\+/g, '-').replace(/\//g, '_'));
  } catch {
    return undefined;
  }
  if (bytes.length !== 36) return undefined;
  const crc = crc16(bytes.subarray(0, 34));
  if (bytes[34] !== crc >> 8 || bytes[35] !== (crc & 0xff)) return undefined;
  const tag = bytes[0]! & ~TAG_TEST_ONLY;
  if (tag !== TAG_BOUNCEABLE && tag !== TAG_NON_BOUNCEABLE) return undefined;
  if (bytes[1] !== 0) return undefined;
  return {
    hash: bytes.slice(2, 34),
    bounceable: tag === TAG_BOUNCEABLE,
    testOnly: (bytes[0]! & TAG_TEST_ONLY) !== 0,
  };
}

export function isValidTonAddress(addr: string): boolean {
  return parseTonAddress(addr) !== undefined;
}

export function rawTonAddress(hash: Uint8Array): string {
  return `0:${bytesToHex(hash)}`;
}

/** Raw lowercase `0:<hex>` for any accepted spelling; undefined for anything else. */
export function normalizeTonAddress(addr: string): string | undefined {
  const p = parseTonAddress(addr);
  return p ? rawTonAddress(p.hash) : undefined;
}

/** TEP-467 normalized hash of an external message to `wallet` carrying `body`. */
export function normalizedMessageHash(wallet: Uint8Array, body: Cell): string {
  return new Builder()
    .uint(0b10, 2)
    .uint(0, 2)
    .address(wallet)
    .coins(0n)
    .bit(false)
    .bit(true)
    .ref(body)
    .build()
    .hashHex();
}

// ---------------------------------------------------------------- dialects

export type AccountStatus = 'active' | 'uninit' | 'frozen' | 'nonexist';
export interface TonAccount {
  balance: bigint;
  status: AccountStatus;
}
export interface TonMessage {
  external: boolean;
  /** Raw `0:<hex>`; null for an external message. */
  source: string | null;
  destination: string | null;
  value: bigint;
  /** The body cell when the endpoint returned it, for normalized hashing. */
  body?: Cell;
}
export interface TonTransaction {
  hash: string;
  lt: string;
  utime: number;
  fee: bigint | null;
  /** Null when the endpoint does not report compute/action phases. */
  aborted: boolean | null;
  /** Seqno of the shard block holding the transaction; both dialects report it. */
  block: number | null;
  account: string;
  inMsg: TonMessage | null;
  outMsgs: TonMessage[];
}
export type SendResult = { accepted: true } | { accepted: false; error: string };

/** One endpoint that proved its network; every call stays on it. */
export interface TonNode {
  readonly url: string;
  account(raw: string): Promise<TonAccount>;
  /** 0 for a wallet that is not active. */
  seqno(raw: string): Promise<number>;
  publicKey(raw: string): Promise<Uint8Array | null>;
  transactions(
    raw: string,
    limit: number,
    before?: { lt: string; hash: string },
  ): Promise<TonTransaction[]>;
  /** By normalized external-message hash or transaction hash (hex); null when unknown. */
  transaction(hashHex: string): Promise<TonTransaction | null>;
  send(bocBase64: string): Promise<SendResult>;
}

const Dec = z
  .union([z.string().regex(/^\d{1,40}$/), z.number().int().nonnegative()])
  .transform(BigInt);
const B64Hash = z.string().regex(/^[A-Za-z0-9+/_-]{43}=?$/);
const HexHash = z.string().regex(/^[0-9a-fA-F]{64}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const LtString = z
  .union([z.string().regex(/^\d{1,20}$/), z.number().int().nonnegative()])
  .transform(String);
const AnyAddr = z.string().max(80);

const b64ToHex = (s: string) => bytesToHex(base64.decode(s.replace(/-/g, '+').replace(/_/g, '/')));
const hexToB64 = (s: string) => base64.encode(hexToBytes(s));
/** Integers beyond 2^53 must stay strings before `JSON.parse` rounds them. */
const quoteBigInts = (text: string) =>
  text.replace(
    /"(balance|value|total_fees|end_balance|lt|created_lt|fwd_fee|import_fee|ihr_fee)":(\d+)/g,
    '"$1":"$2"',
  );
const rawOf = (addr: string | null | undefined): string | null =>
  addr ? (normalizeTonAddress(addr) ?? null) : null;

function bocCell(b64OrHex: string | undefined, hex: boolean): Cell | undefined {
  if (!b64OrHex) return undefined;
  try {
    return parseBoc(hex ? hexToBytes(b64OrHex) : base64.decode(b64OrHex));
  } catch {
    return undefined;
  }
}

const Envelope = <T extends z.ZodTypeAny>(result: T) => z.object({ ok: z.literal(true), result });

const V2Info = z.object({
  init: z.object({ root_hash: B64Hash }).loose(),
  last: z.object({ seqno: SafeInt }).loose(),
});
const V2Account = z.object({
  balance: Dec,
  state: z.enum(['active', 'uninitialized', 'frozen']),
});
const V2Wallet = z.object({
  account_state: z.string().max(32),
  seqno: SafeInt.optional(),
});
const V2RunResult = z.object({
  exit_code: z.number().int(),
  stack: z.array(z.tuple([z.string().max(16), z.unknown()])).max(16),
});
const V2Msg = z
  .object({
    source: AnyAddr,
    destination: AnyAddr,
    value: Dec,
    msg_data: z
      .object({
        '@type': z.string().max(32),
        body: z
          .string()
          .max(1 << 16)
          .optional(),
      })
      .loose()
      .optional(),
  })
  .loose();
const V2Tx = z
  .object({
    utime: SafeInt,
    transaction_id: z.object({ lt: LtString, hash: B64Hash }),
    fee: Dec,
    in_msg: V2Msg.optional(),
    out_msgs: z.array(V2Msg).max(255),
  })
  .loose();
const V3Msg = z
  .object({
    source: AnyAddr.nullable(),
    destination: AnyAddr.nullable(),
    value: Dec.nullable(),
    message_content: z
      .object({
        body: z
          .string()
          .max(1 << 16)
          .nullable()
          .optional(),
      })
      .loose()
      .optional(),
  })
  .loose();
const V3Tx = z
  .object({
    account: AnyAddr,
    hash: B64Hash,
    lt: LtString,
    now: SafeInt,
    block_ref: z.object({ seqno: SafeInt }).loose().nullable().optional(),
    total_fees: Dec,
    description: z.object({ aborted: z.boolean() }).loose(),
    in_msg: V3Msg.nullable(),
    out_msgs: z.array(V3Msg).max(255),
  })
  .loose();
const ApiAccount = z.object({
  balance: Dec,
  status: z.enum(['active', 'uninit', 'frozen', 'nonexist']),
});
const ApiMsg = z
  .object({
    msg_type: z.string().max(32),
    value: Dec,
    source: z.object({ address: AnyAddr }).loose().nullable().optional(),
    destination: z.object({ address: AnyAddr }).loose().nullable().optional(),
    raw_body: z
      .string()
      .max(1 << 17)
      .optional(),
  })
  .loose();
const ApiTx = z
  .object({
    hash: HexHash,
    lt: LtString,
    account: z.object({ address: AnyAddr }).loose(),
    utime: SafeInt,
    total_fees: Dec,
    aborted: z.boolean().optional(),
    success: z.boolean().optional(),
    block: z.string().max(128).optional(),
    in_msg: ApiMsg.nullable().optional(),
    out_msgs: z.array(ApiMsg).max(255),
  })
  .loose();
const ApiError = z.object({ error: z.string().max(4096) }).loose();
const V2Error = z.object({ ok: z.literal(false), error: z.string().max(1 << 14) }).loose();

/** A liteserver or wallet verdict on the message itself, not a sick endpoint. */
const isVerdict = (status: number, error: string) =>
  (status === 500 || status === 400 || status === 406) &&
  /external message|exitcode|exit code|not accepted|duplicate|already/i.test(error);

export function shortReason(error: string): string {
  const exit = /exit ?code[=: ]*(-?\d+)/i.exec(error)?.[1];
  const first = error.split('\n')[0]!.replace(/^LITE_SERVER_UNKNOWN:\s*/, '');
  const meaning: Record<string, string> = {
    '33': 'seqno mismatch',
    '34': 'subwallet mismatch',
    '35': 'invalid signature',
    '36': 'message expired (validUntil passed)',
    '37': 'insufficient balance',
  };
  return (exit ? `${meaning[exit] ?? `wallet exit code ${exit}`}: ${first}` : first).slice(0, 300);
}

function v2Message(m: z.infer<typeof V2Msg>): TonMessage {
  const body =
    m.msg_data?.['@type'] === 'msg.dataRaw' ? bocCell(m.msg_data.body, false) : undefined;
  return {
    external: m.source === '',
    source: rawOf(m.source),
    destination: rawOf(m.destination),
    value: m.value,
    ...(body ? { body } : {}),
  };
}

function v3Message(m: z.infer<typeof V3Msg>): TonMessage {
  const body = bocCell(m.message_content?.body ?? undefined, false);
  return {
    external: m.source === null,
    source: rawOf(m.source),
    destination: rawOf(m.destination),
    value: m.value ?? 0n,
    ...(body ? { body } : {}),
  };
}

function apiMessage(m: z.infer<typeof ApiMsg>): TonMessage {
  const body = bocCell(m.raw_body, true);
  return {
    external: m.msg_type === 'ext_in_msg',
    source: rawOf(m.source?.address),
    destination: rawOf(m.destination?.address),
    value: m.value,
    ...(body ? { body } : {}),
  };
}

function v3Tx(t: z.infer<typeof V3Tx>): TonTransaction {
  return {
    hash: b64ToHex(t.hash),
    lt: t.lt,
    utime: t.now,
    fee: t.total_fees,
    aborted: t.description.aborted,
    block: t.block_ref?.seqno ?? null,
    account: rawOf(t.account) ?? t.account,
    inMsg: t.in_msg ? v3Message(t.in_msg) : null,
    outMsgs: t.out_msgs.map(v3Message),
  };
}

function apiTx(t: z.infer<typeof ApiTx>): TonTransaction {
  const block = /,(\d+)\)$/.exec(t.block ?? '')?.[1];
  return {
    hash: t.hash.toLowerCase(),
    lt: t.lt,
    utime: t.utime,
    fee: t.total_fees,
    aborted: t.aborted ?? (t.success === undefined ? null : !t.success),
    block: block ? Number(block) : null,
    account: rawOf(t.account.address) ?? t.account.address,
    inMsg: t.in_msg ? apiMessage(t.in_msg) : null,
    outMsgs: t.out_msgs.map(apiMessage),
  };
}

export const isTonapi = (url: string) => {
  try {
    return new URL(url).hostname.endsWith('tonapi.io');
  } catch {
    return false;
  }
};

export interface TonAdapterOptions extends BaseAdapterOptions {
  /** Spacing between requests to one origin; keyless toncenter and tonapi allow about 1 rps. */
  minIntervalMs?: number;
}

export class TonAdapter extends BaseAdapter<'ton'> {
  private readonly minIntervalMs: number;
  private readonly nextSlot = new Map<string, number>();

  constructor(opts: TonAdapterOptions = {}) {
    super('ton', opts);
    this.minIntervalMs = opts.minIntervalMs ?? 1100;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    const chain = this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return tonAddressFromPublicKey(publicKeyBytes(pub), chain.testnet);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidTonAddress(addr);
  }

  private async pace(url: string): Promise<void> {
    if (this.minIntervalMs <= 0) return;
    const origin = new URL(url).origin;
    const now = Date.now();
    const slot = Math.max(now, this.nextSlot.get(origin) ?? 0);
    this.nextSlot.set(origin, slot + this.minIntervalMs);
    if (slot > now) await new Promise((r) => setTimeout(r, slot - now));
  }

  /**
   * Keyless toncenter counts requests per IP across all tabs and apps, so a
   * paced client still meets an occasional 429; one spaced retry absorbs it
   * before failover marks the endpoint unhealthy.
   */
  private async paced<T>(url: string, call: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      await this.pace(url);
      try {
        return await call();
      } catch (error) {
        if (!(error instanceof HttpError) || error.status !== 429 || attempt >= 2) throw error;
        const origin = new URL(url).origin;
        const backoff = Math.max(this.minIntervalMs, 1) * (attempt + 2);
        this.nextSlot.set(origin, Math.max(this.nextSlot.get(origin) ?? 0, Date.now() + backoff));
      }
    }
  }

  private getText(url: string): Promise<string> {
    return this.paced(url, () => fetchText(url, this.fetchOptions()));
  }

  private getJson(url: string): Promise<unknown> {
    return this.paced(url, () => fetchJson(url, this.fetchOptions()));
  }

  private postText(url: string, body: unknown): Promise<string> {
    return this.paced(url, () => postJsonText(url, body, this.fetchOptions()));
  }

  /** POST that returns status and parsed body, since TON verdicts arrive as 4xx/5xx JSON. */
  private postRaw(url: string, body: unknown): Promise<{ status: number; body: unknown }> {
    return this.paced(url, async () => {
      const doFetch = this.fetchImpl ?? globalThis.fetch;
      const res = await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs ?? 30_000),
      });
      const text = (await res.text()).slice(0, 1 << 16);
      if (res.status === 429) throw new HttpError(url, res.status, text.slice(0, 512));
      let parsed: unknown;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        throw new HttpError(url, res.status, text.slice(0, 512));
      }
      return { status: res.status, body: parsed };
    });
  }

  private toncenter(url: string): TonNode {
    const base = url.replace(/\/$/, '');
    const v3 = /\/api\/v2$/.test(base) ? base.replace(/\/api\/v2$/, '/api/v3') : null;
    const get = async <T>(method: string, params: Record<string, string>, schema: z.ZodType<T>) => {
      const q = new URLSearchParams(params);
      return Envelope(schema).parse(
        JSON.parse(quoteBigInts(await this.getText(`${base}/${method}?${q}`))),
      ).result;
    };
    const run = async (raw: string, method: string) => {
      const text = await this.postText(`${base}/runGetMethod`, {
        address: raw,
        method,
        stack: [],
      });
      return Envelope(V2RunResult).parse(JSON.parse(text)).result;
    };
    const v3List = async (path: string): Promise<TonTransaction[]> => {
      if (!v3) throw new Error('This toncenter endpoint has no v3 index');
      const raw = JSON.parse(quoteBigInts(await this.getText(`${v3}${path}`)));
      return z
        .object({ transactions: z.array(V3Tx).max(64) })
        .loose()
        .parse(raw)
        .transactions.map(v3Tx);
    };
    const v3Get = async (path: string) => (await v3List(path))[0] ?? null;
    return {
      url,
      account: async (raw) => {
        const a = await get('getAddressInformation', { address: raw }, V2Account);
        const status: AccountStatus = a.state === 'uninitialized' ? 'uninit' : a.state;
        return { balance: a.balance, status };
      },
      seqno: async (raw) => {
        const w = await get('getWalletInformation', { address: raw }, V2Wallet);
        if (w.account_state !== 'active') return 0;
        if (w.seqno === undefined) throw new Error('Endpoint did not report the wallet seqno');
        return w.seqno;
      },
      publicKey: async (raw) => {
        const r = await run(raw, 'get_public_key');
        const top = r.stack[0];
        if (r.exit_code !== 0 || !top || top[0] !== 'num' || typeof top[1] !== 'string')
          return null;
        const hex = top[1].replace(/^-?0x/, '').padStart(64, '0');
        return /^[0-9a-f]{64}$/i.test(hex) ? hexToBytes(hex.toLowerCase()) : null;
      },
      transactions: async (raw, limit, before) => {
        // The v2 history call needs the liteserver to hold the block of every
        // listed transaction, which public testnet nodes often do not; v3 reads its index.
        if (v3) {
          const q = new URLSearchParams({ account: raw, limit: String(limit), sort: 'desc' });
          if (before) q.set('end_lt', (BigInt(before.lt) - 1n).toString());
          return v3List(`/transactions?${q}`);
        }
        const params: Record<string, string> = {
          address: raw,
          limit: String(limit + (before ? 1 : 0)),
          archival: 'true',
        };
        if (before) Object.assign(params, { lt: before.lt, hash: hexToB64(before.hash) });
        const txs = await get('getTransactions', params, z.array(V2Tx).max(64));
        const mapped = txs.map(
          (t): TonTransaction => ({
            hash: b64ToHex(t.transaction_id.hash),
            lt: t.transaction_id.lt,
            utime: t.utime,
            fee: t.fee,
            aborted: null,
            block: null,
            account: raw,
            inMsg: t.in_msg ? v2Message(t.in_msg) : null,
            outMsgs: t.out_msgs.map(v2Message),
          }),
        );
        // v2 pages start at the cursor transaction itself.
        return before ? mapped.filter((t) => t.hash !== before.hash).slice(0, limit) : mapped;
      },
      transaction: async (hashHex) => {
        const byMsg = await v3Get(
          `/transactionsByMessage?msg_hash=${hashHex}&direction=in&limit=1`,
        );
        return byMsg ?? v3Get(`/transactions?hash=${hashHex}&limit=1`);
      },
      send: async (boc) => {
        const res = await this.postRaw(`${base}/sendBocReturnHash`, { boc });
        if (res.status === 200 && Envelope(z.unknown()).safeParse(res.body).success)
          return { accepted: true };
        const err = V2Error.safeParse(res.body);
        if (err.success && isVerdict(res.status, err.data.error))
          return { accepted: false, error: err.data.error };
        throw new HttpError(url, res.status, JSON.stringify(res.body).slice(0, 512));
      },
    };
  }

  private tonapi(url: string): TonNode {
    const base = url.replace(/\/$/, '');
    const get = async <T>(
      path: string,
      schema: z.ZodType<T>,
      notFound = false,
    ): Promise<T | null> => {
      try {
        return schema.parse(JSON.parse(quoteBigInts(await this.getText(`${base}${path}`))));
      } catch (error) {
        if (notFound && error instanceof HttpError && error.status === 404) return null;
        throw error;
      }
    };
    return {
      url,
      account: async (raw) => {
        const a = (await get(`/accounts/${raw}`, ApiAccount))!;
        return { balance: a.balance, status: a.status };
      },
      seqno: async (raw) => {
        const a = (await get(`/accounts/${raw}`, ApiAccount))!;
        if (a.status !== 'active') return 0;
        return (await get(`/wallet/${raw}/seqno`, z.object({ seqno: SafeInt })))!.seqno;
      },
      publicKey: async (raw) => {
        const r = await get(`/accounts/${raw}/publickey`, z.object({ public_key: HexHash }), true);
        return r ? hexToBytes(r.public_key.toLowerCase()) : null;
      },
      transactions: async (raw, limit, before) => {
        const q = new URLSearchParams({ limit: String(limit) });
        if (before) q.set('before_lt', before.lt);
        const r = await get(
          `/blockchain/accounts/${raw}/transactions?${q}`,
          z.object({ transactions: z.array(ApiTx).max(256) }),
        );
        return r!.transactions.map(apiTx);
      },
      transaction: async (hashHex) => {
        const byMsg = await get(`/blockchain/messages/${hashHex}/transaction`, ApiTx, true);
        if (byMsg) return apiTx(byMsg);
        const tx = await get(`/blockchain/transactions/${hashHex}`, ApiTx, true);
        return tx ? apiTx(tx) : null;
      },
      send: async (boc) => {
        const res = await this.postRaw(`${base}/blockchain/message`, { boc });
        if (res.status === 200) return { accepted: true };
        const err = ApiError.safeParse(res.body);
        if (err.success && isVerdict(res.status, err.data.error))
          return { accepted: false, error: err.data.error };
        throw new HttpError(url, res.status, JSON.stringify(res.body).slice(0, 512));
      },
    };
  }

  private node(url: string): TonNode {
    return isTonapi(url) ? this.tonapi(url) : this.toncenter(url);
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const base = url.replace(/\/$/, '');
      let root: string;
      if (isTonapi(url)) {
        const r = z
          .object({ init: z.object({ root_hash: HexHash }).loose() })
          .loose()
          .parse(await this.getJson(`${base}/liteserver/get_masterchain_info`));
        root = r.init.root_hash.toLowerCase();
      } else {
        const r = Envelope(V2Info).parse(await this.getJson(`${base}/getMasterchainInfo`));
        root = b64ToHex(r.result.init.root_hash);
      }
      if (root !== ZEROSTATE_ROOT_HASH[chainId])
        throw new Error('Endpoint zerostate does not match this TON network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (node: TonNode) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(this.node(url));
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const raw = normalizeTonAddress(addr);
    if (!raw) throw new TypeError(`invalid TON address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        return (await this.node(url).account(raw)).balance.toString();
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    const raw = normalizeTonAddress(addr);
    if (!raw) throw new Error('Invalid history address');
    let before: { lt: string; hash: string } | undefined;
    if (cursor !== undefined) {
      const m = /^(\d{1,20}):([0-9a-f]{64})$/.exec(cursor);
      if (!m) throw new Error('Invalid history cursor');
      before = { lt: m[1]!, hash: m[2]! };
    }
    const limit = 20;
    let source = '';
    const txs = await this.withNode(chainId, async (node) => {
      source = node.url;
      return node.transactions(raw, limit, before);
    });
    const last = txs[txs.length - 1];
    return {
      items: txs.map((t) => tonRecord(chain.chainId, chain.nativeAsset.ref, raw, chain.testnet, t)),
      ...(txs.length === limit && last ? { nextCursor: `${last.lt}:${last.hash}` } : {}),
      coverage: 'Native TON movements of this account; jetton transfers are not decoded.',
      source,
    };
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid TON hash');
    const value = hash.replace(/^0x/, '').toLowerCase();
    const tx = await this.withNode(chainId, (node) => node.transaction(value));
    return txStatus(tx);
  }
}

export function txStatus(tx: TonTransaction | null): TxStatus {
  if (!tx) return { state: 'unknown' };
  if (tx.aborted === true) return { state: 'failed', reason: 'transaction aborted' };
  return { state: 'confirmed', blockNumber: tx.block ?? 0, timestampMs: tx.utime * 1000 };
}

function display(raw: string | null, testOnly: boolean): string {
  const p = raw ? parseTonAddress(raw) : undefined;
  return p ? friendlyAddress(p.hash, { bounceable: false, testOnly }) : '';
}

export function tonRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  testOnly: boolean,
  t: TonTransaction,
): TxRecord {
  const incoming = t.inMsg && !t.inMsg.external ? t.inMsg.value : 0n;
  const outgoing = t.outMsgs.reduce((s, m) => s + m.value, 0n);
  const firstOut = t.outMsgs[0];
  const sent = outgoing > 0n || (t.inMsg?.external ?? false);
  const from = sent ? display(holder, testOnly) : display(t.inMsg?.source ?? null, testOnly);
  const to = sent ? display(firstOut?.destination ?? null, testOnly) : display(holder, testOnly);
  return {
    entryId: `${t.lt}:${t.hash}`,
    hash: t.hash,
    chainId,
    ...(t.block !== null ? { blockNumber: t.block } : {}),
    timestampMs: t.utime * 1000,
    from,
    ...(to ? { to } : {}),
    ...(t.outMsgs.length > 1 ? { description: `${t.outMsgs.length} outgoing messages` } : {}),
    assetDeltas: [{ assetRef: nativeRef, amount: String(incoming - outgoing) }],
    feeAssetRef: nativeRef,
    fee: t.fee === null ? null : t.fee.toString(),
    status: t.aborted === true ? 'failed' : 'confirmed',
  };
}

export function createTonAdapter(opts?: TonAdapterOptions): TonAdapter {
  return new TonAdapter(opts);
}
