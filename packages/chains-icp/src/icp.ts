/**
 * Internet Computer adapter. Addresses are legacy-ledger account identifiers
 * (`crc32 || sha224` of domain + principal + subaccount, 64 lowercase hex);
 * the principal is `sha224(DER secp256k1 pubkey) || 0x02`. Reads are anonymous
 * query calls to the ICP ledger (`account_balance`, `query_blocks`) and its
 * index canister (`get_account_identifier_transactions`) over the public
 * boundary nodes, cross-checked across two of them. Certificates are parsed
 * for the reply bytes but their BLS signature is not verified in the browser
 * bundle; cross-checking two boundary nodes is the integrity control here.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha224 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  HttpError,
  nativeHolding,
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

export const ICP_MAINNET = 'icp:00000000000000000000';
export const ICP_LEDGER = 'ryjl3-tyaaa-aaaaa-aaaba-cai';
export const ICP_INDEX = 'qhbym-qaaaa-aaaaa-aaafq-cai';
const LEDGER_BYTES = Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 2, 1, 1]);
const INDEX_BYTES = Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0x0b, 0x01, 0x01]);
const ANONYMOUS = Uint8Array.from([0x04]);
const DER_PREFIX = hexToBytes('3056301006072a8648ce3d020106052b8104000a034200');
/** BLS root key of the one public IC network, from /api/v2/status. */
const MAINNET_ROOT_KEY =
  '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103814200' +
  '814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae';
const MAX_RESPONSE_BYTES = 1 << 20;
const TIMEOUT_MS = 8000;

// --- crc32 (IEEE, reflected) -------------------------------------------------
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC_TABLE[i] = c >>> 0;
}
export function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Candid field id (`h = h*223 + byte`, mod 2^32). */
export function idlHash(name: string): number {
  let h = 0;
  for (const c of new TextEncoder().encode(name)) h = (Math.imul(h, 223) + c) >>> 0;
  return h;
}

export function icpDerPublicKey(sec1Compressed: Uint8Array): Uint8Array {
  const point = secp256k1.Point.fromBytes(sec1Compressed).toBytes(false);
  const der = new Uint8Array(88);
  der.set(DER_PREFIX, 0);
  der.set(point, 23);
  return der;
}

export function icpPrincipal(sec1Compressed: Uint8Array): Uint8Array {
  const digest = sha224(icpDerPublicKey(sec1Compressed));
  const out = new Uint8Array(29);
  out.set(digest, 0);
  out[28] = 2;
  return out;
}

export function icpAccountIdentifier(principal: Uint8Array, subaccount?: Uint8Array): string {
  if (principal.length !== 29) throw new TypeError('principal must be 29 bytes');
  const sub = subaccount ?? new Uint8Array(32);
  if (sub.length !== 32) throw new TypeError('subaccount must be 32 bytes');
  const input = new Uint8Array(11 + 29 + 32);
  input[0] = 0x0a;
  input.set(new TextEncoder().encode('account-id'), 1);
  input.set(principal, 11);
  input.set(sub, 40);
  const digest = sha224(input);
  const out = new Uint8Array(32);
  new DataView(out.buffer).setUint32(0, crc32(digest), false);
  out.set(digest, 4);
  return bytesToHex(out);
}

export function icpAddressFromPublicKey(sec1Compressed: Uint8Array): string {
  return icpAccountIdentifier(icpPrincipal(sec1Compressed));
}

export function isValidIcpAddress(addr: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(addr)) return false;
  const bytes = hexToBytes(addr);
  if (bytes.every((b) => b === 0)) return false;
  const check = new DataView(bytes.buffer).getUint32(0, false);
  return crc32(bytes.subarray(4)) === check;
}

// --- Candid ------------------------------------------------------------------

function uleb(value: bigint | number): number[] {
  let v = BigInt(value);
  const out: number[] = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return out;
}

export type CType =
  | { kind: 'nat64' }
  | { kind: 'nat32' }
  | { kind: 'nat16' }
  | { kind: 'nat' }
  | { kind: 'int64' }
  | { kind: 'int' }
  | { kind: 'nat8' }
  | { kind: 'bool' }
  | { kind: 'text' }
  | { kind: 'principal' }
  | { kind: 'func' }
  | { kind: 'service' }
  | { kind: 'null' }
  | { kind: 'vec'; of: CType }
  | { kind: 'opt'; of: CType }
  | { kind: 'record'; fields: [number, CType][] }
  | { kind: 'variant'; fields: [number, CType][] }
  | { kind: 'ref'; index: number };

const PRIM_CODE: Record<string, number> = {
  nat64: -8,
  nat32: -7,
  nat16: -6,
  nat8: -5,
  nat: -3,
  int64: -12,
  int: -4,
  bool: -2,
  text: -15,
  null: -1,
};

function sleb(value: bigint | number): number[] {
  let v = BigInt(value);
  const out: number[] = [];
  for (;;) {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    const signBit = byte & 0x40;
    if ((v === 0n && !signBit) || (v === -1n && signBit)) {
      out.push(byte);
      return out;
    }
    byte |= 0x80;
    out.push(byte);
  }
}

function encodeType(t: CType): number[] {
  switch (t.kind) {
    case 'vec':
      return [...sleb(-19), ...slebRef(t.of)];
    case 'opt':
      return [0x6e, ...slebRef(t.of)];
    case 'record':
    case 'variant': {
      const fields = [...t.fields].sort((a, b) => a[0] - b[0]);
      const code = t.kind === 'record' ? [0x6c] : [0x6b];
      return [
        ...code,
        ...uleb(fields.length),
        ...fields.flatMap(([id, ft]) => [...uleb(id), ...slebRef(ft)]),
      ];
    }
    case 'ref':
      throw new Error('bare ref outside a composite');
    default:
      return sleb(PRIM_CODE[t.kind]!);
  }
}

/** A composite field type is a non-negative table index; prims are negative. */
function slebRef(t: CType): number[] {
  if (t.kind === 'ref') return sleb(t.index);
  if (t.kind === 'vec' || t.kind === 'opt' || t.kind === 'record' || t.kind === 'variant')
    throw new Error('composite types must be table references');
  return sleb(PRIM_CODE[t.kind]!);
}

function encodeValue(t: CType, table: CType[], value: unknown, out: number[]): void {
  const ty = t.kind === 'ref' ? table[t.index]! : t;
  switch (ty.kind) {
    case 'nat64':
      if (typeof value !== 'bigint' || value < 0n || value > 0xffffffffffffffffn)
        throw new TypeError('nat64 value out of range');
      for (let i = 0; i < 8; i++) out.push(Number((value >> BigInt(8 * i)) & 0xffn));
      return;
    case 'nat8':
      out.push(Number(value));
      return;
    case 'bool':
      out.push(value ? 1 : 0);
      return;
    case 'nat':
      out.push(...uleb(value as bigint));
      return;
    case 'text':
      out.push(...uleb(utf8(value as string).length), ...utf8(value as string));
      return;
    case 'vec': {
      if (ty.of.kind === 'nat8' || (ty.of.kind === 'ref' && table[ty.of.index]!.kind === 'nat8')) {
        const bytes = value as Uint8Array;
        out.push(...uleb(bytes.length), ...bytes);
        return;
      }
      const items = value as unknown[];
      out.push(...uleb(items.length));
      for (const item of items) encodeValue(ty.of, table, item, out);
      return;
    }
    case 'opt':
      if (value === null) {
        out.push(0);
      } else {
        out.push(1);
        encodeValue(ty.of, table, value, out);
      }
      return;
    case 'record':
      for (const [id, ft] of [...ty.fields].sort((a, b) => a[0] - b[0]))
        encodeValue(ft, table, (value as Map<number, unknown>).get(id) ?? null, out);
      return;
    case 'variant': {
      const v = value as { id: number; value: unknown };
      const idx = [...ty.fields].sort((a, b) => a[0] - b[0]).findIndex(([id]) => id === v.id);
      if (idx < 0) throw new Error('unknown variant tag');
      out.push(...uleb(idx));
      encodeValue(ty.fields.find(([id]) => id === v.id)![1], table, v.value, out);
      return;
    }
    case 'null':
      return;
    default:
      throw new Error(`candid: encoding ${ty.kind} is not supported`);
  }
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Encodes one Candid argument; the table lists composite types in definition order. */
export function candidEncode(table: CType[], argType: CType, value: unknown): Uint8Array {
  const out: number[] = [...utf8('DIDL'), ...uleb(table.length)];
  for (const t of table) out.push(...encodeType(t));
  out.push(...uleb(1), ...slebRef(argType));
  encodeValue(argType, table, value, out);
  return Uint8Array.from(out);
}

/** A decoded record is a Map from field id to value; a variant is `{id, value}`. */
export type CValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | CValue[]
  | Map<number, CValue>
  | { id: number; value: CValue };

class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  byte(): number {
    if (this.offset >= this.bytes.length) throw new Error('candid: truncated');
    return this.bytes[this.offset++]!;
  }
  take(n: number): Uint8Array {
    if (n < 0 || this.offset + n > this.bytes.length) throw new Error('candid: truncated');
    const out = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }
  uleb(): bigint {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < 10; i++) {
      const b = this.byte();
      result |= BigInt(b & 0x7f) << shift;
      if (!(b & 0x80)) return result;
      shift += 7n;
    }
    throw new Error('candid: uleb too long');
  }
  sleb(): bigint {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < 10; i++) {
      const b = this.byte();
      result |= BigInt(b & 0x7f) << shift;
      shift += 7n;
      if (!(b & 0x80)) return b & 0x40 ? result | (-1n << shift) : result;
    }
    throw new Error('candid: sleb too long');
  }
}

function decodeType(r: Reader): CType {
  const code = Number(r.sleb());
  if (code === -22) {
    // func: args, return types, modes; values of it are never decoded here.
    const argc = Number(r.uleb());
    for (let i = 0; i < argc; i++) decodeTypeRef(r);
    const retc = Number(r.uleb());
    for (let i = 0; i < retc; i++) decodeTypeRef(r);
    const modes = Number(r.uleb());
    r.take(modes);
    return { kind: 'func' };
  }
  if (code === -23) {
    // service: method table.
    const n = Number(r.uleb());
    if (n > 256) throw new Error('candid: too many methods');
    for (let i = 0; i < n; i++) {
      r.take(Number(r.uleb()));
      decodeTypeRef(r);
    }
    return { kind: 'service' };
  }
  if (code === -20 || code === -21) {
    const n = Number(r.uleb());
    if (n > 256) throw new Error('candid: too many fields');
    const fields: [number, CType][] = [];
    for (let i = 0; i < n; i++) fields.push([Number(r.uleb()), decodeTypeRef(r)]);
    return { kind: code === -20 ? 'record' : 'variant', fields };
  }
  if (code === -18) return { kind: 'opt', of: decodeTypeRef(r) };
  if (code === -19) return { kind: 'vec', of: decodeTypeRef(r) };
  if (code === -24) return { kind: 'principal' };
  throw new Error(`candid: unsupported type constructor ${code}`);
}

function decodeTypeRef(r: Reader): CType {
  const code = Number(r.sleb());
  if (code >= 0) return { kind: 'ref', index: code };
  const prim = Object.entries(PRIM_CODE).find(([, c]) => c === code)?.[0];
  if (prim) return { kind: prim } as CType;
  if (code === -24) return { kind: 'principal' };
  throw new Error(`candid: unsupported prim ${code}`);
}

function decodeValue(r: Reader, t: CType, table: CType[], depth: number): CValue {
  if (depth > 64) throw new Error('candid: nesting too deep');
  const ty = t.kind === 'ref' ? table[t.index]! : t;
  switch (ty.kind) {
    case 'nat64':
      return r.take(8).reduce((acc, b, i) => acc | (BigInt(b) << BigInt(8 * i)), 0n);
    case 'nat8':
      return r.byte();
    case 'nat16':
      return r.take(2).reduce((acc, b, i) => acc + (b << (8 * i)), 0);
    case 'nat32':
      return r.take(4).reduce((acc, b, i) => acc + b * 2 ** (8 * i), 0);
    case 'int64': {
      const u = r.take(8).reduce((acc, b, i) => acc | (BigInt(b) << BigInt(8 * i)), 0n);
      return u >= 1n << 63n ? u - (1n << 64n) : u;
    }
    case 'int':
      return r.sleb();
    case 'bool':
      return r.byte() !== 0;
    case 'nat':
      return r.uleb();
    case 'text':
      return new TextDecoder().decode(r.take(Number(r.uleb())));
    case 'principal': {
      if (r.byte() !== 1) throw new Error('candid: opaque principal reference');
      return r.take(Number(r.uleb()));
    }
    case 'func': {
      // func value: 0x01 tag, then a principal, then the method name text
      if (r.byte() !== 1) throw new Error('candid: opaque func reference');
      if (r.byte() !== 1) throw new Error('candid: opaque principal reference');
      r.take(Number(r.uleb()));
      r.take(Number(r.uleb()));
      return null;
    }
    case 'service': {
      if (r.byte() !== 1) throw new Error('candid: opaque service reference');
      if (r.byte() !== 1) throw new Error('candid: opaque principal reference');
      r.take(Number(r.uleb()));
      return null;
    }
    case 'null':
      return null;
    case 'vec': {
      const len = Number(r.uleb());
      if (len > r.bytes.length) throw new Error('candid: vec length exceeds input');
      const inner = ty.of.kind === 'ref' ? table[ty.of.index]! : ty.of;
      if (inner.kind === 'nat8') return r.take(len);
      const out: CValue[] = [];
      for (let i = 0; i < len; i++) out.push(decodeValue(r, ty.of, table, depth + 1));
      return out;
    }
    case 'opt':
      return r.byte() === 0 ? null : decodeValue(r, ty.of, table, depth + 1);
    case 'record': {
      const map = new Map<number, CValue>();
      for (const [id, ft] of [...ty.fields].sort((a, b) => a[0] - b[0]))
        map.set(id, decodeValue(r, ft, table, depth + 1));
      return map;
    }
    case 'variant': {
      const fields = [...ty.fields].sort((a, b) => a[0] - b[0]);
      const idx = Number(r.uleb());
      if (idx >= fields.length) throw new Error('candid: bad variant tag');
      const [id, ft] = fields[idx]!;
      return { id, value: decodeValue(r, ft, table, depth + 1) };
    }
    case 'ref':
      throw new Error('candid: unresolved ref');
  }
}

/** Decodes a single-argument Candid reply into its value. */
export function candidDecode(bytes: Uint8Array): CValue {
  if (bytes.length > MAX_RESPONSE_BYTES) throw new Error('candid: response too large');
  const r = new Reader(bytes);
  if (new TextDecoder().decode(r.take(4)) !== 'DIDL') throw new Error('candid: bad magic');
  const tableCount = Number(r.uleb());
  if (tableCount > 512) throw new Error('candid: type table too large');
  const table: CType[] = [];
  for (let i = 0; i < tableCount; i++) table.push(decodeType(r));
  const argc = Number(r.uleb());
  if (argc !== 1) throw new Error('candid: expected one reply value');
  const value = decodeValue(r, decodeTypeRef(r), table, 0);
  if (r.offset !== r.bytes.length)
    throw new Error(`candid: trailing bytes (${r.bytes.length - r.offset} left at ${r.offset})`);
  return value;
}

/** Reads a record field by Candid name. */
export function field(value: CValue, name: string): CValue | undefined {
  if (value instanceof Map) return value.get(idlHash(name));
  return undefined;
}

// --- CBOR --------------------------------------------------------------------

export type CborValue =
  | { bytes: Uint8Array }
  | { text: string }
  | { nat: bigint }
  | { array: CborValue[] }
  | { map: [CborValue, CborValue][] }
  | { tag: bigint; value: CborValue }
  | { simple: unknown };

export function cborDecode(bytes: Uint8Array): CborValue {
  if (bytes.length > MAX_RESPONSE_BYTES) throw new Error('cbor: too large');
  const r = new Reader(bytes);
  const value = decodeItem(r, 0);
  if (r.offset !== r.bytes.length) throw new Error('cbor: trailing bytes');
  return value;
}

/** Big-endian unsigned read that respects the reader's offset. */
function readUint(r: Reader, n: 2 | 4 | 8): bigint {
  const bytes = r.take(n);
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

function decodeItem(r: Reader, depth: number): CborValue {
  if (depth > 64) throw new Error('cbor: nesting too deep');
  const head = r.byte();
  const major = head >> 5;
  const info = head & 0x1f;
  const len =
    info < 24
      ? BigInt(info)
      : info === 24
        ? BigInt(r.byte())
        : info === 25
          ? BigInt(readUint(r, 2))
          : info === 26
            ? BigInt(readUint(r, 4))
            : info === 27
              ? readUint(r, 8)
              : (() => {
                  throw new Error('cbor: indefinite lengths are not accepted');
                })();
  if (major === 0) return { nat: len };
  if (major === 1) return { nat: -1n - len };
  if (major === 2) return { bytes: r.take(Number(len)) };
  if (major === 3) return { text: new TextDecoder().decode(r.take(Number(len))) };
  if (major === 4) {
    const out: CborValue[] = [];
    for (let i = 0n; i < len; i++) out.push(decodeItem(r, depth + 1));
    return { array: out };
  }
  if (major === 5) {
    const out: [CborValue, CborValue][] = [];
    for (let i = 0n; i < len; i++) out.push([decodeItem(r, depth + 1), decodeItem(r, depth + 1)]);
    return { map: out };
  }
  if (major === 6) return { tag: len, value: decodeItem(r, depth + 1) };
  if (info === 0xf6) return { simple: null };
  if (info === 0xf7) return { simple: undefined };
  if (info === 0xf4) return { simple: false };
  if (info === 0xf5) return { simple: true };
  throw new Error('cbor: unsupported simple value');
}

/** Decodes a body that may carry the self-describe tag 55799. */
export function cborDecodeRoot(bytes: Uint8Array): CborValue {
  let value = cborDecode(bytes);
  while ('tag' in value && value.tag === 55799n) value = value.value;
  return value;
}

export function cborBytes(v: CborValue | undefined): Uint8Array | undefined {
  return v && 'bytes' in v ? v.bytes : undefined;
}
export function cborText(v: CborValue | undefined): string | undefined {
  return v && 'text' in v ? v.text : undefined;
}
export function cborNat(v: CborValue | undefined): bigint | undefined {
  return v && 'nat' in v ? v.nat : undefined;
}
export function cborMapGet(map: CborValue, key: string): CborValue | undefined {
  if (!('map' in map)) return undefined;
  return map.map.find(([k]) => 'text' in k && k.text === key)?.[1];
}

/** Unsigned LEB128, used for nat values inside request ids and reject codes. */
export function leb128(value: bigint): Uint8Array {
  return Uint8Array.from(uleb(value));
}

function cborHead(major: number, len: number): number[] {
  if (len < 24) return [(major << 5) | len];
  if (len < 256) return [(major << 5) | 24, len];
  return [(major << 5) | 25, len >> 8, len & 0xff];
}

/** Encodes an envelope map exactly like @dfinity/agent (lexicographic keys). */
export function cborEncodeEnvelope(entries: [string, CborValue][]): Uint8Array {
  const encode = (v: CborValue, out: number[]): void => {
    if ('bytes' in v) out.push(...cborHead(2, v.bytes.length), ...v.bytes);
    else if ('text' in v) {
      const bytes = utf8(v.text);
      out.push(...cborHead(3, bytes.length), ...bytes);
    } else if ('tag' in v) {
      // Only tag 2 (positive bignum) is emitted.
      if (v.tag !== 2n || !('bytes' in v.value)) throw new Error('unsupported tag');
      out.push(0xc2, ...cborHead(2, v.value.bytes.length), ...v.value.bytes);
    } else if ('array' in v) {
      out.push(...cborHead(4, v.array.length));
      for (const item of v.array) encode(item, out);
    } else if ('map' in v) {
      const entries = v.map as [CborValue, CborValue][];
      const keyed = entries.map(
        ([k, val]) => [('text' in k ? k.text : '') as string, val] as [string, CborValue],
      );
      out.push(...cborHead(5, keyed.length));
      for (const [k, val] of keyed.sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
        encode({ text: k }, out);
        encode(val, out);
      }
    } else throw new Error('unsupported envelope value');
  };
  const out = [0xd9, 0xd9, 0xf7];
  encode({ map: entries.map(([k, v]) => [{ text: k }, v] as [CborValue, CborValue]) }, out);
  return Uint8Array.from(out);
}

export function bignum(value: bigint): CborValue {
  const bytes: number[] = [];
  let v = value;
  do {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v > 0n);
  return { tag: 2n, value: { bytes: Uint8Array.from(bytes) } };
}

// --- request envelopes -------------------------------------------------------

export interface RequestContent {
  requestType: 'query' | 'call' | 'read_state';
  canister: Uint8Array;
  methodName?: string;
  arg?: Uint8Array;
  paths?: Uint8Array[][];
  sender: Uint8Array;
  ingressExpiryNanos: bigint;
}

export function requestContentMap(c: RequestContent): [string, CborValue][] {
  const entries: [string, CborValue][] = [
    ['request_type', { text: c.requestType }],
    ['canister_id', { bytes: c.canister }],
    ['sender', { bytes: c.sender }],
    ['ingress_expiry', bignum(c.ingressExpiryNanos)],
  ];
  if (c.methodName) entries.push(['method_name', { text: c.methodName }]);
  if (c.arg) entries.push(['arg', { bytes: c.arg }]);
  if (c.paths)
    entries.push([
      'paths',
      { array: c.paths.map((p) => ({ array: p.map((b) => ({ bytes: b })) })) },
    ]);
  return entries;
}

// --- adapter -----------------------------------------------------------------

export type IcpAdapterOptions = BaseAdapterOptions;

export class IcpAdapter extends BaseAdapter<'icp'> {
  constructor(opts: IcpAdapterOptions = {}) {
    super('icp', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return icpAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidIcpAddress(addr);
  }

  private async postCbor(url: string, body: Uint8Array): Promise<Uint8Array> {
    const fetchImpl = this.fetchImpl ?? fetch;
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/cbor' },
      body: body as BodyInit,
      signal: AbortSignal.timeout(this.timeoutMs ?? TIMEOUT_MS),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new HttpError(url, res.status, text.slice(0, 512));
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.length > MAX_RESPONSE_BYTES) throw new Error('ICP response too large');
    return buf;
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const fetchImpl = this.fetchImpl ?? fetch;
      const res = await fetchImpl(`${url.replace(/\/$/, '')}/api/v2/status`, {
        signal: AbortSignal.timeout(this.timeoutMs ?? TIMEOUT_MS),
      });
      if (!res.ok) throw new HttpError(url, res.status, '');
      const status = cborDecode(new Uint8Array(await res.arrayBuffer()));
      const rootKey = cborBytes(cborMapGet(status, 'root_key'));
      if (!rootKey || bytesToHex(rootKey) !== MAINNET_ROOT_KEY)
        throw new Error('Endpoint does not serve the Internet Computer mainnet');
    });
  }

  /** The anonymous query envelope for a canister method. */
  queryBody(canister: Uint8Array, method: string, arg: Uint8Array, now = Date.now()): Uint8Array {
    return cborEncodeEnvelope([
      [
        'content',
        {
          map: requestContentMap({
            requestType: 'query',
            canister,
            methodName: method,
            arg,
            sender: ANONYMOUS,
            ingressExpiryNanos: BigInt(now + 180_000) * 1_000_000n,
          }).map(([k, v]) => [{ text: k }, v] as [CborValue, CborValue]),
        },
      ],
    ]);
  }

  /** POSTs a query envelope to one endpoint and returns the Candid reply arg. */
  async queryAt(url: string, canisterText: string, body: Uint8Array): Promise<Uint8Array> {
    const res = cborDecodeRoot(
      await this.postCbor(`${url.replace(/\/$/, '')}/api/v3/canister/${canisterText}/query`, body),
    );
    const status = cborText(cborMapGet(res, 'status'));
    if (status === 'replied') {
      const reply = cborMapGet(res, 'reply');
      const bytes = reply && cborBytes(cborMapGet(reply, 'arg'));
      if (bytes) return bytes;
      throw new Error('ICP query reply is missing its arg');
    }
    const message = cborText(cborMapGet(res, 'reject_message')) ?? status ?? 'unknown';
    throw new Error(`ICP query rejected: ${String(message).slice(0, 256)}`);
  }

  /** Runs an anonymous query with failover and returns the Candid reply bytes. */
  async query(
    chainId: ChainId,
    canisterText: string,
    canister: Uint8Array,
    method: string,
    arg: Uint8Array,
  ): Promise<Uint8Array> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return this.queryAt(url, canisterText, this.queryBody(canister, method, arg));
    });
  }

  /**
   * POSTs a signed call envelope to the v3 call endpoint. Returns the raw
   * response body (empty when the replica answered 202 Accepted).
   */
  async callCanister(
    chainId: ChainId,
    canisterText: string,
    wire: Uint8Array,
  ): Promise<Uint8Array> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return this.postCbor(`${url.replace(/\/$/, '')}/api/v3/canister/${canisterText}/call`, wire);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidIcpAddress(addr)) throw new TypeError(`invalid icp address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        return decodeBalance(
          await this.queryAt(
            url,
            ICP_LEDGER,
            this.queryBody(LEDGER_BYTES, 'account_balance', accountBalanceArgs(addr)),
          ),
        );
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
    if (!isValidIcpAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,20}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const arg = indexTransactionsArgs(addr, cursor ? BigInt(cursor) : null, 20n);
    const reply = await this.query(
      chainId,
      ICP_INDEX,
      INDEX_BYTES,
      'get_account_identifier_transactions',
      arg,
    );
    const txs = decodeIndexTransactions(reply);
    const items: TxRecord[] = txs.transactions.map((t) =>
      indexRecord(chain.chainId, chain.nativeAsset.ref, addr, t),
    );
    const nextCursor =
      txs.transactions.length === 20 && txs.oldestTxId !== null && txs.oldestTxId > 0n
        ? (txs.oldestTxId - 1n).toString()
        : undefined;
    return {
      items,
      ...(nextCursor ? { nextCursor } : {}),
      coverage:
        'ICP index canister account transactions. Legacy ledger operations only; the fee is the fixed 10_000 e8s ledger charge.',
    };
  }

  /** `hash` is the ledger block height assigned by the transfer reply. */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^\d{1,19}$/.test(hash)) throw new Error('Invalid ICP block height');
    const height = BigInt(hash);
    this.requireChain(chainId);
    const reply = await this.query(
      chainId,
      ICP_LEDGER,
      LEDGER_BYTES,
      'query_blocks',
      queryBlocksArgs(height, 1n),
    );
    const decoded = candidDecode(reply);
    const blocks = field(decoded, 'blocks');
    const first = field(decoded, 'first_block_index');
    if (blocks instanceof Array && blocks.length > 0) {
      const block = blocks[0]!;
      const ts = field(block, 'timestamp');
      const nanos = ts instanceof Map ? field(ts, 'timestamp_nanos') : undefined;
      return {
        state: 'confirmed',
        blockNumber: Number(height),
        ...(typeof nanos === 'bigint' ? { timestampMs: Number(nanos / 1_000_000n) } : {}),
      };
    }
    if (typeof first === 'bigint' && height < first)
      return { state: 'confirmed', blockNumber: Number(height) };
    return { state: 'unknown' };
  }
}

// --- request argument encoders ------------------------------------------------

export function accountBalanceArgs(accountHex: string): Uint8Array {
  const vecNat8: CType = { kind: 'vec', of: { kind: 'nat8' } };
  const record: CType = {
    kind: 'record',
    fields: [[idlHash('account'), { kind: 'ref', index: 0 }]],
  };
  return candidEncode(
    [vecNat8, record],
    { kind: 'ref', index: 1 },
    new Map([[idlHash('account'), hexToBytes(accountHex)]]),
  );
}

export function queryBlocksArgs(start: bigint, length: bigint): Uint8Array {
  const record: CType = {
    kind: 'record',
    fields: [
      [idlHash('start'), { kind: 'nat64' }],
      [idlHash('length'), { kind: 'nat64' }],
    ],
  };
  return candidEncode(
    [record],
    { kind: 'ref', index: 0 },
    new Map([
      [idlHash('start'), start],
      [idlHash('length'), length],
    ]),
  );
}

export function indexTransactionsArgs(
  accountHex: string,
  start: bigint | null,
  maxResults: bigint,
): Uint8Array {
  const optNat64: CType = { kind: 'opt', of: { kind: 'nat64' } };
  const record: CType = {
    kind: 'record',
    fields: [
      [idlHash('account_identifier'), { kind: 'text' }],
      [idlHash('start'), { kind: 'ref', index: 0 }],
      [idlHash('max_results'), { kind: 'nat64' }],
    ],
  };
  return candidEncode(
    [optNat64, record],
    { kind: 'ref', index: 1 },
    new Map<number, unknown>([
      [idlHash('account_identifier'), accountHex],
      [idlHash('start'), start],
      [idlHash('max_results'), maxResults],
    ]),
  );
}

// --- reply decoders ------------------------------------------------------------

export function decodeBalance(argBytes: Uint8Array): string {
  const decoded = candidDecode(argBytes);
  const e8s = field(decoded, 'e8s');
  if (typeof e8s !== 'bigint') throw new Error('ICP balance reply is not a Tokens record');
  return e8s.toString();
}

export interface IndexTx {
  id: bigint;
  memo: bigint;
  timestampNanos: bigint | null;
  operation: {
    kind: 'Transfer' | 'Burn' | 'Mint';
    from?: string;
    to?: string;
    amount: bigint;
    fee?: bigint;
  } | null;
}

export function decodeIndexTransactions(argBytes: Uint8Array): {
  balance: bigint;
  oldestTxId: bigint | null;
  transactions: IndexTx[];
} {
  const decoded = candidDecode(argBytes);
  if (typeof decoded !== 'object' || decoded === null || !('id' in decoded))
    throw new Error('ICP index reply is not a variant');
  const okId = idlHash('Ok');
  if (decoded.id !== okId) {
    const err = decoded.value;
    const message = err instanceof Map ? field(err, 'message') : undefined;
    throw new Error(
      `ICP index query failed: ${typeof message === 'string' ? message.slice(0, 256) : 'unknown'}`,
    );
  }
  const ok = decoded.value;
  const balance = field(ok, 'balance');
  const oldest = field(ok, 'oldest_tx_id');
  const txs = field(ok, 'transactions');
  if (typeof balance !== 'bigint' || !(txs instanceof Array))
    throw new Error('ICP index reply is malformed');
  const transactions: IndexTx[] = txs.map((entry) => {
    const id = field(entry, 'id');
    const transaction = field(entry, 'transaction');
    const memo = transaction instanceof Map ? field(transaction, 'memo') : undefined;
    const ts = transaction instanceof Map ? field(transaction, 'timestamp') : undefined;
    const nanos = ts instanceof Map ? field(ts, 'timestamp_nanos') : undefined;
    const op = transaction instanceof Map ? field(transaction, 'operation') : undefined;
    let operation: IndexTx['operation'] = null;
    if (op && typeof op === 'object' && 'id' in op) {
      const value = op.value;
      const name =
        op.id === idlHash('Transfer') ? 'Transfer' : op.id === idlHash('Burn') ? 'Burn' : 'Mint';
      const amount = value instanceof Map ? field(value, 'amount') : undefined;
      const e8s = amount instanceof Map ? field(amount, 'e8s') : undefined;
      const feeVal = value instanceof Map ? field(value, 'fee') : undefined;
      const feeE8s = feeVal instanceof Map ? field(feeVal, 'e8s') : undefined;
      const from = value instanceof Map ? field(value, 'from') : undefined;
      const to = value instanceof Map ? field(value, 'to') : undefined;
      operation = {
        kind: name as 'Transfer' | 'Burn' | 'Mint',
        ...(typeof from === 'string' ? { from } : {}),
        ...(typeof to === 'string' ? { to } : {}),
        amount: typeof e8s === 'bigint' ? e8s : 0n,
        ...(typeof feeE8s === 'bigint' ? { fee: feeE8s } : {}),
      };
    }
    if (typeof id !== 'bigint' || typeof memo !== 'bigint')
      throw new Error('ICP index transaction is malformed');
    return {
      id,
      memo,
      timestampNanos: typeof nanos === 'bigint' ? nanos : null,
      operation,
    };
  });
  return {
    balance,
    oldestTxId: typeof oldest === 'bigint' ? oldest : null,
    transactions,
  };
}

function indexRecord(chainId: string, nativeRef: string, holder: string, t: IndexTx): TxRecord {
  const op = t.operation;
  let delta = 0n;
  if (op) {
    if (op.to === holder) delta += op.amount;
    if (op.from === holder) delta -= op.amount;
  }
  const fee = op?.from === holder ? (op.fee ?? 10_000n) : 0n;
  return {
    hash: t.id.toString(),
    chainId,
    from: op?.from ?? '',
    ...(op?.to ? { to: op.to } : {}),
    blockNumber: Number(t.id),
    ...(t.timestampNanos !== null ? { timestampMs: Number(t.timestampNanos / 1_000_000n) } : {}),
    ...(op && op.kind !== 'Transfer' ? { description: op.kind } : {}),
    assetDeltas: delta !== 0n ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: String(fee),
    status: 'confirmed',
  };
}

export function createIcpAdapter(opts?: IcpAdapterOptions): IcpAdapter {
  return new IcpAdapter(opts);
}
