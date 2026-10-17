/**
 * The slice of TON's cell model a native wallet transfer needs: ordinary
 * cells with representation hashes, a builder, and bag-of-cells (BoC)
 * parsing and serialization byte-compatible with `@ton/core`.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const BOC_MAGIC = [0xb5, 0xee, 0x9c, 0x72];

export class Cell {
  readonly hash: Uint8Array;
  readonly depth: number;

  constructor(
    readonly data: Uint8Array,
    readonly bits: number,
    readonly refs: readonly Cell[],
  ) {
    if (bits > 1023 || refs.length > 4 || data.length !== Math.ceil(bits / 8))
      throw new Error('cell overflow');
    this.depth = refs.length === 0 ? 0 : Math.max(...refs.map((r) => r.depth)) + 1;
    const padded = Cell.padded(data, bits);
    const repr = new Uint8Array(2 + padded.length + refs.length * 34);
    repr[0] = refs.length;
    repr[1] = Cell.bitsDescriptor(bits);
    repr.set(padded, 2);
    let at = 2 + padded.length;
    for (const r of refs) {
      repr[at++] = r.depth >> 8;
      repr[at++] = r.depth & 0xff;
    }
    for (const r of refs) {
      repr.set(r.hash, at);
      at += 32;
    }
    this.hash = sha256(repr);
  }

  static bitsDescriptor(bits: number): number {
    return Math.ceil(bits / 8) + Math.floor(bits / 8);
  }

  /** Data bytes with the completion tag after an incomplete last byte. */
  static padded(data: Uint8Array, bits: number): Uint8Array {
    const out = data.slice();
    if (bits % 8 !== 0) out[out.length - 1]! |= 0x80 >> bits % 8;
    return out;
  }

  bit(i: number): boolean {
    if (i < 0 || i >= this.bits) throw new RangeError('bit out of range');
    return (this.data[i >> 3]! & (0x80 >> (i & 7))) !== 0;
  }

  /** `n` bits from `offset` as an unsigned integer. */
  uint(offset: number, n: number): bigint {
    let v = 0n;
    for (let i = 0; i < n; i++) v = (v << 1n) | (this.bit(offset + i) ? 1n : 0n);
    return v;
  }

  bytes(offset: number, len: number): Uint8Array {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = Number(this.uint(offset + i * 8, 8));
    return out;
  }

  hashHex(): string {
    return bytesToHex(this.hash);
  }
}

export class Builder {
  private data: number[] = [];
  bits = 0;
  refs: Cell[] = [];

  bit(b: boolean): this {
    if (this.bits % 8 === 0) this.data.push(0);
    if (b) this.data[this.bits >> 3]! |= 0x80 >> (this.bits & 7);
    this.bits++;
    return this;
  }

  uint(v: bigint | number, n: number): this {
    const value = BigInt(v);
    if (value < 0n || value >> BigInt(n) !== 0n) throw new RangeError(`value exceeds ${n} bits`);
    for (let i = n - 1; i >= 0; i--) this.bit(((value >> BigInt(i)) & 1n) === 1n);
    return this;
  }

  bytes(b: Uint8Array): this {
    for (const byte of b) this.uint(byte, 8);
    return this;
  }

  /** `addr_std$10 anycast:nothing workchain_id:int8 address:bits256` on workchain 0. */
  address(hash: Uint8Array): this {
    if (hash.length !== 32) throw new TypeError('account id must be 32 bytes');
    return this.uint(0b10, 2).bit(false).uint(0, 8).bytes(hash);
  }

  /** `VarUInteger 16`: a 4-bit byte length, then the big-endian value. */
  coins(v: bigint): this {
    if (v < 0n || v >> 120n !== 0n) throw new RangeError('coins out of range');
    let len = 0;
    while (v >> BigInt(len * 8) !== 0n) len++;
    return this.uint(len, 4).uint(v, len * 8);
  }

  ref(cell: Cell): this {
    this.refs.push(cell);
    return this;
  }

  append(cell: Cell): this {
    for (let i = 0; i < cell.bits; i++) this.bit(cell.bit(i));
    this.refs.push(...cell.refs);
    return this;
  }

  build(): Cell {
    return new Cell(Uint8Array.from(this.data), this.bits, [...this.refs]);
  }
}

export function crc16(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++)
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

export function crc32c(bytes: Uint8Array): Uint8Array {
  let crc = 0xffffffff;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = crc & 1 ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1;
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  return Uint8Array.of(crc & 0xff, (crc >>> 8) & 0xff, (crc >>> 16) & 0xff, crc >>> 24);
}

/** One-root standard BoC (`b5ee9c72`) of ordinary cells; anything else throws. */
export function parseBoc(src: Uint8Array): Cell {
  let pos = 0;
  const take = (n: number): Uint8Array => {
    if (pos + n > src.length) throw new Error('malformed bag of cells');
    const s = src.subarray(pos, pos + n);
    pos += n;
    return s;
  };
  const uint = (n: number): number => take(n).reduce((acc, x) => acc * 256 + x, 0);
  if (!BOC_MAGIC.every((m, i) => src[i] === m)) throw new Error('not a bag of cells');
  pos = 4;
  const flags = uint(1);
  const size = flags & 7;
  if (size < 1 || size > 4 || (flags & 0x18) !== 0) throw new Error('malformed bag of cells');
  const off = uint(1);
  if (off < 1 || off > 8) throw new Error('malformed bag of cells');
  const count = uint(size);
  const roots = uint(size);
  uint(size);
  const total = uint(off);
  const root = uint(size);
  if (roots !== 1 || count === 0 || count > 1024 || root !== 0)
    throw new Error('unsupported bag of cells');
  if (flags & 0x80) take(count * off);
  const start = pos;
  const raw: { data: Uint8Array; bits: number; refs: number[] }[] = [];
  for (let i = 0; i < count; i++) {
    const d1 = uint(1);
    const d2 = uint(1);
    if ((d1 & 0xf8) !== 0 || (d1 & 7) > 4) throw new Error('only ordinary cells are supported');
    const len = Math.ceil(d2 / 2);
    const data = take(len).slice();
    let bits = len * 8;
    if (d2 % 2 === 1) {
      const last = data[len - 1];
      if (!last) throw new Error('malformed bag of cells');
      let tz = 0;
      while (((last >> tz) & 1) === 0) tz++;
      data[len - 1] = last & ~(1 << tz);
      bits -= tz + 1;
    }
    const refs: number[] = [];
    for (let r = 0; r < (d1 & 7); r++) refs.push(uint(size));
    raw.push({ data, bits, refs });
  }
  if (pos - start !== total) throw new Error('malformed bag of cells');
  if (flags & 0x40) {
    const end = pos;
    const crc = take(4);
    if (bytesToHex(crc32c(src.subarray(0, end))) !== bytesToHex(crc))
      throw new Error('bag of cells checksum mismatch');
  }
  if (pos !== src.length) throw new Error('trailing bytes after bag of cells');
  const built: Cell[] = new Array<Cell>(count);
  for (let i = count - 1; i >= 0; i--) {
    const c = raw[i]!;
    const refs = c.refs.map((r) => {
      if (r <= i || !built[r]) throw new Error('malformed bag of cells');
      return built[r];
    });
    built[i] = new Cell(c.data, c.bits, refs);
  }
  return built[0]!;
}

/**
 * `@ton/core`'s cell order: breadth-first discovery, then a depth-first
 * post-order over refs in reverse, reversed.
 */
function topologicalSort(root: Cell): Cell[] {
  const cells = new Map<string, Cell>();
  let pending: Cell[] = [root];
  while (pending.length > 0) {
    const next: Cell[] = [];
    for (const cell of pending) {
      const key = cell.hashHex();
      if (cells.has(key)) continue;
      cells.set(key, cell);
      next.push(...cell.refs);
    }
    pending = next;
  }
  const open = new Set(cells.keys());
  const sorted: string[] = [];
  const visit = (key: string): void => {
    if (!open.has(key)) return;
    const refs = cells.get(key)!.refs;
    for (let i = refs.length - 1; i >= 0; i--) visit(refs[i]!.hashHex());
    sorted.push(key);
    open.delete(key);
  };
  for (const key of cells.keys()) visit(key);
  return sorted.reverse().map((k) => cells.get(k)!);
}

const byteLen = (n: number): number => Math.max(1, Math.ceil(n.toString(2).length / 8));

/** A one-root BoC with a CRC32C trailer and no index, as `Cell.toBoc()` emits. */
export function serializeBoc(root: Cell): Uint8Array {
  const cells = topologicalSort(root);
  const index = new Map(cells.map((c, i) => [c.hashHex(), i]));
  const size = byteLen(cells.length);
  const total = cells.reduce((s, c) => s + 2 + c.data.length + c.refs.length * size, 0);
  const off = byteLen(total);
  const out: number[] = [...BOC_MAGIC, 0x40 | size, off];
  const be = (v: number, n: number) => {
    for (let i = n - 1; i >= 0; i--) out.push(Math.floor(v / 256 ** i) % 256);
  };
  be(cells.length, size);
  be(1, size);
  be(0, size);
  be(total, off);
  be(0, size);
  for (const c of cells) {
    out.push(c.refs.length, Cell.bitsDescriptor(c.bits), ...Cell.padded(c.data, c.bits));
    for (const r of c.refs) be(index.get(r.hashHex())!, size);
  }
  const bytes = Uint8Array.from(out);
  const result = new Uint8Array(bytes.length + 4);
  result.set(bytes);
  result.set(crc32c(bytes), bytes.length);
  return result;
}
