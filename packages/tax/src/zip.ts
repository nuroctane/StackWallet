export interface ZipEntry {
  name: string;
  data: Uint8Array;
}

const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = (CRC_TABLE[(crc ^ (bytes[i] ?? 0)) & 0xff] ?? 0) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const DOS_EPOCH_DATE = (0 << 9) | (1 << 5) | 1;

// DOS timestamps only cover 1980..2107 with 2-second resolution; anything outside clamps to the
// DOS epoch so the archive stays valid and reproducible.
function dosDateTime(dateMs: number | undefined): { date: number; time: number } {
  if (dateMs === undefined || !Number.isFinite(dateMs)) return { date: DOS_EPOCH_DATE, time: 0 };
  const d = new Date(dateMs);
  const year = d.getUTCFullYear();
  if (Number.isNaN(year) || year < 1980 || year > 2107) return { date: DOS_EPOCH_DATE, time: 0 };
  return {
    date: ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate(),
    time: (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | Math.floor(d.getUTCSeconds() / 2),
  };
}

const UTF8_FLAG = 0x0800;
const VERSION = 20;

export function zipStore(files: ZipEntry[], dateMs?: number): Uint8Array {
  if (files.length > 0xffff) throw new Error('zip: too many entries (zip64 not supported)');
  const { date, time } = dosDateTime(dateMs);
  const encoder = new TextEncoder();
  const entries = files.map((f) => ({
    name: encoder.encode(f.name),
    data: f.data,
    crc: crc32(f.data),
  }));

  let localSize = 0;
  let centralSize = 0;
  for (const e of entries) {
    if (e.name.length > 0xffff) throw new Error('zip: entry name too long');
    localSize += 30 + e.name.length + e.data.length;
    centralSize += 46 + e.name.length;
  }
  const total = localSize + centralSize + 22;
  if (localSize > 0xffffffff || total > 0xffffffff) {
    throw new Error('zip: archive exceeds 4 GiB (zip64 not supported)');
  }

  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  const offsets: number[] = [];
  let p = 0;

  for (const e of entries) {
    offsets.push(p);
    view.setUint32(p, 0x04034b50, true);
    view.setUint16(p + 4, VERSION, true);
    view.setUint16(p + 6, UTF8_FLAG, true);
    view.setUint16(p + 8, 0, true);
    view.setUint16(p + 10, time, true);
    view.setUint16(p + 12, date, true);
    view.setUint32(p + 14, e.crc, true);
    view.setUint32(p + 18, e.data.length, true);
    view.setUint32(p + 22, e.data.length, true);
    view.setUint16(p + 26, e.name.length, true);
    view.setUint16(p + 28, 0, true);
    out.set(e.name, p + 30);
    out.set(e.data, p + 30 + e.name.length);
    p += 30 + e.name.length + e.data.length;
  }

  const centralStart = p;
  entries.forEach((e, i) => {
    view.setUint32(p, 0x02014b50, true);
    view.setUint16(p + 4, VERSION, true);
    view.setUint16(p + 6, VERSION, true);
    view.setUint16(p + 8, UTF8_FLAG, true);
    view.setUint16(p + 10, 0, true);
    view.setUint16(p + 12, time, true);
    view.setUint16(p + 14, date, true);
    view.setUint32(p + 16, e.crc, true);
    view.setUint32(p + 20, e.data.length, true);
    view.setUint32(p + 24, e.data.length, true);
    view.setUint16(p + 28, e.name.length, true);
    view.setUint16(p + 30, 0, true);
    view.setUint16(p + 32, 0, true);
    view.setUint16(p + 34, 0, true);
    view.setUint16(p + 36, 0, true);
    view.setUint32(p + 38, 0, true);
    view.setUint32(p + 42, offsets[i] ?? 0, true);
    out.set(e.name, p + 46);
    p += 46 + e.name.length;
  });

  view.setUint32(p, 0x06054b50, true);
  view.setUint16(p + 4, 0, true);
  view.setUint16(p + 6, 0, true);
  view.setUint16(p + 8, entries.length, true);
  view.setUint16(p + 10, entries.length, true);
  view.setUint32(p + 12, p - centralStart, true);
  view.setUint32(p + 16, centralStart, true);
  view.setUint16(p + 20, 0, true);
  return out;
}
