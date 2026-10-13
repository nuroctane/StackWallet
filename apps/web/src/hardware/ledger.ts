/**
 * A Ledger's Ethereum app over WebHID, with no third-party code: the HID
 * framing and the two APDUs StackWallet needs (get address, sign a
 * transaction). The device shows and confirms; the core decides whether the
 * signature is accepted (`ledger::complete_external`).
 */

export const LEDGER_VENDOR_ID = 0x2c97;
const CHANNEL = 0x0101;
const TAG_APDU = 0x05;
const PACKET = 64;
const CLA = 0xe0;
const INS_GET_ADDRESS = 0x02;
const INS_SIGN = 0x04;
const MAX_CHUNK = 255;

/** Split one APDU into 64-byte HID reports (channel, tag, sequence, length, data). */
export function frameApdu(apdu: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let offset = 0;
  let seq = 0;
  while (offset < apdu.length || seq === 0) {
    const p = new Uint8Array(PACKET);
    p[0] = CHANNEL >> 8;
    p[1] = CHANNEL & 0xff;
    p[2] = TAG_APDU;
    p[3] = seq >> 8;
    p[4] = seq & 0xff;
    let header = 5;
    if (seq === 0) {
      p[5] = apdu.length >> 8;
      p[6] = apdu.length & 0xff;
      header = 7;
    }
    const take = Math.min(PACKET - header, apdu.length - offset);
    p.set(apdu.subarray(offset, offset + take), header);
    offset += take;
    seq += 1;
    out.push(p);
  }
  return out;
}

/** Reassemble reports into a response; `null` until it is complete. */
export function unframe(reports: readonly Uint8Array[]): Uint8Array | null {
  if (reports.length === 0) return null;
  let length = -1;
  const parts: Uint8Array[] = [];
  let have = 0;
  for (const [seq, r] of reports.entries()) {
    if (((r[0]! << 8) | r[1]!) !== CHANNEL || r[2] !== TAG_APDU || ((r[3]! << 8) | r[4]!) !== seq)
      throw new Error('unexpected HID report from the device');
    const header = seq === 0 ? 7 : 5;
    if (seq === 0) length = (r[5]! << 8) | r[6]!;
    const chunk = r.subarray(header, header + Math.min(PACKET - header, length - have));
    parts.push(chunk);
    have += chunk.length;
  }
  if (have < length) return null;
  const out = new Uint8Array(length);
  let o = 0;
  for (const c of parts) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/** BIP32 path as the Ethereum app expects it: count, then 4-byte big-endian indices. */
export function encodePath(path: string): Uint8Array {
  const parts = path.replace(/^m\//, '').split('/');
  if (parts.length === 0 || parts.length > 10) throw new Error('bad derivation path');
  const out = new Uint8Array(1 + parts.length * 4);
  out[0] = parts.length;
  parts.forEach((p, i) => {
    const hardened = p.endsWith("'");
    const n = Number(hardened ? p.slice(0, -1) : p);
    if (!Number.isInteger(n) || n < 0 || n >= 0x80000000) throw new Error('bad derivation path');
    const v = (hardened ? n + 0x80000000 : n) >>> 0;
    new DataView(out.buffer).setUint32(1 + i * 4, v);
  });
  return out;
}

export function apdu(ins: number, p1: number, p2: number, data: Uint8Array): Uint8Array {
  if (data.length > MAX_CHUNK) throw new Error('APDU data too long');
  const out = new Uint8Array(5 + data.length);
  out.set([CLA, ins, p1, p2, data.length]);
  out.set(data, 5);
  return out;
}

/** The sign-transaction APDUs: path then payload, 255 bytes at a time. */
export function signApdus(path: string, payload: Uint8Array): Uint8Array[] {
  const p = encodePath(path);
  const first = Math.min(MAX_CHUNK - p.length, payload.length);
  const out = [apdu(INS_SIGN, 0x00, 0x00, concat(p, payload.subarray(0, first)))];
  for (let o = first; o < payload.length; o += MAX_CHUNK)
    out.push(apdu(INS_SIGN, 0x80, 0x00, payload.subarray(o, o + MAX_CHUNK)));
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

const STATUS: Record<number, string> = {
  0x6985: 'Rejected on the device',
  0x6a80: 'The Ethereum app refused the data (enable blind signing for contract calls)',
  0x6d00: 'Open the Ethereum app on the device',
  0x6e00: 'Open the Ethereum app on the device',
  0x5515: 'Unlock the device',
};

export function checkStatus(resp: Uint8Array): Uint8Array {
  if (resp.length < 2) throw new Error('empty response from the device');
  const sw = (resp[resp.length - 2]! << 8) | resp[resp.length - 1]!;
  if (sw !== 0x9000)
    throw new Error(STATUS[sw] ?? `device status 0x${sw.toString(16).padStart(4, '0')}`);
  return resp.subarray(0, resp.length - 2);
}

export function parseAddress(data: Uint8Array): { publicKeyHex: string; address: string } {
  const pkLen = data[0]!;
  const pk = data.subarray(1, 1 + pkLen);
  const addrLen = data[1 + pkLen]!;
  const addr = new TextDecoder().decode(data.subarray(2 + pkLen, 2 + pkLen + addrLen));
  if (!/^[0-9a-fA-F]{40}$/.test(addr)) throw new Error('the device returned no address');
  return {
    publicKeyHex: [...pk].map((b) => b.toString(16).padStart(2, '0')).join(''),
    address: `0x${addr}`,
  };
}

export function parseSignature(data: Uint8Array): { v: number; r: string; s: string } {
  if (data.length < 65) throw new Error('short signature from the device');
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return { v: data[0]!, r: hex(data.subarray(1, 33)), s: hex(data.subarray(33, 65)) };
}

/** Minimal WebHID surface, so the transport can be faked in tests. */
export interface HidLike {
  opened: boolean;
  open(): Promise<void>;
  close(): Promise<void>;
  sendReport(id: number, data: Uint8Array): Promise<void>;
  addEventListener(type: 'inputreport', l: (e: { data: DataView }) => void): void;
  removeEventListener(type: 'inputreport', l: (e: { data: DataView }) => void): void;
}

export class LedgerEth {
  constructor(private readonly device: HidLike) {}

  static supported(): boolean {
    return typeof navigator !== 'undefined' && 'hid' in navigator;
  }

  /** Ask the browser for a Ledger (a user gesture is required). */
  static async request(): Promise<LedgerEth> {
    const hid = (navigator as unknown as { hid: { requestDevice(o: unknown): Promise<HidLike[]> } })
      .hid;
    const [device] = await hid.requestDevice({ filters: [{ vendorId: LEDGER_VENDOR_ID }] });
    if (!device) throw new Error('No Ledger selected');
    if (!device.opened) await device.open();
    return new LedgerEth(device);
  }

  async exchange(command: Uint8Array, timeoutMs = 120_000): Promise<Uint8Array> {
    const reports: Uint8Array[] = [];
    const done = new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.device.removeEventListener('inputreport', on);
        reject(new Error('The device did not answer'));
      }, timeoutMs);
      const on = (e: { data: DataView }) => {
        reports.push(
          new Uint8Array(
            e.data.buffer.slice(e.data.byteOffset, e.data.byteOffset + e.data.byteLength),
          ),
        );
        try {
          const full = unframe(reports);
          if (full) {
            clearTimeout(timer);
            this.device.removeEventListener('inputreport', on);
            resolve(full);
          }
        } catch (err) {
          clearTimeout(timer);
          this.device.removeEventListener('inputreport', on);
          reject(err);
        }
      };
      this.device.addEventListener('inputreport', on);
    });
    for (const r of frameApdu(command)) await this.device.sendReport(0, r);
    return checkStatus(await done);
  }

  /** The address at `path`; `confirm` shows it on the device for the user to check. */
  async getAddress(path: string, confirm = false) {
    return parseAddress(
      await this.exchange(apdu(INS_GET_ADDRESS, confirm ? 1 : 0, 0, encodePath(path))),
    );
  }

  /** Sign the exact EIP-1559 payload the core produced. */
  async signTransaction(path: string, payloadHex: string) {
    const bytes = Uint8Array.from(
      (payloadHex.replace(/^0x/, '').match(/../g) ?? []).map((h) => parseInt(h, 16)),
    );
    let last: Uint8Array = new Uint8Array();
    for (const a of signApdus(path, bytes)) last = await this.exchange(a);
    return parseSignature(last);
  }

  close(): Promise<void> {
    return this.device.close();
  }
}
