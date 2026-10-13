import { describe, expect, it } from 'vitest';

import {
  LedgerEth,
  apdu,
  checkStatus,
  encodePath,
  frameApdu,
  parseAddress,
  signApdus,
  unframe,
  type HidLike,
} from './ledger.js';

describe('ledger hid framing', () => {
  it('frames and unframes across several reports', () => {
    const data = Uint8Array.from({ length: 150 }, (_, i) => i);
    const reports = frameApdu(data);
    expect(reports).toHaveLength(3);
    expect([...reports[0]!.subarray(0, 7)]).toEqual([0x01, 0x01, 0x05, 0, 0, 0, 150]);
    expect([...reports[1]!.subarray(0, 5)]).toEqual([0x01, 0x01, 0x05, 0, 1]);
    expect(unframe(reports.slice(0, 2))).toBeNull();
    expect([...unframe(reports)!]).toEqual([...data]);
    const bad = reports.map((r) => r.slice());
    bad[1]![4] = 9;
    expect(() => unframe(bad)).toThrow();
  });

  it('encodes paths and splits the signing payload', () => {
    expect([...encodePath("m/44'/60'/0'/0/1")]).toEqual([
      5, 0x80, 0, 0, 44, 0x80, 0, 0, 60, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    expect(() => encodePath("m/44'/x")).toThrow();
    const chunks = signApdus("m/44'/60'/0'/0/0", new Uint8Array(600));
    expect(chunks.map((c) => [c[2], c[4]])).toEqual([
      [0x00, 255],
      [0x80, 255],
      [0x80, 111],
    ]);
    expect([...apdu(4, 0, 0, new Uint8Array(1)).subarray(0, 5)]).toEqual([0xe0, 4, 0, 0, 1]);
  });

  it('maps status words and parses addresses', () => {
    expect(() => checkStatus(Uint8Array.from([0x69, 0x85]))).toThrow(/Rejected/);
    expect([...checkStatus(Uint8Array.from([7, 0x90, 0x00]))]).toEqual([7]);
    const addr = new TextEncoder().encode('f39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
    const data = Uint8Array.from([65, ...new Uint8Array(65).fill(4), 40, ...addr]);
    expect(parseAddress(data).address).toBe('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
  });

  it('exchanges over a fake device', async () => {
    let listener: ((e: { data: DataView }) => void) | null = null;
    const device: HidLike = {
      opened: true,
      open: async () => undefined,
      close: async () => undefined,
      addEventListener: (_t, l) => (listener = l),
      removeEventListener: () => (listener = null),
      sendReport: async () => {
        const reply = frameApdu(Uint8Array.from([1, 2, ...new Uint8Array(63), 0x90, 0x00]));
        queueMicrotask(() => reply.forEach((r) => listener?.({ data: new DataView(r.buffer) })));
      },
    };
    const sig = await new LedgerEth(device).signTransaction("m/44'/60'/0'/0/0", '0x02c0');
    expect(sig.v).toBe(1);
    expect(sig.r).toHaveLength(64);
  });
});
