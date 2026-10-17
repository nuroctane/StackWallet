import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  QUBIC_CHAINS,
  QUBIC_MAINNET,
  QUBIC_RPC,
  QubicAdapter,
  createQubicAdapter,
  isValidQubicIdentity,
  k12,
  qubicIdentityBytes,
  qubicIdentityFromPublicKey,
  qubicTxId,
} from './qubic.js';
import {
  broadcastQubic,
  prepareQubic,
  qubicApprovalValid,
  qubicRawBytes,
  qubicTransferStatus,
} from './send.js';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));
const bytesToHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

// Vectors from `@qubic-lib/qubic-ts-library` (`.nur/qubic-oracle/vectors.cjs`);
// the Rust core (`qubic.rs`) pins the same bytes.
const PUB_A = '1f590d03e613bdded38b4c0820ac44615f91af12435980b3ede3c08c315a2544';
const ID_A = 'BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK';
const PUB_Z = '69e68dc170cd9b6dda32b69490f5f71405c5c8d67012e96a86d3ff98ef915ec5';
const ID_Z = 'ZSDAHLHNHVWTEDYXRTTDWNKGRVPAFQKNTOUXPOXSCDGOPTMUJFWPVATFXHPG';
const RAW_TX =
  '1f590d03e613bdded38b4c0820ac44615f91af12435980b3ede3c08c315a2544' +
  '69e68dc170cd9b6dda32b69490f5f71405c5c8d67012e96a86d3ff98ef915ec5' +
  'b168de3a00000000' +
  '07e1f505' +
  '00000000';
// The Rust-signed broadcast package for tx1 (amount 987654321, tick 100000007);
// a Qubic mainnet node accepted the sibling signature live (probe 2026-10-17).
const SIGNED_PACKAGE_B64 = Buffer.from(
  RAW_TX +
    '5160ae04baf136fe783aa79fe0a470473f1e0e4101f6a4cd33b5fdc13ced2746' +
    '3b5b5db585b75037017bcad8e17fc7918d253cada969919466fb529740562000',
  'hex',
).toString('base64');
const TXID = 'tkvndhloeqpfteojfmhrdhukpsqafymsbguvphnjsfpmugukpjmesmqcxuua';

const TX1 = { chainId: QUBIC_MAINNET, from: ID_A, to: ID_Z, qu: '987654321', tick: 100_000_007 };

const RPC_A = 'https://rpc-a.test';
const RPC_B = 'https://rpc-b.test';

const CHAINS: ChainInfo[] = [{ ...QUBIC_CHAINS[0]!, defaultRpcs: [RPC_A, RPC_B] }];

class TestAdapter extends QubicAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Route = (url: URL, init?: RequestInit) => Response;

function node(routes: Record<string, Route>, tick = 85_222_476) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.pathname);
    if (url.pathname === '/v1/tick-info')
      return Response.json({
        tickInfo: { tick, duration: 0, epoch: 235, initialTick: 84_770_000 },
      });
    const route = routes[url.pathname];
    if (!route) return new Response('not found', { status: 404 });
    return route(url, init);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const adapter = (fetchImpl: typeof fetch) =>
  new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });

describe('k12', () => {
  it('matches the official and oracle vectors', () => {
    const hex = (b: Uint8Array) => bytesToHex(b);
    expect(hex(k12(new Uint8Array(0)))).toBe(
      '1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5',
    );
    expect(hex(k12(new TextEncoder().encode('abc')))).toBe(
      'ab174f328c55a5510b0b209791bf8b60e801a7cfc2aa42042dcb8f547fbe3a7d',
    );
    expect(hex(k12(new Uint8Array(32)))).toBe(
      '235c3c067d94fb13b1dbd3ec5ab5c4587078c4f1442580b3f3a47687cb778089',
    );
    expect(hex(k12(Uint8Array.from({ length: 80 }, (_, i) => i)))).toBe(
      '3eb01170a5c1172bf1a0f26fe38a3bf71283b0c8603f9b266a4e021d9b440ad0',
    );
  });
});

describe('qubic identities', () => {
  it('matches the oracle identities byte for byte', () => {
    expect(qubicIdentityFromPublicKey(hexToBytes(PUB_A))).toBe(ID_A);
    expect(qubicIdentityFromPublicKey(hexToBytes(PUB_Z))).toBe(ID_Z);
  });
  it('round-trips and validates by checksum', () => {
    expect(bytesToHex(qubicIdentityBytes(ID_A)!)).toBe(PUB_A);
    expect(isValidQubicIdentity(ID_Z)).toBe(true);
  });
  it('rejects malformed, lowercase, wrong-checksum, and non-canonical spellings', () => {
    expect(isValidQubicIdentity(ID_A.toLowerCase())).toBe(false);
    expect(isValidQubicIdentity(ID_A.slice(0, 59))).toBe(false);
    expect(isValidQubicIdentity(`${ID_A.slice(0, 10)}B${ID_A.slice(11)}`)).toBe(false);
    expect(isValidQubicIdentity('Z'.repeat(14) + 'A'.repeat(46))).toBe(false);
  });
});

describe('qubic raw bytes and txid', () => {
  it('matches the Rust-encoded bytes exactly', () => {
    expect(bytesToHex(qubicRawBytes(TX1))).toBe(RAW_TX);
  });
  it('derives the explorer transaction id from the signed package', () => {
    expect(qubicTxId(Buffer.from(SIGNED_PACKAGE_B64, 'base64'))).toBe(TXID);
  });
  it('rejects bad fields', () => {
    expect(() => qubicRawBytes({ ...TX1, qu: '0' })).toThrow();
    expect(() => qubicRawBytes({ ...TX1, to: ID_A })).not.toThrow(); // codec allows; Rust refuses
    expect(() => qubicRawBytes({ ...TX1, tick: 0 })).toThrow();
    expect(() => qubicRawBytes({ ...TX1, to: ID_Z.toLowerCase() })).toThrow();
  });
});

describe('qubic adapter reads', () => {
  it('reads the native balance', async () => {
    const { fetchImpl } = node({
      [`/v1/balances/${ID_A}`]: () =>
        Response.json({
          balance: { id: ID_A, balance: '1234567', validForTick: 85_222_480 },
        }),
    });
    const holdings = await adapter(fetchImpl).getBalances(ID_A, QUBIC_MAINNET);
    expect(holdings[0]!.amount).toBe('1234567');
    expect(holdings[0]!.assetRef).toBe(`${QUBIC_MAINNET}:native`);
  });
  it('rejects invalid identities', async () => {
    await expect(
      adapter(node({}).fetchImpl).getBalances(ID_A.toLowerCase(), QUBIC_MAINNET),
    ).rejects.toThrow();
    expect(adapter(node({}).fetchImpl).validateAddress(ID_Z, QUBIC_MAINNET)).toBe(true);
  });
  it('derives an address from a 32-byte public key', () => {
    const a = adapter(node({}).fetchImpl);
    expect(a.deriveAddress({ curve: 'ed25519', hex: PUB_A }, QUBIC_MAINNET)).toBe(ID_A);
  });
  it('reports the history gap instead of failing', async () => {
    const page = await adapter(node({}).fetchImpl).getHistory(ID_A, QUBIC_MAINNET);
    expect(page.items).toEqual([]);
    expect(page.coverage).toMatch(/history/);
  });
});

describe('qubic status', () => {
  it('confirms an executed transaction', async () => {
    const { fetchImpl } = node({
      [`/v1/transactions/${TXID}`]: () =>
        Response.json({
          transaction: { sourceId: ID_A, destId: ID_Z, amount: '1', tickNumber: 85_222_470 },
        }),
      [`/v1/tx-status/${TXID}`]: () =>
        Response.json({ transactionStatus: { txId: TXID, moneyFlew: true } }),
    });
    const s = await adapter(fetchImpl).status(TXID, QUBIC_MAINNET);
    expect(s).toEqual({ state: 'confirmed', blockNumber: 85_222_470 });
  });
  it('flags moneyFlew false as failed', async () => {
    const { fetchImpl } = node({
      [`/v1/transactions/${TXID}`]: () =>
        Response.json({
          transaction: { sourceId: ID_A, destId: ID_Z, amount: '1', tickNumber: 85_222_470 },
        }),
      [`/v1/tx-status/${TXID}`]: () =>
        Response.json({ transactionStatus: { txId: TXID, moneyFlew: false } }),
    });
    const s = await adapter(fetchImpl).status(TXID, QUBIC_MAINNET);
    expect(s.state).toBe('failed');
  });
  it('reports absent ids as unknown', async () => {
    const { fetchImpl } = node({});
    const s = await adapter(fetchImpl).status(TXID, QUBIC_MAINNET);
    expect(s.state).toBe('unknown');
  });
});

describe('qubic send path', () => {
  const intent = {
    id: 'intent-1',
    chainId: QUBIC_MAINNET,
    kind: 'transfer' as const,
    to: ID_Z,
    asset: `${QUBIC_MAINNET}:native`,
    amount: '1000',
  };
  it('prepares a tick-targeted transfer with a zero fee', async () => {
    const { fetchImpl } = node({
      [`/v1/balances/${ID_A}`]: () =>
        Response.json({ balance: { id: ID_A, balance: '5000', validForTick: 85_222_480 } }),
    });
    const { unsigned, simulation } = await prepareQubic(adapter(fetchImpl), intent as never, ID_A);
    expect(unsigned.tick).toBe(85_222_476 + 20);
    expect(unsigned.qu).toBe('1000');
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('0');
  });
  it('fails preparation when the balance is short', async () => {
    const { fetchImpl } = node({
      [`/v1/balances/${ID_A}`]: () =>
        Response.json({ balance: { id: ID_A, balance: '10', validForTick: 85_222_480 } }),
    });
    const { simulation } = await prepareQubic(adapter(fetchImpl), intent as never, ID_A);
    expect(simulation.ok).toBe(false);
  });
  it('refuses approval when too few ticks remain', async () => {
    const near = { ...TX1, tick: 85_222_479 };
    const { fetchImpl } = node({});
    expect(await qubicApprovalValid(adapter(fetchImpl), near)).toBe(false);
    expect(await qubicApprovalValid(adapter(fetchImpl), { ...TX1, tick: 85_222_500 })).toBe(true);
  });
  it('broadcasts only bytes that embed the exact transfer', async () => {
    const { fetchImpl, calls } = node({
      '/v1/broadcast-transaction': () =>
        Response.json({ peersBroadcasted: 3, transactionId: TXID }),
    });
    const a = adapter(fetchImpl);
    const hash = await broadcastQubic(a, TX1, SIGNED_PACKAGE_B64);
    expect(hash).toBe(TXID);
    expect(calls).toContain('/v1/broadcast-transaction');
    await expect(
      broadcastQubic(a, { ...TX1, qu: '987654322' }, SIGNED_PACKAGE_B64),
    ).rejects.toThrow(/not this QU transfer/);
    await expect(broadcastQubic(a, TX1, Buffer.alloc(10).toString('base64'))).rejects.toThrow();
  });
  it('reports expiry once the target tick passes without execution', async () => {
    const stale = { ...TX1, tick: 85_222_470 };
    const { fetchImpl } = node({});
    const s = await qubicTransferStatus(adapter(fetchImpl), stale, TXID);
    expect(s).toEqual({ state: 'expired' });
  });
  it('reports pending while the target tick is ahead', async () => {
    const future = { ...TX1, tick: 85_222_500 };
    const { fetchImpl } = node({});
    const s = await qubicTransferStatus(adapter(fetchImpl), future, TXID);
    expect(s).toEqual({ state: 'pending' });
  });
});

describe('factory and constants', () => {
  it('exposes the mainnet id and factory', () => {
    expect(QUBIC_MAINNET).toBe('qubic:mainnet');
    expect(QUBIC_CHAINS[0]!.defaultRpcs).toContain(QUBIC_RPC);
    expect(createQubicAdapter({ rpc: new MemoryRpcPool(CHAINS) }).chains()[0]!.chainId).toBe(
      QUBIC_MAINNET,
    );
  });
});
