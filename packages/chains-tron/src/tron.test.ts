import { MemoryRpcPool, chainsForFamily } from '@stackwallet/chains';
import type { TronTx } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  TRON_NILE,
  broadcastTron,
  prepareTron,
  transferRawData,
  transferTxId,
  tronTransferStatus,
} from './send.js';
import {
  TronAdapter,
  isValidTronAddress,
  parseTronJson,
  tronAddressFromHex,
  tronAddressFromPublicKey,
} from './tron.js';

const KEY_ONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const DERIVED_ADDRESS_VECTOR = 'TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC';
const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const NILE_GENESIS = '0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc';
const MAINNET_GENESIS = '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc';
const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

const tx: TronTx = {
  chainId: TRON_NILE,
  from: DERIVED_ADDRESS_VECTOR,
  to: USDT,
  sun: '1500000',
  refBlockBytes: 'a1b2',
  refBlockHash: '0123456789abcdef',
  expiration: 1_760_000_060_000,
  timestamp: 1_760_000_000_000,
};
/** Produced by the Rust core's encoder for the same fields (`tron.rs` tests). */
const RAW_VECTOR =
  '0a02a1b222080123456789abcdef40e0d4b6c19c335a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15417e5f4552091a69125d5dfcb7b8c2659029395bdf121541a614f803b6fd780986a42c78ec9c7f77e6ded13c18e0c65b708080b3c19c33';

function node(routes: Record<string, (body: Record<string, unknown>) => unknown>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.host + url.pathname);
    const route = routes[url.pathname];
    if (!route) return new Response('{}', { status: 404 });
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const out = route(body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch, rpcs?: Record<string, string[]>) {
  const chains = chainsForFamily('tron').map((c) =>
    rpcs?.[c.chainId] ? { ...c, defaultRpcs: rpcs[c.chainId]! } : c,
  );
  return new TronAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) });
}

describe('tron addresses', () => {
  it('derives the base58check address of private key 1', () => {
    expect(tronAddressFromPublicKey(hexToBytes(KEY_ONE))).toBe(DERIVED_ADDRESS_VECTOR);
    const a = new TronAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: KEY_ONE }, TRON_NILE)).toBe(
      DERIVED_ADDRESS_VECTOR,
    );
    expect(() => a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, TRON_NILE)).toThrow();
  });

  it('refuses bad checksums, EVM addresses and the zero address', () => {
    expect(isValidTronAddress(USDT)).toBe(true);
    expect(isValidTronAddress(USDT.slice(0, -1) + 'u')).toBe(false);
    expect(isValidTronAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false);
    expect(isValidTronAddress('T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb')).toBe(false);
    expect(tronAddressFromHex('417e5f4552091a69125d5dfcb7b8c2659029395bdf')).toBe(
      DERIVED_ADDRESS_VECTOR,
    );
    expect(tronAddressFromHex('7e5f4552091a69125d5dfcb7b8c2659029395bdf')).toBeUndefined();
  });

  it('keeps balances above 2^53 exact', () => {
    const parsed = parseTronJson('{"balance": 95000000000000001,"free": 600}') as Record<
      string,
      unknown
    >;
    expect(parsed.balance).toBe('95000000000000001');
    expect(parsed.free).toBe(600);
  });
});

describe('tron transfers', () => {
  it('encodes the same raw_data bytes as the core', () => {
    expect(Buffer.from(transferRawData(tx)).toString('hex')).toBe(RAW_VECTOR);
    expect(transferTxId(tx)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('refuses hostile fields', () => {
    expect(() => transferRawData({ ...tx, sun: '0' })).toThrow();
    expect(() => transferRawData({ ...tx, sun: '01' })).toThrow();
    expect(() => transferRawData({ ...tx, to: tx.from })).toThrow();
    expect(() => transferRawData({ ...tx, expiration: tx.timestamp })).toThrow();
    expect(() =>
      transferRawData({ ...tx, chainId: 'tron:0x2b6653dc' as typeof TRON_NILE }),
    ).toThrow();
  });

  it('prepares a Nile transfer with the activation fee for a new account', async () => {
    const { fetchImpl } = node({
      '/wallet/getblockbynum': () => ({ blockID: NILE_GENESIS, block_header: { raw_data: {} } }),
      '/wallet/getnowblock': () => ({
        blockID: '00000000044860b9' + 'ab'.repeat(24),
        block_header: { raw_data: { number: 71852217, timestamp: 1_760_000_000_000 } },
      }),
      '/wallet/getchainparameters': () => ({
        chainParameter: [
          { key: 'getTransactionFee', value: 1000 },
          { key: 'getCreateAccountFee', value: 100000 },
          { key: 'getCreateNewAccountFeeInSystemContract', value: 1000000 },
        ],
      }),
      '/wallet/getaccountresource': () => ({ freeNetLimit: 600 }),
      '/wallet/getaccount': (b) =>
        b.address === DERIVED_ADDRESS_VECTOR
          ? { address: DERIVED_ADDRESS_VECTOR, balance: 5_000_000 }
          : {},
    });
    const a = adapter(fetchImpl);
    const intent = {
      id: 't',
      walletId: 'w',
      accountId: 'a',
      chainId: TRON_NILE,
      kind: 'transfer' as const,
      to: USDT,
      asset: `${TRON_NILE}:native`,
      amount: '1500000',
      proposer: { kind: 'human' as const, deviceId: 'd' },
      untrustedDestinations: [],
      createdAtMs: 0,
    };
    const { unsigned, simulation } = await prepareTron(
      a,
      intent as never,
      DERIVED_ADDRESS_VECTOR,
      1_760_000_000_500,
    );
    expect(unsigned.refBlockBytes).toBe('60b9');
    expect(unsigned.refBlockHash).toBe('abababababababab');
    expect(unsigned.expiration).toBe(1_760_000_000_500 + 30 * 60 * 1000);
    expect(simulation.fee.amount).toBe('1100000');
    expect(simulation.ok).toBe(true);
    expect(simulation.warnings.some((w) => w.kind === 'other')).toBe(true);
  });

  it('refuses an endpoint that serves another Tron network', async () => {
    const { fetchImpl } = node({
      '/wallet/getblockbynum': () => ({ blockID: MAINNET_GENESIS, block_header: { raw_data: {} } }),
      '/wallet/getaccount': () => ({ balance: 1 }),
    });
    await expect(adapter(fetchImpl).getBalances(USDT, TRON_NILE)).rejects.toThrow();
  });

  it('broadcasts only the ledger transfer with one signature', async () => {
    const seen: unknown[] = [];
    const { fetchImpl } = node({
      '/wallet/getblockbynum': () => ({ blockID: NILE_GENESIS, block_header: { raw_data: {} } }),
      '/wallet/broadcasthex': (b) => {
        seen.push(b.transaction);
        return { result: true, txid: transferTxId(tx) };
      },
    });
    const a = adapter(fetchImpl);
    // 133 raw bytes: a two-byte length varint.
    expect(RAW_VECTOR.length).toBe(266);
    const signed = `0x0a8501${RAW_VECTOR}1241${'11'.repeat(65)}`;
    await expect(broadcastTron(a, tx, signed)).resolves.toBe(transferTxId(tx));
    await expect(broadcastTron(a, { ...tx, sun: '1500001' }, signed)).rejects.toThrow();
    await expect(broadcastTron(a, tx, signed + '00')).rejects.toThrow();
    expect(seen).toHaveLength(1);
  });

  it('reports expiry only after a solidified block passes the expiration', async () => {
    let solidTs = tx.expiration - 1;
    const { fetchImpl } = node({
      '/wallet/getblockbynum': () => ({ blockID: NILE_GENESIS, block_header: { raw_data: {} } }),
      '/walletsolidity/gettransactioninfobyid': () => ({}),
      '/wallet/gettransactioninfobyid': () => ({}),
      '/walletsolidity/getnowblock': () => ({
        blockID: NILE_GENESIS,
        block_header: { raw_data: { number: 1, timestamp: solidTs } },
      }),
    });
    const a = adapter(fetchImpl);
    const id = transferTxId(tx);
    await expect(tronTransferStatus(a, tx, id)).resolves.toEqual({ state: 'unknown' });
    solidTs = tx.expiration + 3000;
    await expect(tronTransferStatus(a, tx, id)).resolves.toEqual({ state: 'expired' });
  });

  it('reads TRX and USDT balances on mainnet', async () => {
    const { fetchImpl } = node({
      '/wallet/getblockbynum': () => ({ blockID: MAINNET_GENESIS, block_header: { raw_data: {} } }),
      '/wallet/getaccount': () => '{"address":"x","balance": 95000000000000001}',
      '/wallet/triggerconstantcontract': () => ({
        result: { result: true },
        constant_result: ['00'.repeat(31) + '2a'],
      }),
    });
    const holdings = await adapter(fetchImpl).getBalances(
      DERIVED_ADDRESS_VECTOR,
      'tron:0x2b6653dc',
    );
    expect(holdings[0]!.amount).toBe('95000000000000001');
    expect(holdings[1]).toMatchObject({ assetRef: `tron:0x2b6653dc:trc20:${USDT}`, amount: '42' });
  });
});
