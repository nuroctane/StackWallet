import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { base58, base64 } from '@scure/base';
import { describe, expect, it } from 'vitest';

import {
  WAVES_FEE_WAVELETS,
  WAVES_TX_STALE_MS,
  WavesTx,
  broadcastWaves,
  prepareWaves,
  transferBodyBytes,
  transferTxId,
  wavesApprovalValid,
  wavesTransferStatus,
} from './send.js';
import {
  WAVES_MAINNET,
  WAVES_TESTNET,
  WavesAdapter,
  isValidWavesAddress,
  parseWavesAddress,
  wavesAddressFromPublicKey,
} from './waves.js';

// Vectors produced by @waves/ts-lib-crypto 1.5.2 and pinned in the Rust core
// (`waves.rs` tests assert the same body bytes, id and signature).
const PUBLIC_HEX = '8e4b17a1d571ef23420070bd3b4f3908ca0227237d455f61ef2da464f2c86123';
const PUBLIC_B58 = 'AaTJhNYwNXhAg5LCyMTkeGsmPoQuwfyYh9A3yKxadLyx';
const ADDRESS_T = '3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z9';
const ADDRESS_W = '3PCVpavfjsxHC2VcrYLfqx1vxvipt1NYgkt';
const RECIPIENT_T = '3NBRL1d9WCia865111rFgeF6wfneJeUEj3W';
const BODY_HEX =
  '085412208e4b17a1d571ef23420070bd3b4f3908ca0227237d455f61ef2da464f2c861231a0410a08d06208080b3c19c332803c2061f0a160a14ebe29693861de35ec03b78d11743062defc8d082120510959aef3a';
const TX_ID = 'C2rL58abTr2QstLd2cwwL8cfu9KexYhH9VLn6WkZyQbg';
const SIG_B58 =
  'DJeZZCkUX58S2SjZJh3ZhgbMT3Ks6bYxTQoyf48uEWYiQaH6KUCzLb4NAVwZqjBEkUUND4p7wHC4hUJtYrTSQbp';
const SIGNED_B64 =
  'ClUIVBIgjksXodVx7yNCAHC9O085CMoCJyN9RV9h7y2kZPLIYSMaBBCgjQYggICzwZwzKAPCBh8KFgoU6+KWk4Yd417AO3jRF0MGLe/I0IISBRCVmu86EkAKnFkawCpk3x+w7NkyvrkQCdv4bfsCHohc2YL8V8/U6sOreBYHGZH4vqoYRTLffkfu9w9M5s1p35ul6aj91OuH';
const GENESIS_T =
  '5uqnLK3Z9eiot6FyYBfwUnbyid3abicQbAZjz38GQ1Q8XigQMxTK4C1zNkqS1SVw7FqSidbZKxWAKLVoEsp4nNqa';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

const tx: WavesTx = {
  chainId: WAVES_TESTNET,
  from: ADDRESS_T,
  to: RECIPIENT_T,
  wavelets: '123456789',
  publicKeyHex: PUBLIC_HEX,
  timestamp: 1_760_000_000_000,
  builtAtMs: 1_760_000_000_000,
};

const intent: TxIntent = {
  intentId: 'i',
  chainId: WAVES_TESTNET,
  kind: 'transfer',
  to: RECIPIENT_T,
  asset: `${WAVES_TESTNET}:native`,
  amount: '123456789',
} as unknown as TxIntent;

function node(routes: Record<string, (body: unknown) => unknown>, status = 200) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.host + url.pathname);
    const route = routes[url.pathname];
    if (!route) return new Response('{}', { status: 404 });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const out = route(body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), {
      status:
        out && typeof out === 'object' && '__status' in out ? (out.__status as number) : status,
    });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

// The lead adds catalog entries; tests stand the same chains up inline.
const testChains: ChainInfo[] = [
  {
    chainId: WAVES_TESTNET,
    family: 'waves',
    name: 'Waves Testnet',
    nativeAsset: { ref: `${WAVES_TESTNET}:native`, symbol: 'WAVES', decimals: 8 },
    testnet: true,
    defaultRpcs: ['https://node.test'],
  },
  {
    chainId: WAVES_MAINNET,
    family: 'waves',
    name: 'Waves',
    nativeAsset: { ref: `${WAVES_MAINNET}:native`, symbol: 'WAVES', decimals: 8 },
    testnet: false,
    defaultRpcs: ['https://node.test'],
  },
];

// The lead adds catalog entries; tests stand the same chains up inline.
class TestWavesAdapter extends WavesAdapter {
  override chains(): ChainInfo[] {
    return testChains;
  }
}

function adapter(fetchImpl: typeof fetch) {
  return new TestWavesAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(testChains) });
}

const genesisOk = { '/blocks/at/1': () => ({ signature: GENESIS_T }) };

describe('waves addresses', () => {
  it('derives the pinned address from the Waves public key', () => {
    expect(wavesAddressFromPublicKey(hexToBytes(PUBLIC_HEX), WAVES_TESTNET)).toBe(ADDRESS_T);
    expect(wavesAddressFromPublicKey(hexToBytes(PUBLIC_HEX), WAVES_MAINNET)).toBe(ADDRESS_W);
    const a = adapter((async () => new Response('{}', { status: 404 })) as typeof fetch);
    expect(a.deriveAddress({ curve: 'ed25519', hex: PUBLIC_HEX }, WAVES_TESTNET)).toBe(ADDRESS_T);
    expect(() => a.deriveAddress({ curve: 'secp256k1', hex: PUBLIC_HEX }, WAVES_TESTNET)).toThrow();
  });

  it('validates checksum and chain byte', () => {
    expect(isValidWavesAddress(ADDRESS_T)).toBe(true);
    expect(isValidWavesAddress(ADDRESS_T, WAVES_TESTNET)).toBe(true);
    expect(isValidWavesAddress(ADDRESS_T, WAVES_MAINNET)).toBe(false);
    expect(isValidWavesAddress(ADDRESS_W, WAVES_MAINNET)).toBe(true);
    expect(isValidWavesAddress(ADDRESS_T.slice(0, -1) + '8')).toBe(false);
    expect(isValidWavesAddress('TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC')).toBe(false);
    expect(parseWavesAddress(ADDRESS_T)?.chainByte).toBe(84);
  });
});

describe('waves transfers', () => {
  it('encodes the same body bytes and id as the core', () => {
    expect(Buffer.from(transferBodyBytes(tx)).toString('hex')).toBe(BODY_HEX);
    expect(transferTxId(tx)).toBe(TX_ID);
  });

  it('refuses hostile fields', () => {
    expect(() => transferBodyBytes({ ...tx, wavelets: '0' })).toThrow();
    expect(() => transferBodyBytes({ ...tx, wavelets: '0123' })).toThrow();
    expect(() => transferBodyBytes({ ...tx, wavelets: '9223372036854775808' })).toThrow();
    expect(() => transferBodyBytes({ ...tx, to: tx.from })).toThrow();
    expect(() => transferBodyBytes({ ...tx, to: ADDRESS_W })).toThrow();
    expect(() => transferBodyBytes({ ...tx, publicKeyHex: 'ab'.repeat(32) })).toThrow();
    expect(() => transferBodyBytes({ ...tx, chainId: WAVES_MAINNET as never })).toThrow();
  });

  it('prepares a transfer and flags an underfunded sender', async () => {
    const { fetchImpl } = node({
      ...genesisOk,
      '/addresses/balance/3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z9': () => ({ balance: 1000 }),
    });
    const a = adapter(fetchImpl);
    const { unsigned, simulation } = await prepareWaves(
      a,
      intent,
      ADDRESS_T,
      PUBLIC_HEX,
      1_760_000_000_000,
    );
    expect(unsigned).toEqual(tx);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/Balance/);
    expect(simulation.fee.amount).toBe(String(WAVES_FEE_WAVELETS));
  });

  it('prepares successfully when the balance covers amount plus fee', async () => {
    const { fetchImpl } = node({
      ...genesisOk,
      '/addresses/balance/3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z9': () => ({ balance: 123556789 }),
    });
    const a = adapter(fetchImpl);
    const { simulation } = await prepareWaves(a, intent, ADDRESS_T, PUBLIC_HEX, 1_760_000_000_000);
    expect(simulation.ok).toBe(true);
  });

  it('approval is refused once the timestamp is nearly stale', () => {
    expect(wavesApprovalValid(tx, tx.timestamp + WAVES_TX_STALE_MS - 120_000)).toBe(true);
    expect(wavesApprovalValid(tx, tx.timestamp + WAVES_TX_STALE_MS)).toBe(false);
  });

  it('broadcasts the signed wire and checks the node id', async () => {
    const { fetchImpl, calls } = node({
      ...genesisOk,
      '/transactions/broadcast': (body) => {
        const b = body as Record<string, unknown>;
        expect(b.type).toBe(4);
        expect(b.version).toBe(3);
        expect(b.senderPublicKey).toBe(PUBLIC_B58);
        expect(b.recipient).toBe(RECIPIENT_T);
        expect(b.amount).toBe(123456789);
        expect(b.fee).toBe(100000);
        expect(b.timestamp).toBe(1_760_000_000_000);
        expect((b.proofs as string[])[0]!).toBe(SIG_B58);
        return { id: TX_ID };
      },
    });
    const a = adapter(fetchImpl);
    await expect(broadcastWaves(a, tx, SIGNED_B64)).resolves.toBe(TX_ID);
    expect(calls).toContain('node.test/transactions/broadcast');
  });

  it('refuses a wire that is not exactly this transfer plus one proof', async () => {
    const a = adapter(node(genesisOk).fetchImpl);
    const wire = base64.decode(SIGNED_B64);
    const tampered = Uint8Array.from(wire);
    tampered.set([tampered[20]! ^ 1], 20);
    await expect(broadcastWaves(a, tx, base64.encode(tampered))).rejects.toThrow(/not this WAVES/);
    const withExtra = Uint8Array.from([...wire, 0]);
    await expect(broadcastWaves(a, tx, base64.encode(withExtra))).rejects.toThrow(/not this WAVES/);
    await expect(broadcastWaves(a, tx, '!!!')).rejects.toThrow(/base64/);
  });

  it('surfaces node rejections with their message', async () => {
    const { fetchImpl } = node({
      ...genesisOk,
      '/transactions/broadcast': () => ({
        __status: 400,
        error: 112,
        message: 'State check failed. Reason: Attempt to transfer unavailable funds',
      }),
    });
    const a = adapter(fetchImpl);
    await expect(broadcastWaves(a, tx, SIGNED_B64)).rejects.toThrow(/unavailable funds/);
  });

  it('maps status endpoints to pending/confirmed/failed/unknown/expired', async () => {
    const mk = (infoStatus: number, unconf: boolean, headTs: number) =>
      node({
        ...genesisOk,
        '/transactions/info/C2rL58abTr2QstLd2cwwL8cfu9KexYhH9VLn6WkZyQbg': () => ({
          __status: infoStatus,
          id: TX_ID,
          height: 100,
          timestamp: 1_760_000_000_100,
        }),
        '/transactions/unconfirmed/info/C2rL58abTr2QstLd2cwwL8cfu9KexYhH9VLn6WkZyQbg': () =>
          unconf ? { id: TX_ID } : { __status: 404, error: 311 },
        '/blocks/headers/last': () => ({ timestamp: headTs }),
      }).fetchImpl;

    let a = adapter(mk(200, false, 0));
    await expect(wavesTransferStatus(a, tx, TX_ID)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 100,
      timestampMs: 1_760_000_000_100,
    });

    a = adapter(mk(404, true, 0));
    await expect(wavesTransferStatus(a, tx, TX_ID)).resolves.toEqual({ state: 'pending' });

    a = adapter(mk(404, false, tx.timestamp + 60_000));
    await expect(wavesTransferStatus(a, tx, TX_ID)).resolves.toEqual({ state: 'unknown' });

    a = adapter(mk(404, false, tx.timestamp + WAVES_TX_STALE_MS + 1));
    await expect(wavesTransferStatus(a, tx, TX_ID)).resolves.toEqual({ state: 'expired' });
  });

  it('reads balances and history from the node', async () => {
    const { fetchImpl } = node({
      ...genesisOk,
      // Raw text: a balance above 2^53 must survive JSON parsing exactly.
      '/addresses/balance/3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z9': () =>
        `{"address":"${ADDRESS_T}","confirmations":0,"balance":950000000000000001}`,
      '/transactions/address/3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z9/limit/20': () => [
        [
          {
            type: 4,
            id: TX_ID,
            sender: ADDRESS_T,
            recipient: RECIPIENT_T,
            amount: 123456789,
            fee: 100000,
            feeAssetId: null,
            assetId: null,
            timestamp: 1_760_000_000_000,
            height: 100,
            applicationStatus: 'succeeded',
          },
        ],
      ],
    });
    const a = adapter(fetchImpl);
    const holdings = await a.getBalances(ADDRESS_T, WAVES_TESTNET);
    expect(holdings[0]!.amount).toBe('950000000000000001');
    const page = await a.getHistory(ADDRESS_T, WAVES_TESTNET);
    expect(page.items).toHaveLength(1);
    expect(page.items[0]).toMatchObject({
      hash: TX_ID,
      from: ADDRESS_T,
      to: RECIPIENT_T,
      status: 'confirmed',
      fee: '100000',
    });
    expect(page.items[0]!.assetDeltas).toEqual([
      { assetRef: `${WAVES_TESTNET}:native`, amount: '-123456789' },
    ]);
  });

  it('rejects endpoints serving the wrong network', async () => {
    const { fetchImpl } = node({ '/blocks/at/1': () => ({ signature: 'wrong' }) });
    const a = adapter(fetchImpl);
    await expect(a.getBalances(ADDRESS_T, WAVES_TESTNET)).rejects.toThrow();
  });
});
