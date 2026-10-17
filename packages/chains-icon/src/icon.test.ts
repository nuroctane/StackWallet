import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  ICON_LISBON,
  ICON_MAINNET,
  IconAdapter,
  iconAddressFromPublicKey,
  isValidIconAddress,
} from './icon.js';
import {
  IconTx,
  broadcastIcon,
  iconHashKey,
  iconSighashHex,
  iconTransferStatus,
  iconTxHash,
  prepareIcon,
} from './send.js';

// icon-sdk-js 1.5.3 pins (see .nur/icon-probe3/4/5.mjs): secret 0x07*32.
const SECRET = '07'.repeat(32);
// Compressed SEC1 of that key (x is even => 02 prefix).
const SEC1 = `02${'989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f'}`;
const SENDER = 'hxcd5cd849ef6f20d6d22e4c0b3b3702b7c2667457';
const RECIPIENT = 'hx9d8a8376e7db9f00478feb9a46f44f0d051aab57';
const LISBON_ANCHOR = '0368d6a741b4d91e8ca1ec503168c804ad6b215975a74617c24fa2d4abaccce0';
const MAINNET_ANCHOR = 'd945aeae050639e2f8f67f8cb4cb456ab833cf0923e69326e12b066ff51d311c';

const tx: IconTx = {
  chainId: ICON_LISBON,
  from: SENDER,
  to: RECIPIENT,
  loop: '250000000000000000',
  nonce: 1,
  stepLimit: 100_000,
  timestamp: 1_760_000_000_000_000,
  builtAtMs: 1_760_000_000_000,
};

/** The Rust core asserts these exact strings for the same fields (`icon.rs` tests). */
const HASH_KEY =
  'icx_sendTransaction.from.hxcd5cd849ef6f20d6d22e4c0b3b3702b7c2667457.nid.0x2.nonce.0x1.stepLimit.0x186a0.timestamp.0x640b5eece0000.to.hx9d8a8376e7db9f00478feb9a46f44f0d051aab57.value.0x3782dace9d90000.version.0x3';
const SIGHASH = '19d06d298eefcc44a155c831f3e97c7a1bd6df68565e9d9902936879d9a1ecda';
const SIGNATURE =
  'TVo+ig+MFFtwoXjDdRBbcrogjZaKEvdxzF9iB3Ea4etZPAnFRpgSPYeA+os3TNT4Ol1TBxOGz5Z+fhEpSZ8kjwA=';
const TX_HASH = '0x12db38e5ebe22e8338cc80bf2b634465746cf0a594687688050b8605e7f25e95';

const WIRE = JSON.stringify({
  from: tx.from,
  to: tx.to,
  nid: '0x2',
  nonce: '0x1',
  version: '0x3',
  timestamp: '0x640b5eece0000',
  stepLimit: '0x186a0',
  value: '0x3782dace9d90000',
  signature: SIGNATURE,
});

function node(routes: Record<string, (body: Record<string, unknown>) => unknown>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.host + url.pathname + url.search);
    const route = routes[url.pathname];
    if (!route) return new Response('{}', { status: 404 });
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const out = route(body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const envelope = (result: unknown) => ({ jsonrpc: '2.0', id: 1, result });
const rpcError = (message: string) => ({ jsonrpc: '2.0', id: 1, error: { code: -31000, message } });

/** The catalog entries the lead wires in; seeded here until then. */
const CHAINS: ChainInfo[] = [
  {
    chainId: ICON_LISBON,
    family: 'icon',
    name: 'ICON Lisbon',
    nativeAsset: { ref: `${ICON_LISBON}:native`, symbol: 'ICX', decimals: 18 },
    testnet: true,
    explorerTxUrl: 'https://tracker.lisbon.icon.community/transaction/{hash}',
    defaultRpcs: ['https://lisbon.example/api/v3'],
    layer: 'L1',
  },
  {
    chainId: ICON_MAINNET,
    family: 'icon',
    name: 'ICON',
    nativeAsset: { ref: `${ICON_MAINNET}:native`, symbol: 'ICX', decimals: 18 },
    testnet: false,
    explorerTxUrl: 'https://tracker.icon.community/transaction/{hash}',
    defaultRpcs: ['https://main.example/api/v3'],
    layer: 'L1',
    priceId: 'icon',
  },
];

function adapter(fetchImpl: typeof fetch, rpcs?: Record<string, string[]>) {
  const chains = CHAINS.map((c) =>
    rpcs?.[c.chainId] ? { ...c, defaultRpcs: rpcs[c.chainId]! } : c,
  );
  return new IconAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) });
}

const lisbonNode = {
  '/api/v3': (b: Record<string, unknown>) => {
    const params = (b.params ?? {}) as Record<string, unknown>;
    switch (b.method) {
      case 'icx_getBlockByHeight':
        return params.height === '0xf4240'
          ? envelope({ block_hash: LISBON_ANCHOR, height: 1_000_000 })
          : envelope({});
      case 'icx_getLastBlock':
        return envelope({
          height: 68_000_000,
          block_hash: 'ab'.repeat(32),
          time_stamp: 1_760_000_010_000_000,
        });
      case 'icx_getBalance':
        return envelope('0x3635c9adc5dea00000');
      case 'icx_call':
        return envelope('0x2e90edd00');
      default:
        return envelope({});
    }
  },
};

describe('icon addresses', () => {
  it('derives the hx address of secret 0x07*32 (icon-sdk-js vector)', () => {
    expect(
      iconAddressFromPublicKey(Uint8Array.from(SEC1.match(/../g)!.map((b) => parseInt(b, 16)))),
    ).toBe(SENDER);
    const a = adapter((async () => new Response('{}')) as typeof fetch);
    expect(a.deriveAddress({ curve: 'secp256k1', hex: SEC1 }, ICON_LISBON)).toBe(SENDER);
    expect(() => a.deriveAddress({ curve: 'ed25519', hex: SECRET }, ICON_LISBON)).toThrow();
  });

  it('refuses contract, uppercase, short and zero addresses', () => {
    expect(isValidIconAddress(RECIPIENT)).toBe(true);
    expect(isValidIconAddress('cx9d8a8376e7db9f00478feb9a46f44f0d051aab57')).toBe(false);
    expect(isValidIconAddress(SENDER.toUpperCase().replace('HX', 'hx'))).toBe(false);
    expect(isValidIconAddress('hx9d8a8376e7db9f00478feb9a46f44f0d051aab5')).toBe(false);
    expect(isValidIconAddress('hx0000000000000000000000000000000000000000')).toBe(false);
  });
});

describe('icon transfers', () => {
  it('builds the same hash key, sighash and tx hash as the core', () => {
    expect(iconHashKey(tx)).toBe(HASH_KEY);
    expect(iconSighashHex(tx)).toBe(SIGHASH);
    expect(iconTxHash(tx, SIGNATURE)).toBe(TX_HASH);
  });

  it('refuses hostile fields', () => {
    expect(() => iconHashKey({ ...tx, loop: '0' })).toThrow();
    expect(() => iconHashKey({ ...tx, loop: '0250000000000000000' })).toThrow();
    expect(() => iconHashKey({ ...tx, stepLimit: 99_999 })).toThrow();
    expect(() => iconHashKey({ ...tx, stepLimit: 25_000_001 })).toThrow();
    expect(() => iconHashKey({ ...tx, nonce: 0 })).toThrow();
    expect(() => iconHashKey({ ...tx, chainId: ICON_MAINNET as typeof ICON_LISBON })).toThrow();
    expect(() => iconHashKey({ ...tx, timestamp: 0 })).toThrow();
  });

  it('prepares a Lisbon transfer with the step fee', async () => {
    const { fetchImpl } = node(lisbonNode);
    const a = adapter(fetchImpl);
    const intent = {
      id: 't',
      walletId: 'w',
      accountId: 'a',
      chainId: ICON_LISBON,
      kind: 'transfer' as const,
      to: RECIPIENT,
      asset: `${ICON_LISBON}:native`,
      amount: '250000000000000000',
      proposer: { kind: 'human' as const, deviceId: 'd' },
      untrustedDestinations: [],
      createdAtMs: 0,
    };
    const { unsigned, simulation } = await prepareIcon(
      a,
      intent as never,
      SENDER,
      1_760_000_000_000,
    );
    expect(unsigned).toEqual(tx);
    expect(simulation.ok).toBe(true);
    // 100,000 step at 0x2e90edd00 loop per step.
    expect(simulation.fee.amount).toBe((100_000n * 12_500_000_000n).toString());
  });

  it('fails the simulation when the balance cannot cover amount plus fee', async () => {
    const { fetchImpl } = node({
      '/api/v3': (b) => {
        const m = (b as Record<string, unknown>).method;
        const params = ((b as Record<string, unknown>).params ?? {}) as Record<string, unknown>;
        if (m === 'icx_getBlockByHeight') return envelope({ block_hash: LISBON_ANCHOR });
        if (m === 'icx_getBalance') return envelope('0x1');
        if (m === 'icx_call' && params.to) return envelope('0x2e90edd00');
        return envelope({});
      },
    });
    const a = adapter(fetchImpl);
    const intent = {
      chainId: ICON_LISBON,
      kind: 'transfer' as const,
      to: RECIPIENT,
      asset: `${ICON_LISBON}:native`,
      amount: '250000000000000000',
    };
    const { simulation } = await prepareIcon(a, intent as never, SENDER, 1_760_000_000_000);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/no ICX|does not cover/);
  });

  it('refuses an endpoint that serves another ICON network', async () => {
    const { fetchImpl } = node({
      '/api/v3': () => envelope({ block_hash: MAINNET_ANCHOR }),
    });
    await expect(adapter(fetchImpl).getBalances(SENDER, ICON_LISBON)).rejects.toThrow();
  });

  it('broadcasts only signed params matching this exact transfer', async () => {
    const seen: unknown[] = [];
    const { fetchImpl } = node({
      '/api/v3': (b) => {
        const body = b as Record<string, unknown>;
        if (body.method === 'icx_sendTransaction') {
          seen.push(body.params);
          return envelope(TX_HASH);
        }
        return envelope({ block_hash: LISBON_ANCHOR });
      },
    });
    const a = adapter(fetchImpl);
    await expect(broadcastIcon(a, tx, WIRE)).resolves.toBe(TX_HASH);
    // The wire must sign the fields it carries: a swapped destination fails recovery/field checks.
    await expect(broadcastIcon(a, { ...tx, loop: '250000000000000001' }, WIRE)).rejects.toThrow();
    const tampered = JSON.stringify({ ...JSON.parse(WIRE), value: '0x3782dace9d90001' });
    await expect(broadcastIcon(a, tx, tampered)).rejects.toThrow();
    expect(seen).toHaveLength(1);
  });

  it('treats a duplicate broadcast as success', async () => {
    const { fetchImpl } = node({
      '/api/v3': (b) =>
        (b as Record<string, unknown>).method === 'icx_sendTransaction'
          ? rpcError('SystemError: E2001:Duplicated transaction')
          : envelope({ block_hash: LISBON_ANCHOR }),
    });
    const a = adapter(fetchImpl);
    await expect(broadcastIcon(a, tx, WIRE)).resolves.toBe(TX_HASH);
  });

  it('reports confirmed, failed and expired states', async () => {
    let result: unknown = rpcError('NotFound: E1005:not found tx=0x12');
    const { fetchImpl } = node({
      '/api/v3': (b) => {
        const body = b as Record<string, unknown>;
        if (body.method === 'icx_getTransactionResult') return result;
        if (body.method === 'icx_getTransactionByHash')
          return rpcError('NotFound: E1005:not found tx=0x12');
        return envelope({ block_hash: LISBON_ANCHOR });
      },
    });
    const a = adapter(fetchImpl);
    const now = tx.builtAtMs + 5 * 60 * 1000;
    await expect(iconTransferStatus(a, tx, TX_HASH, now)).resolves.toEqual({ state: 'unknown' });
    result = rpcError('Pending: Pending');
    await expect(iconTransferStatus(a, tx, TX_HASH, now)).resolves.toEqual({ state: 'pending' });
    result = envelope({ status: '0x1', blockHeight: '0x41043b0' });
    await expect(iconTransferStatus(a, tx, TX_HASH, now)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 0x41043b0,
    });
    result = envelope({
      status: '0x0',
      blockHeight: '0x41043b0',
      failure: { message: 'Out of step' },
    });
    await expect(iconTransferStatus(a, tx, TX_HASH, now)).resolves.toEqual({
      state: 'failed',
      reason: 'Out of step',
    });
    result = rpcError('NotFound: E1005:not found tx=0x12');
    const later = tx.builtAtMs + 61 * 60 * 1000;
    await expect(iconTransferStatus(a, tx, TX_HASH, later)).resolves.toEqual({ state: 'expired' });
  });
});
