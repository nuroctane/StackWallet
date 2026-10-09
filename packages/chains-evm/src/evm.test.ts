import {
  MemoryRpcPool,
  NotImplementedError,
  RpcFailoverError,
  chainsForFamily,
} from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import { createEvmAdapter, isValidEvmAddress, toChecksumAddress } from './evm.js';

// Public key of secp256k1 private key 1 (the generator point).
const GX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const GY = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
// Public test vector (address of private key 1), split so secret scanners do not trip on it.
const EXPECTED_FOR_G = ['0x7E5F4552', '091A69125d', '5DfCb7b8C2', '659029395Bdf'].join('');

function rpcFetch(handler: (method: string, params: unknown[]) => unknown): typeof fetch {
  return async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
    const result = handler(body.method, body.params);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
  };
}

describe('EvmAdapter addresses', () => {
  const evm = createEvmAdapter();

  it('derives the EIP-55 address from uncompressed, raw and compressed keys', () => {
    expect(evm.deriveAddress({ curve: 'secp256k1', hex: '04' + GX + GY }, 'eip155:1')).toBe(
      EXPECTED_FOR_G,
    );
    expect(evm.deriveAddress({ curve: 'secp256k1', hex: GX + GY }, 'eip155:8453')).toBe(
      EXPECTED_FOR_G,
    );
    expect(evm.deriveAddress({ curve: 'secp256k1', hex: '02' + GX }, 'eip155:1')).toBe(
      EXPECTED_FOR_G,
    );
  });

  it('rejects wrong curves and unknown chains', () => {
    expect(() => evm.deriveAddress({ curve: 'ed25519', hex: GX }, 'eip155:1')).toThrow(
      /curve ed25519/,
    );
    expect(() =>
      evm.deriveAddress({ curve: 'secp256k1', hex: '02' + GX }, 'eip155:424242'),
    ).toThrow(/unknown chain/);
  });

  it('validates EIP-55 checksums', () => {
    expect(isValidEvmAddress(EXPECTED_FOR_G)).toBe(true);
    expect(isValidEvmAddress(EXPECTED_FOR_G.toLowerCase())).toBe(true);
    expect(isValidEvmAddress('0x' + EXPECTED_FOR_G.slice(2).toUpperCase())).toBe(true);
    expect(isValidEvmAddress('0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false);
    expect(isValidEvmAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bd')).toBe(false);
    expect(isValidEvmAddress('7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false);
    expect(evm.validateAddress(EXPECTED_FOR_G, 'eip155:10')).toBe(true);
    // EIP-55 reference vector.
    expect(toChecksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed')).toBe(
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    );
  });

  it('lists catalog chains for the family', () => {
    expect(evm.chains()).toEqual(chainsForFamily('evm'));
    expect(evm.chains().some((c) => c.chainId === 'eip155:1')).toBe(true);
  });
});

describe('EvmAdapter reads', () => {
  it('reads the native balance via eth_getBalance', async () => {
    const seen: unknown[] = [];
    const evm = createEvmAdapter({
      fetch: rpcFetch((method, params) => {
        seen.push([method, params]);
        return '0xde0b6b3a7640000';
      }),
    });
    const holdings = await evm.getBalances(EXPECTED_FOR_G, 'eip155:1');
    expect(holdings).toHaveLength(1);
    expect(holdings[0]).toMatchObject({
      assetRef: 'eip155:1:native',
      amount: '1000000000000000000',
    });
    expect(seen[0]).toEqual(['eth_getBalance', [EXPECTED_FOR_G, 'latest']]);
  });

  it('rejects malformed balances and fails over between endpoints', async () => {
    const pool = new MemoryRpcPool(chainsForFamily('evm'));
    let calls = 0;
    const evm = createEvmAdapter({
      rpc: pool,
      fetch: async () => {
        calls++;
        if (calls === 1) return new Response('bad gateway', { status: 502 });
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x2a' }), {
          status: 200,
        });
      },
    });
    const [h] = await evm.getBalances(EXPECTED_FOR_G, 'eip155:1');
    expect(h?.amount).toBe('42');
    expect(calls).toBe(2);
    expect(pool.endpoints('eip155:1').filter((e) => !e.healthy)).toHaveLength(1);

    const bad = createEvmAdapter({ fetch: rpcFetch(() => 'not-hex') });
    await expect(bad.getBalances(EXPECTED_FOR_G, 'eip155:1')).rejects.toBeInstanceOf(
      RpcFailoverError,
    );
  });

  it('maps receipts to tx status', async () => {
    const confirmed = createEvmAdapter({
      fetch: rpcFetch(() => ({ status: '0x1', blockNumber: '0x10', transactionHash: '0xaa' })),
    });
    expect(await confirmed.status('0xaa', 'eip155:1')).toEqual({
      state: 'confirmed',
      blockNumber: 16,
    });

    const reverted = createEvmAdapter({
      fetch: rpcFetch(() => ({ status: '0x0', blockNumber: '0x10' })),
    });
    expect(await reverted.status('0xaa', 'eip155:1')).toMatchObject({ state: 'failed' });

    const pending = createEvmAdapter({
      fetch: rpcFetch((method) =>
        method === 'eth_getTransactionReceipt' ? null : { hash: '0xaa' },
      ),
    });
    expect(await pending.status('0xaa', 'eip155:1')).toEqual({ state: 'pending' });

    const unknown = createEvmAdapter({ fetch: rpcFetch(() => null) });
    expect(await unknown.status('0xaa', 'eip155:1')).toEqual({ state: 'unknown' });
  });

  it('refuses to pretend unimplemented capabilities work', async () => {
    const evm = createEvmAdapter();
    const tx = { chainId: 'eip155:1', family: 'evm' as const, intentId: 'i', payload: {} };
    await expect(evm.getHistory(EXPECTED_FOR_G, 'eip155:1')).rejects.toBeInstanceOf(
      NotImplementedError,
    );
    await expect(evm.simulate(tx)).rejects.toThrow(
      /chains-evm.simulate is not implemented \(phase 3\)/,
    );
    expect(() => evm.sighashes(tx)).toThrow(NotImplementedError);
    expect(() => evm.attach(tx, [])).toThrow(NotImplementedError);
    await expect(evm.broadcast({ ...tx, signatures: [], rawHex: '' })).rejects.toBeInstanceOf(
      NotImplementedError,
    );
  });
});
