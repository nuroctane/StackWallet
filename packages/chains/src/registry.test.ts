import { describe, expect, it } from 'vitest';

import { ChainRegistry } from './registry.js';
import type { ChainAdapter } from './types.js';

function fakeAdapter(family: ChainAdapter['family'], chainId: string): ChainAdapter {
  const notYet = () => Promise.reject(new Error('fake'));
  return {
    family,
    chains: () => [
      {
        chainId,
        family,
        name: `${family} test`,
        nativeAsset: { ref: `${chainId}:native`, symbol: 'X', decimals: 18 },
        testnet: true,
        defaultRpcs: [],
      },
    ],
    deriveAddress: () => '0x0',
    getBalances: notYet,
    getHistory: notYet,
    build: notYet,
    simulate: notYet,
    sighashes: () => [],
    attach: (tx, signatures) => ({ ...tx, signatures, rawHex: '' }),
    broadcast: notYet,
    status: notYet,
    rpc: { endpoints: () => [], setEndpoints: () => undefined },
  };
}

describe('ChainRegistry', () => {
  it('routes chain ids to the adapter for their namespace', () => {
    const r = new ChainRegistry()
      .register(fakeAdapter('evm', 'eip155:11155111'))
      .register(fakeAdapter('solana', 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'));
    expect(r.adapterFor('eip155:1').family).toBe('evm');
    expect(r.adapterFor('solana:anything').family).toBe('solana');
    expect(() => r.adapterFor('cosmos:osmosis-1')).toThrow(/no adapter/);
    expect(() => r.adapterFor('foo:bar')).toThrow(/unknown chain namespace/);
    expect(r.chains()).toHaveLength(2);
    expect(r.chainInfo('eip155:11155111')?.testnet).toBe(true);
  });

  it('refuses duplicate families', () => {
    const r = new ChainRegistry().register(fakeAdapter('evm', 'eip155:1'));
    expect(() => r.register(fakeAdapter('evm', 'eip155:10'))).toThrow(/already registered/);
  });
});
