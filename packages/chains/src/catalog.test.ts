import { ChainId, chainFamilyOf } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { CHAIN_CATALOG, catalogChain, chainsForFamily } from './catalog.js';
import { ChainInfo } from './types.js';

describe('CHAIN_CATALOG', () => {
  it('parses every entry against ChainInfo', () => {
    for (const entry of CHAIN_CATALOG) {
      const parsed = ChainInfo.safeParse(entry);
      expect(parsed.success, `${entry.chainId}: ${JSON.stringify(parsed.error?.issues)}`).toBe(
        true,
      );
    }
  });

  it('has unique CAIP-2 chain ids whose namespace matches the family', () => {
    const seen = new Set<string>();
    for (const entry of CHAIN_CATALOG) {
      expect(seen.has(entry.chainId), `duplicate ${entry.chainId}`).toBe(false);
      seen.add(entry.chainId);
      expect(ChainId.safeParse(entry.chainId).success, entry.chainId).toBe(true);
      expect(chainFamilyOf(entry.chainId)).toBe(entry.family);
    }
  });

  it('uses https for every default endpoint and a {hash} explorer template', () => {
    for (const entry of CHAIN_CATALOG) {
      for (const url of entry.defaultRpcs) {
        expect(url.startsWith('https://'), `${entry.chainId} ${url}`).toBe(true);
      }
      expect(entry.explorerTxUrl, entry.chainId).toContain('{hash}');
      expect(entry.nativeAsset.ref).toBe(`${entry.chainId}:native`);
    }
  });

  it('carries the family-specific extras adapters depend on', () => {
    for (const c of chainsForFamily('cosmos')) {
      expect(c.extra?.bech32Prefix, c.chainId).toBeTruthy();
      expect(c.extra?.baseDenom, c.chainId).toBeTruthy();
      expect(c.extra?.addressAlgo, c.chainId).toBeTruthy();
    }
    for (const c of chainsForFamily('bitcoin')) {
      expect(c.extra?.p2pkhVersion, c.chainId).toBeTypeOf('number');
      expect(c.extra?.p2shVersion, c.chainId).toBeTypeOf('number');
      if (c.extra?.segwit) expect(c.extra.bech32Prefix).toBeTruthy();
      expect(c.nativeAsset.decimals).toBe(8);
    }
    for (const c of chainsForFamily('solana')) expect(c.nativeAsset.decimals).toBe(9);
  });

  it('flags testnets and keeps well-known ids', () => {
    expect(catalogChain('eip155:11155111')?.testnet).toBe(true);
    expect(catalogChain('eip155:1')?.testnet).toBe(false);
    expect(catalogChain('bip122:000000000019d6689c085ae165831e93')?.name).toBe('Bitcoin');
    expect(catalogChain('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')?.testnet).toBe(false);
    expect(catalogChain('cosmos:injective-1')?.extra?.addressAlgo).toBe('ethsecp256k1');
    expect(catalogChain('cosmos:dydx-mainnet-1')?.extra?.addressAlgo).toBe('secp256k1');
    expect(chainsForFamily('evm').length).toBeGreaterThanOrEqual(30);
  });
});
