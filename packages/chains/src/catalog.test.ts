import { ChainId, chainFamilyOf } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { CHAIN_CATALOG, catalogChain, chainsForFamily, LLAMA_UNSUPPORTED } from './catalog.js';
import { CURATED_CATALOG } from './catalog-curated.js';
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
      if (entry.explorerTxUrl !== undefined) {
        expect(entry.explorerTxUrl, entry.chainId).toContain('{hash}');
        expect(entry.explorerTxUrl.startsWith('https://'), entry.chainId).toBe(true);
      }
      expect(new Set(entry.defaultRpcs).size, entry.chainId).toBe(entry.defaultRpcs.length);
      expect(entry.nativeAsset.ref).toBe(`${entry.chainId}:native`);
    }
  });

  it('keeps an explorer for every curated chain', () => {
    // No public explorer for these looks extrinsics up by hash (Subscan dropped them).
    const noHashExplorer = new Set([
      'polkadot:2f0555cc76fc2840a25a6ea3b9637146',
      'polkadot:fc41b9bd8ef8fe53d58c7ea67c794c7e',
      'polkadot:baf5aabe40646d11f0ee8abbdc64f4a4',
      'polkadot:7e4e32d0feafd4f9c9414b0be86373f9',
      'polkadot:8b8c140b0af9db70686583e3f6bf2a59',
      // No public explorer indexes these Bitcoin-fork testnets at all.
      'btcfork:bch-testnet',
      'btcfork:zcash-testnet',
      'btcfork:defichain-testnet',
      'btcfork:verus-testnet',
      // GalaChain's explorer API has no by-hash route; Mixin has no verified explorer.
      'gala:mainnet',
      'gala:testnet',
      'mixin:74c6cdb7d51af570',
      // Canton's only explorer is Cloudflare-challenged and its update route is unverified.
      'canton:mainnet',
      'canton:testnet',
      // The Namada mainnet explorer does not index Housefire.
      'namada:cc0d3e0c033be',
    ]);
    for (const entry of CURATED_CATALOG)
      expect(Boolean(entry.explorerTxUrl), entry.chainId).toBe(!noHashExplorer.has(entry.chainId));
  });

  it('lets curated entries win over generated ones', () => {
    for (const curated of CURATED_CATALOG) {
      const merged = catalogChain(curated.chainId);
      expect(merged?.name, curated.chainId).toBe(curated.name);
      expect(merged?.defaultRpcs, curated.chainId).toEqual(curated.defaultRpcs);
    }
  });

  it('prices native assets by CoinGecko id, never on testnets', () => {
    expect(catalogChain('eip155:1')?.priceId).toBe('ethereum');
    expect(catalogChain('bip122:000000000019d6689c085ae165831e93')?.priceId).toBe('bitcoin');
    for (const c of CHAIN_CATALOG) if (c.testnet) expect(c.priceId, c.chainId).toBeUndefined();
  });

  it('covers every DefiLlama chain an existing family can serve', () => {
    expect(chainsForFamily('evm').length).toBeGreaterThanOrEqual(250);
    expect(chainsForFamily('cosmos').length).toBeGreaterThanOrEqual(35);
    expect(chainsForFamily('solana').length).toBeGreaterThanOrEqual(5);
    for (const name of ['Solana', 'Bitcoin', 'Ethereum', 'Base', 'CosmosHub'])
      expect(LLAMA_UNSUPPORTED, name).not.toContain(name);
    expect(catalogChain('eip155:8453')?.layer).toBe('L2');
    expect(catalogChain('eip155:8453')?.parent).toBe('Ethereum');
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
