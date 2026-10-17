import type { ChainInfo } from './types.js';

/**
 * No registered CAIP-2 namespace; the reference is the SDK network alias and
 * the block itself carries the numeric network id, which the adapter verifies
 * live. `keeta` confirmed as the CoinGecko id (2026-10-16). No SLIP-44 coin
 * type exists; 9797 is our unregistered choice.
 */
export const KEETA: ChainInfo[] = [
  {
    chainId: 'keeta:main',
    family: 'keeta',
    name: 'Keeta',
    nativeAsset: { ref: 'keeta:main:native', symbol: 'KTA', decimals: 18 },
    testnet: false,
    explorerTxUrl: 'https://explorer.keeta.com/block/{hash}',
    defaultRpcs: [
      'https://rep1.main.network.api.keeta.com/api',
      'https://rep2.main.network.api.keeta.com/api',
      'https://rep3.main.network.api.keeta.com/api',
      'https://rep4.main.network.api.keeta.com/api',
    ],
    extra: { coinType: 9797 },
    layer: 'L1',
    priceId: 'keeta',
  },
  {
    chainId: 'keeta:test',
    family: 'keeta',
    name: 'Keeta Test Network',
    nativeAsset: { ref: 'keeta:test:native', symbol: 'KTA', decimals: 18 },
    testnet: true,
    explorerTxUrl: 'https://explorer.test.keeta.com/block/{hash}',
    defaultRpcs: [
      'https://rep1.test.network.api.keeta.com/api',
      'https://rep2.test.network.api.keeta.com/api',
    ],
    extra: { coinType: 9797 },
    layer: 'L1',
  },
];
