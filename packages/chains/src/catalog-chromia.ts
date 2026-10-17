import type { ChainInfo } from './types.js';

/**
 * The CAIP-2 reference is the first 8 bytes of the economy chain's BRID, the
 * truncation Chromia deep links use. Endpoints prove the chain via
 * /config/{brid}/features (merkle v2) plus an FT4 query probe. The explorer
 * is an SPA whose transaction route is unverified (probed 2026-10-16).
 */
export const CHROMIA: ChainInfo[] = [
  {
    chainId: 'chromia:0x15c0ca99bee60a3b',
    family: 'chromia',
    name: 'Chromia',
    nativeAsset: { ref: 'chromia:0x15c0ca99bee60a3b:native', symbol: 'CHR', decimals: 6 },
    testnet: false,
    explorerTxUrl: 'https://explorer.chromia.com/transaction/{hash}',
    defaultRpcs: [
      'https://system.chromaway.com',
      'https://chromia.validatrium.club',
      'https://chromia.mainnet-system.nodeops.ninja',
      'https://chromia-api.hashkey.cloud',
    ],
    extra: { coinType: 60 },
    layer: 'L1',
    priceId: 'chromia',
  },
  {
    chainId: 'chromia:0x090bcd47149fbb66',
    family: 'chromia',
    name: 'Chromia Testnet',
    nativeAsset: { ref: 'chromia:0x090bcd47149fbb66:native', symbol: 'CHR', decimals: 6 },
    testnet: true,
    explorerTxUrl: 'https://explorer-testnet.chromia.com/transaction/{hash}',
    defaultRpcs: [
      'https://node0.testnet.chromia.com:7740',
      'https://node1.testnet.chromia.com:7740',
      'https://node2.testnet.chromia.com:7740',
    ],
    extra: { coinType: 60 },
    layer: 'L1',
  },
];
