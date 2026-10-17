import type { ChainInfo } from './types.js';

/**
 * Node API lives at {base}/v3, middleware history at {base}/mdw/v3. Endpoints
 * prove their network via /v3/status network_id. CORS echoes the Origin and
 * preflights allow POST, so browser broadcasts work.
 */
export const AETERNITY: ChainInfo[] = [
  {
    chainId: 'aet:ae_mainnet',
    family: 'aeternity',
    name: 'Aeternity',
    nativeAsset: { ref: 'aet:ae_mainnet:native', symbol: 'AE', decimals: 18 },
    testnet: false,
    explorerTxUrl: 'https://aescan.io/transactions/{hash}',
    defaultRpcs: ['https://mainnet.aeternity.io'],
    extra: { coinType: 457 },
    layer: 'L1',
    priceId: 'aeternity',
  },
  {
    chainId: 'aet:ae_uat',
    family: 'aeternity',
    name: 'Aeternity Testnet',
    nativeAsset: { ref: 'aet:ae_uat:native', symbol: 'AE', decimals: 18 },
    testnet: true,
    explorerTxUrl: 'https://testnet.aescan.io/transactions/{hash}',
    defaultRpcs: ['https://testnet.aeternity.io'],
    extra: { coinType: 457 },
    layer: 'L1',
  },
];
