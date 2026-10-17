import type { ChainInfo } from './types.js';

/**
 * Only HTTPS endpoints are listed. The public full nodes are HTTP-only and
 * would be mixed-content-blocked from the web bundle anyway; reads, status
 * and broadcast all work through the explorer API (its mempool submit route
 * relays transactions to the network). Endpoints prove their network through
 * the height-1 block id fingerprint.
 */
export const ERGO: ChainInfo[] = [
  {
    chainId: 'ergo:mainnet',
    family: 'ergo',
    name: 'Ergo',
    nativeAsset: { ref: 'ergo:mainnet:native', symbol: 'ERG', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://explorer.ergoplatform.com/en/transactions/{hash}',
    defaultRpcs: ['https://api.ergoplatform.com'],
    extra: { coinType: 429 },
    layer: 'L1',
    priceId: 'ergo',
  },
  {
    chainId: 'ergo:testnet',
    family: 'ergo',
    name: 'Ergo Testnet',
    nativeAsset: { ref: 'ergo:testnet:native', symbol: 'ERG', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://testnet.ergoplatform.com/en/transactions/{hash}',
    defaultRpcs: ['https://api-testnet.ergoplatform.com'],
    extra: { coinType: 429 },
    layer: 'L1',
  },
];
