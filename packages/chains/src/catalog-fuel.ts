import type { ChainInfo } from './types.js';

/**
 * Single GraphQL endpoint per network, CORS `*` verified; the network is
 * proven via the chain consensusParameters chainId. Fuel's native asset is
 * bridged ETH with 9 decimals.
 */
export const FUEL: ChainInfo[] = [
  {
    chainId: 'fuel:9889',
    family: 'fuel',
    name: 'Fuel Ignition',
    nativeAsset: { ref: 'fuel:9889:native', symbol: 'ETH', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://app.fuel.network/transaction/{hash}',
    defaultRpcs: ['https://mainnet.fuel.network/v1/graphql'],
    extra: { coinType: 1179993420 },
    layer: 'L2',
    parent: 'Ethereum',
    priceId: 'ethereum',
  },
  {
    chainId: 'fuel:0',
    family: 'fuel',
    name: 'Fuel Sepolia Testnet',
    nativeAsset: { ref: 'fuel:0:native', symbol: 'ETH', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://app-testnet.fuel.network/transaction/{hash}',
    defaultRpcs: ['https://testnet.fuel.network/v1/graphql'],
    extra: { coinType: 1179993420 },
    layer: 'L2',
    parent: 'Ethereum',
  },
];
