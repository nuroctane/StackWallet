import type { ChainInfo } from './types.js';

/**
 * CAIP-2 references are the first 8 hex characters of each network's genesis
 * challenge. coinset.org serves the keyless full-node RPC with CORS `*` on
 * both networks; the network is proven via get_network_info.
 */
export const CHIA: ChainInfo[] = [
  {
    chainId: 'chia:ccd5bb71',
    family: 'chia',
    name: 'Chia',
    nativeAsset: { ref: 'chia:ccd5bb71:native', symbol: 'XCH', decimals: 12 },
    testnet: false,
    explorerTxUrl: 'https://xchscan.com/txns/{hash}',
    defaultRpcs: ['https://api.coinset.org'],
    extra: { coinType: 8444 },
    layer: 'L1',
    priceId: 'chia',
  },
  {
    chainId: 'chia:37a90eb5',
    family: 'chia',
    name: 'Chia Testnet11',
    nativeAsset: { ref: 'chia:37a90eb5:native', symbol: 'TXCH', decimals: 12 },
    testnet: true,
    explorerTxUrl: 'https://testnet11.spacescan.io/txns/{hash}',
    defaultRpcs: ['https://testnet11.api.coinset.org'],
    extra: { coinType: 8444 },
    layer: 'L1',
  },
];
