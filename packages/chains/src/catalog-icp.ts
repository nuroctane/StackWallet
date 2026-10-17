import type { ChainInfo } from './types.js';

/**
 * There is no public ICP testnet ledger; the boundary node proves mainnet
 * through the pinned root key served by /api/v2/status.
 */
export const ICP: ChainInfo[] = [
  {
    chainId: 'icp:00000000000000000000',
    family: 'icp',
    name: 'Internet Computer',
    nativeAsset: { ref: 'icp:00000000000000000000:native', symbol: 'ICP', decimals: 8 },
    testnet: false,
    explorerTxUrl: 'https://www.icpexplorer.org/#/tx/{hash}',
    defaultRpcs: ['https://icp-api.io', 'https://ic0.app', 'https://icp0.io'],
    extra: { coinType: 223 },
    layer: 'L1',
    priceId: 'internet-computer',
  },
];
