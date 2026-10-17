import type { ChainInfo } from './types.js';

/**
 * The seed endpoints are HTTPS but omit CORS headers (probed 2026-10-16), so
 * the web bundle cannot reach them; the desktop shell can. Barnard was
 * unreachable during the build — the wire format is pinned byte-exact against
 * the official SDK, and the network is proven via chain.info chain_id.
 */
export const STARCOIN: ChainInfo[] = [
  {
    chainId: 'starcoin:1',
    family: 'starcoin',
    name: 'Starcoin',
    nativeAsset: { ref: 'starcoin:1:native', symbol: 'STC', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://stcscan.io/main/transactions/detail/{hash}',
    defaultRpcs: ['https://main-seed.starcoin.org'],
    extra: { coinType: 101010 },
    layer: 'L1',
    priceId: 'starcoin',
  },
  {
    chainId: 'starcoin:251',
    family: 'starcoin',
    name: 'Starcoin Barnard Testnet',
    nativeAsset: { ref: 'starcoin:251:native', symbol: 'STC', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://stcscan.io/barnard/transactions/detail/{hash}',
    defaultRpcs: ['https://barnard-seed.starcoin.org'],
    extra: { coinType: 101010 },
    layer: 'L1',
  },
];
