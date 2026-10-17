import type { ChainInfo } from './types.js';

/**
 * One public node per network, CORS `*` verified; the network is proven via
 * chainStatus ChainId. aelf has no keyless view endpoint: balance reads are
 * signed view calls from a well-known throwaway key (see the adapter docs).
 */
export const AELF: ChainInfo[] = [
  {
    chainId: 'aelf:AELF',
    family: 'aelf',
    name: 'aelf',
    nativeAsset: { ref: 'aelf:AELF:native', symbol: 'ELF', decimals: 8 },
    testnet: false,
    explorerTxUrl: 'https://aelfscan.io/AELF/tx/{hash}',
    defaultRpcs: ['https://aelf-public-node.aelf.io'],
    extra: { coinType: 1616 },
    layer: 'L1',
    priceId: 'aelf',
  },
  {
    chainId: 'aelf:tDVV',
    family: 'aelf',
    name: 'aelf Testnet',
    nativeAsset: { ref: 'aelf:tDVV:native', symbol: 'ELF', decimals: 8 },
    testnet: true,
    explorerTxUrl: 'https://aelfscan.io/tDVV/tx/{hash}',
    defaultRpcs: ['https://tdvv-public-node.aelf.io'],
    extra: { coinType: 1616 },
    layer: 'L1',
  },
];
