import type { ChainInfo } from './types.js';

/**
 * Qubic runs a single mainnet (weekly epochs, no public testnet), so it is
 * also the signing network: a deliberate exception, since there is no testnet
 * to gate on. `rpc.qubic.org` is the only keyless public endpoint, so balance
 * provenance is always `single`. Amounts are whole QU (0 decimals) and
 * transfers are fee-free.
 */
export const QUBIC: ChainInfo[] = [
  {
    chainId: 'qubic:mainnet',
    family: 'qubic',
    name: 'Qubic',
    nativeAsset: { ref: 'qubic:mainnet:native', symbol: 'QU', decimals: 0 },
    testnet: false,
    defaultRpcs: ['https://rpc.qubic.org'],
    explorerTxUrl: 'https://explorer.qubic.org/tx/{hash}',
    extra: { coinType: 83293 },
    layer: 'L1',
    priceId: 'qubic-network',
  },
];
