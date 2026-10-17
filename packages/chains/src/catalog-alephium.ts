import type { ChainInfo } from './types.js';

/**
 * Node REST endpoints serve balances/UTXOs/status; the explorer backends
 * serve history. Endpoints prove their network via /infos/chain-params.
 */
export const ALEPHIUM: ChainInfo[] = [
  {
    chainId: 'alephium:0',
    family: 'alephium',
    name: 'Alephium',
    nativeAsset: { ref: 'alephium:0:native', symbol: 'ALPH', decimals: 18 },
    testnet: false,
    explorerTxUrl: 'https://explorer.alephium.org/transactions/{hash}',
    defaultRpcs: ['https://node.mainnet.alephium.org', 'https://backend.mainnet.alephium.org'],
    extra: { coinType: 1234 },
    layer: 'L1',
    priceId: 'alephium',
  },
  {
    chainId: 'alephium:1',
    family: 'alephium',
    name: 'Alephium Testnet',
    nativeAsset: { ref: 'alephium:1:native', symbol: 'ALPH', decimals: 18 },
    testnet: true,
    explorerTxUrl: 'https://testnet.alephium.org/transactions/{hash}',
    defaultRpcs: ['https://node.testnet.alephium.org', 'https://backend.testnet.alephium.org'],
    extra: { coinType: 1234 },
    layer: 'L1',
  },
];
