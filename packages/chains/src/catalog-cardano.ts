import type { ChainInfo } from './types.js';

/**
 * Two endpoint kinds per network, told apart by URL: `/ogmios` bases are Koios Ogmios JSON-RPC
 * (tip, protocol parameters, submit); the rest are Yoroi indexers (UTxOs, history, status). Koios
 * REST sends no CORS headers and Blockfrost needs a key, so neither is listed.
 */
function cardano(spec: {
  chainId: 'cip34:1-764824073' | 'cip34:0-1';
  name: string;
  explorer: string;
  rpcs: string[];
}): ChainInfo {
  const testnet = spec.chainId !== 'cip34:1-764824073';
  return {
    chainId: spec.chainId,
    family: 'cardano',
    name: spec.name,
    nativeAsset: { ref: `${spec.chainId}:native`, symbol: 'ADA', decimals: 6 },
    testnet,
    explorerTxUrl: `${spec.explorer}/transaction/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 1815 },
    layer: 'L1',
    ...(testnet ? {} : { priceId: 'cardano' }),
  };
}

export const CARDANO: ChainInfo[] = [
  cardano({
    chainId: 'cip34:1-764824073',
    name: 'Cardano',
    explorer: 'https://cardanoscan.io',
    rpcs: ['https://api.yoroiwallet.com/api', 'https://api.koios.rest/api/v1/ogmios'],
  }),
  cardano({
    chainId: 'cip34:0-1',
    name: 'Cardano Preprod',
    explorer: 'https://preprod.cardanoscan.io',
    rpcs: [
      'https://preprod-backend.yoroiwallet.com/api',
      'https://preprod.koios.rest/api/v1/ogmios',
    ],
  }),
];
