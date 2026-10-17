import type { ChainInfo } from './types.js';

/**
 * CAIP-2 ids are the first 32 base64url characters of the genesis hash. `defaultRpcs` are algod
 * REST bases that must report the matching genesis; indexers live in the adapter's network table.
 */
function algorand(spec: {
  chainId: string;
  name: string;
  symbol: string;
  testnet: boolean;
  explorerTxUrl: string;
  rpcs: string[];
  priceId?: string;
}): ChainInfo {
  return {
    chainId: spec.chainId,
    family: 'algorand',
    name: spec.name,
    nativeAsset: { ref: `${spec.chainId}:native`, symbol: spec.symbol, decimals: 6 },
    testnet: spec.testnet,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 283 },
    layer: 'L1',
    ...(spec.priceId ? { priceId: spec.priceId } : {}),
  };
}

export const ALGORAND: ChainInfo[] = [
  algorand({
    chainId: 'algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k',
    name: 'Algorand',
    symbol: 'ALGO',
    testnet: false,
    explorerTxUrl: 'https://lora.algokit.io/mainnet/transaction/{hash}',
    rpcs: ['https://mainnet-api.algonode.cloud', 'https://mainnet-api.4160.nodely.dev'],
    priceId: 'algorand',
  }),
  algorand({
    chainId: 'algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe',
    name: 'Algorand Testnet',
    symbol: 'ALGO',
    testnet: true,
    explorerTxUrl: 'https://lora.algokit.io/testnet/transaction/{hash}',
    rpcs: ['https://testnet-api.algonode.cloud', 'https://testnet-api.4160.nodely.dev'],
  }),
  algorand({
    chainId: 'algorand:r20fSQI8gWe_kFZziNonSPCXLwcQmH_n',
    name: 'Voi Network',
    symbol: 'VOI',
    testnet: false,
    explorerTxUrl: 'https://voi.observer/explorer/transaction/{hash}',
    rpcs: ['https://mainnet-api.voi.nodely.dev'],
    priceId: 'voi-network',
  }),
];
