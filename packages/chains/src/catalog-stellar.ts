import type { ChainInfo } from './types.js';

/** Endpoints are Horizon REST bases; each proves its network through `network_passphrase`. */
function stellar(spec: {
  network: 'pubnet' | 'testnet';
  name: string;
  explorer: 'public' | 'testnet';
  rpcs: string[];
}): ChainInfo {
  const chainId = `stellar:${spec.network}`;
  const testnet = spec.network === 'testnet';
  return {
    chainId,
    family: 'stellar',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'XLM', decimals: 7 },
    testnet,
    explorerTxUrl: `https://stellar.expert/explorer/${spec.explorer}/tx/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 148 },
    layer: 'L1',
    ...(testnet ? {} : { priceId: 'stellar' }),
  };
}

export const STELLAR: ChainInfo[] = [
  stellar({
    network: 'pubnet',
    name: 'Stellar',
    explorer: 'public',
    rpcs: ['https://horizon.stellar.org', 'https://horizon.stellar.lobstr.co'],
  }),
  stellar({
    network: 'testnet',
    name: 'Stellar Testnet',
    explorer: 'testnet',
    rpcs: ['https://horizon-testnet.stellar.org'],
  }),
];
