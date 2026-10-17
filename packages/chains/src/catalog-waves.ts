import type { ChainInfo } from './types.js';

/** The node proves its network through the pinned height-1 block signature. */
function waves(spec: {
  ref: '84' | '87';
  name: string;
  testnet: boolean;
  explorer: string;
  rpcs: string[];
}): ChainInfo {
  const chainId = `waves:${spec.ref}`;
  return {
    chainId,
    family: 'waves',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'WAVES', decimals: 8 },
    testnet: spec.testnet,
    explorerTxUrl: `${spec.explorer}/tx/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 5741564 },
    layer: 'L1',
    ...(spec.testnet ? {} : { priceId: 'waves' }),
  };
}

export const WAVES: ChainInfo[] = [
  waves({
    ref: '87',
    name: 'Waves',
    testnet: false,
    explorer: 'https://wavesexplorer.com',
    rpcs: ['https://nodes.wavesnodes.com'],
  }),
  waves({
    ref: '84',
    name: 'Waves Testnet',
    testnet: true,
    explorer: 'https://testnet.wavesexplorer.com',
    // The only working public testnet node; balance provenance is single-source.
    rpcs: ['https://nodes-testnet.wavesnodes.com'],
  }),
];
