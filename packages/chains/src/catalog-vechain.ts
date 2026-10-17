import type { ChainInfo } from './types.js';

/** CAIP-2 references are the last 16 bytes of the genesis block id (VeChain WalletConnect). */
function vechain(spec: {
  ref: string;
  name: string;
  testnet: boolean;
  explorerTxUrl: string;
  rpcs: string[];
}): ChainInfo {
  const chainId = `vechain:${spec.ref}`;
  return {
    chainId,
    family: 'vechain',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'VET', decimals: 18 },
    testnet: spec.testnet,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 818 },
    layer: 'L1',
    ...(spec.testnet ? {} : { priceId: 'vechain' }),
  };
}

export const VECHAIN: ChainInfo[] = [
  vechain({
    ref: 'b1ac3413d346d43539627e6be7ec1b4a',
    name: 'VeChain',
    testnet: false,
    explorerTxUrl: 'https://explore.vechain.org/transactions/{hash}',
    rpcs: [
      'https://mainnet.vechain.org',
      'https://mainnet.vecha.in',
      'https://node-mainnet.vechain.energy',
    ],
  }),
  vechain({
    ref: '87721b09ed2e15997f466536b20bb127',
    name: 'VeChain Testnet',
    testnet: true,
    explorerTxUrl: 'https://insight.vecha.in/#/test/txs/{hash}',
    rpcs: [
      'https://testnet.vechain.org',
      'https://testnet.vecha.in',
      'https://node-testnet.vechain.energy',
    ],
  }),
];
