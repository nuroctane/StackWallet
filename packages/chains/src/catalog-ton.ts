import type { ChainInfo } from './types.js';

/**
 * toncenter v2 and tonapi bases; the adapter picks the dialect from the host and proves the
 * network through the masterchain zerostate root hash. The orbs gateway is left out: its testnet
 * route served stale mainnet state.
 */
function tonLike(spec: {
  chainId: string;
  name: string;
  testnet: boolean;
  explorerTxUrl: string;
  rpcs: string[];
  priceId?: string;
}): ChainInfo {
  return {
    chainId: spec.chainId,
    family: 'ton',
    name: spec.name,
    nativeAsset: { ref: `${spec.chainId}:native`, symbol: 'TON', decimals: 9 },
    testnet: spec.testnet,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 607 },
    layer: 'L1',
    ...(spec.priceId ? { priceId: spec.priceId } : {}),
  };
}

export const TON: ChainInfo[] = [
  tonLike({
    chainId: 'tvm:-239',
    name: 'TON',
    testnet: false,
    explorerTxUrl: 'https://tonviewer.com/transaction/{hash}',
    rpcs: ['https://toncenter.com/api/v2', 'https://tonapi.io/v2'],
    priceId: 'the-open-network',
  }),
  tonLike({
    chainId: 'tvm:-3',
    name: 'TON Testnet',
    testnet: true,
    explorerTxUrl: 'https://testnet.tonviewer.com/transaction/{hash}',
    rpcs: ['https://testnet.toncenter.com/api/v2', 'https://testnet.tonapi.io/v2'],
  }),
];
