import type { ChainInfo } from './types.js';

/**
 * The endpoint proves its network through the key block's TVM global id, which is
 * also the CAIP-2 reference (Everscale 42, Venom 1 / testnet 1002).
 */
function everLike(spec: {
  chainId: string;
  name: string;
  symbol: 'EVER' | 'VENOM';
  testnet: boolean;
  explorerTxUrl: string;
  rpcs: string[];
  priceId?: string;
}): ChainInfo {
  return {
    chainId: spec.chainId,
    family: 'everscale',
    name: spec.name,
    nativeAsset: { ref: `${spec.chainId}:native`, symbol: spec.symbol, decimals: 9 },
    testnet: spec.testnet,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 396 },
    layer: 'L1',
    ...(spec.priceId ? { priceId: spec.priceId } : {}),
  };
}

export const EVERSCALE: ChainInfo[] = [
  everLike({
    chainId: 'ever:42',
    name: 'Everscale',
    symbol: 'EVER',
    testnet: false,
    explorerTxUrl: 'https://everscan.io/transactions/{hash}',
    rpcs: ['https://mainnet.evercloud.dev/graphql'],
    priceId: 'everscale',
  }),
  everLike({
    chainId: 'venom:1',
    name: 'Venom',
    symbol: 'VENOM',
    testnet: false,
    explorerTxUrl: 'https://venomscan.com/transactions/{hash}',
    rpcs: ['https://jrpc.venom.foundation'],
    priceId: 'venom',
  }),
  everLike({
    chainId: 'venom:1002',
    name: 'Venom Testnet',
    symbol: 'VENOM',
    testnet: true,
    explorerTxUrl: 'https://testnet.venomscan.com/transactions/{hash}',
    rpcs: ['https://jrpc-testnet.venom.foundation/rpc'],
  }),
];
