import type { ChainInfo } from './types.js';

/** JSON-RPC endpoints; each proves its network through the genesis hash in `status`. */
function near(spec: { network: 'mainnet' | 'testnet'; name: string; rpcs: string[] }): ChainInfo {
  const chainId = `near:${spec.network}`;
  const testnet = spec.network === 'testnet';
  return {
    chainId,
    family: 'near',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'NEAR', decimals: 24 },
    testnet,
    explorerTxUrl: testnet
      ? 'https://testnet.nearblocks.io/txns/{hash}'
      : 'https://nearblocks.io/txns/{hash}',
    defaultRpcs: spec.rpcs,
    extra: { coinType: 397 },
    layer: 'L1',
    ...(testnet ? {} : { priceId: 'near' }),
  };
}

export const NEAR: ChainInfo[] = [
  near({
    network: 'mainnet',
    name: 'NEAR',
    rpcs: [
      'https://free.rpc.fastnear.com',
      'https://rpc.mainnet.near.org',
      'https://near.drpc.org',
    ],
  }),
  near({
    network: 'testnet',
    name: 'NEAR Testnet',
    rpcs: [
      'https://test.rpc.fastnear.com',
      'https://rpc.testnet.near.org',
      'https://near-testnet.drpc.org',
    ],
  }),
];
