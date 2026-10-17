import type { ChainInfo } from './types.js';

/** Hiro is the only keyless Stacks API; every endpoint proves its network through /v2/info. */
function stacks(spec: {
  ref: string;
  name: string;
  testnet: boolean;
  chain: string;
  rpcs: string[];
}): ChainInfo {
  const chainId = `stacks:${spec.ref}`;
  return {
    chainId,
    family: 'stacks',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'STX', decimals: 6 },
    testnet: spec.testnet,
    explorerTxUrl: `https://explorer.hiro.so/txid/{hash}?chain=${spec.chain}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 5757 },
    layer: 'L2',
    parent: 'Bitcoin',
    ...(spec.testnet ? {} : { priceId: 'blockstack' }),
  };
}

export const STACKS: ChainInfo[] = [
  stacks({
    ref: '1',
    name: 'Stacks',
    testnet: false,
    chain: 'mainnet',
    rpcs: ['https://api.hiro.so'],
  }),
  stacks({
    ref: '2147483648',
    name: 'Stacks Testnet',
    testnet: true,
    chain: 'testnet',
    rpcs: ['https://api.testnet.hiro.so'],
  }),
];
