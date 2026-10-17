import type { ChainInfo } from './types.js';

/** publicnode, drpc and cartridge; every endpoint proves its network through starknet_chainId. */
function starknet(spec: {
  ref: 'SN_MAIN' | 'SN_SEPOLIA';
  name: string;
  testnet: boolean;
  explorer: string;
  rpcs: string[];
}): ChainInfo {
  const chainId = `starknet:${spec.ref}`;
  return {
    chainId,
    family: 'starknet',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'STRK', decimals: 18 },
    testnet: spec.testnet,
    explorerTxUrl: `${spec.explorer}/tx/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 9004 },
    layer: 'L2',
    parent: 'Ethereum',
    ...(spec.testnet ? {} : { priceId: 'starknet' }),
  };
}

export const STARKNET: ChainInfo[] = [
  starknet({
    ref: 'SN_MAIN',
    name: 'Starknet',
    testnet: false,
    explorer: 'https://voyager.online',
    rpcs: [
      'https://starknet-rpc.publicnode.com',
      'https://starknet.drpc.org',
      'https://api.cartridge.gg/x/starknet/mainnet',
    ],
  }),
  starknet({
    ref: 'SN_SEPOLIA',
    name: 'Starknet Sepolia',
    testnet: true,
    explorer: 'https://sepolia.voyager.online',
    rpcs: [
      'https://starknet-sepolia-rpc.publicnode.com',
      'https://starknet-sepolia.drpc.org',
      'https://api.cartridge.gg/x/starknet/sepolia',
    ],
  }),
];
