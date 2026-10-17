import type { ChainInfo } from './types.js';

/** API bases plus explorer RPCs (urls ending in /explorer); one operator, single provenance. */
function hyperliquid(spec: {
  ref: string;
  name: string;
  testnet: boolean;
  explorer: string;
  rpcs: string[];
}): ChainInfo {
  const chainId = `hype:${spec.ref}`;
  return {
    chainId,
    family: 'hyperliquid',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'USDC', decimals: 6 },
    testnet: spec.testnet,
    explorerTxUrl: `${spec.explorer}/explorer/tx/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 60 },
    layer: 'L1',
    ...(spec.testnet ? {} : { priceId: 'usd-coin' }),
  };
}

export const HYPERLIQUID: ChainInfo[] = [
  hyperliquid({
    ref: 'mainnet',
    name: 'Hyperliquid',
    testnet: false,
    explorer: 'https://app.hyperliquid.xyz',
    rpcs: ['https://api.hyperliquid.xyz', 'https://rpc.hyperliquid.xyz/explorer'],
  }),
  hyperliquid({
    ref: 'testnet',
    name: 'Hyperliquid Testnet',
    testnet: true,
    explorer: 'https://app.hyperliquid-testnet.xyz',
    rpcs: ['https://api.hyperliquid-testnet.xyz', 'https://rpc.hyperliquid-testnet.xyz/explorer'],
  }),
];
