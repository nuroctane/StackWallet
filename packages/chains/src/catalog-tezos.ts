import type { ChainInfo } from './types.js';

/** Octez node RPC bases; TzKT indexers live in the adapter's network table. */
function tezos(spec: {
  ref: string;
  name: string;
  testnet: boolean;
  explorer: string;
  rpcs: string[];
  priceId?: string;
}): ChainInfo {
  const chainId = `tezos:${spec.ref}`;
  return {
    chainId,
    family: 'tezos',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'XTZ', decimals: 6 },
    testnet: spec.testnet,
    explorerTxUrl: `${spec.explorer}/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 1729 },
    layer: 'L1',
    ...(spec.priceId ? { priceId: spec.priceId } : {}),
  };
}

export const TEZOS: ChainInfo[] = [
  tezos({
    ref: 'NetXdQprcVkpaWU',
    name: 'Tezos',
    testnet: false,
    explorer: 'https://tzkt.io',
    rpcs: ['https://rpc.tzbeta.net', 'https://mainnet.smartpy.io', 'https://rpc.tzkt.io/mainnet'],
    priceId: 'tezos',
  }),
  tezos({
    ref: 'NetXsqzbfFenSTS',
    name: 'Tezos Shadownet',
    testnet: true,
    explorer: 'https://shadownet.tzkt.io',
    rpcs: ['https://rpc.shadownet.teztnets.com', 'https://rpc.tzkt.io/shadownet'],
  }),
];
