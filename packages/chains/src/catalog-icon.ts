import type { ChainInfo } from './types.js';

/** The node and tracker prove their network through the pinned block-1,000,000 hash anchor. */
function icon(spec: {
  ref: '1' | '2';
  name: string;
  testnet: boolean;
  explorer: string;
  rpcs: string[];
}): ChainInfo {
  const chainId = `icon:${spec.ref}`;
  return {
    chainId,
    family: 'icon',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'ICX', decimals: 18 },
    testnet: spec.testnet,
    explorerTxUrl: `${spec.explorer}/transaction/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 4801368 },
    layer: 'L1',
    ...(spec.testnet ? {} : { priceId: 'icon' }),
  };
}

export const ICON: ChainInfo[] = [
  icon({
    ref: '1',
    name: 'ICON',
    testnet: false,
    explorer: 'https://tracker.icon.community',
    rpcs: ['https://ctz.solidwallet.io/api/v3', 'https://api.icon.community/api/v3'],
  }),
  icon({
    ref: '2',
    name: 'ICON Lisbon',
    testnet: true,
    explorer: 'https://tracker.lisbon.icon.community',
    // Only known public Lisbon JSON-RPC route; was a Cloudflare 502 when last probed.
    rpcs: ['https://api.lisbon.icon.community/api/v3'],
  }),
];
