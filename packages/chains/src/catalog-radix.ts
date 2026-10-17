import type { ChainInfo } from './types.js';

/** The gateway proves its network through /status/gateway-status ledger_state.network. */
function radix(spec: {
  ref: string;
  name: string;
  testnet: boolean;
  explorer: string;
  rpcs: string[];
  priceId?: string;
}): ChainInfo {
  const chainId = `radix:${spec.ref}`;
  return {
    chainId,
    family: 'radix',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'XRD', decimals: 18 },
    testnet: spec.testnet,
    explorerTxUrl: `${spec.explorer}/transaction/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 1022 },
    layer: 'L1',
    ...(spec.priceId ? { priceId: spec.priceId } : {}),
  };
}

export const RADIX: ChainInfo[] = [
  radix({
    ref: 'mainnet',
    name: 'Radix',
    testnet: false,
    explorer: 'https://dashboard.radixdlt.com',
    rpcs: ['https://mainnet.radixdlt.com'],
    priceId: 'radix',
  }),
  radix({
    ref: 'stokenet',
    name: 'Radix Stokenet',
    testnet: true,
    explorer: 'https://stokenet-dashboard.radixdlt.com',
    rpcs: ['https://stokenet.radixdlt.com'],
  }),
];
