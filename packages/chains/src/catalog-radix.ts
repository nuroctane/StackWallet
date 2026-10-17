import type { ChainInfo } from './types.js';

/**
 * The gateway proves its network through /status/gateway-status ledger_state.network.
 * `networkId` is the Babylon network byte; the Radix Wallet puts it in the third
 * level of its CAP-26 derivation path, so the same phrase derives different keys
 * on mainnet and Stokenet.
 */
function radix(spec: {
  ref: string;
  name: string;
  networkId: number;
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
    extra: { coinType: 1022, networkId: spec.networkId },
    layer: 'L1',
    ...(spec.priceId ? { priceId: spec.priceId } : {}),
  };
}

export const RADIX: ChainInfo[] = [
  radix({
    ref: 'mainnet',
    name: 'Radix',
    networkId: 1,
    testnet: false,
    explorer: 'https://dashboard.radixdlt.com',
    rpcs: ['https://mainnet.radixdlt.com'],
    priceId: 'radix',
  }),
  radix({
    ref: 'stokenet',
    name: 'Radix Stokenet',
    networkId: 2,
    testnet: true,
    explorer: 'https://stokenet-dashboard.radixdlt.com',
    rpcs: ['https://stokenet.radixdlt.com'],
  }),
];
