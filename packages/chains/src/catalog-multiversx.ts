import type { ChainInfo } from './types.js';

/** API (pi.*) and gateway (gateway.*) bases; the adapter tells them apart by hostname. */
function multiversx(spec: {
  ref: string;
  name: string;
  testnet: boolean;
  explorer: string;
  rpcs: string[];
}): ChainInfo {
  const chainId = `mvx:${spec.ref}`;
  return {
    chainId,
    family: 'multiversx',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'EGLD', decimals: 18 },
    testnet: spec.testnet,
    explorerTxUrl: `${spec.explorer}/transactions/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 508 },
    layer: 'L1',
    ...(spec.testnet ? {} : { priceId: 'elrond-erd-2' }),
  };
}

export const MULTIVERSX: ChainInfo[] = [
  multiversx({
    ref: '1',
    name: 'MultiversX',
    testnet: false,
    explorer: 'https://explorer.multiversx.com',
    rpcs: ['https://api.multiversx.com', 'https://gateway.multiversx.com'],
  }),
  multiversx({
    ref: 'D',
    name: 'MultiversX Devnet',
    testnet: true,
    explorer: 'https://devnet-explorer.multiversx.com',
    rpcs: ['https://devnet-api.multiversx.com', 'https://devnet-gateway.multiversx.com'],
  }),
];
