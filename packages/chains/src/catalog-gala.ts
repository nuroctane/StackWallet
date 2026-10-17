import type { ChainInfo } from './types.js';

/**
 * GalaChain is a Hyperledger Fabric appchain behind REST gateways; the
 * chaincode recovers the signer from the signature, so addresses are EIP-55
 * `eth|` refs on the plain EVM path. The explorer API has no by-hash route,
 * so no explorer link is published. Signing is testnet-gated.
 */
export const GALA: ChainInfo[] = [
  {
    chainId: 'gala:mainnet',
    family: 'gala',
    name: 'GalaChain',
    nativeAsset: { ref: 'gala:mainnet:native', symbol: 'GALA', decimals: 8 },
    testnet: false,
    defaultRpcs: ['https://gateway-mainnet.galachain.com'],
    extra: { coinType: 60 },
    layer: 'appchain',
    priceId: 'gala',
  },
  {
    chainId: 'gala:testnet',
    family: 'gala',
    name: 'GalaChain Testnet',
    nativeAsset: { ref: 'gala:testnet:native', symbol: 'GALA', decimals: 8 },
    testnet: true,
    defaultRpcs: ['https://gateway-testnet.galachain.com'],
    extra: { coinType: 60 },
    layer: 'appchain',
  },
];
