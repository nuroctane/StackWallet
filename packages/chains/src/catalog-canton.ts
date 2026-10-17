import type { ChainInfo } from './types.js';

/**
 * Canton scan APIs implement the official Splice OpenAPI, but every public SV
 * scan host answers 403 RBAC without CORS today (five probe rounds, both
 * networks), so reads only work where a keyless scan answers (a user's own
 * validator scan). Self-custodial transfers additionally require validator
 * node credentials for topology onboarding, so the family is read-only. No
 * explorer link is published: cantonscan is Cloudflare-challenged and its
 * update route is unverified.
 */
export const CANTON: ChainInfo[] = [
  {
    chainId: 'canton:mainnet',
    family: 'canton',
    name: 'Canton Network',
    nativeAsset: { ref: 'canton:mainnet:native', symbol: 'CC', decimals: 10 },
    testnet: false,
    defaultRpcs: [
      'https://scan.sv-1.global.canton.network.sync.global',
      'https://scan.sv-2.global.canton.network.digitalasset.com',
    ],
    extra: { coinType: 6767 },
    layer: 'L1',
    priceId: 'canton-network',
  },
  {
    chainId: 'canton:testnet',
    family: 'canton',
    name: 'Canton Testnet',
    nativeAsset: { ref: 'canton:testnet:native', symbol: 'CC', decimals: 10 },
    testnet: true,
    defaultRpcs: ['https://scan.sv-1.test.global.canton.network.sync.global'],
    extra: { coinType: 1 },
    layer: 'L1',
  },
];
