import type { ChainInfo } from './types.js';

/**
 * The Mixin kernel (self-custodial flow only; the Messenger/Safe APIs are
 * app-custodial by design). No public test kernel exists and
 * `kernel.mixin.dev` is the only HTTPS endpoint found, so reads are
 * single-sourced. No verified explorer. The reference is the first 16 hex of
 * the kernel network id.
 */
export const MIXIN: ChainInfo[] = [
  {
    chainId: 'mixin:74c6cdb7d51af570',
    family: 'mixin',
    name: 'Mixin Kernel',
    nativeAsset: { ref: 'mixin:74c6cdb7d51af570:native', symbol: 'XIN', decimals: 8 },
    testnet: false,
    defaultRpcs: ['https://kernel.mixin.dev'],
    extra: { coinType: 2365 },
    layer: 'L1',
    priceId: 'mixin',
  },
];
