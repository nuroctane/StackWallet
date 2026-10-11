export * from './types.js';
export * from './text.js';
export * from './blockscout.js';
export * from './solana.js';
export * from './media.js';

import type { ChainRegistry, FetchOptions } from '@stackwallet/chains';

import { blockscoutSource } from './blockscout.js';
import { solanaSource } from './solana.js';
import type { CollectibleSource } from './types.js';

export function defaultCollectibleSources(opts: {
  registry: ChainRegistry;
  fetchOptions?: FetchOptions;
}): CollectibleSource[] {
  return [blockscoutSource(opts), solanaSource(opts)];
}
