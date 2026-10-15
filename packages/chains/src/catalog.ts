/**
 * Static chain catalog bundled with the app. User-added chains and endpoint
 * overrides layer on top at runtime; nothing here is fetched.
 *
 * Curated entries come first and win; generated entries (every DefiLlama chain
 * an existing family can serve, with endpoints verified when the file was
 * generated) fill in the rest. `CHAIN_META` adds DefiLlama's layer, parent and
 * price id to both.
 */
import type { ChainFamily } from '@stackwallet/core-client';

import { CURATED_CATALOG } from './catalog-curated.js';
import { CHAIN_META, GENERATED_COSMOS, GENERATED_EVM, GENERATED_SVM } from './catalog-generated.js';
import { mergeCatalog } from './catalog-merge.js';
import type { ChainInfo } from './types.js';

export { LLAMA_UNSUPPORTED } from './catalog-generated.js';

export const CHAIN_CATALOG: readonly ChainInfo[] = Object.freeze(
  mergeCatalog({
    curated: CURATED_CATALOG,
    evm: GENERATED_EVM,
    cosmos: GENERATED_COSMOS,
    svm: GENERATED_SVM,
    meta: CHAIN_META,
  }),
);

const BY_ID = new Map(CHAIN_CATALOG.map((c) => [c.chainId, c]));

export function chainsForFamily(family: ChainFamily): ChainInfo[] {
  return CHAIN_CATALOG.filter((c) => c.family === family);
}

export function catalogChain(chainId: string): ChainInfo | undefined {
  return BY_ID.get(chainId);
}
