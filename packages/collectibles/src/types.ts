import type { ChainFamily, ChainId } from '@stackwallet/core-client';
import { z } from 'zod';

export const CollectibleStandard = z.enum([
  'erc721',
  'erc1155',
  'erc404',
  'spl-nft',
  'ordinal',
  'cw721',
  'other',
]);
export type CollectibleStandard = z.infer<typeof CollectibleStandard>;

/**
 * One collectible held by an account. Every string here came from an indexer
 * or from on-chain metadata anyone can write, so the UI treats all of it as
 * untrusted text and loads media only through `loadMedia`.
 */
export const Collectible = z.object({
  /** Stable key: `${chainId}:${contract}:${tokenId}`. */
  key: z.string().min(1).max(400),
  chainId: z.string().min(1),
  standard: CollectibleStandard,
  contract: z.string().min(1).max(128),
  tokenId: z.string().min(1).max(100),
  name: z.string().max(120),
  collection: z.string().max(120),
  /** https:, ipfs:, ar: or data:image URL; null when the token has no image. */
  image: z.string().max(100_000).nullable(),
  /** Decimal string; above 1 only for semi-fungible standards. */
  amount: z.string().regex(/^\d{1,40}$/),
  /** The indexer marked the collection as spam or unverified-suspicious. */
  suspicious: z.boolean(),
  source: z.string().min(1).max(64),
});
export type Collectible = z.infer<typeof Collectible>;

export interface CollectiblesPage {
  items: Collectible[];
  /** Opaque cursor for the next page; null at the end. */
  cursor: string | null;
}

export interface CollectibleAccount {
  family: ChainFamily;
  chainId: ChainId;
  address: string;
}

export interface CollectibleSource {
  id: string;
  appliesTo(account: CollectibleAccount): boolean;
  list(account: CollectibleAccount, cursor?: string | null): Promise<CollectiblesPage>;
}

/** Families or chains with no keyless indexer yet, and why; shown instead of an empty grid. */
export const UNSUPPORTED_REASON: Partial<Record<ChainFamily, string>> = {
  bitcoin: 'Ordinals need an indexer API key; they arrive with provider keys.',
  cosmos: 'No keyless Cosmos NFT indexer is reachable from the browser yet.',
};
