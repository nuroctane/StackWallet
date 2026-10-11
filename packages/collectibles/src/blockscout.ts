import { fetchJson, type FetchOptions } from '@stackwallet/chains';
import { z } from 'zod';

import { cleanText } from './text.js';
import type {
  Collectible,
  CollectibleAccount,
  CollectibleSource,
  CollectibleStandard,
  CollectiblesPage,
} from './types.js';

/**
 * Blockscout instances that answer the v2 NFT endpoint with CORS. Keyed by
 * EVM chain id; chains without a keyless instance are simply not covered.
 */
export const BLOCKSCOUT_HOSTS: Readonly<Record<string, string>> = {
  'eip155:1': 'https://eth.blockscout.com',
  'eip155:11155111': 'https://eth-sepolia.blockscout.com',
  'eip155:8453': 'https://base.blockscout.com',
  'eip155:84532': 'https://base-sepolia.blockscout.com',
  'eip155:42161': 'https://arbitrum.blockscout.com',
  'eip155:10': 'https://explorer.optimism.io',
  'eip155:137': 'https://polygon.blockscout.com',
  'eip155:324': 'https://zksync.blockscout.com',
  'eip155:42220': 'https://celo.blockscout.com',
  'eip155:130': 'https://unichain.blockscout.com',
  'eip155:57073': 'https://explorer.inkonchain.com',
  'eip155:34443': 'https://explorer.mode.network',
  'eip155:480': 'https://worldchain-mainnet.explorer.alchemy.com',
};

const Str = z.string().max(100_000).nullish();

const Item = z.object({
  id: z.string().max(100),
  image_url: Str,
  media_url: Str,
  metadata: z
    .object({ name: z.unknown().optional(), image: z.unknown().optional() })
    .passthrough()
    .nullish(),
  token: z.object({
    address_hash: z.string().max(64).optional(),
    address: z.string().max(64).optional(),
    name: z.string().max(400).nullish(),
    symbol: z.string().max(400).nullish(),
    type: z.string().max(32).nullish(),
    reputation: z.string().max(32).nullish(),
  }),
  token_type: z.string().max(32).nullish(),
  value: z.string().max(80).nullish(),
});

const Page = z.object({
  items: z.array(Item).max(200),
  next_page_params: z.record(z.string(), z.union([z.string(), z.number()])).nullish(),
});

function standardOf(t: string | null | undefined): CollectibleStandard {
  switch (t) {
    case 'ERC-721':
      return 'erc721';
    case 'ERC-1155':
      return 'erc1155';
    case 'ERC-404':
      return 'erc404';
    default:
      return 'other';
  }
}

const ADDR = /^0x[0-9a-fA-F]{40}$/;

export function parseBlockscoutPage(chainId: string, raw: unknown): CollectiblesPage {
  const page = Page.parse(raw);
  const items: Collectible[] = [];
  for (const it of page.items) {
    const contract = it.token.address_hash ?? it.token.address ?? '';
    if (!ADDR.test(contract) || !/^\d{1,80}$/.test(it.id)) continue;
    const metaImage = typeof it.metadata?.image === 'string' ? it.metadata.image : null;
    const image = it.image_url ?? it.media_url ?? metaImage ?? null;
    const amount = it.value && /^\d{1,40}$/.test(it.value) ? it.value : '1';
    const collection = cleanText(it.token.name ?? it.token.symbol ?? '') || 'unnamed collection';
    items.push({
      key: `${chainId}:${contract.toLowerCase()}:${it.id}`,
      chainId,
      standard: standardOf(it.token_type ?? it.token.type),
      contract,
      tokenId: it.id,
      name:
        cleanText(it.metadata?.name) || `#${it.id.length > 12 ? `${it.id.slice(0, 10)}…` : it.id}`,
      collection,
      image,
      amount,
      // Blockscout labels known spam collections; anything but "ok" is worth a warning.
      suspicious: it.token.reputation != null && it.token.reputation !== 'ok',
      source: 'blockscout',
    });
  }
  const next = page.next_page_params;
  return {
    items,
    cursor: next
      ? new URLSearchParams(Object.entries(next).map(([k, v]) => [k, String(v)])).toString()
      : null,
  };
}

export function blockscoutSource(opts: { fetchOptions?: FetchOptions } = {}): CollectibleSource {
  return {
    id: 'blockscout',
    appliesTo: (a: CollectibleAccount) =>
      a.family === 'evm' && a.chainId in BLOCKSCOUT_HOSTS && ADDR.test(a.address),
    async list(account, cursor) {
      const host = BLOCKSCOUT_HOSTS[account.chainId];
      if (!host) return { items: [], cursor: null };
      const qs = new URLSearchParams(cursor ?? '');
      qs.set('type', 'ERC-721,ERC-1155,ERC-404');
      const url = `${host}/api/v2/addresses/${account.address}/nft?${qs.toString()}`;
      return parseBlockscoutPage(account.chainId, await fetchJson(url, opts.fetchOptions));
    },
  };
}
