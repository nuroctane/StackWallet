import { z } from 'zod';

import type { MarketClient } from './client.js';
import { COINGECKO_API } from './prices.js';
import { cleanText } from './text.js';

/**
 * Asset search against CoinGecko, run only on an explicit query (the query
 * itself is what the provider learns). Names and symbols are untrusted text.
 */

export const SEARCH_TTL_MS = 10 * 60_000;
export const MAX_RESULTS = 25;

export interface AssetHit {
  id: string;
  name: string;
  symbol: string;
  rank: number | null;
}

const SearchResponse = z.object({
  coins: z
    .array(
      z.object({
        id: z.string().regex(/^[a-z0-9-]{1,80}$/),
        name: z.string().max(400),
        symbol: z.string().max(100),
        market_cap_rank: z.number().int().positive().nullable().optional(),
      }),
    )
    .max(1000),
});

export function parseSearch(raw: unknown): AssetHit[] {
  const out: AssetHit[] = [];
  for (const c of SearchResponse.parse(raw).coins.slice(0, MAX_RESULTS)) {
    const name = cleanText(c.name, 60);
    const symbol = cleanText(c.symbol, 16).toUpperCase();
    if (!name || !symbol) continue;
    out.push({ id: c.id, name, symbol, rank: c.market_cap_rank ?? null });
  }
  return out;
}

export async function searchAssets(client: MarketClient, query: string): Promise<AssetHit[]> {
  const q = cleanText(query, 60);
  if (q.length < 2) return [];
  const raw = await client.getJson(
    'coingecko',
    `${COINGECKO_API}/search?query=${encodeURIComponent(q)}`,
    SEARCH_TTL_MS,
  );
  return parseSearch(raw);
}
