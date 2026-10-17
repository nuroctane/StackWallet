import { z } from 'zod';

import type { MarketClient, MarketSource } from './client.js';
import { COINGECKO_API } from './prices.js';

/**
 * USD quotes with provenance. Each enabled source is asked by coin id only;
 * the quote keeps every source's answer, and when two sources disagree by
 * more than `DIVERGENCE_PCT` the quote says so instead of silently picking one.
 */

export const DEFILLAMA_API = 'https://coins.llama.fi';
export const QUOTE_TTL_MS = 60_000;
export const DIVERGENCE_PCT = 2;

export type Confidence = 'single' | 'agreed' | 'divergent';

export interface SourcePrice {
  source: MarketSource;
  usd: number;
  /** The provider's own observation time when it gives one, else the fetch time. */
  observedAtMs: number;
}

export interface Quote {
  id: string;
  usd: number;
  /** CoinGecko's 24h change in percent; null when CoinGecko did not answer. */
  change24hPct: number | null;
  fetchedAtMs: number;
  sources: SourcePrice[];
  confidence: Confidence;
  /** Largest relative gap between sources, in percent. */
  spreadPct: number;
}

const COIN_ID = /^[a-z0-9-]{1,80}$/;
const Usd = z.number().finite().nonnegative().max(1e12);

const GeckoSimple = z.record(
  z.string().max(80),
  z.object({
    usd: Usd.optional(),
    usd_24h_change: z.number().finite().min(-100).max(1e6).nullable().optional(),
    last_updated_at: z.number().int().nonnegative().optional(),
  }),
);

const LlamaCurrent = z.object({
  coins: z.record(
    z.string().max(100),
    z.object({
      price: Usd,
      timestamp: z.number().int().nonnegative().optional(),
    }),
  ),
});

export function validIds(ids: readonly string[]): string[] {
  return [...new Set(ids)].filter((id) => COIN_ID.test(id)).sort();
}

export function parseGeckoSimple(
  raw: unknown,
  now: number,
): Map<string, { price: SourcePrice; change: number | null }> {
  const out = new Map<string, { price: SourcePrice; change: number | null }>();
  for (const [id, v] of Object.entries(GeckoSimple.parse(raw))) {
    if (v.usd === undefined || !COIN_ID.test(id)) continue;
    const observed = v.last_updated_at !== undefined ? v.last_updated_at * 1000 : now;
    out.set(id, {
      price: { source: 'coingecko', usd: v.usd, observedAtMs: Math.min(observed, now) },
      change: v.usd_24h_change ?? null,
    });
  }
  return out;
}

export function parseLlamaCurrent(raw: unknown, now: number): Map<string, SourcePrice> {
  const out = new Map<string, SourcePrice>();
  for (const [key, v] of Object.entries(LlamaCurrent.parse(raw).coins)) {
    if (!key.startsWith('coingecko:')) continue;
    const id = key.slice('coingecko:'.length);
    if (!COIN_ID.test(id)) continue;
    const observed = v.timestamp !== undefined ? v.timestamp * 1000 : now;
    out.set(id, { source: 'defillama', usd: v.price, observedAtMs: Math.min(observed, now) });
  }
  return out;
}

/** Merge per-source prices into one quote; the headline is the median of the sources. */
export function mergeQuote(
  id: string,
  sources: readonly SourcePrice[],
  change24hPct: number | null,
  fetchedAtMs: number,
): Quote | null {
  if (sources.length === 0) return null;
  const prices = sources.map((s) => s.usd).sort((a, b) => a - b);
  const mid = prices.length / 2;
  const usd =
    prices.length % 2 === 1
      ? (prices[Math.floor(mid)] as number)
      : ((prices[mid - 1] as number) + (prices[mid] as number)) / 2;
  const lo = prices[0] as number;
  const hi = prices[prices.length - 1] as number;
  const spreadPct = lo > 0 ? ((hi - lo) / lo) * 100 : hi > 0 ? Infinity : 0;
  const confidence: Confidence =
    sources.length === 1 ? 'single' : spreadPct > DIVERGENCE_PCT ? 'divergent' : 'agreed';
  return { id, usd, change24hPct, fetchedAtMs, sources: [...sources], confidence, spreadPct };
}

export interface QuoteResult {
  quotes: Quote[];
  /** Per-source failures, shown next to the quotes rather than hidden. */
  errors: { source: MarketSource; message: string }[];
}

export interface QuoteDeps {
  /**
   * On-chain Chainlink answers by coin id, supplied by the caller because the
   * reader needs an RPC pool the market package does not own. Only consulted
   * when the `chainlink` source is enabled.
   */
  chainlink?: (ids: readonly string[]) => Promise<Map<string, SourcePrice>>;
}

export async function fetchQuotes(
  client: MarketClient,
  ids: readonly string[],
  now: () => number = Date.now,
  deps: QuoteDeps = {},
): Promise<QuoteResult> {
  const unique = validIds(ids);
  const errors: QuoteResult['errors'] = [];
  if (unique.length === 0) return { quotes: [], errors };

  const gecko = client.isEnabled('coingecko')
    ? client
        .getJson(
          'coingecko',
          `${COINGECKO_API}/simple/price?ids=${unique.join(',')}&vs_currencies=usd&include_24hr_change=true&include_last_updated_at=true`,
          QUOTE_TTL_MS,
        )
        .then((raw) => parseGeckoSimple(raw, now()))
        .catch((err: unknown) => {
          errors.push({ source: 'coingecko', message: messageOf(err) });
          return null;
        })
    : Promise.resolve(null);
  const llama = client.isEnabled('defillama')
    ? client
        .getJson(
          'defillama',
          `${DEFILLAMA_API}/prices/current/${unique.map((id) => `coingecko:${id}`).join(',')}`,
          QUOTE_TTL_MS,
        )
        .then((raw) => parseLlamaCurrent(raw, now()))
        .catch((err: unknown) => {
          errors.push({ source: 'defillama', message: messageOf(err) });
          return null;
        })
    : Promise.resolve(null);

  const onchain =
    deps.chainlink && client.isEnabled('chainlink')
      ? deps.chainlink(unique).catch((err: unknown) => {
          errors.push({ source: 'chainlink', message: messageOf(err) });
          return null;
        })
      : Promise.resolve(null);

  const [g, l, c] = await Promise.all([gecko, llama, onchain]);
  const at = now();
  const quotes: Quote[] = [];
  for (const id of unique) {
    const sources: SourcePrice[] = [];
    const gq = g?.get(id);
    if (gq) sources.push(gq.price);
    const lq = l?.get(id);
    if (lq) sources.push(lq);
    const cq = c?.get(id);
    if (cq) sources.push(cq);
    const q = mergeQuote(id, sources, gq?.change ?? null, at);
    if (q) quotes.push(q);
  }
  return { quotes, errors };
}

export function messageOf(err: unknown): string {
  return (err instanceof Error ? err.message : String(err)).slice(0, 200);
}
