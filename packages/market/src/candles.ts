import { z } from 'zod';

import type { MarketClient } from './client.js';
import { COINGECKO_API } from './prices.js';
import { validIds } from './quotes.js';

/**
 * OHLC candles and price history from CoinGecko's keyless endpoints. Rows
 * are untrusted: each one must be internally consistent (low ≤ open, close ≤
 * high), timestamps must be strictly increasing, and anything else is
 * dropped and counted so the chart can say how much it left out.
 */

/** Ranges CoinGecko's free OHLC endpoint accepts, in days. */
export const CANDLE_DAYS = [1, 7, 14, 30, 90, 180, 365] as const;
export type CandleDays = (typeof CANDLE_DAYS)[number];

export const CANDLE_TTL_MS = 5 * 60_000;
export const HISTORY_TTL_MS = 10 * 60_000;
const MAX_ROWS = 5000;

export interface Candle {
  t: number;
  o: number;
  h: number;
  l: number;
  c: number;
}

export interface CandleSet {
  id: string;
  days: CandleDays;
  candles: Candle[];
  dropped: number;
  fetchedAtMs: number;
}

const Num = z.number().finite().nonnegative().max(1e12);
const OhlcRow = z.tuple([z.number().int().nonnegative(), Num, Num, Num, Num]);
const OhlcResponse = z.array(z.unknown()).max(MAX_ROWS);

export function parseOhlc(raw: unknown): { candles: Candle[]; dropped: number } {
  const rows = OhlcResponse.parse(raw);
  const candles: Candle[] = [];
  let dropped = 0;
  for (const row of rows) {
    const r = OhlcRow.safeParse(row);
    if (!r.success) {
      dropped += 1;
      continue;
    }
    const [t, o, h, l, c] = r.data;
    const last = candles.at(-1);
    if (l > Math.min(o, c) || h < Math.max(o, c) || (last && t <= last.t)) {
      dropped += 1;
      continue;
    }
    candles.push({ t, o, h, l, c });
  }
  return { candles, dropped };
}

export async function fetchCandles(
  client: MarketClient,
  id: string,
  days: CandleDays,
  now: () => number = Date.now,
): Promise<CandleSet> {
  if (validIds([id]).length !== 1) throw new Error('not a coin id');
  if (!CANDLE_DAYS.includes(days)) throw new Error('unsupported candle range');
  const raw = await client.getJson(
    'coingecko',
    `${COINGECKO_API}/coins/${id}/ohlc?vs_currency=usd&days=${days}`,
    CANDLE_TTL_MS,
  );
  return { id, days, ...parseOhlc(raw), fetchedAtMs: now() };
}

export interface PricePoint {
  t: number;
  usd: number;
}

const HistoryResponse = z.object({
  prices: z.array(z.unknown()).max(MAX_ROWS * 2),
});
const HistoryRow = z.tuple([z.number().int().nonnegative(), Num]);

export function parseHistory(raw: unknown): { points: PricePoint[]; dropped: number } {
  const { prices } = HistoryResponse.parse(raw);
  const points: PricePoint[] = [];
  let dropped = 0;
  for (const row of prices) {
    const r = HistoryRow.safeParse(row);
    const last = points.at(-1);
    if (!r.success || (last && r.data[0] <= last.t)) {
      dropped += 1;
      continue;
    }
    points.push({ t: r.data[0], usd: r.data[1] });
  }
  return { points, dropped };
}

/** History ranges accepted for portfolio valuation, in days. */
export const HISTORY_DAYS = [1, 7, 30, 90, 365] as const;
export type HistoryDays = (typeof HISTORY_DAYS)[number];

export async function fetchHistory(
  client: MarketClient,
  id: string,
  days: HistoryDays,
): Promise<PricePoint[]> {
  if (validIds([id]).length !== 1) throw new Error('not a coin id');
  if (!HISTORY_DAYS.includes(days)) throw new Error('unsupported history range');
  const raw = await client.getJson(
    'coingecko',
    `${COINGECKO_API}/coins/${id}/market_chart?vs_currency=usd&days=${days}`,
    HISTORY_TTL_MS,
  );
  return parseHistory(raw).points;
}

/**
 * The price in force at `t`: the latest point at or before it, if that point
 * is no older than `maxAgeMs`. Values are never interpolated or extrapolated.
 */
export function priceAt(points: readonly PricePoint[], t: number, maxAgeMs: number): number | null {
  let lo = 0;
  let hi = points.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if ((points[mid] as PricePoint).t <= t) {
      found = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  if (found < 0) return null;
  const p = points[found] as PricePoint;
  return t - p.t <= maxAgeMs ? p.usd : null;
}
