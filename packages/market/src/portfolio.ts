import { priceAt, type PricePoint } from './candles.js';
import { usdMicros } from './prices.js';

/**
 * Portfolio value over time, computed on this device from locally recorded
 * balance snapshots and public price history. Holdings are a step function
 * (the last snapshot at or before each moment); prices are the last known
 * point no older than the gap tolerance. A moment where an observed priced
 * asset has no usable price is marked incomplete rather than valued at zero.
 */

export interface Snapshot {
  t: number;
  assetRef: string;
  amount: string;
  decimals: number;
}

export interface ValuePoint {
  t: number;
  usd: number;
  complete: boolean;
}

export interface ValueSeries {
  points: ValuePoint[];
  /** Assets with snapshots but no market id (testnets, unknown coins). */
  unpricedAssets: string[];
}

export const MAX_VALUE_POINTS = 600;

export function valueSeries(
  snapshots: readonly Snapshot[],
  coinFor: (assetRef: string) => string | null,
  history: ReadonlyMap<string, readonly PricePoint[]>,
  range: { sinceMs: number; untilMs: number },
  maxGapMs: number,
): ValueSeries {
  const byAsset = new Map<string, Snapshot[]>();
  const unpriced = new Set<string>();
  for (const s of [...snapshots].sort((a, b) => a.t - b.t)) {
    if (!coinFor(s.assetRef)) {
      unpriced.add(s.assetRef);
      continue;
    }
    const list = byAsset.get(s.assetRef) ?? [];
    list.push(s);
    byAsset.set(s.assetRef, list);
  }
  const firstObserved = Math.min(...[...byAsset.values()].map((l) => (l[0] as Snapshot).t));

  const times = new Set<number>();
  for (const [ref] of byAsset) {
    for (const p of history.get(coinFor(ref) as string) ?? []) {
      if (p.t >= range.sinceMs && p.t <= range.untilMs && p.t >= firstObserved) times.add(p.t);
    }
  }
  for (const list of byAsset.values())
    for (const s of list) if (s.t >= range.sinceMs && s.t <= range.untilMs) times.add(s.t);

  let sorted = [...times].sort((a, b) => a - b);
  if (sorted.length > MAX_VALUE_POINTS) {
    const step = sorted.length / MAX_VALUE_POINTS;
    const sampled: number[] = [];
    for (let i = 0; i < MAX_VALUE_POINTS; i++) sampled.push(sorted[Math.floor(i * step)] as number);
    sampled.push(sorted.at(-1) as number);
    sorted = [...new Set(sampled)];
  }

  const points: ValuePoint[] = [];
  for (const t of sorted) {
    let micros = 0n;
    let complete = true;
    let any = false;
    for (const [ref, list] of byAsset) {
      const held = lastAtOrBefore(list, t);
      if (!held) continue;
      any = true;
      if (held.amount === '0') continue;
      const usd = priceAt(history.get(coinFor(ref) as string) ?? [], t, maxGapMs);
      if (usd === null) {
        complete = false;
        continue;
      }
      micros += usdMicros(held.amount, held.decimals, usd);
    }
    if (any) points.push({ t, usd: Number(micros) / 1e6, complete });
  }
  return { points, unpricedAssets: [...unpriced].sort() };
}

function lastAtOrBefore(list: readonly Snapshot[], t: number): Snapshot | undefined {
  let found: Snapshot | undefined;
  for (const s of list) {
    if (s.t > t) break;
    found = s;
  }
  return found;
}

export interface Holding {
  assetRef: string;
  symbol: string;
  amount: string;
  decimals: number;
  coinId: string | null;
}

export interface AllocationRow {
  assetRef: string;
  symbol: string;
  usdMicros: bigint;
  /** Share of the priced total, 0..1. */
  share: number;
}

export interface Allocation {
  rows: AllocationRow[];
  totalMicros: bigint;
  unpriced: string[];
}

export function allocation(
  holdings: readonly Holding[],
  priceOf: (coinId: string) => number | undefined,
): Allocation {
  const rows: AllocationRow[] = [];
  const unpriced: string[] = [];
  let total = 0n;
  for (const h of holdings) {
    if (h.amount === '0') continue;
    const usd = h.coinId ? priceOf(h.coinId) : undefined;
    if (usd === undefined) {
      unpriced.push(h.symbol);
      continue;
    }
    const m = usdMicros(h.amount, h.decimals, usd);
    total += m;
    rows.push({ assetRef: h.assetRef, symbol: h.symbol, usdMicros: m, share: 0 });
  }
  for (const r of rows) r.share = total > 0n ? Number((r.usdMicros * 10_000n) / total) / 10_000 : 0;
  rows.sort((a, b) => (a.usdMicros === b.usdMicros ? 0 : a.usdMicros > b.usdMicros ? -1 : 1));
  return { rows, totalMicros: total, unpriced };
}
