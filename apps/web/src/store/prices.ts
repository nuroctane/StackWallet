import { useEffect, useSyncExternalStore } from 'react';
import { fetchQuotes, type MarketSource, type Quote, type QuoteResult } from '@stackwallet/market';

import { chainlinkStore } from './chainlink.js';
import { marketClient } from './market.js';

/**
 * USD quotes, in memory only, asked for by coin id when a view needs them and
 * refreshed when older than the TTL. Each quote names its sources and whether
 * they agree. A failed source keeps the previous answer, which ages into
 * stale rather than being replaced by an invented value.
 */
export const PRICE_TTL_MS = 2 * 60 * 1000;

class PriceStore {
  private prices = new Map<string, Quote>();
  private pending = false;
  private wanted = new Set<string>();
  private listeners = new Set<() => void>();
  private version = 0;
  errors: { source: MarketSource; message: string }[] = [];

  constructor(
    private readonly fetcher: (ids: string[]) => Promise<QuoteResult> = (ids) =>
      fetchQuotes(marketClient, ids, Date.now, {
        chainlink: (want) => chainlinkStore.quotes(want),
      }),
    private readonly now: () => number = Date.now,
  ) {}

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  getVersion = () => this.version;

  get(id: string): Quote | undefined {
    return this.prices.get(id);
  }

  private due(): string[] {
    return [...this.wanted].filter((id) => {
      const p = this.prices.get(id);
      return !p || this.now() - p.fetchedAtMs > PRICE_TTL_MS;
    });
  }

  async want(ids: readonly string[]): Promise<void> {
    for (const id of ids) this.wanted.add(id);
    if (this.pending) return;
    let due = this.due();
    while (due.length > 0) {
      this.pending = true;
      try {
        const r = await this.fetcher(due);
        for (const q of r.quotes) this.prices.set(q.id, q);
        this.errors = r.errors;
      } catch (err) {
        this.errors = [
          { source: 'coingecko', message: err instanceof Error ? err.message : String(err) },
        ];
      } finally {
        this.pending = false;
        this.version += 1;
        for (const l of this.listeners) l();
      }
      // Ids asked for while the fetch was running; ids that just failed wait for the next ask.
      const next = this.due().filter((id) => !due.includes(id));
      due = next;
    }
  }

  /** Drop cached quotes so the next ask refetches (after a source setting changes). */
  clear(): void {
    this.prices.clear();
    this.version += 1;
    for (const l of this.listeners) l();
  }
}

export const priceStore = new PriceStore();
export { PriceStore };

export function usePrices(ids: readonly string[]): (id: string) => Quote | undefined {
  useSyncExternalStore(priceStore.subscribe, priceStore.getVersion, priceStore.getVersion);
  const key = [...new Set(ids)].sort().join(',');
  useEffect(() => {
    if (key) void priceStore.want(key.split(','));
  }, [key]);
  return (id) => priceStore.get(id);
}

export function usePriceErrors(): PriceStore['errors'] {
  useSyncExternalStore(priceStore.subscribe, priceStore.getVersion, priceStore.getVersion);
  return priceStore.errors;
}
