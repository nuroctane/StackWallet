import { useEffect, useSyncExternalStore } from 'react';
import { fetchUsdPrices, type UsdPrice } from '@stackwallet/market';

/**
 * USD prices of native coins, in memory only. Asked for by id when a view
 * needs them, refreshed when older than the TTL; a failed fetch keeps the
 * previous answer and marks it stale rather than inventing a value.
 */
export const PRICE_TTL_MS = 5 * 60 * 1000;

class PriceStore {
  private prices = new Map<string, UsdPrice>();
  private pending = false;
  private wanted = new Set<string>();
  private listeners = new Set<() => void>();
  private version = 0;
  error: string | null = null;

  constructor(
    private readonly fetcher: (ids: string[]) => Promise<UsdPrice[]> = (ids) => fetchUsdPrices(ids),
    private readonly now: () => number = Date.now,
  ) {}

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  getVersion = () => this.version;

  get(id: string): UsdPrice | undefined {
    return this.prices.get(id);
  }

  async want(ids: readonly string[]): Promise<void> {
    for (const id of ids) this.wanted.add(id);
    const due = [...this.wanted].filter((id) => {
      const p = this.prices.get(id);
      return !p || this.now() - p.fetchedAtMs > PRICE_TTL_MS;
    });
    if (due.length === 0 || this.pending) return;
    this.pending = true;
    try {
      for (const p of await this.fetcher(due)) this.prices.set(p.id, p);
      this.error = null;
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    } finally {
      this.pending = false;
      this.version += 1;
      for (const l of this.listeners) l();
    }
  }
}

export const priceStore = new PriceStore();
export { PriceStore };

export function usePrices(ids: readonly string[]): (id: string) => UsdPrice | undefined {
  useSyncExternalStore(priceStore.subscribe, priceStore.getVersion, priceStore.getVersion);
  const key = [...new Set(ids)].sort().join(',');
  useEffect(() => {
    if (key) void priceStore.want(key.split(','));
  }, [key]);
  return (id) => priceStore.get(id);
}
