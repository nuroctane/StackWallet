import { useSyncExternalStore } from 'react';
import { MarketClient, type SourceSettings } from '@stackwallet/market';
import { z } from 'zod';

import type { StorageLike } from './persist.js';

/**
 * Which keyless market sources this device may contact, and the user's
 * watchlist. Both are public metadata in local storage. CoinGecko is on by
 * default because totals already use it; DefiLlama is an opt-in cross-check,
 * since every extra provider also learns which coins are being looked at.
 */
export const MARKET_SETTINGS_KEY = 'stackwallet.market.v1';
export const WATCHLIST_KEY = 'stackwallet.watchlist.v1';
export const MAX_WATCHLIST = 50;

export const MarketSettings = z.object({
  coingecko: z.boolean(),
  defillama: z.boolean(),
  // Default-filled so settings saved before Chainlink existed survive an upgrade.
  chainlink: z.boolean().default(true),
});
export type MarketSettings = z.infer<typeof MarketSettings>;
export const DEFAULT_MARKET_SETTINGS: MarketSettings = {
  coingecko: true,
  defillama: false,
  // On-chain reads through the user's own EVM endpoints name a feed contract,
  // never an address, so Chainlink is on unless the user turns it off.
  chainlink: true,
};

export const WatchItem = z.object({
  id: z.string().regex(/^[a-z0-9-]{1,80}$/),
  symbol: z.string().max(16),
  name: z.string().max(60),
});
export type WatchItem = z.infer<typeof WatchItem>;
const Watchlist = WatchItem.array().max(MAX_WATCHLIST);

class JsonStore<T> {
  private value: T;
  private listeners = new Set<() => void>();

  constructor(
    private readonly storage: StorageLike | null,
    private readonly key: string,
    private readonly schema: z.ZodType<T>,
    fallback: T,
  ) {
    this.value = fallback;
    try {
      const raw = storage?.getItem(key);
      if (raw) {
        const parsed = schema.safeParse(JSON.parse(raw));
        if (parsed.success) this.value = parsed.data;
      }
    } catch {
      // Unreadable storage falls back to the defaults for this session.
    }
  }

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  getSnapshot = () => this.value;

  set(next: T): void {
    this.value = this.schema.parse(next);
    try {
      this.storage?.setItem(this.key, JSON.stringify(this.value));
    } catch {
      // Kept in memory only.
    }
    for (const l of this.listeners) l();
  }
}

function safeStorage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export class MarketSettingsStore extends JsonStore<MarketSettings> {
  constructor(storage: StorageLike | null) {
    super(storage, MARKET_SETTINGS_KEY, MarketSettings, DEFAULT_MARKET_SETTINGS);
  }
  toggle(source: keyof MarketSettings, on: boolean): void {
    this.set({ ...this.getSnapshot(), [source]: on });
  }
}

export class WatchlistStore extends JsonStore<WatchItem[]> {
  constructor(storage: StorageLike | null) {
    super(storage, WATCHLIST_KEY, Watchlist, []);
  }
  add(item: WatchItem): boolean {
    const list = this.getSnapshot();
    if (list.some((w) => w.id === item.id) || list.length >= MAX_WATCHLIST) return false;
    this.set([...list, item]);
    return true;
  }
  remove(id: string): void {
    this.set(this.getSnapshot().filter((w) => w.id !== id));
  }
}

export const marketSettings = new MarketSettingsStore(safeStorage());
export const watchlist = new WatchlistStore(safeStorage());

export const marketClient = new MarketClient({
  enabled: (): SourceSettings => marketSettings.getSnapshot(),
});

export function useMarketSettings(): MarketSettings {
  return useSyncExternalStore(
    marketSettings.subscribe,
    marketSettings.getSnapshot,
    marketSettings.getSnapshot,
  );
}

export function useWatchlist(): WatchItem[] {
  return useSyncExternalStore(watchlist.subscribe, watchlist.getSnapshot, watchlist.getSnapshot);
}
