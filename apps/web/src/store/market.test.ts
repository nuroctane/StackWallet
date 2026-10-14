import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Quote, QuoteResult } from '@stackwallet/market';

import { AlertStore } from './alerts.js';
import {
  DEFAULT_MARKET_SETTINGS,
  MARKET_SETTINGS_KEY,
  MAX_WATCHLIST,
  MarketSettingsStore,
  WatchlistStore,
} from './market.js';
import { PriceStore, priceStore } from './prices.js';

function memory(seed: Record<string, string> = {}) {
  const m = new Map(Object.entries(seed));
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    m,
  };
}

const quote = (id: string, usd: number, at: number): Quote => ({
  id,
  usd,
  change24hPct: 1,
  fetchedAtMs: at,
  sources: [{ source: 'coingecko', usd, observedAtMs: at }],
  confidence: 'single',
  spreadPct: 0,
});

afterEach(() => vi.restoreAllMocks());

describe('market settings and watchlist', () => {
  it('defaults to CoinGecko only and persists toggles', () => {
    const s = memory();
    const a = new MarketSettingsStore(s);
    expect(a.getSnapshot()).toEqual(DEFAULT_MARKET_SETTINGS);
    a.toggle('defillama', true);
    expect(new MarketSettingsStore(s).getSnapshot()).toEqual({ coingecko: true, defillama: true });
  });

  it('ignores a corrupted settings blob', () => {
    const s = memory({ [MARKET_SETTINGS_KEY]: '{"coingecko":"yes"}' });
    expect(new MarketSettingsStore(s).getSnapshot()).toEqual(DEFAULT_MARKET_SETTINGS);
  });

  it('deduplicates and caps the watchlist and refuses malformed ids', () => {
    const w = new WatchlistStore(memory());
    expect(w.add({ id: 'bitcoin', symbol: 'BTC', name: 'Bitcoin' })).toBe(true);
    expect(w.add({ id: 'bitcoin', symbol: 'BTC', name: 'Bitcoin' })).toBe(false);
    expect(() => w.add({ id: '../x', symbol: 'X', name: 'x' })).toThrow();
    for (let i = 0; i < MAX_WATCHLIST + 5; i++) w.add({ id: `c${i}`, symbol: 'X', name: 'x' });
    expect(w.getSnapshot()).toHaveLength(MAX_WATCHLIST);
    w.remove('bitcoin');
    expect(w.getSnapshot().some((x) => x.id === 'bitcoin')).toBe(false);
  });
});

describe('price store', () => {
  it('fetches due ids, keeps per-source errors and fetches ids asked for mid-flight', async () => {
    let t = 0;
    const calls: string[][] = [];
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const store = new PriceStore(
      async (ids): Promise<QuoteResult> => {
        calls.push(ids);
        if (calls.length === 1) await gate;
        return {
          quotes: ids.map((id) => quote(id, 1, t)),
          errors: [{ source: 'defillama', message: 'down' }],
        };
      },
      () => t,
    );
    const first = store.want(['bitcoin']);
    void store.want(['ethereum']);
    release();
    await first;
    expect(calls).toEqual([['bitcoin'], ['ethereum']]);
    expect(store.get('ethereum')?.usd).toBe(1);
    expect(store.errors).toEqual([{ source: 'defillama', message: 'down' }]);
    await store.want(['bitcoin']);
    expect(calls).toHaveLength(2);
    t = 10 * 60_000;
    await store.want(['bitcoin']);
    expect(calls).toHaveLength(3);
  });
});

describe('alert store', () => {
  it('fires listeners once and persists the fired state', async () => {
    const s = memory();
    let now = 1_000;
    let n = 0;
    const store = new AlertStore(
      s,
      () => now,
      () => `id${++n}`,
    );
    expect(store.add('btc', { kind: 'price', coinId: 'bitcoin', op: 'above', usd: 100 })).toEqual({
      ok: true,
    });
    vi.spyOn(priceStore, 'want').mockResolvedValue();
    vi.spyOn(priceStore, 'get').mockImplementation((id) =>
      id === 'bitcoin' ? quote('bitcoin', 150, now) : undefined,
    );
    const heard: string[] = [];
    store.onFired((e, a) => heard.push(`${a.name}@${e.usd}`));
    expect(await store.check()).toHaveLength(1);
    now += 1;
    expect(await store.check()).toHaveLength(0);
    expect(heard).toEqual(['btc@150']);
    const reloaded = new AlertStore(s, () => now);
    expect(reloaded.getSnapshot().alerts[0]?.armed).toBe(false);
    expect(reloaded.getSnapshot().events).toHaveLength(1);
  });

  it('rejects invalid alerts', () => {
    const store = new AlertStore(memory());
    const r = store.add('x', { kind: 'price', coinId: 'bitcoin', op: 'above', usd: -1 });
    expect(r.ok).toBe(false);
  });
});
