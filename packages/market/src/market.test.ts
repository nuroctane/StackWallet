import { describe, expect, it } from 'vitest';

import { fetchCandles, parseHistory, parseOhlc, priceAt } from './candles.js';
import { MarketClient, RateLimitedError, SourceDisabledError } from './client.js';
import { allocation, valueSeries } from './portfolio.js';
import { fetchQuotes, mergeQuote, parseGeckoSimple, parseLlamaCurrent } from './quotes.js';
import { parseSearch, searchAssets } from './search.js';

type Handler = (url: string) => Response;

function harness(handler: Handler, enabled = { coingecko: true, defillama: true }) {
  const urls: string[] = [];
  let t = 1_000_000;
  const sleeps: number[] = [];
  const fetch = (async (u: RequestInfo | URL) => {
    urls.push(String(u));
    return handler(String(u));
  }) as typeof globalThis.fetch;
  const client = new MarketClient({
    enabled: () => enabled,
    fetchOptions: { fetch },
    now: () => t,
    sleep: async (ms) => {
      sleeps.push(ms);
      t += ms;
    },
  });
  return {
    client,
    urls,
    sleeps,
    advance: (ms: number) => {
      t += ms;
    },
    now: () => t,
  };
}

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status });

describe('market client', () => {
  it('caches per URL, shares in-flight requests and spaces a source', async () => {
    const h = harness(() => json({ ok: 1 }));
    const [a, b] = await Promise.all([
      h.client.getJson('coingecko', 'https://x/a', 60_000),
      h.client.getJson('coingecko', 'https://x/a', 60_000),
    ]);
    expect(a).toEqual(b);
    expect(h.urls).toHaveLength(1);
    await h.client.getJson('coingecko', 'https://x/a', 60_000);
    expect(h.urls).toHaveLength(1);
    await h.client.getJson('coingecko', 'https://x/b', 60_000);
    expect(h.urls).toHaveLength(2);
    expect(h.sleeps).toEqual([2_500]);
  });

  it('never contacts a disabled source and parks a rate-limited one', async () => {
    const off = harness(() => json({}), { coingecko: false, defillama: true });
    await expect(off.client.getJson('coingecko', 'https://x', 1)).rejects.toBeInstanceOf(
      SourceDisabledError,
    );
    expect(off.urls).toHaveLength(0);

    const limited = harness(() => json({ error: 'slow down' }, 429));
    await expect(limited.client.getJson('defillama', 'https://y', 1)).rejects.toBeInstanceOf(
      RateLimitedError,
    );
    await expect(limited.client.getJson('defillama', 'https://z', 1)).rejects.toBeInstanceOf(
      RateLimitedError,
    );
    expect(limited.urls).toHaveLength(1);
    limited.advance(61_000);
    await expect(limited.client.getJson('defillama', 'https://z', 1)).rejects.toBeInstanceOf(
      RateLimitedError,
    );
    expect(limited.urls).toHaveLength(2);
  });
});

describe('quotes', () => {
  it('parses both sources and caps provider times at now', () => {
    const g = parseGeckoSimple(
      { ethereum: { usd: 2000, usd_24h_change: -1.5, last_updated_at: 10 }, bad: {} },
      5_000,
    );
    expect(g.get('ethereum')).toEqual({
      price: { source: 'coingecko', usd: 2000, observedAtMs: 5_000 },
      change: -1.5,
    });
    expect(g.has('bad')).toBe(false);
    const l = parseLlamaCurrent(
      {
        coins: {
          'coingecko:bitcoin': { price: 60000, timestamp: 1 },
          'ethereum:0xabc': { price: 1 },
        },
      },
      5_000,
    );
    expect([...l.keys()]).toEqual(['bitcoin']);
    expect(() => parseGeckoSimple({ ethereum: { usd: -1 } }, 1)).toThrow();
  });

  it('flags sources that disagree instead of picking one', () => {
    const at = { observedAtMs: 1 };
    expect(mergeQuote('x', [], null, 1)).toBeNull();
    expect(mergeQuote('x', [{ source: 'coingecko', usd: 100, ...at }], null, 1)?.confidence).toBe(
      'single',
    );
    const agreed = mergeQuote(
      'x',
      [
        { source: 'coingecko', usd: 100, ...at },
        { source: 'defillama', usd: 101, ...at },
      ],
      null,
      1,
    );
    expect(agreed?.confidence).toBe('agreed');
    expect(agreed?.usd).toBe(100.5);
    const divergent = mergeQuote(
      'x',
      [
        { source: 'coingecko', usd: 100, ...at },
        { source: 'defillama', usd: 110, ...at },
      ],
      null,
      1,
    );
    expect(divergent?.confidence).toBe('divergent');
    expect(divergent?.spreadPct).toBeCloseTo(10);
  });

  it('asks each enabled source by coin id and reports a failing one', async () => {
    const h = harness((url) =>
      url.includes('coingecko.com')
        ? json({ ethereum: { usd: 2000, usd_24h_change: 3 } })
        : json({ error: 'down' }, 500),
    );
    const r = await fetchQuotes(h.client, ['ethereum', 'Not An Id', 'ethereum'], h.now);
    expect(h.urls[0]).toContain('ids=ethereum&');
    expect(h.urls[1]).toBe('https://coins.llama.fi/prices/current/coingecko:ethereum');
    expect(r.quotes).toHaveLength(1);
    expect(r.quotes[0]).toMatchObject({
      id: 'ethereum',
      usd: 2000,
      change24hPct: 3,
      confidence: 'single',
    });
    expect(r.errors.map((e) => e.source)).toEqual(['defillama']);
  });
});

describe('candles and history', () => {
  it('drops inconsistent and out-of-order candles and counts them', () => {
    const r = parseOhlc([
      [1000, 10, 12, 9, 11],
      [2000, 11, 10, 9, 11.5], // high below close
      [900, 11, 12, 10, 11], // goes back in time
      [3000, 11, 13, 10, 12],
      ['x', 1, 1, 1, 1],
    ]);
    expect(r.candles.map((c) => c.t)).toEqual([1000, 3000]);
    expect(r.dropped).toBe(3);
    expect(() => parseOhlc({ not: 'rows' })).toThrow();
  });

  it('requests only supported ranges and valid ids', async () => {
    const h = harness(() => json([[1, 1, 2, 0.5, 1.5]]));
    const set = await fetchCandles(h.client, 'bitcoin', 7, h.now);
    expect(h.urls[0]).toBe(
      'https://api.coingecko.com/api/v3/coins/bitcoin/ohlc?vs_currency=usd&days=7',
    );
    expect(set.candles).toHaveLength(1);
    await expect(fetchCandles(h.client, '../evil', 7)).rejects.toThrow();
    await expect(fetchCandles(h.client, 'bitcoin', 3 as never)).rejects.toThrow();
  });

  it('uses the last price at or before a moment and never a stale one', () => {
    const { points } = parseHistory({
      prices: [
        [100, 1],
        [200, 2],
        [150, 9],
        [300, 3],
      ],
    });
    expect(points.map((p) => p.t)).toEqual([100, 200, 300]);
    expect(priceAt(points, 99, 1_000)).toBeNull();
    expect(priceAt(points, 250, 1_000)).toBe(2);
    expect(priceAt(points, 250, 10)).toBeNull();
    expect(priceAt(points, 5_000, 1e9)).toBe(3);
  });
});

describe('portfolio', () => {
  const coinFor = (ref: string) => (ref === 'eth:native' ? 'ethereum' : null);

  it('values holdings as a step function and marks gaps incomplete', () => {
    const snapshots = [
      { t: 100, assetRef: 'eth:native', amount: '1000000000000000000', decimals: 18 },
      { t: 250, assetRef: 'eth:native', amount: '2000000000000000000', decimals: 18 },
      { t: 120, assetRef: 'sepolia:native', amount: '5', decimals: 18 },
    ];
    const history = new Map([
      [
        'ethereum',
        [
          { t: 50, usd: 1000 },
          { t: 200, usd: 1500 },
          { t: 300, usd: 2000 },
        ],
      ],
    ]);
    const s = valueSeries(snapshots, coinFor, history, { sinceMs: 0, untilMs: 1_000 }, 120);
    expect(s.unpricedAssets).toEqual(['sepolia:native']);
    expect(s.points).toEqual([
      { t: 100, usd: 1000, complete: true },
      { t: 200, usd: 1500, complete: true },
      { t: 250, usd: 3000, complete: true },
      { t: 300, usd: 4000, complete: true },
    ]);
    const gappy = valueSeries(snapshots, coinFor, history, { sinceMs: 0, untilMs: 1_000 }, 10);
    expect(gappy.points.find((p) => p.t === 250)).toEqual({ t: 250, usd: 0, complete: false });
  });

  it('splits allocation over priced holdings only', () => {
    const a = allocation(
      [
        {
          assetRef: 'a',
          symbol: 'ETH',
          amount: '1000000000000000000',
          decimals: 18,
          coinId: 'ethereum',
        },
        { assetRef: 'b', symbol: 'BTC', amount: '100000000', decimals: 8, coinId: 'bitcoin' },
        { assetRef: 'c', symbol: 'tETH', amount: '1', decimals: 18, coinId: null },
        { assetRef: 'd', symbol: 'SOL', amount: '0', decimals: 9, coinId: 'solana' },
      ],
      (id) => ({ ethereum: 1000, bitcoin: 3000 })[id],
    );
    expect(a.totalMicros).toBe(4_000_000_000n);
    expect(a.rows.map((r) => [r.symbol, r.share])).toEqual([
      ['BTC', 0.75],
      ['ETH', 0.25],
    ]);
    expect(a.unpriced).toEqual(['tETH']);
  });
});

describe('search', () => {
  it('cleans hostile names and skips short queries', async () => {
    const hits = parseSearch({
      coins: [
        { id: 'evil', name: 'Good\u202eliveCoin', symbol: 'ev\u200bl', market_cap_rank: null },
        { id: 'blank', name: '\u200b', symbol: 'X' },
      ],
    });
    expect(hits).toEqual([{ id: 'evil', name: 'GoodliveCoin', symbol: 'EVL', rank: null }]);
    const h = harness(() => json({ coins: [] }));
    expect(await searchAssets(h.client, 'a')).toEqual([]);
    expect(h.urls).toHaveLength(0);
    await searchAssets(h.client, 'sol ana');
    expect(h.urls[0]).toBe('https://api.coingecko.com/api/v3/search?query=sol%20ana');
  });
});
