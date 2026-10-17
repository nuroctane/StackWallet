import { MemoryRpcPool, type ChainRegistry } from '@stackwallet/chains';
import type { ChainlinkFeed, ChainlinkReader, ChainlinkTick } from '@stackwallet/market';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ChainlinkStore, chainlinkStore } from './chainlink.js';
import { marketSettings } from './market.js';

const FEED: ChainlinkFeed = {
  chainId: 'eip155:1',
  pair: 'ETH / USD',
  base: 'ETH',
  quote: 'USD',
  proxy: '0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419',
  decimals: 8,
  heartbeatSec: 3600,
  category: 'crypto',
};

const tick = (roundId: string, t: number, price = 3000): ChainlinkTick => ({
  roundId,
  t,
  price,
});

const registry = () => {
  const pool = new MemoryRpcPool([]);
  pool.setEndpoints('eip155:1', ['https://a.example']);
  return {
    pool,
    registry: { adapterFor: () => ({ rpc: pool }) } as unknown as ChainRegistry,
  };
};

function scripted(walks: { ticks: ChainlinkTick[]; exhausted: boolean }[]) {
  const calls: (string | undefined)[] = [];
  const reader = {
    roundsBack: vi.fn(async (_feed: ChainlinkFeed, _n: number, before?: string) => {
      calls.push(before);
      const next = walks.length > 1 ? walks.shift() : walks[0];
      return next ?? { ticks: [], exhausted: true };
    }),
    latest: vi.fn(),
  } as unknown as ChainlinkReader;
  return { reader, calls };
}

afterEach(() => {
  vi.restoreAllMocks();
  if (!marketSettings.getSnapshot().chainlink) marketSettings.toggle('chainlink', true);
});

describe('chainlink store', () => {
  it('syncs the newest rounds and exposes them ascending', async () => {
    const { registry: reg } = registry();
    const { reader, calls } = scripted([
      { ticks: [tick('5', 5000), tick('4', 4000), tick('3', 3000)], exhausted: false },
    ]);
    const store = new ChainlinkStore(() => reader);
    store.configure(reg);
    expect(store.available).toBe(true);
    await store.sync(FEED);
    const s = store.seriesFor(FEED);
    expect(s.error).toBeNull();
    expect(s.loading).toBe(false);
    expect(s.ticks.map((t) => t.roundId)).toEqual(['3', '4', '5']);
    expect(s.oldestRoundId).toBe('3');
    expect(calls).toEqual([undefined]);
  });

  it('backfills older pages and marks exhaustion', async () => {
    const { registry: reg } = registry();
    const { reader, calls } = scripted([
      { ticks: [tick('10', 10_000), tick('9', 9_000)], exhausted: false },
      { ticks: [tick('8', 8_000), tick('7', 7_000)], exhausted: true },
    ]);
    const store = new ChainlinkStore(() => reader);
    store.configure(reg);
    await store.sync(FEED);
    await store.backfill(FEED);
    const s = store.seriesFor(FEED);
    expect(s.ticks.map((t) => t.roundId)).toEqual(['7', '8', '9', '10']);
    expect(s.exhausted).toBe(true);
    expect(calls).toEqual([undefined, '9']);
    await store.backfill(FEED);
    expect(reader.roundsBack).toHaveBeenCalledTimes(2);
  });

  it('deduplicates rounds across overlapping pages', async () => {
    const { registry: reg } = registry();
    const { reader } = scripted([
      { ticks: [tick('5', 5000), tick('4', 4000)], exhausted: false },
      { ticks: [tick('4', 4000), tick('3', 3000)], exhausted: false },
    ]);
    const store = new ChainlinkStore(() => reader);
    store.configure(reg);
    await store.sync(FEED);
    await store.backfill(FEED);
    expect(store.seriesFor(FEED).ticks.map((t) => t.roundId)).toEqual(['3', '4', '5']);
  });

  it('shares a concurrent walk instead of doubling requests', async () => {
    const { registry: reg } = registry();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const reader = {
      roundsBack: vi.fn(async () => {
        await gate;
        return { ticks: [tick('2', 2000)], exhausted: false };
      }),
      latest: vi.fn(),
    } as unknown as ChainlinkReader;
    const store = new ChainlinkStore(() => reader);
    store.configure(reg);
    const a = store.sync(FEED);
    const b = store.sync(FEED);
    release();
    await Promise.all([a, b]);
    expect(reader.roundsBack).toHaveBeenCalledTimes(1);
  });

  it('records a read failure on the series instead of throwing', async () => {
    const { registry: reg } = registry();
    const reader = {
      roundsBack: vi.fn(async () => {
        throw new Error('all endpoints down');
      }),
      latest: vi.fn(),
    } as unknown as ChainlinkReader;
    const store = new ChainlinkStore(() => reader);
    store.configure(reg);
    await store.sync(FEED);
    const s = store.seriesFor(FEED);
    expect(s.loading).toBe(false);
    expect(s.error).toBe('all endpoints down');
    expect(s.ticks).toEqual([]);
  });

  it('does not walk while the source is turned off', async () => {
    const { registry: reg } = registry();
    const { reader } = scripted([{ ticks: [tick('1', 1000)], exhausted: false }]);
    const store = new ChainlinkStore(() => reader);
    store.configure(reg);
    marketSettings.toggle('chainlink', false);
    await store.sync(FEED);
    await store.backfill(FEED);
    expect(reader.roundsBack).not.toHaveBeenCalled();
  });

  it('answers quotes only for coins with a feed', async () => {
    const { registry: reg } = registry();
    const reader = {
      roundsBack: vi.fn(),
      latest: vi.fn(async () => ({
        roundId: '9',
        price: 3123.45,
        t: 1_700_000_000_000,
        stale: false,
        provenance: 'agreed' as const,
      })),
    } as unknown as ChainlinkReader;
    const store = new ChainlinkStore(() => reader);
    store.configure(reg);
    const out = await store.quotes(['ethereum', 'definitely-not-a-feed-coin']);
    expect(out.get('ethereum')).toEqual({
      source: 'chainlink',
      usd: 3123.45,
      observedAtMs: 1_700_000_000_000,
    });
    expect(out.has('definitely-not-a-feed-coin')).toBe(false);
  });

  it('the singleton stays unavailable before configure', () => {
    expect(chainlinkStore.seriesFor(FEED).ticks).toEqual([]);
  });
});
