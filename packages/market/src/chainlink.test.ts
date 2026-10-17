import { MemoryRpcPool } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  ChainlinkReader,
  feedForCoinId,
  feedsForBase,
  feedsForChain,
  findFeed,
  innerOf,
  isStale,
  makeRoundId,
  phaseOf,
  selectorOf,
  ticksToCandles,
  type ChainlinkTick,
} from './chainlink.js';
import type { ChainlinkFeed } from './chainlink-feeds.js';

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

const SEL = {
  decimals: selectorOf('decimals()'),
  latestRoundData: selectorOf('latestRoundData()'),
  getRoundData: selectorOf('getRoundData(uint80)'),
  latestRound: selectorOf('latestRound()'),
  phaseAggregators: selectorOf('phaseAggregators(uint16)'),
};

function word(v: bigint): string {
  return v.toString(16).padStart(64, '0');
}

function roundHex(roundId: bigint, answer: bigint, updatedAtSec: bigint): string {
  return `0x${word(roundId)}${word(answer)}${word(updatedAtSec)}${word(updatedAtSec)}${word(roundId)}`;
}

interface Call {
  to: string;
  data: string;
}

interface JsonRpcCall {
  id: number;
  method: string;
  params: [{ to: string; data: string }, string];
}

/** A scripted node: the handler answers each eth_call, batched or single. */
function node(handler: (call: Call) => string | { error: true }) {
  return async (_url: string, init?: RequestInit): Promise<Response> => {
    const parsed = JSON.parse(String(init?.body)) as JsonRpcCall | JsonRpcCall[];
    const body = Array.isArray(parsed) ? parsed : [parsed];
    const out = body.map((req) => {
      const r = handler(req.params[0]);
      return typeof r === 'object'
        ? { jsonrpc: '2.0', id: req.id, error: { code: -32000, message: 'execution reverted' } }
        : { jsonrpc: '2.0', id: req.id, result: r };
    });
    return new Response(JSON.stringify(Array.isArray(parsed) ? out : out[0]), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
}

function poolWith(urls: string[] = ['https://a.example']): MemoryRpcPool {
  const pool = new MemoryRpcPool([]);
  pool.setEndpoints('eip155:1', urls);
  return pool;
}

const NOW = 1_700_000_000_000;
const now = () => NOW;

function readerFor(handler: (call: Call) => string | { error: true }, urls?: string[]) {
  const fetchImpl = node(handler) as unknown as typeof fetch;
  return new ChainlinkReader({
    pool: poolWith(urls),
    fetchOptions: { fetch: fetchImpl },
    now,
  });
}

describe('selectors', () => {
  it('derives the published Chainlink selectors', () => {
    expect(SEL.decimals).toBe('313ce567');
    expect(SEL.latestRoundData).toBe('feaf968c');
    expect(SEL.getRoundData).toBe('9a6fc8f5');
    expect(SEL.latestRound).toBe('668a0f02');
    expect(SEL.phaseAggregators).toBe('c1597304');
  });
});

describe('round id arithmetic', () => {
  it('splits and recombines phase and inner ids', () => {
    const id = makeRoundId(7n, 12345n);
    expect(phaseOf(id)).toBe(7n);
    expect(innerOf(id)).toBe(12345n);
  });
  it('rejects out-of-range parts', () => {
    expect(() => makeRoundId(0n, 1n)).toThrow();
    expect(() => makeRoundId(1n, -1n)).toThrow();
  });
});

describe('feed registry lookups', () => {
  it('finds the canonical mainnet ETH / USD proxy', () => {
    const f = findFeed('eip155:1', 'ETH');
    expect(f?.proxy).toBe('0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419');
    expect(f?.decimals).toBe(8);
  });
  it('prefers the cheapest heartbeat for a coin id', () => {
    const f = feedForCoinId('ethereum');
    expect(f?.base).toBe('ETH');
    const all = feedsForBase('ETH');
    expect(all.length).toBeGreaterThan(1);
    expect(f?.heartbeatSec).toBe(Math.min(...all.map((x) => x.heartbeatSec || Infinity)));
  });
  it('lists feeds per chain without duplicates', () => {
    const pairs = feedsForChain('eip155:1').map((f) => f.pair);
    expect(new Set(pairs).size).toBe(pairs.length);
  });
});

describe('ChainlinkReader.latest', () => {
  it('decodes the newest round and flags freshness', async () => {
    const reader = readerFor((call) => {
      if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(8n)}`;
      if (call.data.startsWith(`0x${SEL.latestRoundData}`))
        return roundHex(makeRoundId(5n, 900n), 312345678901n, BigInt(NOW / 1000 - 120));
      return { error: true };
    });
    const latest = await reader.latest(FEED);
    expect(latest.price).toBeCloseTo(3123.45678901);
    expect(latest.roundId).toBe(makeRoundId(5n, 900n).toString(10));
    expect(latest.stale).toBe(false);
    expect(latest.provenance).toBe('single');
  });

  it('cross-checks two operators and reports disagreement', async () => {
    const answers: Record<string, bigint> = {
      'https://a.example': 300000000000n,
      'https://b.example': 333000000000n,
    };
    const combined = (async (url: string, init?: RequestInit) => {
      const answer = url.includes('b.example')
        ? answers['https://b.example']!
        : answers['https://a.example']!;
      const handler = node((call) => {
        if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(8n)}`;
        return roundHex(makeRoundId(5n, 900n), answer, BigInt(NOW / 1000 - 60));
      });
      return handler(url, init);
    }) as typeof fetch;
    const pool = poolWith(['https://a.example', 'https://b.example']);
    const reader = new ChainlinkReader({ pool, fetchOptions: { fetch: combined }, now });
    const latest = await reader.latest(FEED);
    expect(latest.provenance).toBe('disagreed');
  });

  it('refuses a feed whose on-chain decimals contradict the registry', async () => {
    const reader = readerFor((call) => {
      if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(18n)}`;
      return roundHex(makeRoundId(5n, 900n), 1n, BigInt(NOW / 1000));
    });
    await expect(reader.latest(FEED)).rejects.toThrow(/decimals/);
  });

  it('refuses a non-positive answer', async () => {
    const reader = readerFor((call) => {
      if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(8n)}`;
      return roundHex(makeRoundId(5n, 900n), 0n, BigInt(NOW / 1000));
    });
    await expect(reader.latest(FEED)).rejects.toThrow();
  });

  it('marks an answer older than three heartbeats stale', async () => {
    const reader = readerFor((call) => {
      if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(8n)}`;
      return roundHex(makeRoundId(5n, 900n), 300000000000n, BigInt(NOW / 1000 - 4 * 3600));
    });
    expect((await reader.latest(FEED)).stale).toBe(true);
    expect(isStale(FEED, NOW - 4 * 3600_000, NOW)).toBe(true);
    expect(isStale(FEED, NOW - 1800_000, NOW)).toBe(false);
  });
});

describe('ChainlinkReader.roundsBack', () => {
  it('walks one phase backwards and skips missing rounds', async () => {
    const latestId = makeRoundId(3n, 50n);
    const reader = readerFor((call) => {
      if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(8n)}`;
      if (call.data.startsWith(`0x${SEL.latestRoundData}`))
        return roundHex(latestId, 300000000000n, BigInt(NOW / 1000 - 60));
      if (call.data.startsWith(`0x${SEL.getRoundData}`)) {
        const id = BigInt(`0x${call.data.slice(10, 74)}`);
        if (innerOf(id) === 47n) return { error: true };
        return roundHex(id, 200000000000n + innerOf(id), BigInt(NOW / 1000 - 3600));
      }
      return { error: true };
    });
    const { ticks, exhausted } = await reader.roundsBack(FEED, 10);
    expect(exhausted).toBe(false);
    expect(ticks).toHaveLength(10);
    expect(ticks[0]!.roundId).toBe(latestId.toString(10));
    // Newest first; round 47 missing, so the tail jumps 48 -> 46.
    const inners = ticks.map((t) => innerOf(BigInt(t.roundId)));
    expect(inners).toEqual([50n, 49n, 48n, 46n, 45n, 44n, 43n, 42n, 41n, 40n]);
  });

  it('crosses into the previous aggregator at the phase floor', async () => {
    const AGG = '0x00000000000000000000000000000000000000aa';
    const latestId = makeRoundId(2n, 3n);
    const reader = readerFor((call) => {
      if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(8n)}`;
      if (call.data.startsWith(`0x${SEL.latestRoundData}`))
        return roundHex(latestId, 100n, BigInt(NOW / 1000 - 60));
      if (call.data.startsWith(`0x${SEL.phaseAggregators}`))
        return `0x${'0'.repeat(24)}${AGG.slice(2)}`;
      if (call.data.startsWith(`0x${SEL.latestRound}`)) return `0x${word(2n)}`;
      if (call.data.startsWith(`0x${SEL.getRoundData}`)) {
        const id = BigInt(`0x${call.data.slice(10, 74)}`);
        if (call.to === AGG) return roundHex(id, 1000n + id, BigInt(NOW / 1000 - 7200));
        if (innerOf(id) >= 1n) return roundHex(id, 100n, BigInt(NOW / 1000 - 3600));
      }
      return { error: true };
    });
    const { ticks, exhausted } = await reader.roundsBack(FEED, 8);
    expect(exhausted).toBe(true);
    // latest (2/3), then 2/2, 2/1 on the proxy, then phase 1 rounds 2 and 1 on the aggregator.
    expect(ticks.map((t) => t.roundId)).toEqual([
      makeRoundId(2n, 3n).toString(10),
      makeRoundId(2n, 2n).toString(10),
      makeRoundId(2n, 1n).toString(10),
      '2',
      '1',
    ]);
    // Aggregator-phase ticks keep the aggregator's prices.
    expect(ticks.at(-1)!.price).toBeCloseTo(0.00001001);
  });

  it('stops at the first phase', async () => {
    const reader = readerFor((call) => {
      if (call.data.startsWith(`0x${SEL.decimals}`)) return `0x${word(8n)}`;
      if (call.data.startsWith(`0x${SEL.latestRoundData}`))
        return roundHex(makeRoundId(1n, 2n), 100n, BigInt(NOW / 1000 - 60));
      if (call.data.startsWith(`0x${SEL.getRoundData}`)) {
        const id = BigInt(`0x${call.data.slice(10, 74)}`);
        if (innerOf(id) >= 1n) return roundHex(id, 100n, BigInt(NOW / 1000 - 3600));
      }
      return { error: true };
    });
    const { ticks, exhausted } = await reader.roundsBack(FEED, 20);
    expect(exhausted).toBe(true);
    expect(ticks).toHaveLength(2);
  });
});

describe('ticksToCandles', () => {
  const H = 3_600_000;
  const tick = (t: number, price: number): ChainlinkTick => ({ roundId: '1', price, t });

  it('carries the last tick through empty buckets as flat candles', () => {
    const candles = ticksToCandles([tick(0, 100), tick(2.5 * H, 120), tick(2.6 * H, 80)], H);
    expect(candles.map((c) => [c.o, c.h, c.l, c.c])).toEqual([
      [100, 100, 100, 100],
      [100, 100, 100, 100],
      [100, 120, 80, 80],
    ]);
  });

  it('keeps high and low of every tick inside the bucket', () => {
    const candles = ticksToCandles([tick(0, 10), tick(100, 15), tick(200, 5)], 1000);
    expect(candles).toHaveLength(1);
    expect(candles[0]).toMatchObject({ o: 10, h: 15, l: 5, c: 5 });
  });

  it('returns nothing for an empty feed', () => {
    expect(ticksToCandles([], H)).toEqual([]);
  });
});
