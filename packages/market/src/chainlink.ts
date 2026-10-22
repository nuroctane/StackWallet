import {
  fetchJsonRpc,
  fetchJsonRpcBatch,
  withCrossCheck,
  withFailover,
  type FetchOptions,
  type JsonRpcBatchResult,
  type RpcPool,
} from '@stackwallet/chains';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';

import type { Candle } from './candles.js';
import { CHAINLINK_FEEDS, type ChainlinkFeed } from './chainlink-feeds.js';
import { NATIVE_IDS } from './prices.js';

/**
 * On-chain prices read straight from Chainlink aggregator proxies over the
 * user's own EVM endpoints: no API key, no intermediary, and the answer is
 * the one DeFi contracts settle on. The latest answer is cross-checked across
 * two endpoint operators (a lying node must not move a displayed price);
 * round history walks `getRoundData` backwards in JSON-RPC batches, crossing
 * aggregator upgrades through `phaseAggregators`. Everything a node returns
 * is treated as untrusted: answers must be positive, timestamps ordered and
 * sane, and a feed whose on-chain decimals contradict the registry is refused.
 */

export interface ChainlinkTick {
  /** Full uint80 round id (phase << 64 | aggregator round), decimal string. */
  roundId: string;
  /** Whole-unit price. */
  price: number;
  /** Oracle observation time. */
  t: number;
}

export interface ChainlinkLatest extends ChainlinkTick {
  /** true when the answer is older than three heartbeats (or six hours without one). */
  stale: boolean;
  /** `disagreed` means two operators gave different answers; the catalog endpoint won. */
  provenance: 'single' | 'agreed' | 'disagreed';
}

const MASK_64 = (1n << 64n) - 1n;
const MAX_ROUND_INNER = MASK_64;
const MAX_UINT256 = (1n << 256n) - 1n;
/** A price beyond this is a garbage answer, not a market. */
const MAX_PRICE = 1e12;
/** Reject observations from the future beyond normal clock skew. */
const FUTURE_SKEW_MS = 15 * 60_000;
/** Round history pages: one JSON-RPC batch per page. */
const ROUND_PAGE = 150;
const MAX_ROUNDS_PER_PULL = 600;

export function selectorOf(signature: string): string {
  return bytesToHex(keccak_256(new TextEncoder().encode(signature)).slice(0, 4));
}

const SEL = {
  decimals: selectorOf('decimals()'),
  latestRoundData: selectorOf('latestRoundData()'),
  getRoundData: selectorOf('getRoundData(uint80)'),
  latestRound: selectorOf('latestRound()'),
  phaseAggregators: selectorOf('phaseAggregators(uint16)'),
};

function word(v: bigint): string {
  if (v < 0n || v > MAX_UINT256) throw new Error('word out of range');
  return v.toString(16).padStart(64, '0');
}

function callData(selector: string, ...words: bigint[]): string {
  return `0x${selector}${words.map(word).join('')}`;
}

function readWord(data: string, i: number): bigint {
  const hex = data.slice(2 + i * 64, 2 + (i + 1) * 64);
  if (hex.length !== 64 || !/^[0-9a-fA-F]+$/.test(hex)) throw new Error('short return data');
  return BigInt(`0x${hex}`);
}

/** Signed int256 decode; prices arrive as int256 even though they are positive. */
function readInt(data: string, i: number): bigint {
  const v = readWord(data, i);
  return v >= 1n << 255n ? v - (1n << 256n) : v;
}

function decodeRound(data: unknown): { roundId: bigint; answer: bigint; updatedAtMs: number } {
  if (typeof data !== 'string' || !data.startsWith('0x')) throw new Error('round is not hex');
  if (data.length < 2 + 5 * 64) throw new Error('short return data');
  const roundId = readWord(data, 0);
  const answer = readInt(data, 1);
  const updatedAtMs = Number(readWord(data, 3)) * 1000;
  return { roundId, answer, updatedAtMs };
}

export function phaseOf(roundId: bigint): bigint {
  return roundId >> 64n;
}

export function innerOf(roundId: bigint): bigint {
  return roundId & MASK_64;
}

export function makeRoundId(phase: bigint, inner: bigint): bigint {
  if (phase < 1n || inner < 0n || inner > MAX_ROUND_INNER) throw new Error('bad round id parts');
  return (phase << 64n) | inner;
}

export function feedKey(feed: Pick<ChainlinkFeed, 'chainId' | 'pair'>): string {
  return `${feed.chainId}:${feed.pair}`;
}

/** Reverse of `feedKey`; undefined for a key the registry does not know. */
export function feedByKey(key: string): ChainlinkFeed | undefined {
  return CHAINLINK_FEEDS.find((f) => feedKey(f) === key);
}

export function findFeed(chainId: string, base: string, quote = 'USD'): ChainlinkFeed | undefined {
  return CHAINLINK_FEEDS.find((f) => f.chainId === chainId && f.base === base && f.quote === quote);
}

export function feedsForChain(chainId: string): ChainlinkFeed[] {
  return CHAINLINK_FEEDS.filter((f) => f.chainId === chainId);
}

/** Every feed for a base asset, cheapest heartbeat first. */
export function feedsForBase(base: string, quote = 'USD'): ChainlinkFeed[] {
  return CHAINLINK_FEEDS.filter((f) => f.base === base && f.quote === quote).sort(
    (a, b) => (a.heartbeatSec || Infinity) - (b.heartbeatSec || Infinity),
  );
}

const ID_TO_BASE = new Map(Object.entries(NATIVE_IDS).map(([symbol, id]) => [id, symbol]));

/** The freshest USD feed for a CoinGecko coin id, when Chainlink covers it. */
export function feedForCoinId(id: string): ChainlinkFeed | undefined {
  const base = ID_TO_BASE.get(id);
  return base ? feedsForBase(base)[0] : undefined;
}

export function isStale(feed: ChainlinkFeed, updatedAtMs: number, now: number): boolean {
  const horizon = feed.heartbeatSec > 0 ? feed.heartbeatSec * 3_000 : 6 * 3_600_000;
  return now - updatedAtMs > horizon;
}

export interface ChainlinkReaderOptions {
  pool: RpcPool;
  fetchOptions?: FetchOptions;
  now?: () => number;
}

export class ChainlinkReader {
  private readonly now: () => number;
  private readonly decimalsOk = new Map<string, Promise<void>>();

  constructor(private readonly opts: ChainlinkReaderOptions) {
    this.now = opts.now ?? Date.now;
  }

  /** The newest round, answered the same by two endpoint operators when the pool has them. */
  async latest(feed: ChainlinkFeed): Promise<ChainlinkLatest> {
    await this.verifyDecimals(feed);
    const read = async (url: string) => {
      const result = await fetchJsonRpc(
        url,
        'eth_call',
        [{ to: feed.proxy, data: callData(SEL.latestRoundData) }, 'latest'],
        this.opts.fetchOptions,
      );
      return this.toTick(feed, decodeRound(result));
    };
    const signal = this.opts.fetchOptions?.signal;
    const { value, provenance } = await withCrossCheck(this.opts.pool, feed.chainId, read, {
      equal: (a, b) => a.roundId === b.roundId && a.price === b.price,
      ...(signal ? { signal } : {}),
    });
    return { ...value, stale: isStale(feed, value.t, this.now()), provenance: provenance.kind };
  }

  /**
   * Up to `maxRounds` ticks strictly before `before` (a round id; defaults to
   * the latest), newest first. Stops early with `exhausted: true` when the
   * feed's first round is reached; missing rounds inside a phase are skipped.
   */
  async roundsBack(
    feed: ChainlinkFeed,
    maxRounds: number,
    before?: string,
  ): Promise<{ ticks: ChainlinkTick[]; exhausted: boolean }> {
    await this.verifyDecimals(feed);
    const limit = Math.max(1, Math.min(MAX_ROUNDS_PER_PULL, maxRounds));

    // The walk accumulates into closure-local state so a failover retry starts
    // clean; only a completed walk is committed to the caller.
    const walked = await withFailover(this.opts.pool, feed.chainId, async (url) => {
      const call = (calls: { method: string; params?: unknown[] }[]) =>
        fetchJsonRpcBatch(url, calls, this.opts.fetchOptions);
      const ticks: ChainlinkTick[] = [];
      let exhausted = false;
      let cursor: { contract: string; phase: bigint; inner: bigint };
      if (before !== undefined) {
        const id = BigInt(before);
        cursor = { contract: feed.proxy, phase: phaseOf(id), inner: innerOf(id) - 1n };
      } else {
        const result = await fetchJsonRpc(
          url,
          'eth_call',
          [{ to: feed.proxy, data: callData(SEL.latestRoundData) }, 'latest'],
          this.opts.fetchOptions,
        );
        const d = decodeRound(result);
        ticks.push(this.toTick(feed, d));
        cursor = {
          contract: feed.proxy,
          phase: phaseOf(d.roundId),
          inner: innerOf(d.roundId) - 1n,
        };
      }

      while (ticks.length < limit) {
        if (cursor.inner < 1n) {
          // Cross into the previous aggregator; phase 1 is the feed's start.
          if (cursor.phase <= 1n) {
            exhausted = true;
            break;
          }
          const prev = await this.phaseStart(call, feed.proxy, cursor.phase - 1n);
          if (!prev) {
            exhausted = true;
            break;
          }
          cursor = { contract: prev.contract, phase: cursor.phase - 1n, inner: prev.lastInner };
          continue;
        }
        const n = Math.min(Number(cursor.inner), ROUND_PAGE, limit - ticks.length);
        const startInner = cursor.inner;
        const calls = Array.from({ length: n }, (_, i) => ({
          method: 'eth_call',
          params: [
            {
              to: cursor.contract,
              data:
                cursor.contract === feed.proxy
                  ? callData(SEL.getRoundData, makeRoundId(cursor.phase, startInner - BigInt(i)))
                  : callData(SEL.getRoundData, startInner - BigInt(i)),
            },
            'latest',
          ],
        }));
        const results = await call(calls);
        let firstMissing: number | null = null;
        for (let i = 0; i < results.length; i++) {
          const r = results[i];
          if (!r || !r.ok) {
            // A missing round mid-phase is a gap; at inner 1 it is the phase floor.
            if (firstMissing === null) firstMissing = i;
            continue;
          }
          try {
            ticks.push(this.toTick(feed, decodeRound(r.result)));
          } catch {
            if (firstMissing === null) firstMissing = i;
          }
        }
        if (firstMissing !== null && startInner - BigInt(firstMissing) <= 1n) {
          cursor = { ...cursor, inner: 0n };
        } else {
          cursor = { ...cursor, inner: startInner - BigInt(n) };
        }
      }
      return { ticks, exhausted };
    });
    return walked;
  }

  /**
   * Where the previous phase's rounds live: its aggregator contract and last
   * round. Returns null when the proxy does not know that phase.
   */
  private async phaseStart(
    call: (calls: { method: string; params?: unknown[] }[]) => Promise<JsonRpcBatchResult[]>,
    proxy: string,
    phase: bigint,
  ): Promise<{ contract: string; lastInner: bigint } | null> {
    const [agg] = await call([
      {
        method: 'eth_call',
        params: [{ to: proxy, data: callData(SEL.phaseAggregators, phase) }, 'latest'],
      },
    ]);
    if (!agg?.ok || typeof agg.result !== 'string' || agg.result.length < 66) return null;
    const contract = `0x${agg.result.slice(-40).toLowerCase()}`;
    const [lr] = await call([
      { method: 'eth_call', params: [{ to: contract, data: callData(SEL.latestRound) }, 'latest'] },
    ]);
    if (!lr?.ok || typeof lr.result !== 'string') return null;
    const lastInner = readWord(lr.result, 0);
    return lastInner >= 1n ? { contract, lastInner } : null;
  }

  /** The registry's decimals must match the proxy's, once per feed per session. */
  private verifyDecimals(feed: ChainlinkFeed): Promise<void> {
    let pending = this.decimalsOk.get(feedKey(feed));
    if (!pending) {
      pending = withFailover(this.opts.pool, feed.chainId, async (url) => {
        const result = await fetchJsonRpc(
          url,
          'eth_call',
          [{ to: feed.proxy, data: callData(SEL.decimals) }, 'latest'],
          this.opts.fetchOptions,
        );
        if (typeof result !== 'string') throw new Error('decimals() returned no data');
        const onChain = Number(readWord(result, 0));
        if (onChain !== feed.decimals)
          throw new Error(
            `${feed.pair} on ${feed.chainId}: on-chain decimals ${onChain} != registry ${feed.decimals}`,
          );
      });
      this.decimalsOk.set(feedKey(feed), pending);
      pending.catch(() => this.decimalsOk.delete(feedKey(feed)));
    }
    return pending;
  }

  private toTick(
    feed: ChainlinkFeed,
    d: { roundId: bigint; answer: bigint; updatedAtMs: number },
  ): ChainlinkTick {
    if (d.answer <= 0n) throw new Error('non-positive answer');
    if (d.roundId <= 0n) throw new Error('non-positive round id');
    const now = this.now();
    if (d.updatedAtMs <= 0 || d.updatedAtMs > now + FUTURE_SKEW_MS)
      throw new Error('implausible round timestamp');
    const price = Number(d.answer) / 10 ** feed.decimals;
    if (!Number.isFinite(price) || price <= 0 || price > MAX_PRICE)
      throw new Error('implausible answer magnitude');
    return { roundId: d.roundId.toString(10), price, t: d.updatedAtMs };
  }
}

/**
 * Bucket sparse oracle ticks into OHLC candles of `frameMs`. A tick's price
 * holds until the next tick, so buckets without a tick repeat the carry-over
 * price as a flat candle rather than leaving a gap. Ticks must be ascending.
 */
export function ticksToCandles(ticks: readonly ChainlinkTick[], frameMs: number): Candle[] {
  if (frameMs <= 0 || ticks.length === 0) return [];
  const first = ticks[0] as ChainlinkTick;
  const last = ticks[ticks.length - 1] as ChainlinkTick;
  const start = Math.floor(first.t / frameMs) * frameMs;
  const end = Math.floor(last.t / frameMs) * frameMs;
  const out: Candle[] = [];
  let carry = first.price;
  let i = 0;
  for (let b = start; b <= end; b += frameMs) {
    const open = carry;
    let high = carry;
    let low = carry;
    while (i < ticks.length && (ticks[i] as ChainlinkTick).t < b + frameMs) {
      const p = (ticks[i] as ChainlinkTick).price;
      if (p > high) high = p;
      if (p < low) low = p;
      carry = p;
      i += 1;
    }
    out.push({ t: b, o: open, h: high, l: low, c: carry });
  }
  return out;
}

/** Round-trip helper for callers that page history: oldest tick first. */
export function oldestFirst(ticks: readonly ChainlinkTick[]): ChainlinkTick[] {
  return [...ticks].sort((a, b) => a.t - b.t);
}
