import { useSyncExternalStore } from 'react';
import type { ChainRegistry, RpcPool } from '@stackwallet/chains';
import {
  ChainlinkReader,
  feedForCoinId,
  feedKey,
  type ChainlinkFeed,
  type ChainlinkTick,
  type SourcePrice,
} from '@stackwallet/market';

import { marketSettings } from './market.js';

/**
 * On-chain price history from Chainlink feeds, read through the shared RPC
 * pool so the user's own endpoint choices apply. Ticks are immutable once
 * published, so the store keeps them in memory per feed, deduplicated by
 * round id; sync pulls the newest page, backfill walks older pages when a
 * chart pans into unknown territory. Nothing here is persisted: it is public
 * data that is cheap to refetch.
 */

export const CHAINLINK_SYNC_PAGE = 80;
export const CHAINLINK_BACKFILL_PAGE = 150;
export const CHAINLINK_MAX_TICKS = 8000;

export interface FeedSeries {
  /** Ascending by round. */
  ticks: readonly ChainlinkTick[];
  /** Round id of the oldest known tick; the next backfill starts below it. */
  oldestRoundId: string | null;
  /** true when the walk reached the feed's first round. */
  exhausted: boolean;
  loading: boolean;
  error: string | null;
  /** Last successful contact with the feed, for the freshness display. */
  fetchedAtMs: number;
}

const EMPTY_SERIES: FeedSeries = {
  ticks: [],
  oldestRoundId: null,
  exhausted: false,
  loading: false,
  error: null,
  fetchedAtMs: 0,
};

function mergeTicks(
  existing: readonly ChainlinkTick[],
  incoming: readonly ChainlinkTick[],
): { ticks: ChainlinkTick[]; added: number } {
  const byRound = new Map<string, ChainlinkTick>();
  for (const t of existing) byRound.set(t.roundId, t);
  let added = 0;
  for (const t of incoming) {
    if (!byRound.has(t.roundId)) added += 1;
    byRound.set(t.roundId, t);
  }
  if (added === 0 && byRound.size === existing.length) return { ticks: [...existing], added: 0 };
  const ticks = [...byRound.values()].sort((a, b) => {
    const ai = BigInt(a.roundId);
    const bi = BigInt(b.roundId);
    return ai < bi ? -1 : ai > bi ? 1 : 0;
  });
  while (ticks.length > CHAINLINK_MAX_TICKS) ticks.shift();
  return { ticks, added };
}

export class ChainlinkStore {
  private reader: ChainlinkReader | null = null;
  private series = new Map<string, FeedSeries>();
  private inflight = new Set<string>();
  private listeners = new Set<() => void>();
  private version = 0;

  /** Tests inject a scripted reader; production builds it from the pool. */
  constructor(private readonly makeReader?: (pool: RpcPool) => ChainlinkReader) {}

  /** Wire the shared pool. Called once from App with the registry. */
  configure(registry: ChainRegistry): () => void {
    let pool: RpcPool | null = null;
    try {
      pool = registry.adapterFor('eip155:1').rpc;
    } catch {
      pool = null;
    }
    this.reader = pool ? (this.makeReader?.(pool) ?? new ChainlinkReader({ pool })) : null;
    this.series = new Map();
    this.bump();
    return () => {
      this.reader = null;
      this.series = new Map();
      this.bump();
    };
  }

  get available(): boolean {
    return this.reader !== null;
  }

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  getVersion = () => this.version;

  seriesFor(feed: ChainlinkFeed): FeedSeries {
    return this.series.get(feedKey(feed)) ?? EMPTY_SERIES;
  }

  /** Latest answers by coin id for the quote merge; only ids with a feed answer. */
  async quotes(ids: readonly string[]): Promise<Map<string, SourcePrice>> {
    const out = new Map<string, SourcePrice>();
    if (!this.reader) return out;
    await Promise.all(
      ids.map(async (id) => {
        const feed = feedForCoinId(id);
        if (!feed || !this.reader) return;
        try {
          const latest = await this.reader.latest(feed);
          out.set(id, { source: 'chainlink', usd: latest.price, observedAtMs: latest.t });
        } catch {
          // A feed that fails to read simply sits this round of quotes out.
        }
      }),
    );
    return out;
  }

  /**
   * Bring a feed current: pull the newest rounds and merge them. Concurrent
   * callers share one walk; a failure is recorded on the series, not thrown.
   */
  async sync(feed: ChainlinkFeed): Promise<void> {
    if (!marketSettings.getSnapshot().chainlink) return;
    await this.walk(feed, CHAINLINK_SYNC_PAGE, undefined);
  }

  /** Extend a feed backwards; a no-op once the first round is reached. */
  async backfill(feed: ChainlinkFeed): Promise<void> {
    if (!marketSettings.getSnapshot().chainlink) return;
    const s = this.seriesFor(feed);
    if (s.exhausted || s.loading) return;
    if (s.ticks.length === 0) {
      // Never synced: start at the head.
      await this.sync(feed);
      return;
    }
    if (!s.oldestRoundId) return;
    await this.walk(feed, CHAINLINK_BACKFILL_PAGE, s.oldestRoundId);
  }

  private async walk(
    feed: ChainlinkFeed,
    count: number,
    before: string | undefined,
  ): Promise<void> {
    const reader = this.reader;
    if (!reader) {
      this.setSeries(feed, { ...this.seriesFor(feed), error: 'No EVM RPC pool is available' });
      return;
    }
    const key = feedKey(feed);
    if (this.inflight.has(key)) return;
    this.inflight.add(key);
    this.setSeries(feed, { ...this.seriesFor(feed), loading: true, error: null });
    try {
      const { ticks, exhausted } = await reader.roundsBack(feed, count, before);
      const prev = this.seriesFor(feed);
      const merged = mergeTicks(prev.ticks, ticks);
      const oldest = merged.ticks[0];
      this.setSeries(feed, {
        ticks: merged.ticks,
        oldestRoundId: oldest ? oldest.roundId : prev.oldestRoundId,
        exhausted: prev.exhausted || exhausted,
        loading: false,
        error: null,
        fetchedAtMs: Date.now(),
      });
    } catch (err) {
      this.setSeries(feed, {
        ...this.seriesFor(feed),
        loading: false,
        error: (err instanceof Error ? err.message : String(err)).slice(0, 200),
      });
    } finally {
      this.inflight.delete(key);
    }
  }

  private setSeries(feed: ChainlinkFeed, next: FeedSeries): void {
    this.series.set(feedKey(feed), next);
    this.bump();
  }

  private bump(): void {
    this.version += 1;
    for (const l of this.listeners) l();
  }
}

export const chainlinkStore = new ChainlinkStore();

export function useChainlinkSeries(feed: ChainlinkFeed | null): FeedSeries {
  useSyncExternalStore(chainlinkStore.subscribe, chainlinkStore.getVersion);
  return feed ? chainlinkStore.seriesFor(feed) : EMPTY_SERIES;
}
