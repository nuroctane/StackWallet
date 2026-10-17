import { fetchJson, HttpError, type FetchOptions } from '@stackwallet/chains';

/**
 * One gate per keyless market source: responses are cached per URL, identical
 * requests in flight share one fetch, requests are spaced so the free tiers'
 * limits are respected, and a 429 parks the source for a while instead of
 * hammering it. A source the user turned off is never contacted.
 */

export type MarketSource = 'coingecko' | 'defillama' | 'chainlink';

export const SOURCE_LABEL: Readonly<Record<MarketSource, string>> = {
  coingecko: 'CoinGecko',
  defillama: 'DefiLlama',
  chainlink: 'Chainlink (on-chain)',
};

/** Minimum gap between two requests to the same source. */
export const SOURCE_SPACING_MS: Readonly<Record<MarketSource, number>> = {
  coingecko: 2_500,
  defillama: 500,
  // Chainlink reads ride the EVM RPC pool, which paces itself; this only
  // spaces the reader's own cache misses.
  chainlink: 250,
};

export const RATE_LIMIT_COOLDOWN_MS = 60_000;

export class SourceDisabledError extends Error {
  override readonly name = 'SourceDisabledError';
  constructor(readonly source: MarketSource) {
    super(`${SOURCE_LABEL[source]} is turned off in market data settings`);
  }
}

export class RateLimitedError extends Error {
  override readonly name = 'RateLimitedError';
  constructor(
    readonly source: MarketSource,
    readonly untilMs: number,
  ) {
    super(`${SOURCE_LABEL[source]} is rate limiting requests; retrying after a pause`);
  }
}

export type SourceSettings = Readonly<Record<MarketSource, boolean>>;

export interface MarketClientOptions {
  enabled: () => SourceSettings;
  fetchOptions?: FetchOptions;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** Upper bound on cached responses across sources. */
  maxEntries?: number;
}

interface Entry {
  at: number;
  value: unknown;
}

export class MarketClient {
  private cache = new Map<string, Entry>();
  private inflight = new Map<string, Promise<unknown>>();
  private nextSlot: Record<MarketSource, number> = { coingecko: 0, defillama: 0, chainlink: 0 };
  private cooldownUntil: Record<MarketSource, number> = {
    coingecko: 0,
    defillama: 0,
    chainlink: 0,
  };
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly maxEntries: number;

  constructor(private readonly opts: MarketClientOptions) {
    this.now = opts.now ?? Date.now;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.maxEntries = opts.maxEntries ?? 200;
  }

  isEnabled(source: MarketSource): boolean {
    return this.opts.enabled()[source];
  }

  /** Cached response of `url` from `source` if younger than `ttlMs`, otherwise a fresh fetch. */
  async getJson(source: MarketSource, url: string, ttlMs: number): Promise<unknown> {
    if (!this.isEnabled(source)) throw new SourceDisabledError(source);
    const hit = this.cache.get(url);
    if (hit && this.now() - hit.at < ttlMs) return hit.value;
    const pending = this.inflight.get(url);
    if (pending) return pending;
    const p = this.fetchSpaced(source, url).finally(() => this.inflight.delete(url));
    this.inflight.set(url, p);
    return p;
  }

  private async fetchSpaced(source: MarketSource, url: string): Promise<unknown> {
    const now = this.now();
    if (now < this.cooldownUntil[source])
      throw new RateLimitedError(source, this.cooldownUntil[source]);
    // Reserve a slot before awaiting so concurrent callers queue behind each other.
    const slot = Math.max(now, this.nextSlot[source]);
    this.nextSlot[source] = slot + SOURCE_SPACING_MS[source];
    if (slot > now) await this.sleep(slot - now);
    try {
      const value = await fetchJson(url, this.opts.fetchOptions);
      this.cache.set(url, { at: this.now(), value });
      if (this.cache.size > this.maxEntries) {
        const oldest = this.cache.keys().next().value;
        if (oldest !== undefined) this.cache.delete(oldest);
      }
      return value;
    } catch (err) {
      if (err instanceof HttpError && err.status === 429) {
        this.cooldownUntil[source] = this.now() + RATE_LIMIT_COOLDOWN_MS;
        throw new RateLimitedError(source, this.cooldownUntil[source]);
      }
      throw err;
    }
  }
}
