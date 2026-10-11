import { useEffect, useState, useSyncExternalStore } from 'react';
import type { ChainRegistry } from '@stackwallet/chains';
import {
  defaultCollectibleSources,
  directMediaUrl,
  loadMedia,
  type Collectible,
  type CollectibleSource,
} from '@stackwallet/collectibles';
import type { Account } from '@stackwallet/core-client';

/** Holdings change slowly; a revisit inside this window reuses the last answer. */
export const COLLECTIBLES_TTL_MS = 10 * 60 * 1000;
const MAX_ITEMS_PER_ACCOUNT = 1000;

export interface CollectiblesEntry {
  items: Collectible[];
  cursor: string | null;
  loading: boolean;
  error: string | null;
  fetchedAtMs: number;
  supported: boolean;
}

const EMPTY: CollectiblesEntry = {
  items: [],
  cursor: null,
  loading: false,
  error: null,
  fetchedAtMs: 0,
  supported: true,
};

export function collectiblesKey(a: Pick<Account, 'chainId' | 'address'>): string {
  return `${a.chainId}:${a.address}`;
}

/**
 * In-memory only: collectible lists are public data and cheap to refetch,
 * and keeping them out of storage keeps a stranger's airdrop spam off disk.
 */
export class CollectiblesStore {
  private entries = new Map<string, CollectiblesEntry>();
  private readonly listeners = new Set<() => void>();
  private sources: CollectibleSource[] = [];
  private version = 0;

  constructor(private readonly now: () => number = Date.now) {}

  readonly subscribe = (l: () => void): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getVersion = (): number => this.version;

  configure(registry: ChainRegistry, sources?: CollectibleSource[]): void {
    this.sources = sources ?? defaultCollectibleSources({ registry });
  }

  get(a: Pick<Account, 'chainId' | 'address'>): CollectiblesEntry {
    return this.entries.get(collectiblesKey(a)) ?? EMPTY;
  }

  private set(key: string, entry: CollectiblesEntry): void {
    this.entries.set(key, entry);
    this.version += 1;
    for (const l of this.listeners) l();
  }

  private sourceFor(a: Account): CollectibleSource | undefined {
    return this.sources.find((s) =>
      s.appliesTo({ family: a.family, chainId: a.chainId, address: a.address }),
    );
  }

  supports(a: Account): boolean {
    return this.sourceFor(a) !== undefined;
  }

  /** First page, unless a fresh answer is cached. */
  async load(a: Account, force = false): Promise<void> {
    const key = collectiblesKey(a);
    const cur = this.get(a);
    if (cur.loading) return;
    if (!force && cur.fetchedAtMs > 0 && this.now() - cur.fetchedAtMs < COLLECTIBLES_TTL_MS) return;
    const source = this.sourceFor(a);
    if (!source) {
      this.set(key, { ...EMPTY, supported: false, fetchedAtMs: this.now() });
      return;
    }
    this.set(key, { ...cur, loading: true, error: null, supported: true });
    try {
      const page = await source.list({ family: a.family, chainId: a.chainId, address: a.address });
      this.set(key, {
        items: page.items,
        cursor: page.cursor,
        loading: false,
        error: null,
        fetchedAtMs: this.now(),
        supported: true,
      });
    } catch (err) {
      this.set(key, {
        ...cur,
        loading: false,
        error: err instanceof Error ? err.message : String(err),
        fetchedAtMs: this.now(),
      });
    }
  }

  async loadMore(a: Account): Promise<void> {
    const key = collectiblesKey(a);
    const cur = this.get(a);
    const source = this.sourceFor(a);
    if (!source || cur.loading || !cur.cursor || cur.items.length >= MAX_ITEMS_PER_ACCOUNT) return;
    this.set(key, { ...cur, loading: true });
    try {
      const page = await source.list(
        { family: a.family, chainId: a.chainId, address: a.address },
        cur.cursor,
      );
      const seen = new Set(cur.items.map((i) => i.key));
      this.set(key, {
        ...cur,
        items: [...cur.items, ...page.items.filter((i) => !seen.has(i.key))].slice(
          0,
          MAX_ITEMS_PER_ACCOUNT,
        ),
        cursor: page.cursor,
        loading: false,
      });
    } catch (err) {
      this.set(key, {
        ...cur,
        loading: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}

export const collectiblesStore = new CollectiblesStore();

export function useCollectiblesVersion(): number {
  return useSyncExternalStore(
    collectiblesStore.subscribe,
    collectiblesStore.getVersion,
    collectiblesStore.getVersion,
  );
}

export type MediaMode = 'all' | 'vetted' | 'off';
export const MEDIA_MODE_KEY = 'stackwallet.media.v1';

/**
 * How collectible images load. `vetted`: fetched over CORS, type-checked and
 * size-capped, shown from a blob. `all`: also lets hosts without CORS serve a
 * plain image. `off`: nothing remote. Every remote image tells its host this
 * device's IP, which is why spam-flagged items never load media at all.
 */
function loadMediaMode(): MediaMode {
  try {
    const v = globalThis.localStorage?.getItem(MEDIA_MODE_KEY);
    return v === 'vetted' || v === 'off' ? v : 'all';
  } catch {
    return 'all';
  }
}

let mediaMode: MediaMode = loadMediaMode();
const modeListeners = new Set<() => void>();

export function setMediaMode(mode: MediaMode): void {
  mediaMode = mode;
  try {
    globalThis.localStorage?.setItem(MEDIA_MODE_KEY, mode);
  } catch {
    // Kept for this session only.
  }
  for (const l of modeListeners) l();
}

export function useMediaMode(): MediaMode {
  return useSyncExternalStore(
    (l) => {
      modeListeners.add(l);
      return () => modeListeners.delete(l);
    },
    () => mediaMode,
    () => mediaMode,
  );
}

const MEDIA_CACHE_MAX = 160;
interface MediaHit {
  src: string | null;
  /** True when the bytes passed the vetted loader; false for a direct fallback. */
  vetted: boolean;
}
const mediaCache = new Map<string, MediaHit>();
const mediaPending = new Map<string, Promise<MediaHit>>();

function rememberMedia(url: string, hit: MediaHit): void {
  mediaCache.set(url, hit);
  while (mediaCache.size > MEDIA_CACHE_MAX) {
    const [oldKey, old] = mediaCache.entries().next().value as [string, MediaHit];
    mediaCache.delete(oldKey);
    if (old.vetted && old.src) URL.revokeObjectURL(old.src);
  }
}

/** Image source for `url` under the current media mode; `undefined` while loading. */
export function useMedia(url: string | null): string | null | undefined {
  const mode = useMediaMode();
  const [, bump] = useState(0);
  const key = url && mode !== 'off' ? `${mode}|${url}` : null;
  useEffect(() => {
    if (!key || !url || mediaCache.has(key)) return;
    let live = true;
    let p = mediaPending.get(key);
    if (!p) {
      p = loadMedia(url).then((r): MediaHit => {
        const hit: MediaHit = r.ok
          ? { src: URL.createObjectURL(r.blob), vetted: true }
          : // A network/CORS refusal is the only failure a plain <img> can get past.
            mode === 'all' && r.reason === 'TypeError'
            ? { src: directMediaUrl(url), vetted: false }
            : { src: null, vetted: false };
        rememberMedia(key, hit);
        mediaPending.delete(key);
        return hit;
      });
      mediaPending.set(key, p);
    }
    void p.then(() => {
      if (live) bump((n) => n + 1);
    });
    return () => {
      live = false;
    };
  }, [key, url, mode]);
  if (!key) return null;
  const hit = mediaCache.get(key);
  return hit ? hit.src : undefined;
}
