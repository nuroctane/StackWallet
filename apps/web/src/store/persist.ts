import { useSyncExternalStore } from 'react';

import { emptyState, type ReducerContext } from './reducers.js';
import { DirectoryState } from './schema.js';
import { defaultContext, DirectoryStore } from './store.js';
import { reportStorageSave } from './storageStatus.js';

export const STORAGE_KEY = 'stackwallet.directory.v1';
export const SAVE_DEBOUNCE_MS = 150;

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface LoadResult {
  state: DirectoryState;
  /** Set when an unreadable blob was moved aside and a fresh directory started. */
  quarantinedKey?: string;
}

export function loadDirectory(storage: StorageLike | null, ctx: ReducerContext): LoadResult {
  if (!storage) return { state: emptyState(ctx) };
  let raw: string | null = null;
  try {
    raw = storage.getItem(STORAGE_KEY);
  } catch {
    return { state: emptyState(ctx) };
  }
  if (raw === null || raw === '') return { state: emptyState(ctx) };

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  const result = parsed === undefined ? undefined : DirectoryState.safeParse(parsed);
  if (result?.success) return { state: result.data };

  // Keep the bad blob for manual recovery; a wallet directory is never silently discarded.
  const quarantinedKey = `${STORAGE_KEY}.corrupt-${ctx.now()}`;
  try {
    storage.setItem(quarantinedKey, raw);
  } catch {
    // Storage full or blocked: nothing more we can do but start fresh.
  }
  return { state: emptyState(ctx), quarantinedKey };
}

export function saveDirectory(storage: StorageLike, state: DirectoryState): boolean {
  try {
    storage.setItem(STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

export interface PersistedStore {
  store: DirectoryStore;
  quarantinedKey?: string;
  flush(): void;
  dispose(): void;
}

export function createPersistedStore(
  options: {
    storage?: StorageLike | null;
    ctx?: ReducerContext;
    debounceMs?: number;
  } = {},
): PersistedStore {
  const ctx = options.ctx ?? defaultContext;
  const storage = options.storage === undefined ? safeLocalStorage() : options.storage;
  const debounceMs = options.debounceMs ?? SAVE_DEBOUNCE_MS;
  const loaded = loadDirectory(storage, ctx);
  const store = new DirectoryStore(loaded.state, ctx);

  let timer: ReturnType<typeof setTimeout> | undefined;
  let dirty = false;
  let failures = 0;
  let disposed = false;
  const flush = () => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    if (!dirty) return;
    const ok = !!storage && saveDirectory(storage, store.getSnapshot());
    reportStorageSave('directory', ok);
    if (ok) {
      dirty = false;
      failures = 0;
    } else if (!disposed && ++failures < 3) timer = setTimeout(flush, 5_000);
  };
  const unsubscribe = store.subscribe(() => {
    dirty = true;
    failures = 0;
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(flush, debounceMs);
  });

  const hasWindow = typeof window !== 'undefined';
  if (hasWindow) window.addEventListener('pagehide', flush);
  if (hasWindow) window.addEventListener('focus', flush);

  const result: PersistedStore = {
    store,
    flush,
    dispose() {
      disposed = true;
      unsubscribe();
      if (hasWindow) window.removeEventListener('pagehide', flush);
      if (hasWindow) window.removeEventListener('focus', flush);
      flush();
    },
  };
  if (loaded.quarantinedKey) result.quarantinedKey = loaded.quarantinedKey;
  return result;
}

function safeLocalStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

const persisted = createPersistedStore();

export const directory: DirectoryStore = persisted.store;
export const directoryQuarantinedKey: string | undefined = persisted.quarantinedKey;

export function useDirectory(): DirectoryState {
  return useSyncExternalStore(directory.subscribe, directory.getSnapshot, directory.getSnapshot);
}
