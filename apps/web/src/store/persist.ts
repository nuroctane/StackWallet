import { useSyncExternalStore } from 'react';

import { emptyState, type ReducerContext } from './reducers.js';
import { DirectoryState } from './schema.js';
import { defaultContext, DirectoryStore } from './store.js';
import { mergeDirectory } from './metadataMerge.js';
import { createMetadataPersistence } from './metadataPersistence.js';

export const STORAGE_KEY = 'stackwallet.directory.v1';
export const SAVE_DEBOUNCE_MS = 150;

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  readonly length?: number;
  key?(index: number): string | null;
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
  flush(): Promise<void>;
  dispose(): Promise<void>;
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

  const persistence = createMetadataPersistence({
    storage,
    key: STORAGE_KEY,
    name: 'directory',
    debounceMs,
    snapshot: store.getSnapshot,
    subscribe: store.subscribe,
    adopt: (state) => store.adoptPersisted(state),
    parse: (raw) => DirectoryState.parse(JSON.parse(raw)),
    merge: (base, local, remote) => mergeDirectory(base, local, remote, ctx),
  });
  const result: PersistedStore = {
    store,
    ...persistence,
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
