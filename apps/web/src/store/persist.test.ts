import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { emptyState, rootOf, type ReducerContext } from './reducers.js';
import { createPersistedStore, loadDirectory, STORAGE_KEY, type StorageLike } from './persist.js';

class MemoryStorage implements StorageLike {
  readonly map = new Map<string, string>();
  getItem(key: string) {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.map.set(key, value);
  }
  removeItem(key: string) {
    this.map.delete(key);
  }
}

function makeCtx(): ReducerContext {
  let n = 0;
  return { now: () => 5_000, newId: () => `id-${++n}` };
}

describe('loadDirectory', () => {
  it('starts fresh with no storage or an empty key', () => {
    const ctx = makeCtx();
    expect(loadDirectory(null, ctx).state.folders).toHaveLength(1);
    expect(loadDirectory(new MemoryStorage(), ctx).state.folders).toHaveLength(1);
  });

  it('round-trips a valid blob', () => {
    const ctx = makeCtx();
    const storage = new MemoryStorage();
    const state = emptyState(ctx);
    storage.setItem(STORAGE_KEY, JSON.stringify(state));
    const loaded = loadDirectory(storage, ctx);
    expect(loaded.state).toEqual(state);
    expect(loaded.quarantinedKey).toBeUndefined();
  });

  it('quarantines unparseable and schema-invalid blobs, then starts fresh', () => {
    const ctx = makeCtx();
    for (const bad of ['{not json', JSON.stringify({ version: 2, folders: [] })]) {
      const storage = new MemoryStorage();
      storage.setItem(STORAGE_KEY, bad);
      const loaded = loadDirectory(storage, ctx);
      expect(loaded.quarantinedKey).toBe(`${STORAGE_KEY}.corrupt-5000`);
      expect(storage.getItem(loaded.quarantinedKey!)).toBe(bad);
      expect(rootOf(loaded.state).name).toBe('Wallets');
    }
  });
});

describe('createPersistedStore', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('debounces saves and flushes on dispose', () => {
    const storage = new MemoryStorage();
    const { store, dispose } = createPersistedStore({ storage, ctx: makeCtx(), debounceMs: 150 });
    const root = rootOf(store.getSnapshot());

    store.createFolder('A', root.id);
    store.createFolder('B', root.id);
    expect(storage.getItem(STORAGE_KEY)).toBeNull();

    vi.advanceTimersByTime(149);
    expect(storage.getItem(STORAGE_KEY)).toBeNull();
    vi.advanceTimersByTime(1);
    const saved = JSON.parse(storage.getItem(STORAGE_KEY)!) as { folders: unknown[] };
    expect(saved.folders).toHaveLength(3);

    store.createFolder('C', root.id);
    dispose();
    const flushed = JSON.parse(storage.getItem(STORAGE_KEY)!) as { folders: unknown[] };
    expect(flushed.folders).toHaveLength(4);
  });

  it('repairs a structurally broken but schema-valid blob on load', () => {
    const ctx = makeCtx();
    const storage = new MemoryStorage();
    const state = emptyState(ctx);
    storage.setItem(
      STORAGE_KEY,
      JSON.stringify({ ...state, folders: [], ui: { expandedFolderIds: [], selectedId: 'x' } }),
    );
    const { store } = createPersistedStore({ storage, ctx });
    expect(rootOf(store.getSnapshot()).name).toBe('Wallets');
    expect(store.getSnapshot().ui.selectedId).toBeNull();
  });
});
