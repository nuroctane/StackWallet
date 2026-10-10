import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { defaultWorkspace, elementDefaults } from './defaults.js';
import {
  createPersistedWorkspace,
  loadWorkspace,
  saveWorkspace,
  WORKSPACE_STORAGE_KEY,
  type StorageLike,
} from './persist.js';
import { ElementKind, WorkspaceState } from './schema.js';
import { emptyState, type Rect, type StoreContext } from './store.js';

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

function makeCtx(): StoreContext {
  let n = 0;
  return { now: () => 5_000, newId: () => `id-${++n}` };
}

const overlaps = (a: Rect, b: Rect) =>
  a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;

describe('defaultWorkspace', () => {
  it('validates, has home active and non-overlapping panes inside a 1440x820 canvas', () => {
    const state = defaultWorkspace(makeCtx());
    expect(WorkspaceState.parse(state)).toEqual(state);
    expect(state.layouts.map((l) => l.name)).toEqual(['home', 'devices']);
    expect(state.activeId).toBe(state.layouts[0]?.id);
    for (const layout of state.layouts) {
      const ids = new Set(layout.panes.map((p) => p.id));
      expect(ids.size).toBe(layout.panes.length);
      layout.panes.forEach((p, i) => {
        expect(p.z).toBe(i);
        expect(p.x % 8).toBe(0);
        expect(p.y % 8).toBe(0);
        expect(p.w % 8).toBe(0);
        expect(p.h % 8).toBe(0);
        expect(p.x).toBeGreaterThanOrEqual(8);
        expect(p.y).toBeGreaterThanOrEqual(8);
        expect(p.x + p.w).toBeLessThanOrEqual(1424);
        expect(p.y + p.h).toBeLessThanOrEqual(812);
        for (const q of layout.panes) {
          if (q !== p) expect(overlaps(p, q)).toBe(false);
        }
      });
    }
    const home = state.layouts[0]!;
    const kind = (k: string) => home.panes.find((p) => p.kind === k);
    expect(kind('terrain')?.props).toEqual({ weeks: 26 });
    expect(kind('ledger')?.props).toEqual({ range: '30d' });
    expect(kind('holdings')?.props).toEqual({ hideZero: false });
    expect(home.panes.map((p) => p.kind).sort()).toEqual(
      ['overview', 'directory', 'holdings', 'terrain', 'ledger', 'approvals'].sort(),
    );
    expect(state.layouts[1]?.panes.map((p) => p.kind)).toEqual(['devices', 'network']);
  });

  it('elementDefaults covers every kind with a valid size', () => {
    for (const k of ElementKind.options) {
      const size = elementDefaults[k];
      expect(size.w).toBeGreaterThanOrEqual(240);
      expect(size.h).toBeGreaterThanOrEqual(120);
    }
  });
});

describe('loadWorkspace', () => {
  it('starts from the default workspace with no storage or an empty key', () => {
    const ctx = makeCtx();
    expect(loadWorkspace(null, ctx).state.layouts.map((l) => l.name)).toEqual(['home', 'devices']);
    expect(loadWorkspace(new MemoryStorage(), ctx).state.layouts).toHaveLength(2);
  });

  it('uses a supplied initialiser when storage is empty', () => {
    const ctx = makeCtx();
    const loaded = loadWorkspace(new MemoryStorage(), ctx, () => emptyState(ctx));
    expect(loaded.state.layouts).toHaveLength(1);
    expect(loaded.state.layouts[0]?.panes).toHaveLength(0);
  });

  it('round-trips a valid blob', () => {
    const ctx = makeCtx();
    const storage = new MemoryStorage();
    const state = defaultWorkspace(ctx);
    expect(saveWorkspace(storage, state)).toBe(true);
    const loaded = loadWorkspace(storage, ctx);
    expect(loaded.state).toEqual(state);
    expect(loaded.quarantinedKey).toBeUndefined();
  });

  it('quarantines unparseable and schema-invalid blobs, then starts fresh', () => {
    const ctx = makeCtx();
    for (const bad of ['{not json', JSON.stringify({ version: 2, layouts: [] })]) {
      const storage = new MemoryStorage();
      storage.setItem(WORKSPACE_STORAGE_KEY, bad);
      const loaded = loadWorkspace(storage, ctx);
      expect(loaded.quarantinedKey).toBe(`${WORKSPACE_STORAGE_KEY}.corrupt-5000`);
      expect(storage.getItem(loaded.quarantinedKey!)).toBe(bad);
      expect(storage.getItem(WORKSPACE_STORAGE_KEY)).toBeNull();
      expect(loaded.state.layouts[0]?.name).toBe('home');
    }
  });

  it('repairs an activeId that matches no layout', () => {
    const ctx = makeCtx();
    const storage = new MemoryStorage();
    const state = defaultWorkspace(ctx);
    storage.setItem(
      WORKSPACE_STORAGE_KEY,
      JSON.stringify({ ...state, activeId: 'gone', focusedPaneId: 'x' }),
    );
    const loaded = loadWorkspace(storage, ctx);
    expect(loaded.quarantinedKey).toBeUndefined();
    expect(loaded.state.activeId).toBe(state.layouts[0]?.id);
    expect(loaded.state.focusedPaneId).toBeNull();
  });
});

describe('createPersistedWorkspace', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('debounces saves, flushes on demand and on dispose', () => {
    const storage = new MemoryStorage();
    const { store, flush, dispose } = createPersistedWorkspace({
      storage,
      ctx: makeCtx(),
      debounceMs: 150,
    });
    const viewport = { x: 0, y: 0, w: 1440, h: 820 };

    store.addPane({ kind: 'wallet', props: {}, w: 240, h: 120 }, viewport);
    store.addPane({ kind: 'wallet', props: {}, w: 240, h: 120 }, viewport);
    expect(storage.getItem(WORKSPACE_STORAGE_KEY)).toBeNull();

    vi.advanceTimersByTime(149);
    expect(storage.getItem(WORKSPACE_STORAGE_KEY)).toBeNull();
    vi.advanceTimersByTime(1);
    const saved = WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!));
    expect(saved.layouts[0]?.panes).toHaveLength(8);

    store.toggleLock();
    flush();
    expect(WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!)).locked).toBe(
      true,
    );

    store.toggleLock();
    dispose();
    expect(WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!)).locked).toBe(
      false,
    );

    store.toggleLock();
    vi.advanceTimersByTime(1000);
    expect(WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!)).locked).toBe(
      false,
    );
  });

  it('reports the quarantined key and uses the initialiser', () => {
    const storage = new MemoryStorage();
    storage.setItem(WORKSPACE_STORAGE_KEY, 'garbage');
    const ctx = makeCtx();
    const { store, quarantinedKey } = createPersistedWorkspace({
      storage,
      ctx,
      initial: () => emptyState(ctx),
    });
    expect(quarantinedKey).toBe(`${WORKSPACE_STORAGE_KEY}.corrupt-5000`);
    expect(store.getSnapshot().layouts[0]?.panes).toHaveLength(0);
  });
});
