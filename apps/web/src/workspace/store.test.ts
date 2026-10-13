import { describe, expect, it } from 'vitest';

import {
  LayoutExport,
  MAX_PANES_PER_LAYOUT,
  PANE_MAX,
  PANE_MIN_H,
  PANE_MIN_W,
  type Pane,
  type PaneConfig,
  WorkspaceState,
} from './schema.js';
import {
  clampRect,
  emptyState,
  GRID,
  placeNew,
  SNAP_TOLERANCE,
  snapRect,
  WorkspaceStore,
  type Rect,
  type StoreContext,
} from './store.js';

function makeCtx(): StoreContext {
  let t = 1_000;
  let n = 0;
  return { now: () => t++, newId: () => `id-${++n}` };
}

const VIEWPORT: Rect = { x: 0, y: 0, w: 1440, h: 820 };
const CFG: PaneConfig = { kind: 'wallet', props: {}, w: 240, h: 120 };

describe('collapse and fullscreen transitions', () => {
  it('retains geometry through collapse, fullscreen and restore, including saved layouts', () => {
    const { store } = makeStore();
    const added = store.addPane(CFG, VIEWPORT);
    if (!added.ok) throw new Error(added.error);
    const id = added.value;
    store.setRect(id, { x: 80, y: 96, w: 400, h: 320 });
    store.toggleCollapsed(id);
    const saved = WorkspaceState.parse(JSON.parse(JSON.stringify(store.getSnapshot())));
    expect(saved.layouts[0]?.panes[0]?.collapsed).toBe(true);
    const exported = LayoutExport.parse(store.exportLayout());
    expect(exported.panes[0]?.collapsed).toBe(true);
    store.toggleFullscreen(id);
    expect(paneAt(store, id)).toMatchObject({ fullscreen: true, collapsed: false });
    store.toggleCollapsed(id);
    expect(paneAt(store, id)).toMatchObject({ fullscreen: false, collapsed: true });
    store.toggleCollapsed(id);
    expect(paneAt(store, id)).toMatchObject({ x: 80, y: 96, w: 400, h: 320, collapsed: false });
  });

  it('allows only one fullscreen pane and does not change state for an unknown id', () => {
    const { store } = makeStore();
    const a = store.addPane(CFG, VIEWPORT);
    const b = store.addPane(CFG, VIEWPORT);
    if (!a.ok || !b.ok) throw new Error('pane creation failed');
    store.toggleFullscreen(a.value);
    store.toggleFullscreen(b.value);
    expect(paneAt(store, a.value).fullscreen).toBe(false);
    expect(paneAt(store, b.value).fullscreen).toBe(true);
    const before = store.getSnapshot();
    store.toggleFullscreen('missing');
    expect(store.getSnapshot()).toBe(before);
  });
});

function makeStore() {
  const ctx = makeCtx();
  const store = new WorkspaceStore(emptyState(ctx), ctx);
  let notified = 0;
  store.subscribe(() => notified++);
  return { ctx, store, count: () => notified };
}

function paneAt(store: WorkspaceStore, id: string): Pane {
  const p = store.active.panes.find((x) => x.id === id);
  if (!p) throw new Error(`pane ${id} missing`);
  return p;
}

const overlaps = (a: Rect, b: Rect) =>
  a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;

describe('placeNew', () => {
  it('puts the first pane one grid step inside the viewport', () => {
    expect(placeNew([], 240, 120, { x: 100, y: 50, w: 800, h: 600 })).toEqual({
      x: 100 + GRID,
      y: 50 + GRID,
      w: 240,
      h: 120,
    });
  });

  it('picks a free slot that does not overlap existing panes', () => {
    const existing: Pane = { id: 'a', kind: 'wallet', props: {}, x: 8, y: 8, w: 240, h: 120, z: 0 };
    const r = placeNew([existing], 240, 120, VIEWPORT);
    expect(overlaps(r, existing)).toBe(false);
    expect(r.y).toBe(8);
    expect(r.x % GRID).toBe(0);
  });

  it('cascades from the top pane when the viewport is full', () => {
    const existing: Pane = { id: 'a', kind: 'wallet', props: {}, x: 8, y: 8, w: 240, h: 120, z: 3 };
    const r = placeNew([existing], 240, 120, { x: 0, y: 0, w: 256, h: 136 });
    expect(r).toEqual({ x: 32, y: 32, w: 240, h: 120 });
  });
});

describe('clampRect', () => {
  it('enforces minimum size and canvas bounds', () => {
    expect(clampRect({ x: -99_999, y: 99_999, w: 1, h: 1 })).toEqual({
      x: -PANE_MAX,
      y: PANE_MAX,
      w: PANE_MIN_W,
      h: PANE_MIN_H,
    });
  });
});

describe('snapRect', () => {
  const other: Rect = { x: 300, y: 0, w: 100, h: 100 };

  it('snaps to the grid when no neighbour is close', () => {
    expect(snapRect({ x: 13, y: 19, w: 240, h: 120 }, [], 'move')).toEqual({
      x: 16,
      y: 16,
      w: 240,
      h: 120,
    });
  });

  it('moves the left edge onto a neighbour edge within tolerance', () => {
    const r = snapRect({ x: 403, y: 300, w: 240, h: 120 }, [other], 'move');
    expect(r.x).toBe(400);
    expect(r.w).toBe(240);
  });

  it('moves the right edge onto a neighbour gutter within tolerance', () => {
    const r = snapRect({ x: 55, y: 300, w: 240, h: 120 }, [other], 'move');
    expect(r.x + r.w).toBe(other.x - GRID);
    expect(r.w).toBe(240);
  });

  it('ignores neighbour edges beyond the tolerance', () => {
    const far = 400 + SNAP_TOLERANCE + 3;
    const r = snapRect({ x: far, y: 300, w: 240, h: 120 }, [other], 'move');
    expect(r.x).toBe(Math.round(far / GRID) * GRID);
  });

  it('resizes by snapping only the right and bottom edges', () => {
    const r = snapRect({ x: 0, y: -100, w: 297, h: 203 }, [other], 'resize');
    expect(r.x).toBe(0);
    expect(r.y).toBe(-100);
    expect(r.w).toBe(300);
    expect(r.h).toBe(200);
  });

  it('resizes to the grid without neighbours', () => {
    // The moving edges land on the grid, so the size follows from the snapped edge.
    const r = snapRect({ x: 8, y: 8, w: 253, h: 131 }, [], 'resize');
    expect(r.x + r.w).toBe(264);
    expect(r.y + r.h).toBe(136);
  });
});

describe('WorkspaceStore panes', () => {
  it('adds panes with increasing z, focuses the new one and never exceeds the cap', () => {
    const { store } = makeStore();
    const a = store.addPane(CFG, VIEWPORT);
    const b = store.addPane(CFG, VIEWPORT);
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(paneAt(store, a.value).z).toBe(0);
    expect(paneAt(store, b.value).z).toBe(1);
    expect(store.getSnapshot().focusedPaneId).toBe(b.value);
    expect(overlaps(paneAt(store, a.value), paneAt(store, b.value))).toBe(false);

    for (let i = store.active.panes.length; i < MAX_PANES_PER_LAYOUT; i++) {
      expect(store.addPane(CFG, VIEWPORT, { x: i * 8, y: 0 }).ok).toBe(true);
    }
    expect(store.active.panes).toHaveLength(MAX_PANES_PER_LAYOUT);
    const over = store.addPane(CFG, VIEWPORT);
    expect(over.ok).toBe(false);
  });

  it('places at an explicit point snapped to the grid and clamped to minimum size', () => {
    const { store } = makeStore();
    const r = store.addPane({ ...CFG, w: 10, h: 10 }, VIEWPORT, { x: 13, y: 21 });
    if (!r.ok) throw new Error(r.error);
    const p = paneAt(store, r.value);
    expect([p.x, p.y, p.w, p.h]).toEqual([16, 24, PANE_MIN_W, PANE_MIN_H]);
  });

  it('removePane drops the pane and clears focus; unknown ids do not notify', () => {
    const { store, count } = makeStore();
    const r = store.addPane(CFG, VIEWPORT);
    if (!r.ok) throw new Error(r.error);
    const before = count();
    store.removePane('nope');
    expect(count()).toBe(before);
    store.removePane(r.value);
    expect(store.active.panes).toHaveLength(0);
    expect(store.getSnapshot().focusedPaneId).toBeNull();
  });

  it('setRect clamps and skips no-op updates', () => {
    const { store, count } = makeStore();
    const r = store.addPane(CFG, VIEWPORT);
    if (!r.ok) throw new Error(r.error);
    store.setRect(r.value, { x: 0, y: 0, w: 1, h: 1 });
    let p = paneAt(store, r.value);
    expect([p.w, p.h]).toEqual([PANE_MIN_W, PANE_MIN_H]);
    store.setRect(r.value, { x: PANE_MAX * 2, y: -PANE_MAX * 2, w: PANE_MAX * 2, h: 200 });
    p = paneAt(store, r.value);
    expect([p.x, p.y, p.w, p.h]).toEqual([PANE_MAX, -PANE_MAX, PANE_MAX, 200]);
    const before = count();
    store.setRect(r.value, { x: p.x, y: p.y, w: p.w, h: p.h });
    expect(count()).toBe(before);
  });

  it('nudge and grow move and resize within limits', () => {
    const { store } = makeStore();
    const r = store.addPane(CFG, VIEWPORT);
    if (!r.ok) throw new Error(r.error);
    const start = paneAt(store, r.value);
    store.nudge(r.value, 8, -8);
    expect(paneAt(store, r.value)).toMatchObject({ x: start.x + 8, y: start.y - 8 });
    store.grow(r.value, 16, -1000);
    expect(paneAt(store, r.value)).toMatchObject({ w: start.w + 16, h: PANE_MIN_H });
  });

  it('raise brings a pane to the top and compacts z past 10_000', () => {
    const ctx = makeCtx();
    const base = emptyState(ctx);
    const low: Pane = { id: 'low', kind: 'wallet', props: {}, x: 0, y: 0, w: 240, h: 120, z: 0 };
    const mid: Pane = { ...low, id: 'mid', z: 5 };
    const high: Pane = { ...low, id: 'high', z: 10_000 };
    const layout = {
      ...(base.layouts[0] as (typeof base.layouts)[number]),
      panes: [low, mid, high],
    };
    const store = new WorkspaceStore({ ...base, layouts: [layout] }, ctx);
    let notified = 0;
    store.subscribe(() => notified++);

    store.raise('high');
    expect(notified).toBe(0);

    store.raise('low');
    const zs = Object.fromEntries(store.active.panes.map((p) => [p.id, p.z]));
    expect(zs).toEqual({ mid: 0, high: 1, low: 2 });
  });

  it('setProps merges into existing props', () => {
    const { store } = makeStore();
    const r = store.addPane({ ...CFG, props: { a: 1, b: 'x' } }, VIEWPORT);
    if (!r.ok) throw new Error(r.error);
    store.setProps(r.value, { b: 'y', c: true });
    expect(paneAt(store, r.value).props).toEqual({ a: 1, b: 'y', c: true });
  });

  it('toggleFullscreen flips the flag and raises the pane', () => {
    const { store } = makeStore();
    const a = store.addPane(CFG, VIEWPORT);
    const b = store.addPane(CFG, VIEWPORT);
    if (!a.ok || !b.ok) throw new Error('add failed');
    store.toggleFullscreen(a.value);
    expect(paneAt(store, a.value).fullscreen).toBe(true);
    expect(paneAt(store, a.value).z).toBeGreaterThan(paneAt(store, b.value).z);
    store.toggleFullscreen(a.value);
    expect(paneAt(store, a.value).fullscreen).toBe(false);
  });

  it('focus and findPane', () => {
    const { store, count } = makeStore();
    const a = store.addPane({ ...CFG, kind: 'folder', props: { folderId: 'f1' } }, VIEWPORT);
    const b = store.addPane({ ...CFG, kind: 'folder', props: { folderId: 'f2' } }, VIEWPORT);
    if (!a.ok || !b.ok) throw new Error('add failed');
    const before = count();
    store.focus(b.value);
    expect(count()).toBe(before);
    expect(store.findPane('folder')?.id).toBe(a.value);
    expect(store.findPane('folder', (p) => p['folderId'] === 'f2')?.id).toBe(b.value);
    expect(store.findPane('wallet')).toBeUndefined();
  });
});

describe('WorkspaceStore layouts', () => {
  it('addLayout activates the new layout and falls back to a generated name', () => {
    const { store } = makeStore();
    const r = store.addLayout('   ');
    if (!r.ok) throw new Error(r.error);
    expect(store.getSnapshot().activeId).toBe(r.value);
    expect(store.active.name).toBe('layout 2');
  });

  it('duplicateLayout copies panes with fresh ids', () => {
    const { store } = makeStore();
    const src = store.active.id;
    const a = store.addPane(CFG, VIEWPORT);
    if (!a.ok) throw new Error(a.error);
    const dup = store.duplicateLayout(src);
    if (!dup.ok) throw new Error(dup.error);
    expect(store.active.name).toBe('home copy');
    expect(store.active.panes).toHaveLength(1);
    expect(store.active.panes[0]?.id).not.toBe(a.value);
    expect(store.active.panes[0]).toMatchObject({ kind: 'wallet', w: 240, h: 120 });
    expect(store.duplicateLayout('missing').ok).toBe(false);
  });

  it('renameLayout trims and rejects empty names', () => {
    const { store } = makeStore();
    const id = store.active.id;
    expect(store.renameLayout(id, '  work  ').ok).toBe(true);
    expect(store.active.name).toBe('work');
    const bad = store.renameLayout(id, '   ');
    expect(bad.ok).toBe(false);
    expect(store.active.name).toBe('work');
  });

  it('removeLayout keeps the last layout and moves active to the first', () => {
    const { store } = makeStore();
    const first = store.active.id;
    expect(store.removeLayout(first).ok).toBe(false);
    const second = store.addLayout('two');
    if (!second.ok) throw new Error(second.error);
    expect(store.getSnapshot().activeId).toBe(second.value);
    expect(store.removeLayout(second.value).ok).toBe(true);
    expect(store.getSnapshot().activeId).toBe(first);
    expect(store.getSnapshot().layouts).toHaveLength(1);
  });

  it('setActive ignores unknown ids and the current id', () => {
    const { store, count } = makeStore();
    const before = count();
    store.setActive('missing');
    store.setActive(store.active.id);
    expect(count()).toBe(before);
    const two = store.addLayout('two');
    if (!two.ok) throw new Error(two.error);
    store.setActive(store.getSnapshot().layouts[0]?.id ?? '');
    expect(store.active.name).toBe('home');
  });

  it('setScroll and toggleLock', () => {
    const { store, count } = makeStore();
    store.setScroll(40, 80);
    expect(store.active).toMatchObject({ scrollX: 40, scrollY: 80 });
    const before = count();
    store.setScroll(40, 80);
    expect(count()).toBe(before);
    store.toggleLock();
    expect(store.getSnapshot().locked).toBe(true);
  });

  it('exportLayout round-trips through LayoutExport.parse and importLayout', () => {
    const { store } = makeStore();
    store.addPane({ ...CFG, kind: 'terrain', props: { weeks: 12 } }, VIEWPORT);
    store.addPane(CFG, VIEWPORT, { x: 400, y: 400 });
    const exported = store.exportLayout();
    expect(exported).toBeDefined();
    const parsed = LayoutExport.parse(JSON.parse(JSON.stringify(exported)));
    const imported = store.importLayout(parsed);
    if (!imported.ok) throw new Error(imported.error);
    const copy = store.active;
    expect(copy.id).toBe(imported.value);
    expect(copy.name).toBe('home');
    expect(copy.panes.map((p) => p.z)).toEqual([0, 1]);
    expect(copy.panes.map(({ kind, props, x, y, w, h }) => ({ kind, props, x, y, w, h }))).toEqual(
      parsed.panes,
    );
    expect(store.exportLayout('missing')).toBeUndefined();
  });
});
