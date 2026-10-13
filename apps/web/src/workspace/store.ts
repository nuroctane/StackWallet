import {
  MAX_LAYOUTS,
  MAX_PANES_PER_LAYOUT,
  PANE_MAX,
  PANE_MIN_H,
  PANE_MIN_W,
  type ElementKind,
  type Layout,
  type LayoutExport,
  type Pane,
  type PaneConfig,
  type PaneProps,
  type WorkspaceState,
} from './schema.js';

export type Listener = () => void;
export type Result<T = undefined> = { ok: true; value: T } | { ok: false; error: string };

export interface StoreContext {
  now: () => number;
  newId: () => string;
}

export const defaultContext: StoreContext = {
  now: () => Date.now(),
  newId: () => crypto.randomUUID(),
};

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Grid the canvas snaps to. Pane edges also snap to each other within SNAP_TOLERANCE. */
export const GRID = 8;
export const SNAP_TOLERANCE = 6;
/** Stagger applied when a new pane would land exactly on an existing one. */
const CASCADE = 24;

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));
export const snap = (n: number) => Math.round(n / GRID) * GRID;

export function clampRect(r: Rect): Rect {
  return {
    x: clamp(r.x, -PANE_MAX, PANE_MAX),
    y: clamp(r.y, -PANE_MAX, PANE_MAX),
    w: clamp(r.w, PANE_MIN_W, PANE_MAX),
    h: clamp(r.h, PANE_MIN_H, PANE_MAX),
  };
}

export function emptyLayout(ctx: StoreContext, name = 'home'): Layout {
  return { id: ctx.newId(), name, panes: [], scrollX: 0, scrollY: 0 };
}

export function emptyState(ctx: StoreContext): WorkspaceState {
  const layout = emptyLayout(ctx);
  return { version: 1, layouts: [layout], activeId: layout.id, locked: false, focusedPaneId: null };
}

/** Find a free top-left for a new pane: next grid slot right of the rightmost pane in the top row, else cascade. */
export function placeNew(panes: readonly Pane[], w: number, h: number, viewport: Rect): Rect {
  if (panes.length === 0) return { x: viewport.x + GRID, y: viewport.y + GRID, w, h };
  const margin = GRID;
  // Scan row by row across the visible viewport for the first slot that does not overlap.
  for (let y = viewport.y + margin; y + h <= viewport.y + viewport.h; y += GRID * 4) {
    for (let x = viewport.x + margin; x + w <= viewport.x + viewport.w; x += GRID * 4) {
      const candidate = { x, y, w, h };
      if (!panes.some((p) => overlaps(candidate, p))) return candidate;
    }
  }
  // Viewport is full: cascade from the top-most pane so the new one is still reachable.
  const top = panes.reduce((a, b) => (b.z > a.z ? b : a));
  return { x: top.x + CASCADE, y: top.y + CASCADE, w, h };
}

function overlaps(a: Rect, b: Rect): boolean {
  return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;
}

/**
 * Snap a rect being dragged or resized against the grid and the edges of the
 * other panes. Pure so the gesture hook can call it every frame.
 */
export function snapRect(r: Rect, others: readonly Rect[], mode: 'move' | 'resize'): Rect {
  let { x, y, w, h } = r;
  let right = x + w;
  let bottom = y + h;
  const nearest = (value: number, targets: number[]): number | null => {
    let best: number | null = null;
    let bestD = SNAP_TOLERANCE + 1;
    for (const t of targets) {
      const d = Math.abs(value - t);
      if (d < bestD) {
        bestD = d;
        best = t;
      }
    }
    return best;
  };
  const xs: number[] = [];
  const ys: number[] = [];
  for (const o of others) {
    xs.push(o.x, o.x + o.w, o.x - GRID, o.x + o.w + GRID);
    ys.push(o.y, o.y + o.h, o.y - GRID, o.y + o.h + GRID);
  }
  if (mode === 'move') {
    const sx = nearest(x, xs) ?? nearest(right, xs);
    if (sx !== null) {
      const dx = Math.abs(sx - x) <= SNAP_TOLERANCE ? sx - x : sx - right;
      x += dx;
    } else {
      x = snap(x);
    }
    const sy = nearest(y, ys) ?? nearest(bottom, ys);
    if (sy !== null) {
      const dy = Math.abs(sy - y) <= SNAP_TOLERANCE ? sy - y : sy - bottom;
      y += dy;
    } else {
      y = snap(y);
    }
    return clampRect({ x, y, w, h });
  }
  // Resize: left/top stay put; snap the moving right/bottom edges.
  right = nearest(right, xs) ?? snap(right);
  bottom = nearest(bottom, ys) ?? snap(bottom);
  w = right - x;
  h = bottom - y;
  return clampRect({ x, y, w, h });
}

/** Minimal external store; React reads it through `useSyncExternalStore`. */
export class WorkspaceStore {
  private state: WorkspaceState;
  private readonly listeners = new Set<Listener>();
  private readonly ctx: StoreContext;

  constructor(initial: WorkspaceState, ctx: StoreContext = defaultContext) {
    this.ctx = ctx;
    this.state = initial;
  }

  readonly subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  readonly getSnapshot = (): WorkspaceState => this.state;

  private commit(next: WorkspaceState): void {
    if (next === this.state) return;
    this.state = next;
    for (const l of this.listeners) l();
  }

  get active(): Layout {
    const found = this.state.layouts.find((l) => l.id === this.state.activeId);
    // The schema guarantees at least one layout; activeId is repaired on load.
    return found ?? (this.state.layouts[0] as Layout);
  }

  private updateActive(fn: (layout: Layout) => Layout): void {
    const current = this.active;
    const next = fn(current);
    if (next === current) return;
    this.commit({
      ...this.state,
      layouts: this.state.layouts.map((l) => (l.id === current.id ? next : l)),
    });
  }

  private updatePane(id: string, fn: (pane: Pane) => Pane): void {
    this.updateActive((layout) => {
      const idx = layout.panes.findIndex((p) => p.id === id);
      if (idx < 0) return layout;
      const pane = layout.panes[idx] as Pane;
      const next = fn(pane);
      if (next === pane) return layout;
      const panes = layout.panes.slice();
      panes[idx] = next;
      return { ...layout, panes };
    });
  }

  private topZ(layout: Layout): number {
    return layout.panes.reduce((m, p) => Math.max(m, p.z), -1);
  }

  // ----- panes -----

  addPane(config: PaneConfig, viewport: Rect, at?: { x: number; y: number }): Result<string> {
    const layout = this.active;
    if (layout.panes.length >= MAX_PANES_PER_LAYOUT) {
      return { ok: false, error: `A layout holds at most ${MAX_PANES_PER_LAYOUT} elements` };
    }
    const size = clampRect({ x: 0, y: 0, w: config.w, h: config.h });
    const rect = at
      ? clampRect({ x: snap(at.x), y: snap(at.y), w: size.w, h: size.h })
      : placeNew(layout.panes, size.w, size.h, viewport);
    const id = this.ctx.newId();
    const pane: Pane = {
      id,
      kind: config.kind,
      props: config.props,
      ...(config.collapsed !== undefined ? { collapsed: config.collapsed } : {}),
      ...rect,
      z: this.topZ(layout) + 1,
    };
    this.updateActive((l) => ({ ...l, panes: [...l.panes, pane] }));
    this.focus(id);
    return { ok: true, value: id };
  }

  removePane(id: string): void {
    this.updateActive((l) =>
      l.panes.some((p) => p.id === id) ? { ...l, panes: l.panes.filter((p) => p.id !== id) } : l,
    );
    if (this.state.focusedPaneId === id) this.focus(null);
  }

  setRect(id: string, rect: Rect): void {
    const r = clampRect(rect);
    this.updatePane(id, (p) =>
      p.x === r.x && p.y === r.y && p.w === r.w && p.h === r.h ? p : { ...p, ...r },
    );
  }

  nudge(id: string, dx: number, dy: number): void {
    this.updatePane(id, (p) => ({
      ...p,
      ...clampRect({ x: p.x + dx, y: p.y + dy, w: p.w, h: p.h }),
    }));
  }

  grow(id: string, dw: number, dh: number): void {
    this.updatePane(id, (p) => ({
      ...p,
      ...clampRect({ x: p.x, y: p.y, w: p.w + dw, h: p.h + dh }),
    }));
  }

  /** Bring to front. Z values are compacted when they get large so they never overflow. */
  raise(id: string): void {
    this.updateActive((l) => {
      const top = this.topZ(l);
      const target = l.panes.find((p) => p.id === id);
      if (!target || target.z === top) return l;
      let panes = l.panes.map((p) => (p.id === id ? { ...p, z: top + 1 } : p));
      if (top + 1 > 10_000) {
        panes = panes
          .slice()
          .sort((a, b) => a.z - b.z)
          .map((p, i) => ({ ...p, z: i }));
      }
      return { ...l, panes };
    });
  }

  setProps(id: string, props: PaneProps): void {
    this.updatePane(id, (p) => ({ ...p, props: { ...p.props, ...props } }));
  }

  toggleFullscreen(id: string): void {
    this.updateActive((layout) => {
      const target = layout.panes.find((p) => p.id === id);
      if (!target) return layout;
      const entering = !target.fullscreen;
      return {
        ...layout,
        panes: layout.panes.map((p) =>
          p.id === id
            ? { ...p, fullscreen: entering, collapsed: false }
            : entering && p.fullscreen
              ? { ...p, fullscreen: false }
              : p,
        ),
      };
    });
    this.raise(id);
  }

  toggleCollapsed(id: string): void {
    this.updatePane(id, (p) => ({ ...p, collapsed: !p.collapsed, fullscreen: false }));
  }

  focus(id: string | null): void {
    if (this.state.focusedPaneId === id) return;
    this.commit({ ...this.state, focusedPaneId: id });
  }

  /** First pane of a kind in the active layout, used to reuse a pane instead of stacking duplicates. */
  findPane(kind: ElementKind, match?: (props: PaneProps) => boolean): Pane | undefined {
    return this.active.panes.find((p) => p.kind === kind && (!match || match(p.props)));
  }

  // ----- layouts -----

  addLayout(name: string, panes: Pane[] = []): Result<string> {
    if (this.state.layouts.length >= MAX_LAYOUTS) {
      return { ok: false, error: `At most ${MAX_LAYOUTS} layouts` };
    }
    const trimmed = name.trim().slice(0, 60) || `layout ${this.state.layouts.length + 1}`;
    const layout: Layout = { ...emptyLayout(this.ctx, trimmed), panes };
    this.commit({
      ...this.state,
      layouts: [...this.state.layouts, layout],
      activeId: layout.id,
      focusedPaneId: null,
    });
    return { ok: true, value: layout.id };
  }

  duplicateLayout(id: string): Result<string> {
    const src = this.state.layouts.find((l) => l.id === id);
    if (!src) return { ok: false, error: 'Layout not found' };
    const panes = src.panes.map((p) => ({ ...p, id: this.ctx.newId() }));
    return this.addLayout(`${src.name} copy`, panes);
  }

  renameLayout(id: string, name: string): Result {
    const trimmed = name.trim().slice(0, 60);
    if (!trimmed) return { ok: false, error: 'Name is required' };
    this.commit({
      ...this.state,
      layouts: this.state.layouts.map((l) => (l.id === id ? { ...l, name: trimmed } : l)),
    });
    return { ok: true, value: undefined };
  }

  removeLayout(id: string): Result {
    if (this.state.layouts.length <= 1)
      return { ok: false, error: 'The last layout cannot be removed' };
    const layouts = this.state.layouts.filter((l) => l.id !== id);
    const activeId = this.state.activeId === id ? (layouts[0] as Layout).id : this.state.activeId;
    this.commit({ ...this.state, layouts, activeId, focusedPaneId: null });
    return { ok: true, value: undefined };
  }

  setActive(id: string): void {
    if (this.state.activeId === id || !this.state.layouts.some((l) => l.id === id)) return;
    this.commit({ ...this.state, activeId: id, focusedPaneId: null });
  }

  setScroll(x: number, y: number): void {
    this.updateActive((l) =>
      l.scrollX === x && l.scrollY === y ? l : { ...l, scrollX: x, scrollY: y },
    );
  }

  toggleLock(): void {
    this.commit({ ...this.state, locked: !this.state.locked });
  }

  exportLayout(id = this.state.activeId): LayoutExport | undefined {
    const layout = this.state.layouts.find((l) => l.id === id);
    if (!layout) return undefined;
    return {
      stackwalletLayout: 1,
      name: layout.name,
      panes: layout.panes.map(({ kind, props, x, y, w, h, collapsed }) => ({
        kind,
        props,
        x,
        y,
        w,
        h,
        ...(collapsed !== undefined ? { collapsed } : {}),
      })),
    };
  }

  importLayout(data: LayoutExport): Result<string> {
    const panes: Pane[] = data.panes.map((p, i) => ({ ...p, id: this.ctx.newId(), z: i }));
    return this.addLayout(data.name, panes);
  }
}
