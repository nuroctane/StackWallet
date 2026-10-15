import type { ElementKind, Layout, Pane, PaneProps, WorkspaceState } from './schema.js';
import type { StoreContext } from './store.js';

/** Starting size for each element kind when it is added from the catalogue. */
export const elementDefaults: Record<ElementKind, { w: number; h: number }> = {
  overview: { w: 640, h: 220 },
  directory: { w: 300, h: 520 },
  wallet: { w: 620, h: 440 },
  folder: { w: 620, h: 440 },
  holdings: { w: 760, h: 360 },
  terrain: { w: 520, h: 300 },
  activityLog: { w: 520, h: 380 },
  ledger: { w: 620, h: 300 },
  transactions: { w: 680, h: 480 },
  approvals: { w: 320, h: 360 },
  devices: { w: 760, h: 520 },
  network: { w: 640, h: 420 },
  agent: { w: 520, h: 560 },
  automations: { w: 520, h: 480 },
  collectibles: { w: 640, h: 480 },
  watchlist: { w: 560, h: 420 },
  candles: { w: 680, h: 420 },
  portfolio: { w: 620, h: 480 },
  alerts: { w: 440, h: 460 },
  tax: { w: 760, h: 620 },
};

interface Seed {
  kind: ElementKind;
  x: number;
  y: number;
  w: number;
  h: number;
  props?: PaneProps;
}

// Both default layouts are laid out for a 1440x820 canvas with an 8px gutter
// on every side so a fresh install shows every element without scrolling.
const HOME: readonly Seed[] = [
  { kind: 'overview', x: 8, y: 8, w: 688, h: 384 },
  { kind: 'watchlist', x: 704, y: 8, w: 416, h: 384 },
  { kind: 'approvals', x: 1128, y: 8, w: 296, h: 784 },
  { kind: 'directory', x: 8, y: 400, w: 296, h: 392 },
  { kind: 'holdings', x: 312, y: 400, w: 384, h: 392, props: { hideZero: false } },
  { kind: 'ledger', x: 704, y: 400, w: 416, h: 392, props: { range: '30d' } },
];

const DEVICES: readonly Seed[] = [
  { kind: 'devices', x: 8, y: 8, w: 760, h: 520 },
  { kind: 'network', x: 776, y: 8, w: 640, h: 424 },
];

function seedLayout(ctx: StoreContext, name: string, seeds: readonly Seed[]): Layout {
  const panes: Pane[] = seeds.map((s, i) => ({
    id: ctx.newId(),
    kind: s.kind,
    props: s.props ?? {},
    x: s.x,
    y: s.y,
    w: s.w,
    h: s.h,
    z: i,
  }));
  return { id: ctx.newId(), name, panes, scrollX: 0, scrollY: 0 };
}

export function defaultWorkspace(ctx: StoreContext): WorkspaceState {
  const home = seedLayout(ctx, 'home', HOME);
  const devices = seedLayout(ctx, 'devices', DEVICES);
  return {
    version: 1,
    layouts: [home, devices],
    activeId: home.id,
    locked: false,
    focusedPaneId: null,
  };
}
