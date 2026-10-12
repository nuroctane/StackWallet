import { z } from 'zod';

/**
 * Element kinds the workspace can host. The registry in `elements/registry.ts`
 * maps each to a component; the schema only needs the closed set so a saved
 * layout from a newer build fails loudly instead of rendering a blank frame.
 */
export const ElementKind = z.enum([
  'overview',
  'directory',
  'wallet',
  'folder',
  'holdings',
  'terrain',
  'activityLog',
  'ledger',
  'transactions',
  'approvals',
  'devices',
  'network',
  'collectibles',
]);
export type ElementKind = z.infer<typeof ElementKind>;

/** Element props are a flat bag of scalars so every pane serialises to one JSON line. */
export const PaneProps = z.record(z.string(), z.union([z.string(), z.number(), z.boolean()]));
export type PaneProps = z.infer<typeof PaneProps>;

export const PANE_MIN_W = 240;
export const PANE_MIN_H = 120;
export const PANE_MAX = 20_000;

export const Pane = z.object({
  id: z.string().min(1),
  kind: ElementKind,
  props: PaneProps,
  x: z.number().min(-PANE_MAX).max(PANE_MAX),
  y: z.number().min(-PANE_MAX).max(PANE_MAX),
  w: z.number().min(PANE_MIN_W).max(PANE_MAX),
  h: z.number().min(PANE_MIN_H).max(PANE_MAX),
  z: z.number().int().min(0),
  /** Set while the pane fills the canvas; the saved rect is restored on exit. */
  fullscreen: z.boolean().optional(),
});
export type Pane = z.infer<typeof Pane>;

export const MAX_PANES_PER_LAYOUT = 64;
export const MAX_LAYOUTS = 32;

export const Layout = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(60),
  panes: Pane.array().max(MAX_PANES_PER_LAYOUT),
  /** Scroll offset of the canvas so a layout reopens where it was left. */
  scrollX: z.number().default(0),
  scrollY: z.number().default(0),
});
export type Layout = z.infer<typeof Layout>;

export const WORKSPACE_VERSION = 1 as const;

export const WorkspaceState = z.object({
  version: z.literal(WORKSPACE_VERSION),
  layouts: Layout.array().min(1).max(MAX_LAYOUTS),
  activeId: z.string().min(1),
  /** Locked layouts ignore drag and resize gestures; everything else still works. */
  locked: z.boolean(),
  /** Pane that owns keyboard focus for nudge/resize/close shortcuts. */
  focusedPaneId: z.string().nullable(),
});
export type WorkspaceState = z.infer<typeof WorkspaceState>;

/** Portable form of one pane, used by "copy element config" and the catalogue. */
export const PaneConfig = Pane.pick({ kind: true, props: true, w: true, h: true });
export type PaneConfig = z.infer<typeof PaneConfig>;

/** Portable form of a layout for export/import through the clipboard. */
export const LayoutExport = z.object({
  stackwalletLayout: z.literal(1),
  name: Layout.shape.name,
  panes: PaneConfig.extend({ x: Pane.shape.x, y: Pane.shape.y }).array().max(MAX_PANES_PER_LAYOUT),
});
export type LayoutExport = z.infer<typeof LayoutExport>;
