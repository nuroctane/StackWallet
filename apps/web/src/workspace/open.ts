import { directory } from '../store/persist.js';
import { taxStore } from '../store/tax.js';
import { registry as elementRegistry } from './elements/registry.js';
import { workspace } from './persist.js';
import type { ElementKind, PaneProps } from './schema.js';
import { getCanvasViewport } from './WorkspaceContext.js';

/** Raise the first pane of a kind that matches, or add one at the next free slot. */
export function openOrAddPane(
  kind: ElementKind,
  props: PaneProps = {},
  match?: (p: PaneProps) => boolean,
): void {
  const existing = workspace.findPane(kind, match);
  if (existing) {
    workspace.raise(existing.id);
    workspace.focus(existing.id);
    return;
  }
  const def = elementRegistry[kind];
  workspace.addPane(
    {
      kind,
      props: { ...(def.defaultProps ?? {}), ...props },
      w: def.defaultSize.w,
      h: def.defaultSize.h,
    },
    getCanvasViewport(),
  );
}

/** Point the tax report at one directory (or everything, for the root) and show it. */
export function openTaxFor(folderId: string | null): void {
  taxStore.setScope({ tags: [], folderIds: folderId ? [folderId] : [], excluded: [] });
  openOrAddPane('tax');
}

/**
 * Select a wallet or folder in the directory and show it. A pane already showing the item is
 * raised; otherwise the front-most pane of that kind is pointed at it, so clicking through
 * wallets reuses one pane instead of piling up a new one per click.
 */
export function openDirectoryItem(id: string): void {
  directory.reveal(id);
  const state = directory.getSnapshot();
  const isWallet = state.wallets.some((w) => w.id === id);
  const folder = isWallet ? undefined : state.folders.find((f) => f.id === id);
  if (!isWallet && (!folder || folder.parentId === null)) return;
  const kind: ElementKind = isWallet ? 'wallet' : 'folder';
  const key = isWallet ? 'walletId' : 'folderId';
  if (workspace.findPane(kind, (p) => p[key] === id)) {
    openOrAddPane(kind, { [key]: id }, (p) => p[key] === id);
    return;
  }
  const reusable = workspace.active.panes
    .filter((p) => p.kind === kind)
    .reduce<
      (typeof workspace.active.panes)[number] | undefined
    >((top, p) => (!top || p.z > top.z ? p : top), undefined);
  if (reusable) {
    workspace.setProps(reusable.id, { [key]: id });
    workspace.raise(reusable.id);
    workspace.focus(reusable.id);
    return;
  }
  // A fresh wallet or folder opens tall between the directory and approvals columns of the
  // default layout, so the tree it was picked from stays visible beside it.
  const vp = getCanvasViewport();
  const SIDE = 312;
  const w = Math.max(560, Math.min(816, vp.w - 2 * SIDE));
  const h = Math.max(440, vp.h - 16);
  const def = elementRegistry[kind];
  workspace.addPane({ kind, props: { ...(def.defaultProps ?? {}), [key]: id }, w, h }, vp, {
    x: vp.x + Math.min(SIDE, Math.max(8, vp.w - w - 8)),
    y: vp.y + 8,
  });
}
