import { buildLayoutDirectory, referencedIds, remapProps } from '../store/layoutBundle.js';
import { subtree } from '../store/sets.js';
import type { DirectoryStore } from '../store/store.js';
import { LayoutExport } from './schema.js';
import type { WorkspaceStore } from './store.js';

/**
 * Layouts travel with no security and no tagging: the bundle is plain JSON
 * on the clipboard, carries the wallets it shows as public addresses only,
 * and neither side records anything in key provenance. A wallet becomes more
 * than watch-only on the receiving side only when its keys arrive through
 * the gated wallet or directory export.
 */

export const MAX_LAYOUT_JSON_CHARS = 2 * 1024 * 1024;

export function exportLayoutBundle(
  workspace: WorkspaceStore,
  directory: DirectoryStore,
  layoutId?: string,
): LayoutExport | undefined {
  const base = workspace.exportLayout(layoutId);
  if (!base) return undefined;
  return {
    ...base,
    stackwalletLayout: 2,
    directory: buildLayoutDirectory(directory.getSnapshot(), base.panes),
  };
}

export interface LayoutImportReport {
  layoutId: string;
  createdWallets: number;
  matchedWallets: number;
  createdFolders: number;
  /** Panes whose wallet or folder could not be resolved and now ask for one. */
  unresolved: number;
}

export function importLayoutBundle(
  workspace: WorkspaceStore,
  directory: DirectoryStore,
  text: string,
): { ok: true; value: LayoutImportReport } | { ok: false; error: string } {
  if (text.length > MAX_LAYOUT_JSON_CHARS) return { ok: false, error: 'That layout is too large' };
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, error: 'That is not layout JSON' };
  }
  const parsed = LayoutExport.safeParse(raw);
  if (!parsed.success) return { ok: false, error: 'That JSON is not a StackWallet layout' };
  const data = parsed.data;

  let map = new Map<string, string>();
  let createdWallets = 0;
  let matchedWallets = 0;
  let createdFolders = 0;
  if (data.directory !== undefined) {
    const adopted = directory.adoptLayoutDirectory(data.directory);
    if (!adopted.ok) return adopted;
    ({ map, createdWallets, matchedWallets, createdFolders } = adopted.value);
  } else {
    // Version 1 carried bare ids; keep the ones that exist here, drop the rest.
    const state = directory.getSnapshot();
    for (const w of state.wallets) map.set(`w:${w.id}`, w.id);
    for (const f of state.folders) map.set(`f:${f.id}`, f.id);
  }
  let unresolved = 0;
  const panes = data.panes.map((p) => {
    const props = remapProps(p.props, map);
    if (
      (['walletId', 'folderId'] as const).some(
        (k) => typeof p.props[k] === 'string' && p.props[k] !== '' && props[k] === '',
      )
    )
      unresolved += 1;
    return { ...p, props };
  });
  const added = workspace.importLayout({ ...data, panes });
  if (!added.ok) return added;
  return {
    ok: true,
    value: { layoutId: added.value, createdWallets, matchedWallets, createdFolders, unresolved },
  };
}

/**
 * Layouts that show anything inside a directory, for a directory export.
 * They travel inside the sealed set with their ids intact, since the set
 * keeps its folder and wallet ids on the receiving device.
 */
export function associatedLayouts(
  workspace: WorkspaceStore,
  directory: DirectoryStore,
  folderId: string,
): LayoutExport[] {
  const state = directory.getSnapshot();
  const folders = new Set(subtree(state, folderId));
  const wallets = new Set(state.wallets.filter((w) => folders.has(w.folderId)).map((w) => w.id));
  const out: LayoutExport[] = [];
  for (const layout of workspace.getSnapshot().layouts) {
    const refs = referencedIds(layout.panes);
    const touches =
      [...refs.walletIds].some((id) => wallets.has(id)) ||
      [...refs.folderIds].some((id) => folders.has(id));
    const data = touches ? workspace.exportLayout(layout.id) : undefined;
    if (data) out.push(data);
  }
  return out;
}
