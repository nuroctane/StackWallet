import { ensureRoot, rootOf, type ReducerContext } from './reducers.js';
import { subtree } from './sets.js';
import { DirectoryState } from './schema.js';
import { WorkspaceState } from '../workspace/schema.js';

export class MetadataConflict extends Error {}
const equal = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const object = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);
const entity = (v: unknown): v is Record<string, unknown> & { id: string } =>
  object(v) && typeof v.id === 'string';

function merge(base: unknown, local: unknown, remote: unknown, path = ''): unknown {
  if (equal(local, base)) return remote;
  if (equal(remote, base) || equal(local, remote)) return local;
  if (path.endsWith('.updatedAtMs') && typeof local === 'number' && typeof remote === 'number')
    return Math.max(local, remote);
  if (object(base) && object(local) && object(remote)) {
    const result: Record<string, unknown> = {};
    const pane =
      typeof local.kind === 'string' && object(local.props) && typeof local.w === 'number';
    for (const key of new Set([
      ...Object.keys(base),
      ...Object.keys(local),
      ...Object.keys(remote),
    ])) {
      if (pane && (key === 'fullscreen' || key === 'collapsed')) continue;
      if (
        (path === '' && ['ui', 'activeId', 'focusedPaneId'].includes(key)) ||
        (pane && key === 'z') ||
        (Array.isArray(local.panes) && ['scrollX', 'scrollY'].includes(key))
      ) {
        result[key] = local[key];
        continue;
      }
      const value = merge(base[key], local[key], remote[key], `${path}.${key}`);
      if (value !== undefined) result[key] = value;
    }
    if (pane) {
      const modes = (value: Record<string, unknown>) => [
        value.fullscreen === true,
        value.collapsed === true,
      ];
      const chosen = equal(modes(local), modes(base)) ? remote : local;
      result.fullscreen = chosen.fullscreen === true;
      result.collapsed = !result.fullscreen && chosen.collapsed === true;
    }
    return result;
  }
  if (
    Array.isArray(base) &&
    Array.isArray(local) &&
    Array.isArray(remote) &&
    [...base, ...local, ...remote].every(entity)
  ) {
    const index = (rows: unknown[]) => {
      const result = new Map<string, unknown>();
      for (const row of rows) {
        if (!entity(row) || result.has(row.id))
          throw new MetadataConflict(`Duplicate id in ${path}`);
        result.set(row.id, row);
      }
      return result;
    };
    const b = index(base),
      l = index(local),
      r = index(remote);
    const result: unknown[] = [];
    for (const id of new Set([...r.keys(), ...l.keys(), ...b.keys()])) {
      const value = merge(b.get(id), l.get(id), r.get(id), `${path}.${id}`);
      if (value !== undefined) result.push(value);
    }
    return result;
  }
  throw new MetadataConflict(
    `Conflicting changes at ${path || 'metadata'}. A recovery copy is available.`,
  );
}

export function mergeDirectory(
  base: DirectoryState,
  local: DirectoryState,
  remote: DirectoryState,
  ctx: ReducerContext,
): DirectoryState {
  const canonical = rootOf(remote).id;
  const normalize = (state: DirectoryState) => {
    const old = rootOf(state).id;
    if (old === canonical) return state;
    if (state.folders.some((f) => f.id === canonical))
      throw new MetadataConflict('Directory roots conflict');
    const id = (value: string | null) => (value === old ? canonical : value);
    return {
      ...state,
      folders: state.folders.map((f) => ({ ...f, id: id(f.id)!, parentId: id(f.parentId) })),
      wallets: state.wallets.map((w) => ({ ...w, folderId: id(w.folderId)! })),
      ui: {
        ...state.ui,
        selectedId: id(state.ui.selectedId),
        expandedFolderIds: state.ui.expandedFolderIds.map((v) => id(v)!),
      },
    };
  };
  const normalizedLocal = normalize(local);
  const result = DirectoryState.parse(merge(normalize(base), normalizedLocal, remote));
  result.ui = normalizedLocal.ui;
  const ids = new Set([...result.folders, ...result.wallets, ...result.accounts].map((v) => v.id));
  if (ids.size !== result.folders.length + result.wallets.length + result.accounts.length)
    throw new MetadataConflict('Directory ids conflict');
  const folders = new Set(result.folders.map((v) => v.id));
  const wallets = new Set(result.wallets.map((v) => v.id));
  if (
    result.wallets.some((v) => !folders.has(v.folderId)) ||
    result.accounts.some((v) => !wallets.has(v.walletId))
  )
    throw new MetadataConflict(
      'A concurrent deletion conflicts with newly added wallet information',
    );
  if (
    result.folders.filter((f) => f.parentId === null).length !== 1 ||
    subtree(result, rootOf(result).id).length !== result.folders.length
  )
    throw new MetadataConflict('Concurrent folder moves create a cyclic or disconnected directory');
  return ensureRoot(result, ctx);
}

export function mergeWorkspace(
  base: WorkspaceState,
  local: WorkspaceState,
  remote: WorkspaceState,
  bootstrap = false,
): WorkspaceState {
  const mapping = new Map<string, string>();
  for (const layout of bootstrap ? base.layouts : []) {
    if (remote.layouts.some((l) => l.id === layout.id)) continue;
    const matches = remote.layouts.filter((l) => l.name === layout.name);
    if (matches.length !== 1) continue;
    const other = matches[0]!;
    mapping.set(layout.id, other.id);
    const used = new Set<string>();
    for (const pane of layout.panes) {
      const candidates = other.panes.filter(
        (p) => !used.has(p.id) && p.kind === pane.kind && equal(p.props, pane.props),
      );
      const match =
        candidates.find((p) => p.x === pane.x && p.y === pane.y) ??
        (candidates.length === 1 ? candidates[0] : undefined);
      if (match) {
        mapping.set(pane.id, match.id);
        used.add(match.id);
      }
    }
  }
  const normalize = (state: WorkspaceState) => ({
    ...state,
    activeId: mapping.get(state.activeId) ?? state.activeId,
    focusedPaneId: state.focusedPaneId
      ? (mapping.get(state.focusedPaneId) ?? state.focusedPaneId)
      : null,
    layouts: state.layouts.map((l) => ({
      ...l,
      id: mapping.get(l.id) ?? l.id,
      panes: l.panes.map((p) => ({ ...p, id: mapping.get(p.id) ?? p.id })),
    })),
  });
  const result = WorkspaceState.parse(merge(normalize(base), normalize(local), remote));
  const layoutIds = new Set(result.layouts.map((l) => l.id));
  const paneIds = result.layouts.flatMap((l) => l.panes.map((p) => p.id));
  if (layoutIds.size !== result.layouts.length || new Set(paneIds).size !== paneIds.length)
    throw new MetadataConflict('Layout ids conflict');
  const normalizedLocal = normalize(local);
  result.activeId = normalizedLocal.activeId;
  result.focusedPaneId = normalizedLocal.focusedPaneId;
  for (const layout of result.layouts) {
    const previous = normalizedLocal.layouts.find((l) => l.id === layout.id);
    if (previous) {
      layout.scrollX = previous.scrollX;
      layout.scrollY = previous.scrollY;
      layout.panes = layout.panes.map((p) => {
        const prior = previous.panes.find((v) => v.id === p.id);
        return prior ? { ...p, z: prior.z } : p;
      });
    }
    const fullscreen = layout.panes.filter((p) => p.fullscreen);
    if (fullscreen.length === 0) continue;
    const preferred = normalizedLocal.layouts
      .find((l) => l.id === layout.id)
      ?.panes.find((p) => p.fullscreen)?.id;
    const winner =
      fullscreen.find((p) => p.id === preferred) ??
      fullscreen.reduce((a, b) => (a.z > b.z ? a : b));
    layout.panes = layout.panes.map((p) =>
      p.fullscreen ? { ...p, fullscreen: p.id === winner.id, collapsed: false } : p,
    );
  }
  if (!layoutIds.has(result.activeId)) result.activeId = result.layouts[0]!.id;
  if (
    !result.layouts
      .find((l) => l.id === result.activeId)
      ?.panes.some((p) => p.id === result.focusedPaneId)
  )
    result.focusedPaneId = null;
  return result;
}
