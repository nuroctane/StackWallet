import { useSyncExternalStore } from 'react';
import { mergeWorkspace } from '../store/metadataMerge.js';
import { createMetadataPersistence } from '../store/metadataPersistence.js';

import type { StorageLike } from '../store/persist.js';
import { defaultWorkspace } from './defaults.js';
import { WorkspaceState, type Layout, type Pane } from './schema.js';
import { defaultContext, WorkspaceStore, type StoreContext } from './store.js';

export type { StorageLike };

export const WORKSPACE_STORAGE_KEY = 'stackwallet.workspace.v1';
export const WORKSPACE_SAVE_DEBOUNCE_MS = 150;

export interface WorkspaceLoadResult {
  state: WorkspaceState;
  /** Set when an unreadable blob was moved aside and the default workspace started. */
  quarantinedKey?: string;
}

export function loadWorkspace(
  storage: StorageLike | null,
  ctx: StoreContext,
  initial: () => WorkspaceState = () => defaultWorkspace(ctx),
): WorkspaceLoadResult {
  if (!storage) return { state: initial() };
  let raw: string | null = null;
  try {
    raw = storage.getItem(WORKSPACE_STORAGE_KEY);
  } catch {
    return { state: initial() };
  }
  if (raw === null || raw === '') return { state: initial() };

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  const result = parsed === undefined ? undefined : WorkspaceState.safeParse(parsed);
  if (result?.success) return { state: repairActive(result.data) };

  // Keep the original until a coordinated save replaces it; another tab may
  // have published a valid layout since this read.
  const quarantinedKey = `${WORKSPACE_STORAGE_KEY}.corrupt-${ctx.now()}`;
  try {
    storage.setItem(quarantinedKey, raw);
  } catch {
    // Storage full or blocked: nothing more we can do but start fresh.
  }
  return { state: initial(), quarantinedKey };
}

function repairActive(state: WorkspaceState): WorkspaceState {
  if (state.layouts.some((l) => l.id === state.activeId)) return state;
  return { ...state, activeId: (state.layouts[0] as Layout).id, focusedPaneId: null };
}

export function saveWorkspace(storage: StorageLike, state: WorkspaceState): boolean {
  try {
    storage.setItem(WORKSPACE_STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

export interface PersistedWorkspace {
  store: WorkspaceStore;
  quarantinedKey?: string;
  flush(): Promise<void>;
  dispose(): Promise<void>;
}

export function createPersistedWorkspace(
  options: {
    storage?: StorageLike | null;
    ctx?: StoreContext;
    debounceMs?: number;
    initial?: () => WorkspaceState;
  } = {},
): PersistedWorkspace {
  const ctx = options.ctx ?? defaultContext;
  const storage = options.storage === undefined ? safeLocalStorage() : options.storage;
  const debounceMs = options.debounceMs ?? WORKSPACE_SAVE_DEBOUNCE_MS;
  const loaded = loadWorkspace(storage, ctx, options.initial ?? (() => defaultWorkspace(ctx)));
  const store = new WorkspaceStore(loaded.state, ctx);

  const persistence = createMetadataPersistence({
    storage,
    key: WORKSPACE_STORAGE_KEY,
    name: 'layout',
    debounceMs,
    snapshot: store.getSnapshot,
    subscribe: store.subscribe,
    adopt: (state) => store.adoptPersisted(state),
    parse: (raw) => repairActive(WorkspaceState.parse(JSON.parse(raw))),
    merge: mergeWorkspace,
  });
  const result: PersistedWorkspace = {
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
    const probe = `${WORKSPACE_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

const persisted = createPersistedWorkspace();

export const workspace: WorkspaceStore = persisted.store;
export const workspaceQuarantinedKey: string | undefined = persisted.quarantinedKey;

export function useWorkspace(): WorkspaceState {
  return useSyncExternalStore(workspace.subscribe, workspace.getSnapshot, workspace.getSnapshot);
}

const getActive = () => workspace.active;

export function useActiveLayout(): Layout {
  return useSyncExternalStore(workspace.subscribe, getActive, getActive);
}

export function usePane(id: string): Pane | undefined {
  // Panes are immutable records, so returning the same reference until the
  // pane itself changes keeps unrelated panes from re-rendering.
  const get = () => workspace.active.panes.find((p) => p.id === id);
  return useSyncExternalStore(workspace.subscribe, get, get);
}
