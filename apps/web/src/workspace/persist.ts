import { useSyncExternalStore } from 'react';
import { reportStorageSave } from '../store/storageStatus.js';

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

  // A hand-built layout is worth keeping for manual recovery. The live key is
  // cleared so the same blob is not quarantined again on every reload.
  const quarantinedKey = `${WORKSPACE_STORAGE_KEY}.corrupt-${ctx.now()}`;
  try {
    storage.setItem(quarantinedKey, raw);
    storage.removeItem(WORKSPACE_STORAGE_KEY);
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
  flush(): void;
  dispose(): void;
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

  let timer: ReturnType<typeof setTimeout> | undefined;
  let dirty = false;
  let failures = 0;
  let disposed = false;
  const flush = () => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    if (!dirty) return;
    const ok = !!storage && saveWorkspace(storage, store.getSnapshot());
    reportStorageSave('layout', ok);
    if (ok) {
      dirty = false;
      failures = 0;
    } else if (!disposed && ++failures < 3) timer = setTimeout(flush, 5_000);
  };
  const unsubscribe = store.subscribe(() => {
    dirty = true;
    failures = 0;
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(flush, debounceMs);
  });

  const hasWindow = typeof window !== 'undefined';
  if (hasWindow) window.addEventListener('pagehide', flush);
  if (hasWindow) window.addEventListener('focus', flush);

  const result: PersistedWorkspace = {
    store,
    flush,
    dispose() {
      disposed = true;
      unsubscribe();
      if (hasWindow) window.removeEventListener('pagehide', flush);
      if (hasWindow) window.removeEventListener('focus', flush);
      flush();
    },
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
