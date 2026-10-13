import { describe, expect, it, vi } from 'vitest';
import { createPersistedStore, STORAGE_KEY, type StorageLike } from './persist.js';
import { emptyState, ensureRoot, rootOf } from './reducers.js';
import { flattenTree } from './selectors.js';
import { DirectoryState } from './schema.js';
import { mergeDirectory, mergeWorkspace } from './metadataMerge.js';
import { createPersistedWorkspace, WORKSPACE_STORAGE_KEY } from '../workspace/persist.js';
import { defaultWorkspace } from '../workspace/defaults.js';
import { emptyState as emptyWorkspace, WorkspaceStore } from '../workspace/store.js';
import { WorkspaceState } from '../workspace/schema.js';

class MemoryStorage implements StorageLike {
  readonly values = new Map<string, string>();
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
  key(index: number) {
    return [...this.values.keys()][index] ?? null;
  }
  get length() {
    return this.values.size;
  }
}
const context = (prefix: string) => {
  let id = 0;
  return { now: () => 100, newId: () => `${prefix}-${++id}` };
};
const folders = (storage: MemoryStorage) =>
  DirectoryState.parse(JSON.parse(storage.getItem(STORAGE_KEY)!)).folders;
const viewport = { x: 0, y: 0, w: 1440, h: 820 };
const pane = { kind: 'overview' as const, props: {}, w: 320, h: 240 };
function seedDirectory(storage: MemoryStorage) {
  const state = emptyState(context('base'));
  storage.setItem(STORAGE_KEY, JSON.stringify(state));
  return state;
}
function seedWorkspace(storage: MemoryStorage) {
  const ctx = context('base');
  const store = new WorkspaceStore(emptyWorkspace(ctx), ctx);
  store.addPane(pane, viewport);
  store.addPane(pane, viewport);
  storage.setItem(WORKSPACE_STORAGE_KEY, JSON.stringify(store.getSnapshot()));
  return store.getSnapshot();
}
const recoveryKeys = (storage: MemoryStorage) =>
  [...storage.values.keys()].filter(
    (key) => key.includes('.recovery.') && !key.endsWith('.applied'),
  );

describe('coordinated metadata persistence', () => {
  it('keeps view preferences local while merging ordinary element props with similar names', () => {
    const storage = new MemoryStorage();
    const base = seedWorkspace(storage);
    const local = structuredClone(base),
      remote = structuredClone(base);
    local.layouts[0]!.panes[0]!.props.label = 'local';
    remote.layouts[0]!.panes[0]!.props.z = 'remote';
    remote.layouts[0]!.scrollX = 200;
    remote.focusedPaneId = remote.layouts[0]!.panes[1]!.id;
    const merged = mergeWorkspace(base, local, remote);
    expect(merged.layouts[0]!.panes[0]!.props).toMatchObject({ label: 'local', z: 'remote' });
    expect(merged.layouts[0]!.scrollX).toBe(local.layouts[0]!.scrollX);
    expect(merged.focusedPaneId).toBe(local.focusedPaneId);
    const passive = mergeWorkspace(base, base, remote);
    expect(passive.layouts[0]!.scrollX).toBe(base.layouts[0]!.scrollX);
    expect(passive.focusedPaneId).toBe(base.focusedPaneId);
  });
  it('keeps collapse and fullscreen coherent when tabs toggle different modes', async () => {
    const storage = new MemoryStorage();
    const initial = seedWorkspace(storage);
    const id = initial.layouts[0]!.panes[0]!.id;
    const a = createPersistedWorkspace({ storage, ctx: context('a') });
    const b = createPersistedWorkspace({ storage, ctx: context('b') });
    try {
      a.store.toggleFullscreen(id);
      b.store.toggleCollapsed(id);
      await a.flush();
      await b.flush();
      const result = WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!));
      expect(result.layouts[0]?.panes.find((p) => p.id === id)).toMatchObject({
        fullscreen: false,
        collapsed: true,
      });
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('retains one fullscreen pane after two tabs expand different panes', async () => {
    const storage = new MemoryStorage();
    const initial = seedWorkspace(storage);
    const a = createPersistedWorkspace({ storage, ctx: context('a') });
    const b = createPersistedWorkspace({ storage, ctx: context('b') });
    try {
      a.store.toggleFullscreen(initial.layouts[0]!.panes[0]!.id);
      b.store.toggleFullscreen(initial.layouts[0]!.panes[1]!.id);
      await a.flush();
      await b.flush();
      const result = WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!));
      expect(result.layouts[0]?.panes.filter((p) => p.fullscreen).map((p) => p.id)).toEqual([
        initial.layouts[0]!.panes[1]!.id,
      ]);
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });
  it('refuses to discard a new account whose wallet was concurrently deleted', () => {
    const ctx = context('accounts');
    const base = emptyState(ctx);
    base.wallets.push({
      id: 'w',
      folderId: rootOf(base).id,
      name: 'Watch',
      kind: 'watch',
      keyGroupId: null,
      tags: [],
      createdAtMs: 1,
      updatedAtMs: 1,
    });
    const local = structuredClone(base),
      remote = structuredClone(base);
    local.wallets = [];
    remote.accounts.push({
      id: 'a',
      walletId: 'w',
      family: 'evm',
      chainId: 'eip155:1',
      address: '0x' + '11'.repeat(20),
      publicKeyHex: '',
      hidden: false,
    });
    expect(() => mergeDirectory(base, local, remote, ctx)).toThrow(/concurrent deletion/);
  });

  it('does not lose a newer recovery revision published while an older revision is applied', async () => {
    const storage = new MemoryStorage();
    const base = seedDirectory(storage),
      local = structuredClone(base);
    local.folders.push({ ...base.folders[0]!, id: 'a', parentId: rootOf(base).id, name: 'A' });
    const key = `${STORAGE_KEY}.recovery.active-tab`;
    storage.setItem(
      key,
      JSON.stringify({ stackwalletRecovery: 1, source: 'directory', base, local }),
    );
    const newer = structuredClone(local);
    newer.folders.push({ ...base.folders[0]!, id: 'b', parentId: rootOf(base).id, name: 'B' });
    const write = storage.setItem.bind(storage);
    let update = true;
    storage.setItem = (name, value) => {
      write(name, value);
      if (name === STORAGE_KEY && update) {
        update = false;
        write(
          key,
          JSON.stringify({ stackwalletRecovery: 1, source: 'directory', base, local: newer }),
        );
      }
    };
    const a = createPersistedStore({ storage, ctx: context('first') });
    await a.flush();
    await a.dispose();
    const b = createPersistedStore({ storage, ctx: context('reload') });
    try {
      await b.flush();
      expect(folders(storage).map((f) => f.name)).toEqual(['Wallets', 'A', 'B']);
    } finally {
      await b.dispose();
    }
  });
  it('repairs legacy folder cycles without hiding wallets or mutating the input', () => {
    const ctx = context('legacy');
    const base = emptyState(ctx);
    const template = base.folders[0]!;
    base.folders.push(
      { ...template, id: 'a', parentId: 'b' },
      { ...template, id: 'b', parentId: 'a' },
    );
    base.wallets.push({
      id: 'w',
      folderId: 'b',
      name: 'Previously hidden',
      kind: 'watch',
      keyGroupId: null,
      tags: [],
      createdAtMs: 1,
      updatedAtMs: 1,
    });
    const repaired = ensureRoot(base, ctx);
    expect(flattenTree(repaired, 'Previously hidden').some((row) => row.id === 'w')).toBe(true);
    expect(base.folders[1]?.parentId).toBe('b');
    expect(base.folders[2]?.parentId).toBe('a');
  });
  it('keeps additions from two stale directory tabs and synchronizes a clean tab', async () => {
    const storage = new MemoryStorage();
    const initial = seedDirectory(storage);
    const a = createPersistedStore({ storage, ctx: context('a') });
    const b = createPersistedStore({ storage, ctx: context('b') });
    try {
      a.store.createFolder('A', rootOf(initial).id);
      await a.flush();
      b.store.createFolder('B', rootOf(initial).id);
      await b.flush();
      expect(folders(storage).map((f) => f.name)).toEqual(['Wallets', 'A', 'B']);
      await a.flush();
      expect(a.store.getSnapshot().folders).toHaveLength(3);
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('normalizes independently initialized directory roots', async () => {
    const storage = new MemoryStorage();
    const a = createPersistedStore({ storage, ctx: context('a') });
    const b = createPersistedStore({ storage, ctx: context('b') });
    try {
      a.store.createFolder('A', rootOf(a.store.getSnapshot()).id);
      b.store.createFolder('B', rootOf(b.store.getSnapshot()).id);
      await Promise.all([a.flush(), b.flush()]);
      const result = folders(storage);
      const root = result.find((f) => f.parentId === null)!;
      expect(result).toHaveLength(3);
      expect(result.filter((f) => f.parentId === root.id).map((f) => f.name)).toEqual(['A', 'B']);
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('preserves conflicting renames without overwriting the committed folder', async () => {
    const storage = new MemoryStorage();
    seedDirectory(storage);
    const a = createPersistedStore({ storage, ctx: context('a') });
    const b = createPersistedStore({ storage, ctx: context('b') });
    try {
      const root = rootOf(a.store.getSnapshot()).id;
      a.store.renameNode(root, 'A');
      b.store.renameNode(root, 'B');
      await a.flush();
      await b.flush();
      expect(folders(storage)[0]?.name).toBe('A');
      expect(rootOf(b.store.getSnapshot()).name).toBe('B');
      const copy = JSON.parse(storage.getItem(recoveryKeys(storage)[0]!)!);
      expect(copy.local.folders[0].name).toBe('B');
      expect(copy.reason).toContain('Conflicting changes');
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('merges pane changes and additions from stale workspace tabs', async () => {
    const storage = new MemoryStorage();
    const initial = seedWorkspace(storage);
    const first = initial.layouts[0]!.panes[0]!,
      second = initial.layouts[0]!.panes[1]!;
    const a = createPersistedWorkspace({ storage, ctx: context('a') });
    const b = createPersistedWorkspace({ storage, ctx: context('b') });
    try {
      a.store.setRect(first.id, { ...first, x: 800 });
      await a.flush();
      b.store.toggleCollapsed(second.id);
      b.store.addPane(pane, viewport);
      await b.flush();
      const result = WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!));
      expect(result.layouts[0]?.panes).toHaveLength(3);
      expect(result.layouts[0]?.panes.find((p) => p.id === first.id)?.x).toBe(800);
      expect(result.layouts[0]?.panes.find((p) => p.id === second.id)?.collapsed).toBe(true);
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('uses one set of default layouts when two new tabs initialize together', async () => {
    const storage = new MemoryStorage();
    const a = createPersistedWorkspace({ storage, ctx: context('a') });
    const b = createPersistedWorkspace({ storage, ctx: context('b') });
    try {
      const first = a.store.active.panes[0]!;
      a.store.setRect(first.id, { ...first, x: 888 });
      await a.flush();
      b.store.addPane(pane, viewport);
      await b.flush();
      const result = WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!));
      expect(result.layouts.map((l) => l.name)).toEqual(['home', 'devices']);
      expect(result.layouts[0]?.panes).toHaveLength(
        defaultWorkspace(context('count')).layouts[0]!.panes.length + 1,
      );
      expect(result.layouts[0]?.panes.find((p) => p.id === first.id)?.x).toBe(888);
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('does not resurrect a deleted pane while another pane changes', async () => {
    const storage = new MemoryStorage();
    const initial = seedWorkspace(storage);
    const [first, second] = initial.layouts[0]!.panes;
    const a = createPersistedWorkspace({ storage, ctx: context('a') });
    const b = createPersistedWorkspace({ storage, ctx: context('b') });
    try {
      a.store.removePane(first!.id);
      await a.flush();
      b.store.toggleCollapsed(second!.id);
      await b.flush();
      expect(
        WorkspaceState.parse(
          JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!),
        ).layouts[0]?.panes.map((p) => p.id),
      ).toEqual([second!.id]);
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('keeps a recovery copy when deletion races with an edit', async () => {
    const storage = new MemoryStorage();
    const initial = seedWorkspace(storage);
    const first = initial.layouts[0]!.panes[0]!;
    const a = createPersistedWorkspace({ storage, ctx: context('a') });
    const b = createPersistedWorkspace({ storage, ctx: context('b') });
    try {
      a.store.removePane(first.id);
      await a.flush();
      b.store.setRect(first.id, { ...first, x: 800 });
      await b.flush();
      const result = WorkspaceState.parse(JSON.parse(storage.getItem(WORKSPACE_STORAGE_KEY)!));
      expect(result.layouts[0]?.panes.some((p) => p.id === first.id)).toBe(false);
      expect(recoveryKeys(storage)).toHaveLength(1);
    } finally {
      await a.dispose();
      await b.dispose();
    }
  });

  it('rejects folder moves that become cyclic only when combined', () => {
    const base = emptyState(context('base'));
    const root = rootOf(base).id;
    const make = (id: string) => ({ ...base.folders[0]!, id, parentId: root, name: id });
    base.folders.push(make('a'), make('b'));
    const local = structuredClone(base),
      remote = structuredClone(base);
    local.folders[1]!.parentId = 'b';
    remote.folders[2]!.parentId = 'a';
    expect(() => mergeDirectory(base, local, remote, context('repair'))).toThrow(/cyclic/);
  });

  it('recovers an interrupted save on reload and marks the exact recovered revision', async () => {
    const storage = new MemoryStorage();
    const base = seedDirectory(storage),
      local = structuredClone(base);
    local.folders.push({
      ...base.folders[0]!,
      id: 'new',
      parentId: rootOf(base).id,
      name: 'recovered',
    });
    const key = `${STORAGE_KEY}.recovery.closed-tab`;
    storage.setItem(
      key,
      JSON.stringify({ stackwalletRecovery: 1, source: 'directory', base, local }),
    );
    const p = createPersistedStore({ storage, ctx: context('reload') });
    try {
      await p.flush();
      expect(folders(storage).map((f) => f.name)).toContain('recovered');
      expect(storage.getItem(`${key}.applied`)).toMatch(/^[0-9a-f]{64}$/);
      expect(storage.getItem(key)).not.toBeNull();
    } finally {
      await p.dispose();
    }
  });

  it('archives pending edits synchronously while the page-exit save waits for a lock', async () => {
    const storage = new MemoryStorage();
    seedDirectory(storage);
    const target = Object.assign(new EventTarget(), { localStorage: storage });
    let release!: () => void;
    let tail: Promise<unknown> = new Promise<void>((resolve) => {
      release = resolve;
    });
    const request = (_key: string, op: () => Promise<unknown>) => {
      const next = tail.then(op);
      tail = next.catch(() => undefined);
      return next;
    };
    vi.stubGlobal('window', target);
    vi.stubGlobal('navigator', { locks: { request } });
    const p = createPersistedStore({ storage, ctx: context('a') });
    try {
      p.store.createFolder('exit', rootOf(p.store.getSnapshot()).id);
      target.dispatchEvent(new Event('pagehide'));
      expect(folders(storage)).toHaveLength(1);
      expect(JSON.parse(storage.getItem(recoveryKeys(storage)[0]!)!).local.folders).toHaveLength(2);
      release();
      await p.flush();
      expect(folders(storage)).toHaveLength(2);
    } finally {
      release();
      await p.dispose();
      vi.unstubAllGlobals();
    }
  });
});
