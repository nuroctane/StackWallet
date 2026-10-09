import { describe, expect, it } from 'vitest';

import * as r from './reducers.js';
import { DirectoryState } from './schema.js';
import {
  chainIdsInUse,
  countByKind,
  descendantWallets,
  findNode,
  flattenTree,
  kindLabel,
  pathTo,
  walletFamilies,
} from './selectors.js';

function makeCtx(): r.ReducerContext {
  let n = 0;
  let t = 1_000;
  return { now: () => (t += 1), newId: () => `id-${++n}` };
}

function expectOk<T>(o: r.Outcome<T>): r.Success<T> {
  if (!o.ok) throw new Error(`expected ok, got: ${o.error}`);
  return o;
}

function expectFail<T>(o: r.Outcome<T>): string {
  if (o.ok) throw new Error('expected failure');
  return o.error;
}

function seeded() {
  const ctx = makeCtx();
  let s = r.emptyState(ctx);
  const root = r.rootOf(s);
  const cold = expectOk(r.createFolder(s, 'Cold', root.id, ctx));
  s = cold.state;
  const trading = expectOk(r.createFolder(s, 'Trading', root.id, ctx));
  s = trading.state;
  const lanes = expectOk(r.createFolder(s, 'Agent lanes', trading.value, ctx));
  s = lanes.state;
  const w = expectOk(
    r.createWatchWallet(
      s,
      { name: 'Whale', folderId: cold.value, chainId: 'eip155:1', address: '0xabc' },
      ctx,
    ),
  );
  s = w.state;
  return { ctx, s, root, cold: cold.value, trading: trading.value, lanes: lanes.value, w: w.value };
}

describe('emptyState', () => {
  it('creates a single root named Wallets that validates against the schema', () => {
    const s = r.emptyState(makeCtx());
    expect(s.folders).toHaveLength(1);
    expect(r.rootOf(s).name).toBe(r.ROOT_FOLDER_NAME);
    expect(r.rootOf(s).parentId).toBeNull();
    expect(DirectoryState.safeParse(JSON.parse(JSON.stringify(s))).success).toBe(true);
  });
});

describe('createFolder', () => {
  it('adds, expands the parent and selects the new folder', () => {
    const ctx = makeCtx();
    const s0 = r.emptyState(ctx);
    const out = expectOk(r.createFolder(s0, '  Cold ', r.rootOf(s0).id, ctx));
    expect(out.state.folders.map((f) => f.name)).toEqual(['Wallets', 'Cold']);
    expect(out.state.ui.selectedId).toBe(out.value);
    expect(out.state.ui.expandedFolderIds).toContain(r.rootOf(s0).id);
    expect(s0.folders).toHaveLength(1);
  });

  it('rejects blank names, missing parents and sibling duplicates', () => {
    const { s, ctx, root } = seeded();
    expect(expectFail(r.createFolder(s, '   ', root.id, ctx))).toMatch(/required/);
    expect(expectFail(r.createFolder(s, 'X', 'nope', ctx))).toMatch(/not found/);
    expect(expectFail(r.createFolder(s, 'cold', root.id, ctx))).toMatch(/already exists/);
  });
});

describe('renameNode', () => {
  it('renames folders and wallets and bumps updatedAtMs', () => {
    const { s, ctx, cold, w } = seeded();
    const a = expectOk(r.renameNode(s, cold, 'Freezer', ctx));
    expect(findNode(a.state, cold)).toMatchObject({ kind: 'folder', folder: { name: 'Freezer' } });
    const b = expectOk(r.renameNode(a.state, w, 'Orca', ctx));
    const wallet = b.state.wallets.find((x) => x.id === w);
    expect(wallet?.name).toBe('Orca');
    expect(wallet!.updatedAtMs).toBeGreaterThan(wallet!.createdAtMs);
  });

  it('returns the same state for a no-op rename and fails for unknown ids', () => {
    const { s, ctx, cold } = seeded();
    expect(expectOk(r.renameNode(s, cold, 'Cold', ctx)).state).toBe(s);
    expect(expectFail(r.renameNode(s, 'ghost', 'X', ctx))).toMatch(/Nothing/);
    expect(expectFail(r.renameNode(s, cold, '', ctx))).toMatch(/required/);
  });
});

describe('deleteFolder', () => {
  it('refuses root, non-empty folders and unknown ids', () => {
    const { s, root, cold, trading } = seeded();
    expect(expectFail(r.deleteFolder(s, root.id))).toMatch(/root/);
    expect(expectFail(r.deleteFolder(s, cold))).toMatch(/contains wallets/);
    expect(expectFail(r.deleteFolder(s, trading))).toMatch(/subfolders/);
    expect(expectFail(r.deleteFolder(s, 'ghost'))).toMatch(/not found/);
  });

  it('deletes an empty folder and clears ui references', () => {
    const { s, lanes } = seeded();
    const selected = r.select(r.setFolderExpanded(s, lanes, true), lanes);
    const out = expectOk(r.deleteFolder(selected, lanes));
    expect(out.state.folders.find((f) => f.id === lanes)).toBeUndefined();
    expect(out.state.ui.selectedId).toBeNull();
    expect(out.state.ui.expandedFolderIds).not.toContain(lanes);
  });
});

describe('moveWallet', () => {
  it('moves and expands the target; no-op when already there', () => {
    const { s, ctx, w, lanes, cold } = seeded();
    const out = expectOk(r.moveWallet(s, w, lanes, ctx));
    expect(out.state.wallets[0]?.folderId).toBe(lanes);
    expect(out.state.ui.expandedFolderIds).toContain(lanes);
    expect(expectOk(r.moveWallet(out.state, w, lanes, ctx)).state).toBe(out.state);
    expect(expectFail(r.moveWallet(s, w, 'ghost', ctx))).toMatch(/Target folder/);
    expect(expectFail(r.moveWallet(s, 'ghost', cold, ctx))).toMatch(/Wallet not found/);
  });
});

describe('createWatchWallet', () => {
  it('creates a watch wallet with exactly one account and no public key', () => {
    const { s, w } = seeded();
    const wallet = s.wallets.find((x) => x.id === w);
    expect(wallet).toMatchObject({ kind: 'watch', keyGroupId: null, tags: [] });
    const accounts = s.accounts.filter((a) => a.walletId === w);
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      family: 'evm',
      chainId: 'eip155:1',
      address: '0xabc',
      publicKeyHex: '',
      hidden: false,
    });
    expect(s.ui.selectedId).toBe(w);
    expect(DirectoryState.safeParse(JSON.parse(JSON.stringify(s))).success).toBe(true);
  });

  it('validates its input', () => {
    const { s, ctx, cold } = seeded();
    const base = { name: 'X', folderId: cold, chainId: 'eip155:1', address: '0x1' };
    expect(expectFail(r.createWatchWallet(s, { ...base, name: ' ' }, ctx))).toMatch(/required/);
    expect(expectFail(r.createWatchWallet(s, { ...base, folderId: 'nope' }, ctx))).toMatch(
      /Folder not found/,
    );
    expect(expectFail(r.createWatchWallet(s, { ...base, chainId: 'bad' }, ctx))).toMatch(/CAIP-2/);
    expect(expectFail(r.createWatchWallet(s, { ...base, chainId: 'tezos:main' }, ctx))).toMatch(
      /Unsupported/,
    );
    expect(expectFail(r.createWatchWallet(s, { ...base, address: '  ' }, ctx))).toMatch(/Address/);
  });
});

describe('deleteWallet', () => {
  it('removes the wallet and its accounts, clearing selection', () => {
    const { s, w } = seeded();
    const out = expectOk(r.deleteWallet(s, w));
    expect(out.state.wallets).toHaveLength(0);
    expect(out.state.accounts).toHaveLength(0);
    expect(out.state.ui.selectedId).toBeNull();
    expect(expectFail(r.deleteWallet(s, 'ghost'))).toMatch(/not found/);
  });
});

describe('ui reducers', () => {
  it('toggles expansion only for real folders', () => {
    const seed = seeded();
    const { trading } = seed;
    const s = { ...seed.s, ui: { expandedFolderIds: [], selectedId: null } };
    const a = r.toggleFolder(s, trading);
    expect(a.ui.expandedFolderIds).toContain(trading);
    const b = r.toggleFolder(a, trading);
    expect(b.ui.expandedFolderIds).not.toContain(trading);
    expect(r.toggleFolder(s, 'ghost')).toBe(s);
  });

  it('select falls back to null for unknown ids', () => {
    const { s, cold } = seeded();
    expect(r.select(s, cold).ui.selectedId).toBe(cold);
    expect(r.select(s, 'ghost').ui.selectedId).toBeNull();
    const nulled = r.select(s, null);
    expect(r.select(nulled, null)).toBe(nulled);
  });

  it('expandTo opens every ancestor below the root', () => {
    const { s, ctx, lanes, trading } = seeded();
    const deep = expectOk(r.createFolder(s, 'Deep', lanes, ctx));
    const w = expectOk(
      r.createWatchWallet(
        deep.state,
        { name: 'Deep wallet', folderId: deep.value, chainId: 'solana:mainnet', address: 'So1' },
        ctx,
      ),
    );
    const collapsed = { ...w.state, ui: { expandedFolderIds: [], selectedId: null } };
    const out = r.expandTo(collapsed, w.value);
    expect(new Set(out.ui.expandedFolderIds)).toEqual(new Set([trading, lanes, deep.value]));
    expect(r.expandTo(out, w.value)).toBe(out);
  });
});

describe('ensureRoot', () => {
  it('adds a missing root and reparents orphans', () => {
    const { s, ctx, root } = seeded();
    const broken: DirectoryState = {
      ...s,
      folders: s.folders
        .filter((f) => f.id !== root.id)
        .map((f) => (f.name === 'Cold' ? { ...f, parentId: 'missing' } : f)),
      wallets: s.wallets.map((w) => ({ ...w, folderId: 'gone' })),
      accounts: [...s.accounts, { ...s.accounts[0]!, id: 'stray', walletId: 'no-wallet' }],
      ui: { expandedFolderIds: ['nope'], selectedId: 'nope' },
    };
    const fixed = r.ensureRoot(broken, ctx);
    const newRoot = r.rootOf(fixed);
    expect(newRoot.name).toBe('Wallets');
    const parentOf = (name: string) => fixed.folders.find((f) => f.name === name)?.parentId;
    expect(parentOf('Cold')).toBe(newRoot.id);
    expect(parentOf('Trading')).toBe(newRoot.id);
    expect(parentOf('Agent lanes')).toBe(fixed.folders.find((f) => f.name === 'Trading')?.id);
    expect(fixed.wallets[0]?.folderId).toBe(newRoot.id);
    expect(fixed.accounts.find((a) => a.id === 'stray')).toBeUndefined();
    expect(fixed.ui).toEqual({ expandedFolderIds: [], selectedId: null });
  });
});

describe('selectors', () => {
  it('pathTo walks from the root to the containing folder', () => {
    const { s, w, lanes } = seeded();
    expect(pathTo(s, w).map((f) => f.name)).toEqual(['Wallets', 'Cold']);
    expect(pathTo(s, lanes).map((f) => f.name)).toEqual(['Wallets', 'Trading', 'Agent lanes']);
    expect(pathTo(s, 'ghost')).toEqual([]);
  });

  it('counts, families and chains', () => {
    const { s, w, root } = seeded();
    expect(countByKind(s)).toEqual({ tss: 0, single: 0, watch: 1, hardware: 0 });
    expect(walletFamilies(s, w)).toEqual(['evm']);
    expect(chainIdsInUse(s)).toEqual(['eip155:1']);
    expect(descendantWallets(s, root.id)).toHaveLength(1);
    expect(kindLabel(s.wallets[0]!)).toBe('watch');
    expect(
      kindLabel(
        { ...s.wallets[0]!, kind: 'tss', keyGroupId: 'kg' },
        {
          id: 'kg',
          threshold: 2,
          parties: [
            { deviceId: 'a', role: 'human' },
            { deviceId: 'b', role: 'human' },
            { deviceId: 'c', role: 'agent' },
          ],
          curves: ['secp256k1'],
          publicKeys: [],
        },
      ),
    ).toBe('2-of-3');
  });

  it('flattenTree honors expansion, nests depth and sorts by name', () => {
    const { s, trading, cold } = seeded();
    const closed = flattenTree({ ...s, ui: { expandedFolderIds: [], selectedId: null } });
    expect(closed.map((x) => [x.name, x.depth])).toEqual([
      ['Cold', 0],
      ['Trading', 0],
    ]);
    const open = flattenTree({
      ...s,
      ui: { expandedFolderIds: [trading, cold], selectedId: null },
    });
    expect(open.map((x) => [x.name, x.depth, x.kind])).toEqual([
      ['Cold', 0, 'folder'],
      ['Whale', 1, 'wallet'],
      ['Trading', 0, 'folder'],
      ['Agent lanes', 1, 'folder'],
    ]);
    expect(open[0]?.hasChildren).toBe(true);
    expect(open[3]?.hasChildren).toBe(false);
  });

  it('flattenTree with a filter flattens matches regardless of expansion, including addresses', () => {
    const { s } = seeded();
    const collapsed = { ...s, ui: { expandedFolderIds: [], selectedId: null } };
    expect(flattenTree(collapsed, 'whale').map((x) => x.name)).toEqual(['Whale']);
    expect(flattenTree(collapsed, '0xabc').map((x) => x.name)).toEqual(['Whale']);
    expect(flattenTree(collapsed, 'lanes').map((x) => [x.name, x.depth])).toEqual([
      ['Agent lanes', 0],
    ]);
    expect(flattenTree(collapsed, 'zzz')).toEqual([]);
  });
});
