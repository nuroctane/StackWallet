import { describe, expect, it } from 'vitest';

import * as r from '../store/reducers.js';
import { createKeyedWallet } from '../store/sets.js';
import { DirectoryStore } from '../store/store.js';
import { exportLayoutBundle, importLayoutBundle } from './layoutTransfer.js';
import { emptyState, WorkspaceStore } from './store.js';

function ctx(prefix: string) {
  let n = 0;
  let t = 1_000;
  return { now: () => (t += 1), newId: () => `${prefix}-${++n}` };
}

const EVM = '0x1111111111111111111111111111111111111111';

function sender() {
  const c = ctx('a');
  let s = r.emptyState(c);
  const root = r.rootOf(s).id;
  const cold = r.createFolder(s, 'Cold', root, c);
  if (!cold.ok) throw new Error(cold.error);
  const vaults = r.createFolder(cold.state, 'Vaults', cold.value, c);
  if (!vaults.ok) throw new Error(vaults.error);
  const keyed = createKeyedWallet(
    vaults.state,
    {
      walletId: 'keyed-1',
      name: 'Savings',
      folderId: vaults.value,
      accounts: [
        {
          chainId: 'eip155:1',
          address: EVM,
          derivationPath: "m/44'/60'/0'/0/0",
          publicKeyHex: `02${'ab'.repeat(32)}`,
        },
      ],
    },
    c,
  );
  if (!keyed.ok) throw new Error(keyed.error);
  s = keyed.state;
  const tagged = r.resolveTagInput(s, 'Long Term', c);
  if (!tagged.ok) throw new Error(tagged.error);
  s = tagged.state;
  const set = r.setWalletTags(s, 'keyed-1', [tagged.value], c);
  if (!set.ok) throw new Error(set.error);
  const directory = new DirectoryStore(set.state, c);
  const workspace = new WorkspaceStore(emptyState(c), c);
  const vp = { x: 0, y: 0, w: 2000, h: 2000 };
  workspace.addPane({ kind: 'wallet', props: { walletId: 'keyed-1' }, w: 300, h: 200 }, vp);
  workspace.addPane({ kind: 'folder', props: { folderId: cold.value }, w: 300, h: 200 }, vp);
  workspace.addPane({ kind: 'transactions', props: { walletId: '' }, w: 300, h: 200 }, vp);
  return { directory, workspace };
}

describe('layout transfer', () => {
  it('exports wallets as public addresses only: no keys, no kind, no key history', () => {
    const { directory, workspace } = sender();
    const bundle = exportLayoutBundle(workspace, directory)!;
    const json = JSON.stringify(bundle);
    expect(bundle.stackwalletLayout).toBe(2);
    expect(json).toContain(EVM);
    for (const secretish of ['publicKeyHex', 'derivationPath', '"single"', 'keyGroupId', 'abab'])
      expect(json).not.toContain(secretish);
    expect(json).toContain('Long Term');
  });

  it('arrives watch-only under the same folder path, and re-importing matches by address', () => {
    const { directory, workspace } = sender();
    const text = JSON.stringify(exportLayoutBundle(workspace, directory));

    const c = ctx('b');
    const receiver = new DirectoryStore(r.emptyState(c), c);
    const ws = new WorkspaceStore(emptyState(c), c);
    const first = importLayoutBundle(ws, receiver, text);
    if (!first.ok) throw new Error(first.error);
    expect(first.value).toMatchObject({ createdWallets: 1, matchedWallets: 0, createdFolders: 2 });

    const state = receiver.getSnapshot();
    const wallet = state.wallets.find((w) => w.name === 'Savings')!;
    expect(wallet.kind).toBe('watch');
    expect(wallet.tags).toEqual(['long-term']);
    expect(state.tagDefs.map((d) => d.label)).toEqual(['Long Term']);
    const folder = state.folders.find((f) => f.id === wallet.folderId)!;
    expect(folder.name).toBe('Vaults');
    expect(state.folders.find((f) => f.id === folder.parentId)!.name).toBe('Cold');
    expect(state.accounts.filter((a) => a.walletId === wallet.id)).toMatchObject([
      { chainId: 'eip155:1', address: EVM, publicKeyHex: '' },
    ]);
    const layout = ws.getSnapshot().layouts.find((l) => l.id === first.value.layoutId)!;
    expect(layout.panes.find((p) => p.kind === 'wallet')!.props['walletId']).toBe(wallet.id);
    expect(layout.panes.find((p) => p.kind === 'transactions')!.props['walletId']).toBe('');

    const again = importLayoutBundle(ws, receiver, text);
    if (!again.ok) throw new Error(again.error);
    expect(again.value).toMatchObject({ createdWallets: 0, matchedWallets: 1, createdFolders: 0 });
    expect(receiver.getSnapshot().wallets).toHaveLength(1);
  });

  it('maps onto a keyed wallet that already holds the address', () => {
    const { directory, workspace } = sender();
    const text = JSON.stringify(exportLayoutBundle(workspace, directory));
    const ws = new WorkspaceStore(emptyState(ctx('c')), ctx('c'));
    const out = importLayoutBundle(ws, directory, text);
    if (!out.ok) throw new Error(out.error);
    expect(out.value.matchedWallets).toBe(1);
    expect(directory.getSnapshot().wallets.map((w) => w.kind)).toEqual(['single']);
  });

  it('refuses junk and keeps version 1 layouts working', () => {
    const c = ctx('d');
    const d = new DirectoryStore(r.emptyState(c), c);
    const ws = new WorkspaceStore(emptyState(c), c);
    expect(importLayoutBundle(ws, d, 'nope').ok).toBe(false);
    expect(importLayoutBundle(ws, d, '{"stackwalletLayout":3}').ok).toBe(false);
    const v1 = importLayoutBundle(
      ws,
      d,
      JSON.stringify({
        stackwalletLayout: 1,
        name: 'old',
        panes: [{ kind: 'wallet', props: { walletId: 'gone' }, x: 0, y: 0, w: 300, h: 200 }],
      }),
    );
    if (!v1.ok) throw new Error(v1.error);
    expect(v1.value.unresolved).toBe(1);
  });
});
