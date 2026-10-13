import { describe, expect, it } from 'vitest';

import {
  createFolder,
  createWatchWallet,
  emptyState,
  rootOf,
  type ReducerContext,
} from './reducers.js';
import {
  absorbWatchDuplicates,
  createKeyedWallet,
  exportPayload,
  exportWalletPayload,
  importPayload,
  importWalletPayload,
  payloadLayouts,
} from './sets.js';

function ctx(): ReducerContext {
  let n = 0;
  return { now: () => 1, newId: () => `id${++n}` };
}

describe('directory sets', () => {
  it('exports a subtree and imports it elsewhere under the root', () => {
    const c = ctx();
    let s = emptyState(c);
    const root = rootOf(s).id;
    const a = createFolder(s, 'A', root, c);
    if (!a.ok) throw new Error(a.error);
    s = a.state;
    const b = createFolder(s, 'B', a.value, c);
    if (!b.ok) throw new Error(b.error);
    s = b.state;
    const w = createKeyedWallet(
      s,
      {
        walletId: 'w1',
        name: 'K',
        folderId: b.value,
        accounts: [
          {
            chainId: 'eip155:1',
            address: '0xabc',
            derivationPath: "m/44'/60'/0'/0/0",
            publicKeyHex: '02',
          },
        ],
      },
      c,
    );
    if (!w.ok) throw new Error(w.error);
    s = w.state;

    const out = exportPayload(s, a.value);
    if ('error' in out) throw new Error(out.error);
    expect(out.payload.folders.map((f) => f.name)).toEqual(['A', 'B']);
    expect(out.walletIds).toEqual(['w1']);
    expect(exportPayload(s, root)).toEqual({ error: expect.stringMatching(/inside the root/) });

    const other = emptyState({ now: () => 5, newId: () => 'other-root' });
    const merged = importPayload(other, out.payload, a.value, c);
    if (!merged.ok) throw new Error(merged.error);
    const top = merged.state.folders.find((f) => f.id === a.value)!;
    expect(top.parentId).toBe('other-root');
    expect(merged.state.accounts).toHaveLength(1);
    // Twice is refused rather than duplicated.
    expect(importPayload(merged.state, out.payload, a.value, c).ok).toBe(false);
  });

  it('refuses payloads that point outside themselves', () => {
    const c = ctx();
    const s = emptyState(c);
    const bad = {
      stackwalletSet: 1,
      folders: [
        {
          id: 'f',
          parentId: 'elsewhere',
          name: 'x',
          tags: [],
          defaultPolicyIds: [],
          createdAtMs: 1,
          updatedAtMs: 1,
        },
      ],
      wallets: [],
      accounts: [],
    };
    expect(importPayload(s, bad, 'nope', c).ok).toBe(false);
    expect(
      importPayload(
        s,
        { ...bad, folders: [{ ...bad.folders[0]!, id: 'g' }, { ...bad.folders[0]! }] },
        'g',
        c,
      ).ok,
    ).toBe(false);
    expect(importPayload(s, { junk: true }, 'f', c).ok).toBe(false);
  });

  it('exports one wallet without its folder and upgrades a watch stand-in on arrival', () => {
    const c = ctx();
    let s = emptyState(c);
    const root = rootOf(s).id;
    const f = createFolder(s, 'Hot', root, c);
    if (!f.ok) throw new Error(f.error);
    s = f.state;
    for (const [id, address] of [
      ['w1', '0xAAA'],
      ['w2', '0xBBB'],
    ] as const) {
      const w = createKeyedWallet(
        s,
        {
          walletId: id,
          name: id,
          folderId: f.value,
          accounts: [
            {
              chainId: 'eip155:1',
              address,
              derivationPath: "m/44'/60'/0'/0/0",
              publicKeyHex: '02',
            },
          ],
        },
        c,
      );
      if (!w.ok) throw new Error(w.error);
      s = w.state;
    }
    const out = exportWalletPayload(s, 'w1');
    if ('error' in out) throw new Error(out.error);
    expect(out.folderId).toBe(f.value);
    expect(out.payload.accounts.map((a) => a.walletId)).toEqual(['w1']);
    expect(JSON.stringify(out.payload)).not.toContain('w2');

    // The receiver had the address as a watch-only wallet from a layout.
    const rc: ReducerContext = { now: () => 9, newId: () => `r${Math.random()}` };
    let other = emptyState({ now: () => 5, newId: () => 'other-root' });
    const watch = createWatchWallet(
      other,
      { name: 'from layout', folderId: 'other-root', chainId: 'eip155:1', address: '0xaaa' },
      rc,
    );
    if (!watch.ok) throw new Error(watch.error);
    other = { ...watch.state, wallets: watch.state.wallets.map((w) => ({ ...w, tags: ['cold'] })) };

    const merged = importWalletPayload(other, out.payload, rc);
    if (!merged.ok) throw new Error(merged.error);
    expect(merged.state.wallets.find((w) => w.id === 'w1')!.folderId).toBe('other-root');
    expect(importWalletPayload(merged.state, out.payload, rc).ok).toBe(false);

    const absorbed = absorbWatchDuplicates(merged.state, ['w1']);
    expect(absorbed.remap.get(watch.value)).toBe('w1');
    expect(absorbed.state.wallets.map((w) => w.id)).toEqual(['w1']);
    expect(absorbed.state.wallets[0]!.tags).toEqual(['cold']);
    expect(absorbed.state.accounts.map((a) => a.walletId)).toEqual(['w1']);
  });

  it('carries layouts and tag looks inside a set', () => {
    const c = ctx();
    let s = emptyState(c);
    const f = createFolder(s, 'A', rootOf(s).id, c);
    if (!f.ok) throw new Error(f.error);
    s = f.state;
    const layout = {
      stackwalletLayout: 1 as const,
      name: 'desk',
      panes: [
        { kind: 'folder' as const, props: { folderId: f.value }, x: 0, y: 0, w: 300, h: 200 },
      ],
    };
    const out = exportPayload(s, f.value, [layout]);
    if ('error' in out) throw new Error(out.error);
    expect(payloadLayouts(out.payload)).toEqual([layout]);
    expect(payloadLayouts({ junk: 1 })).toEqual([]);
  });
});
