import { describe, expect, it } from 'vitest';

import { createFolder, emptyState, rootOf, type ReducerContext } from './reducers.js';
import { createKeyedWallet, exportPayload, importPayload } from './sets.js';

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
});
