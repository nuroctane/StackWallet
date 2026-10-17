import { MemoryRpcPool } from '@stackwallet/chains';
import {
  MIXIN_CHAINS,
  MIXIN_NETWORK_ID,
  MixinAdapter,
  XIN_ASSET_ID,
} from '@stackwallet/chains-mixin';
import { describe, expect, it } from 'vitest';

import { MixinScanStore, type MixinScanDeps } from './mixinScan.js';
import type { StorageLike } from './persist.js';

const ADDRESS =
  'XIN8AJMgQUD11jZYN9ggbQDqkmozrha3zPEZxEkKxVFBufZpEVMtrR6PjtmgtNAH6jrg8dTUQFb9waqqw9euU7Ea8AC6DEu8';
const MINE = 'c1'.repeat(32);
const MASK = 'ab'.repeat(32);

function memory(): StorageLike {
  const m = new Map<string, string>();
  return {
    getItem: (k) => m.get(k) ?? null,
    setItem: (k, v) => void m.set(k, v),
    removeItem: (k) => void m.delete(k),
  };
}

/** A kernel at `head` whose snapshot `t` pays MINE one XIN when `t` is in `paying`. */
function kernel(head: number, paying: number[]) {
  const calls: string[] = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: string[] };
    calls.push(body.method);
    if (body.method === 'getinfo')
      return Response.json({ data: { network: MIXIN_NETWORK_ID, graph: { topology: head } } });
    if (body.method === 'listsnapshots') {
      const offset = Number(body.params[0]);
      const count = Number(body.params[1]);
      const data = [];
      for (let t = offset; t < Math.min(head, offset + count); t++) {
        data.push({
          topology: t,
          transactions: paying.includes(t)
            ? [
                {
                  hash: t.toString(16).padStart(64, '0'),
                  asset: XIN_ASSET_ID,
                  inputs: [],
                  outputs: [{ type: 0, amount: '1', keys: [MINE], mask: MASK, script: 'fffe01' }],
                },
              ]
            : [],
        });
      }
      return Response.json({ data });
    }
    return Response.json({ error: 'invalid method' });
  }) as typeof fetch;
  const adapter = new MixinAdapter({
    fetch: fetchImpl,
    rpc: new MemoryRpcPool(
      MIXIN_CHAINS.map((c) => ({ ...c, defaultRpcs: ['https://kernel.test'] })),
    ),
  });
  return { adapter, calls };
}

const deps: MixinScanDeps = {
  accountFor: (address) =>
    address === ADDRESS ? { walletId: 'w', derivationPath: "m/44'/2365'/0'/0'/0'" } : undefined,
  owned: async (_w, _p, candidates) =>
    candidates.flatMap((c, position) =>
      c.keys.includes(MINE) ? [{ position, key: c.keys.indexOf(MINE) }] : [],
    ),
};

describe('MixinScanStore', () => {
  it('starts a new address at the head and persists the cursor', async () => {
    const storage = memory();
    const store = new MixinScanStore(storage);
    const { adapter } = kernel(1000, [5]);
    await expect(store.sync(adapter, ADDRESS, deps)).resolves.toEqual([]);
    expect(store.cursor(ADDRESS)).toEqual({ topology: 1000, utxos: [] });
    expect(new MixinScanStore(storage).cursor(ADDRESS)?.topology).toBe(1000);
  });

  it('advances from the stored cursor and reports what it found', async () => {
    const store = new MixinScanStore(memory());
    store.rewind(ADDRESS, 0);
    const { adapter, calls } = kernel(1200, [5, 700]);
    const utxos = await store.sync(adapter, ADDRESS, deps);
    expect(utxos.map((u) => u.hash)).toEqual([
      (5).toString(16).padStart(64, '0'),
      (700).toString(16).padStart(64, '0'),
    ]);
    expect(store.cursor(ADDRESS)?.topology).toBe(1200);
    expect(store.progressOf(ADDRESS)).toEqual({ topology: 1200, head: 1200, reachedHead: true });
    expect(calls.filter((c) => c === 'listsnapshots')).toHaveLength(3);
  });

  it('shares one scan between concurrent refreshes', async () => {
    const store = new MixinScanStore(memory());
    store.rewind(ADDRESS, 0);
    const { adapter, calls } = kernel(600, [1]);
    const [a, b] = await Promise.all([
      store.sync(adapter, ADDRESS, deps),
      store.sync(adapter, ADDRESS, deps),
    ]);
    expect(a).toEqual(b);
    expect(calls.filter((c) => c === 'listsnapshots')).toHaveLength(2);
  });

  it('returns the known set unchanged for watch-only accounts or a locked vault', async () => {
    const store = new MixinScanStore(memory());
    store.rewind(ADDRESS, 0);
    const { adapter, calls } = kernel(10, [1]);
    const other = ADDRESS.slice(0, -1) + (ADDRESS.endsWith('8') ? '9' : '8');
    await expect(store.sync(adapter, other, deps)).resolves.toEqual([]);
    expect(calls).toHaveLength(0);
    const locked: MixinScanDeps = {
      ...deps,
      owned: async () => {
        throw new Error('vault locked');
      },
    };
    await expect(store.sync(adapter, ADDRESS, locked)).resolves.toEqual([]);
    expect(store.cursor(ADDRESS)?.topology).toBe(0);
  });
});
