import { MemoryRpcPool } from '@stackwallet/chains';
import type { MixinCandidateOutput } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  MIXIN_CHAINS,
  MIXIN_MAINNET,
  MIXIN_NETWORK_ID,
  MixinAdapter,
  XIN_ASSET_ID,
} from './mixin.js';
import { SNAPSHOT_PAGE, scanMixinOutputs, xinToXinat } from './scan.js';

const MASK = 'ab'.repeat(32);
const MINE = 'c1'.repeat(32);
const OTHER = 'd2'.repeat(32);
const FOREIGN_ASSET = 'ee'.repeat(32);

interface Out {
  amount: string;
  keys: string[];
  script?: string;
  type?: number;
}
interface Tx {
  hash: string;
  asset?: string;
  inputs?: { hash: string; index: number }[];
  outputs: Out[];
}

function snapshot(topology: number, txs: Tx[]) {
  return {
    topology,
    hash: '11'.repeat(32),
    transactions: txs.map((t) => ({
      hash: t.hash,
      asset: t.asset ?? XIN_ASSET_ID,
      inputs: t.inputs ?? [],
      outputs: t.outputs.map((o) => ({
        type: o.type ?? 0,
        amount: o.amount,
        keys: o.keys,
        mask: MASK,
        script: o.script ?? 'fffe01',
      })),
    })),
  };
}

/**
 * A kernel whose ledger is `snapshots`; `listsnapshots` pages it like the real
 * node unless `stale`, which ignores the offset the way a broken node might.
 */
function kernel(snapshots: ReturnType<typeof snapshot>[], head = snapshots.length, stale = false) {
  const calls: string[] = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: string[] };
    calls.push(body.method);
    if (body.method === 'getinfo')
      return Response.json({ data: { network: MIXIN_NETWORK_ID, graph: { topology: head } } });
    if (body.method === 'listsnapshots') {
      const offset = Number(body.params[0]);
      const count = Number(body.params[1]);
      if (count > SNAPSHOT_PAGE) return Response.json({ error: 'count too large' });
      return Response.json({
        data: (stale ? snapshots : snapshots.filter((s) => s.topology >= offset)).slice(0, count),
      });
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

/** Stands in for the core: recognises ghost key MINE wherever it appears. */
const matcher = async (candidates: MixinCandidateOutput[]) =>
  candidates.flatMap((c, position) => {
    const key = c.keys.indexOf(MINE);
    return key === -1 ? [] : [{ position, key }];
  });

describe('xinToXinat', () => {
  it('scales kernel decimal strings to integer xinat', () => {
    expect(xinToXinat('0.00000060')).toBe('60');
    expect(xinToXinat('1.5')).toBe('150000000');
    expect(xinToXinat('2')).toBe('200000000');
    expect(() => xinToXinat('1.123456789')).toThrow();
  });
});

describe('scanMixinOutputs', () => {
  it('collects owned XIN outputs and drops the ones later spent', async () => {
    const { adapter } = kernel([
      snapshot(0, [{ hash: 'a1'.repeat(32), outputs: [{ amount: '1.5', keys: [MINE] }] }]),
      snapshot(1, [
        {
          hash: 'a2'.repeat(32),
          outputs: [
            { amount: '0.1', keys: [OTHER] },
            { amount: '0.2', keys: [OTHER, MINE] },
          ],
        },
      ]),
      // Foreign asset and multisig scripts are never ours to spend alone.
      snapshot(2, [
        { hash: 'a3'.repeat(32), asset: FOREIGN_ASSET, outputs: [{ amount: '9', keys: [MINE] }] },
        { hash: 'a4'.repeat(32), outputs: [{ amount: '9', keys: [MINE], script: 'fffe02' }] },
      ]),
      // Spending the first output removes it from the unspent set.
      snapshot(3, [
        {
          hash: 'a5'.repeat(32),
          inputs: [{ hash: 'a1'.repeat(32), index: 0 }],
          outputs: [{ amount: '1.5', keys: [OTHER] }],
        },
      ]),
    ]);
    const result = await scanMixinOutputs(adapter, MIXIN_MAINNET, {
      from: { topology: 0, utxos: [] },
      matcher,
    });
    expect(result.reachedHead).toBe(true);
    expect(result.cursor.topology).toBe(4);
    expect(result.cursor.utxos).toEqual([
      { hash: 'a2'.repeat(32), index: 1, key: MINE, mask: MASK, xinat: '20000000' },
    ]);
  });

  it('resumes from a cursor and pages up to the limit', async () => {
    const snapshots = Array.from({ length: 1200 }, (_, i) =>
      snapshot(i, [
        {
          hash: i.toString(16).padStart(64, '0'),
          outputs: [{ amount: '1', keys: [i % 600 === 599 ? MINE : OTHER] }],
        },
      ]),
    );
    const { adapter, calls } = kernel(snapshots);
    const progress: number[] = [];
    const first = await scanMixinOutputs(adapter, MIXIN_MAINNET, {
      from: { topology: 100, utxos: [] },
      matcher,
      maxPages: 1,
      onProgress: (c) => progress.push(c.topology),
    });
    expect(first.reachedHead).toBe(false);
    expect(first.cursor.topology).toBe(600);
    expect(first.cursor.utxos.map((u) => u.hash)).toEqual([(599).toString(16).padStart(64, '0')]);
    expect(progress).toEqual([600]);
    expect(calls.filter((c) => c === 'listsnapshots')).toHaveLength(1);

    const second = await scanMixinOutputs(adapter, MIXIN_MAINNET, {
      from: first.cursor,
      matcher,
    });
    expect(second.reachedHead).toBe(true);
    expect(second.cursor.topology).toBe(1200);
    expect(second.cursor.utxos).toHaveLength(2);
  });

  it('stops at the head without asking the core about anything', async () => {
    const { adapter, calls } = kernel([snapshot(0, [])], 1);
    let asked = 0;
    const result = await scanMixinOutputs(adapter, MIXIN_MAINNET, {
      from: { topology: 1, utxos: [] },
      matcher: async (c) => {
        asked += c.length;
        return [];
      },
    });
    expect(result.reachedHead).toBe(true);
    expect(asked).toBe(0);
    expect(calls).not.toContain('listsnapshots');
  });

  it('refuses a node that pages backwards', async () => {
    const { adapter } = kernel([snapshot(5, [])], 10, true);
    await expect(
      scanMixinOutputs(adapter, MIXIN_MAINNET, {
        from: { topology: 7, utxos: [] },
        matcher,
        head: 10,
      }),
    ).rejects.toThrow(/below the requested offset/);
  });
});
