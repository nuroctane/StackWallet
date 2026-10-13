import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { describe, it, expect, vi } from 'vitest';
import { WasmCoreClient } from '@stackwallet/core-client';
import { EvmAdapter } from '@stackwallet/chains-evm';
import { SolanaAdapter } from '@stackwallet/chains-solana';
import { MemoryRpcPool } from '@stackwallet/chains';
import { VaultStore } from './core/vault.js';
import { emptyState } from './store/reducers.js';
import { importPayload, subtree } from './store/sets.js';
import { aggregateNative } from './store/totals.js';
import { createPersistedStore } from './store/persist.js';
import { createPersistedWorkspace } from './workspace/persist.js';
import { emptyState as emptyWorkspace } from './workspace/store.js';

const mocks = vi.hoisted(() => ({ txApprove: vi.fn(), txReport: vi.fn(), broadcastEvm: vi.fn() }));
vi.mock('./core/bridge.js', () => ({ vault: mocks }));
vi.mock('@stackwallet/chains-evm', async (original) => ({
  ...(await original()),
  broadcastEvm: mocks.broadcastEvm,
}));
import { approveAndSend, pollPending } from './store/txs.js';

const repo = resolve(process.cwd(), '../..');
const pass = 'audit scratch passphrase';
async function core() {
  const m = await import(pathToFileURL(`${repo}/apps/web/public/wasm/stackwallet_wasm.js`).href);
  await m.default({
    module_or_path: readFileSync(`${repo}/apps/web/public/wasm/stackwallet_wasm_bg.wasm`),
  });
  return new WasmCoreClient(m);
}
const ctx = { now: () => 1, newId: () => 'root' };

describe('audit regressions', () => {
  it('serializes simultaneous browser vault writes through the shared Web Lock', async () => {
    const c = await core();
    const values = new Map<string, string>();
    const storage = {
      getItem: (k: string) => values.get(k) ?? null,
      setItem: (k: string, v: string) => {
        values.set(k, v);
      },
      removeItem: (k: string) => {
        values.delete(k);
      },
    };
    let tail: Promise<unknown> = Promise.resolve();
    const request = vi.fn((_name: string, op: () => Promise<unknown>) => {
      const result = tail.catch(() => undefined).then(op);
      tail = result;
      return result;
    });
    vi.stubGlobal('navigator', { locks: { request } });
    try {
      const a = new VaultStore({ storage });
      await a.attach(c);
      await a.create(pass);
      const b = new VaultStore({ storage: { ...storage } });
      await b.attach(c);
      await b.unlock(pass);
      const results = await Promise.all([a.createSingle('a'), b.createSingle('b')]);
      expect(results.filter((r) => r.ok)).toHaveLength(1);
      const reloaded = new VaultStore({ storage });
      await reloaded.attach(c);
      await reloaded.unlock(pass);
      expect(reloaded.getSnapshot().provenance.wallets).toHaveLength(1);
      expect(request.mock.calls.every(([name]) => name === 'stackwallet.vault.v1')).toBe(true);
      await a.lock();
      await b.lock();
      await reloaded.lock();
    } finally {
      vi.unstubAllGlobals();
    }
  }, 20000);

  it('fails closed for browser writes without a cross-tab lock', async () => {
    const c = await core();
    const values = new Map<string, string>();
    const storage = {
      getItem: (k: string) => values.get(k) ?? null,
      setItem: (k: string, v: string) => {
        values.set(k, v);
      },
      removeItem: (k: string) => {
        values.delete(k);
      },
    };
    vi.stubGlobal('navigator', {});
    vi.stubGlobal('window', { localStorage: storage });
    try {
      const store = new VaultStore({ storage });
      await store.attach(c);
      expect(await store.create(pass)).toMatchObject({
        ok: false,
        error: expect.stringContaining('Web Locks'),
      });
      expect(values.size).toBe(0);
    } finally {
      vi.unstubAllGlobals();
    }
  }, 20000);

  it('retains layout changes after a failed save until storage recovers', async () => {
    const values = new Map<string, string>();
    let full = true;
    const storage = {
      getItem: (k: string) => values.get(k) ?? null,
      setItem: (k: string, v: string) => {
        if (full) throw new Error('quota');
        values.set(k, v);
      },
      removeItem: (k: string) => {
        values.delete(k);
      },
    };
    const p = createPersistedWorkspace({ storage, ctx, initial: () => emptyWorkspace(ctx) });
    p.store.toggleLock();
    await p.flush();
    full = false;
    await p.flush();
    expect(JSON.parse([...values.values()][0]!).locked).toBe(true);
    await p.dispose();
  });

  it('terminates traversal even for an already corrupt cyclic directory', async () => {
    const state = emptyState(ctx);
    const folder = {
      name: 'cycle',
      tags: [],
      defaultPolicyIds: [],
      createdAtMs: 1,
      updatedAtMs: 1,
    };
    state.folders.push(
      { ...folder, id: 'a', parentId: 'b' },
      { ...folder, id: 'b', parentId: 'a' },
    );
    expect(subtree(state, 'a')).toEqual(['a', 'b']);
  });
  it('rejects disconnected folder cycles', async () => {
    const folder = (id: string, parentId: string | null) => ({
      id,
      parentId,
      name: id,
      tags: [],
      defaultPolicyIds: [],
      createdAtMs: 1,
      updatedAtMs: 1,
    });
    const r = importPayload(
      emptyState(ctx),
      {
        stackwalletSet: 1,
        folders: [folder('top', null), folder('a', 'b'), folder('b', 'a')],
        wallets: [
          {
            id: 'w',
            folderId: 'a',
            name: 'Hidden wallet',
            kind: 'watch',
            keyGroupId: null,
            tags: [],
            createdAtMs: 1,
            updatedAtMs: 1,
          },
        ],
        accounts: [],
      },
      'top',
      ctx,
    );
    expect(r.ok).toBe(false);
  });

  it('counts duplicate on-chain balances once', async () => {
    const accounts = ['a', 'b'].map((id) => ({ id, chainId: 'eip155:1', address: 'same' }));
    const entry = {
      holdings: [{ assetRef: 'eip155:1:native', amount: '100' }],
      fetchedAtMs: 1,
      loading: false,
    };
    const totals = aggregateNative(
      accounts as any,
      new Map(accounts.map((a) => [a.id, entry])) as any,
      () => ({ nativeAsset: { ref: 'eip155:1:native', symbol: 'ETH', decimals: 18 } }) as any,
      { now: 2 },
    );
    expect(totals).toHaveLength(1);
    expect(totals[0]?.amount).toBe('100');
    expect(totals[0]?.incomplete).toBe(false);
  });

  it('retries a failed directory save when storage recovers', async () => {
    const values = new Map<string, string>();
    let full = true;
    let attempts = 0;
    const storage = {
      getItem: (k: string) => values.get(k) ?? null,
      setItem: (k: string, v: string) => {
        attempts++;
        if (full) throw new Error('quota');
        values.set(k, v);
      },
      removeItem: (k: string) => {
        values.delete(k);
      },
    };
    const p = createPersistedStore({ storage, ctx });
    p.store.createFolder('unsaved', 'root');
    await p.flush();
    full = false;
    await p.flush();
    expect(attempts).toBe(3);
    expect(values.size).toBe(1);
    await p.dispose();
  });

  it('refuses wallet creation without persistent storage', async () => {
    const c = await core();
    const store = new VaultStore({ storage: null });
    await store.attach(c);
    expect((await store.create(pass)).ok).toBe(false);
    expect((await store.createSingle('volatile-wallet')).ok).toBe(false);
    expect(store.getSnapshot().status.kind).toBe('unavailable');
  }, 20000);

  it('refuses a stale writer and preserves both keys after reloading', async () => {
    const c = await core();
    const values = new Map<string, string>();
    const storage = {
      getItem: (k: string) => values.get(k) ?? null,
      setItem: (k: string, v: string) => {
        values.set(k, v);
      },
      removeItem: (k: string) => {
        values.delete(k);
      },
    };
    const a = new VaultStore({ storage });
    await a.attach(c);
    await a.create(pass);
    const b = new VaultStore({ storage });
    await b.attach(c);
    await b.unlock(pass);
    expect(await a.createSingle('only-in-a')).toEqual({ ok: true });
    expect((await b.createSingle('only-in-b')).ok).toBe(false);
    expect(b.getSnapshot().status.kind).toBe('locked');
    expect(await b.unlock(pass)).toEqual({ ok: true });
    expect(await b.createSingle('only-in-b')).toEqual({ ok: true });
    const reopened = new VaultStore({ storage });
    await reopened.attach(c);
    await reopened.unlock(pass);
    const ids = reopened.getSnapshot().provenance.wallets.map((w) => w.walletId);
    expect(ids).toEqual(['only-in-a', 'only-in-b']);
    await a.lock();
    await b.lock();
    await reopened.lock();
  }, 20000);

  it('reloads committed ciphertext after failed passphrase persistence', async () => {
    const c = await core();
    const values = new Map<string, string>();
    let full = false;
    const storage = {
      getItem: (k: string) => values.get(k) ?? null,
      setItem: (k: string, v: string) => {
        if (full) throw new Error('quota');
        values.set(k, v);
      },
      removeItem: (k: string) => {
        values.delete(k);
      },
    };
    const a = new VaultStore({ storage });
    await a.attach(c);
    await a.create(pass);
    full = true;
    expect((await a.changePassphrase(pass, 'next scratch passphrase')).ok).toBe(false);
    full = false;
    expect(a.getSnapshot().status.kind).toBe('locked');
    const b = new VaultStore({ storage });
    await b.attach(c);
    expect((await b.unlock('next scratch passphrase')).ok).toBe(false);
    expect((await b.unlock(pass)).ok).toBe(true);
    expect((await a.unlock('next scratch passphrase')).ok).toBe(false);
    expect((await a.unlock(pass)).ok).toBe(true);
    expect((await a.changePassphrase(pass, 'next scratch passphrase')).ok).toBe(true);
    await a.lock();
    expect((await a.unlock('next scratch passphrase')).ok).toBe(true);
    await a.lock();
    await b.lock();
  }, 20000);

  it('retains ambiguous EVM broadcasts and checks their receipts', async () => {
    vi.clearAllMocks();
    const tx: any = {
      id: 'evm',
      intent: { chainId: 'eip155:1' },
      unsigned: { nonce: 0 },
      state: 'awaiting',
      hash: null,
      rawSignedHex: null,
    };
    const signed = { ...tx, state: 'signed', hash: '0x' + 'a'.repeat(64), rawSignedHex: '0x02' };
    mocks.txApprove.mockResolvedValue({ ok: true, value: signed });
    mocks.txReport.mockImplementation(async (_: string, state: string) => ({
      ok: true,
      value: { ...signed, state },
    }));
    mocks.broadcastEvm.mockRejectedValue(
      new Error('response timeout after node accepted transaction'),
    );
    const status = vi.fn().mockResolvedValue({ state: 'confirmed', blockNumber: 10 });
    const registry: any = { adapterFor: () => ({ family: 'evm', status }) };
    const result = await approveAndSend(registry, tx, pass);
    expect(result.ok && result.value.state).toBe('pending');
    if (result.ok) await pollPending(registry, [result.value]);
    expect(status).toHaveBeenCalled();
    expect(mocks.txReport).toHaveBeenLastCalledWith('evm', 'confirmed', 'block 10');
  });

  it('resumes EVM signed/broadcast records after restart', async () => {
    vi.clearAllMocks();
    const status = vi.fn().mockResolvedValue({ state: 'pending' });
    await pollPending(
      { adapterFor: () => ({ family: 'evm', status }) } as any,
      ['signed', 'broadcast'].map((state) => ({
        id: state,
        state,
        hash: '0x' + 'a'.repeat(64),
        unsigned: { nonce: 0 },
        intent: { chainId: 'eip155:1' },
      })) as any,
    );
    expect(status).toHaveBeenCalledTimes(2);
    expect(mocks.txReport).toHaveBeenCalled();
  });

  it('rejects receipts for a different transaction hash', async () => {
    const adapter = new EvmAdapter({
      fetch: (async (_url: unknown, opts: any) => {
        const req = JSON.parse(opts.body);
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: req.id,
            result:
              req.method === 'eth_chainId'
                ? '0x1'
                : {
                    status: '0x1',
                    blockNumber: '0xa',
                    transactionHash: '0x' + 'b'.repeat(64),
                  },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }) as any,
    });
    await expect(adapter.status('0x' + 'a'.repeat(64), 'eip155:1')).rejects.toThrow(
      /Receipt transaction hash/,
    );
  });

  it('rejects native balances from a different Solana cluster', async () => {
    const chain = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
    const rpc = new MemoryRpcPool();
    rpc.setEndpoints(chain, ['https://mainnet.invalid']);
    const methods: string[] = [];
    const adapter = new SolanaAdapter({
      rpc,
      fetch: (async (_url: unknown, opts: any) => {
        const req = JSON.parse(opts.body);
        methods.push(req.method);
        const result =
          req.method === 'getGenesisHash'
            ? '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'
            : { context: { slot: 123 }, value: 100 };
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }), {
          status: 200,
        });
      }) as any,
    });
    await expect(adapter.getBalances('11111111111111111111111111111111', chain)).rejects.toThrow(
      /genesis hash/,
    );
    expect(methods).toEqual(['getGenesisHash']);
  });
});
