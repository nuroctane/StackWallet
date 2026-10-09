import { describe, expect, it } from 'vitest';
import type { ChainAdapter, Holding } from '@stackwallet/chains';

import { BalanceCache, balanceKey, type BalanceSource } from './balances.js';

function source(impl: (addr: string, chainId: string) => Promise<Holding[]>): BalanceSource & {
  calls: number;
} {
  const s = {
    calls: 0,
    adapterFor: (_chainId: string) =>
      ({
        getBalances: (addr: string, chainId: string) => {
          s.calls += 1;
          return impl(addr, chainId);
        },
      }) as unknown as ChainAdapter,
  };
  return s;
}

const acct = { chainId: 'eip155:1', address: '0xabc' };

describe('BalanceCache', () => {
  it('fetches once, dedupes concurrent callers and marks loading', async () => {
    let clock = 1_000;
    const cache = new BalanceCache({ now: () => clock, staleMs: 60_000 });
    let resolve!: (h: Holding[]) => void;
    const src = source(() => new Promise<Holding[]>((res) => (resolve = res)));

    const p1 = cache.ensure(src, acct);
    const p2 = cache.ensure(src, acct);
    expect(p1).toBe(p2);
    expect(cache.get(acct.chainId, acct.address)?.loading).toBe(true);

    // The fetch body starts one microtask later; let it reach getBalances.
    await new Promise((r) => setTimeout(r, 0));
    clock = 2_000;
    resolve([{ assetRef: 'eip155:1/slip44:60', amount: '5', updatedAtMs: 2_000 }]);
    await p1;
    const entry = cache.get(acct.chainId, acct.address);
    expect(entry).toEqual({
      holdings: [{ assetRef: 'eip155:1/slip44:60', amount: '5', updatedAtMs: 2_000 }],
      fetchedAtMs: 2_000,
      loading: false,
    });
    expect(src.calls).toBe(1);
  });

  it('skips fresh entries, refetches stale ones, and forces on refresh', async () => {
    let clock = 0;
    const cache = new BalanceCache({ now: () => clock, staleMs: 60_000 });
    const src = source(async () => []);
    await cache.ensure(src, acct);
    await cache.ensure(src, acct);
    expect(src.calls).toBe(1);
    clock = 60_000;
    await cache.ensure(src, acct);
    expect(src.calls).toBe(2);
    await cache.refresh(src, [acct]);
    expect(src.calls).toBe(3);
  });

  it('a forced refresh during an in-flight fetch still produces a second read', async () => {
    const cache = new BalanceCache({ now: () => 1, staleMs: 60_000 });
    let resolve!: (h: Holding[]) => void;
    const src = source(() => new Promise<Holding[]>((res) => (resolve = res)));
    const first = cache.ensure(src, acct);
    const forced = cache.ensure(src, acct, { force: true });
    expect(forced).not.toBe(first);
    await new Promise((r) => setTimeout(r, 0));
    resolve([]);
    await first;
    await new Promise((r) => setTimeout(r, 0));
    resolve([]);
    await forced;
    expect(src.calls).toBe(2);
  });

  it('records adapter and fetch errors on the entry instead of throwing', async () => {
    const cache = new BalanceCache({ now: () => 1 });
    const noAdapter: BalanceSource = {
      adapterFor: () => {
        throw new Error('no adapter registered for evm');
      },
    };
    await expect(cache.ensure(noAdapter, acct)).resolves.toBeUndefined();
    expect(cache.get(acct.chainId, acct.address)).toMatchObject({
      error: 'no adapter registered for evm',
      loading: false,
      holdings: [],
    });

    const failing = source(async () => {
      throw new Error('rpc down');
    });
    await cache.ensure(failing, acct, { force: true });
    expect(cache.get(acct.chainId, acct.address)?.error).toBe('rpc down');
  });

  it('publishes a new snapshot to subscribers on every change', async () => {
    const cache = new BalanceCache({ now: () => 1 });
    const before = cache.getSnapshot();
    let notified = 0;
    const unsub = cache.subscribe(() => (notified += 1));
    await cache.ensure(
      source(async () => []),
      acct,
    );
    expect(notified).toBe(2);
    expect(cache.getSnapshot()).not.toBe(before);
    expect(cache.getSnapshot().has(balanceKey(acct.chainId, acct.address))).toBe(true);
    unsub();
  });
});
