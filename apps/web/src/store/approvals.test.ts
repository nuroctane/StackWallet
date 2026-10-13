import { describe, expect, it } from 'vitest';
import type { ApprovalScan } from '@stackwallet/chains-evm';

import { APPROVALS_STORAGE_KEY, ApprovalsStore } from './approvals.js';

class MemoryStorage {
  data = new Map<string, string>();
  getItem(k: string) {
    return this.data.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.data.set(k, v);
  }
  removeItem(k: string) {
    this.data.delete(k);
  }
}

const OWNER = '0x1111111111111111111111111111111111111111';
const SPENDER = '0x2222222222222222222222222222222222222222';
const TOKEN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const accounts = [{ family: 'evm' as const, address: OWNER.toUpperCase().replace('0X', '0x') }];

function scan(chainId: string, open: ApprovalScan['open'], at = 1): ApprovalScan {
  return { chainId, owner: OWNER, open, truncated: false, checkedAtMs: at };
}

const allowance = (chainId: string): ApprovalScan['open'][number] => ({
  chainId,
  kind: 'erc20',
  token: TOKEN,
  spender: SPENDER,
  granted: '5',
  amount: '5',
  unlimited: false,
  verified: true,
  txHash: `0x${'ab'.repeat(32)}`,
  blockNumber: 1,
});

describe('approvals store', () => {
  it('scans an address on every indexed chain and sums the open approvals', async () => {
    const storage = new MemoryStorage();
    const store = new ApprovalsStore(storage, () => 10);
    store.setScanner(
      async (chainId) =>
        scan(
          chainId,
          chainId === 'eip155:1'
            ? [allowance(chainId), { ...allowance(chainId), kind: 'operator', unlimited: true }]
            : [allowance(chainId)],
        ),
      ['eip155:1', 'eip155:8453'],
    );
    expect(store.summary(accounts)).toEqual({ tokens: 0, collectibles: 0 });
    await store.scan(OWNER);
    expect(store.summary(accounts)).toEqual({ tokens: 2, collectibles: 1 });
    expect(store.summary([{ family: 'solana', address: 'x' }])).toBeNull();
    // Reloads from the local cache.
    const again = new ApprovalsStore(storage);
    expect(again.summary(accounts)).toEqual({ tokens: 2, collectibles: 1 });
    expect(storage.getItem(APPROVALS_STORAGE_KEY)).toContain(SPENDER);
  });

  it('never clears the tag on a failed scan, and only rescans after the TTL or on demand', async () => {
    let now = 0;
    let calls = 0;
    let fail = false;
    const store = new ApprovalsStore(null, () => now);
    store.setScanner(
      async (chainId) => {
        calls += 1;
        if (fail) throw new Error('indexer down');
        return scan(chainId, [allowance(chainId)], now);
      },
      ['eip155:1'],
    );
    await store.scan(OWNER);
    await store.scan(OWNER);
    expect(calls).toBe(1);
    fail = true;
    await store.scan(OWNER, { force: true });
    expect(store.summary(accounts)).toEqual({ tokens: 1, collectibles: 0 });
    expect(store.statusOf('eip155:1', OWNER).error).toBe('indexer down');
    fail = false;
    now = 60 * 60 * 1000;
    store.setScanner(async (chainId) => scan(chainId, [], now), ['eip155:1']);
    await store.scan(OWNER);
    expect(store.summary(accounts)).toEqual({ tokens: 0, collectibles: 0 });
  });
});
