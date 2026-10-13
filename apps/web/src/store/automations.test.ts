import { describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  proposeSend: vi.fn(),
  ensure: vi.fn(),
  get: vi.fn(),
  status: { kind: 'unlocked' },
  accounts: [] as unknown[],
}));
vi.mock('../core/bridge.js', () => ({ vault: { getSnapshot: () => ({ status: mocks.status }) } }));
vi.mock('./txs.js', () => ({ proposeSend: mocks.proposeSend }));
vi.mock('./balances.js', () => ({ balanceCache: { ensure: mocks.ensure, get: mocks.get } }));
vi.mock('./persist.js', () => ({
  directory: { getSnapshot: () => ({ accounts: mocks.accounts }) },
}));

import { AutomationStore } from './automations.js';

class Mem {
  m = new Map<string, string>();
  getItem(k: string) {
    return this.m.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.m.set(k, v);
  }
  removeItem(k: string) {
    this.m.delete(k);
  }
}

const account = {
  id: 'acc',
  walletId: 'w',
  family: 'evm',
  chainId: 'eip155:11155111',
  address: '0x1111111111111111111111111111111111111111',
  derivationPath: "m/44'/60'/0'/0/0",
  publicKeyHex: '02',
  hidden: false,
};

describe('automation scheduler', () => {
  it('proposes due runs as automation proposals and persists them', async () => {
    mocks.accounts = [account];
    mocks.ensure.mockResolvedValue(undefined);
    mocks.get.mockReturnValue({
      holdings: [{ assetRef: 'eip155:11155111:native', amount: '150' }],
    });
    mocks.proposeSend.mockResolvedValue({ ok: true, value: { id: 'tx1', state: 'awaiting' } });
    const storage = new Mem();
    let t = 1_000;
    let n = 0;
    const store = new AutomationStore(
      storage,
      () => t,
      () => `id${++n}`,
    );
    const added = store.add({
      name: 'sweep',
      enabled: true,
      walletId: 'w',
      accountId: 'acc',
      asset: 'eip155:11155111:native',
      trigger: { kind: 'balanceAbove', above: '100' },
      action: { kind: 'sweep', to: '0x2222222222222222222222222222222222222222', keep: '40' },
    });
    expect(added.ok).toBe(true);
    expect(await store.runDue({} as never)).toBe(1);
    const call = mocks.proposeSend.mock.calls[0]![1];
    expect(call).toMatchObject({ amount: '110', by: { kind: 'automation', automationId: 'id1' } });
    expect(store.getSnapshot().runs[0]).toMatchObject({ outcome: 'proposed', txId: 'tx1' });
    // Not due again until the floor interval passes.
    expect(await store.runDue({} as never)).toBe(0);
    t += 16 * 60 * 1000;
    mocks.get.mockReturnValue({ holdings: [{ assetRef: 'eip155:11155111:native', amount: '20' }] });
    await store.runDue({} as never);
    expect(store.getSnapshot().runs[1]).toMatchObject({ outcome: 'skipped' });
    expect(new AutomationStore(storage).getSnapshot().runs).toHaveLength(2);
  });

  it('does nothing while the vault is locked', async () => {
    mocks.status = { kind: 'locked' };
    const store = new AutomationStore(null, () => 1);
    store.add({
      name: 'x',
      enabled: true,
      walletId: 'w',
      accountId: 'acc',
      asset: 'a',
      trigger: { kind: 'interval', everyMs: 3_600_000, startAtMs: 0 },
      action: { kind: 'transfer', to: '0x2', amount: '1' },
    });
    expect(await store.runDue({} as never)).toBe(0);
    mocks.status = { kind: 'unlocked' };
  });
});
