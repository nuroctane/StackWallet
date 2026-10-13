import { afterEach, describe, expect, it, vi } from 'vitest';
import type { StorageLike } from '../store/persist.js';
import { withStorageWriter } from '../store/storageWriter.js';
import {
  ActivityLog,
  ACTIVITY_STORAGE_KEY,
  emptyActivity,
  loadActivity,
  mergeActivity,
} from './activity.js';
import {
  TotalsLedger,
  LEDGER_STORAGE_KEY,
  loadLedger,
  mergeLedger,
  LEDGER_MAX_POINTS,
} from './ledger.js';
import type { NativeTotal } from '../store/totals.js';

class MemoryStorage implements StorageLike {
  readonly values = new Map<string, string>();
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
  key(index: number) {
    return [...this.values.keys()][index] ?? null;
  }
  get length() {
    return this.values.size;
  }
}
const logs: Array<{ dispose(): Promise<void> }> = [];
const activity = (storage: StorageLike | null, at = Date.UTC(2026, 9, 13, 12)) => {
  const log = new ActivityLog(storage, () => at);
  logs.push(log);
  return log;
};
const ledger = (storage: StorageLike | null, at: number) => {
  const log = new TotalsLedger(storage, () => at);
  logs.push(log);
  return log;
};
const total = (amount: string): NativeTotal => ({
  assetRef: 'eip155:1/slip44:60',
  decimals: 18,
  symbol: 'ETH',
  amount,
  accounts: 1,
  incomplete: false,
  disputed: false,
});
afterEach(async () => {
  for (const log of logs.splice(0)) await log.dispose();
  vi.unstubAllGlobals();
});

describe('coordinated history persistence', () => {
  it('updates subscribed graphs and logs after a storage event without a new local record', async () => {
    const storage = new MemoryStorage();
    const events = new EventTarget();
    vi.stubGlobal('window', {
      localStorage: storage,
      addEventListener: events.addEventListener.bind(events),
      removeEventListener: events.removeEventListener.bind(events),
    });
    const a = activity(storage),
      b = activity(storage);
    let notify!: () => void;
    const updated = new Promise<void>((resolve) => {
      notify = resolve;
    });
    b.subscribe(notify);
    a.record('directory');
    await a.flush();
    const event = new Event('storage');
    Object.assign(event, { key: ACTIVITY_STORAGE_KEY, storageArea: storage });
    events.dispatchEvent(event);
    await updated;
    expect(b.getSnapshot().events).toHaveLength(1);
  });

  it('orders observations after a clock rollback and ignores invalid observation metadata', async () => {
    const storage = new MemoryStorage();
    const log = ledger(storage, 200);
    log.record([total('1')]);
    log.record([total('1')], 100);
    log.record([{ ...total('2'), decimals: -1 }], 300);
    log.record([total('2')], Number.NaN);
    await log.flush();
    expect(loadLedger(storage).points.map((p) => p.t)).toEqual([100, 200]);
  });
  it('retains same-timestamp events and daily totals from concurrently saving tabs', async () => {
    const storage = new MemoryStorage();
    const a = activity(storage),
      b = activity(storage);
    a.record('directory', 2);
    b.record('directory', 3);
    await Promise.all([a.flush(), b.flush()]);
    await a.flush();
    expect(a.getSnapshot()).toEqual(b.getSnapshot());
    expect(loadActivity(storage).events).toHaveLength(2);
    expect(Object.values(loadActivity(storage).days)[0]?.n).toBe(5);
    await Promise.all([a.flush(), b.flush()]);
    expect(Object.values(loadActivity(storage).days)[0]?.n).toBe(5);
  });

  it('preserves shared legacy counts exactly once when both tabs migrate', async () => {
    const storage = new MemoryStorage();
    storage.setItem(
      ACTIVITY_STORAGE_KEY,
      JSON.stringify({
        version: 1,
        days: { '2026-10-13': { n: 7, kinds: { layout: 7 } } },
        events: [],
      }),
    );
    const a = activity(storage),
      b = activity(storage);
    a.record('layout', 2);
    b.record('layout', 3);
    await a.flush();
    await b.flush();
    expect(loadActivity(storage).days['2026-10-13']?.n).toBe(12);
    expect(loadActivity(storage).days['2026-10-13']?.kinds.layout).toBe(12);
  });

  it('replaying revised recovery copies never doubles counts after event trimming', async () => {
    const storage = new MemoryStorage();
    const original = activity(null);
    for (let i = 0; i < 1005; i++) original.record('balance');
    const recoveryKey = `${ACTIVITY_STORAGE_KEY}.recovery.interrupted`;
    const archive = () =>
      storage.setItem(
        recoveryKey,
        JSON.stringify({
          stackwalletRecovery: 1,
          source: 'activity history',
          base: emptyActivity(),
          local: original.getSnapshot(),
        }),
      );
    archive();
    const recovered = activity(storage);
    await recovered.flush();
    expect(Object.values(loadActivity(storage).days)[0]?.n).toBe(1005);
    original.record('balance', 2);
    archive();
    const next = activity(storage);
    await next.flush();
    expect(Object.values(loadActivity(storage).days)[0]?.n).toBe(1007);
    expect(loadActivity(storage).events).toHaveLength(1000);
    expect(mergeActivity(next.getSnapshot(), next.getSnapshot())).toEqual(next.getSnapshot());
  });

  it('includes records added while the storage lock is held', async () => {
    const storage = new MemoryStorage();
    const log = activity(storage);
    let release!: () => void, acquired!: () => void;
    const ready = new Promise<void>((resolve) => {
      acquired = resolve;
    });
    const hold = withStorageWriter(storage, ACTIVITY_STORAGE_KEY, async () => {
      acquired();
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    });
    await ready;
    log.record('device');
    const pending = log.flush();
    log.record('ceremony');
    release();
    await hold;
    await pending;
    expect(loadActivity(storage).events).toHaveLength(2);
  });

  it('keeps concurrent balance observations ordered and adopts them in an idle tab', async () => {
    const storage = new MemoryStorage();
    const a = ledger(storage, 200),
      b = ledger(storage, 100),
      idle = ledger(storage, 300);
    a.record([total('2')]);
    b.record([total('1')]);
    await Promise.all([a.flush(), b.flush()]);
    await idle.flush();
    expect(idle.getSnapshot().points.map((p) => p.t)).toEqual([100, 200]);
    expect(loadLedger(storage).points.map((p) => p.amount)).toEqual(['1', '2']);
  });

  it('retains distinct observations with identical timestamps and quantities', async () => {
    const storage = new MemoryStorage();
    const a = ledger(storage, 100),
      b = ledger(storage, 100);
    a.record([total('1')]);
    b.record([total('1')]);
    await Promise.all([a.flush(), b.flush()]);
    const saved = loadLedger(storage);
    expect(saved.points).toHaveLength(2);
    expect(mergeLedger(saved, saved)).toEqual(saved);
  });

  it('preserves legacy duplicate observations without multiplying them on replay', () => {
    const point = { t: 100, assetRef: 'native', amount: '1', decimals: 0 };
    const state = { version: 1 as const, points: [point, point] };
    expect(mergeLedger(state, state).points).toHaveLength(2);
  });

  it('caps a merged balance history by timestamp rather than tab save order', () => {
    const points = Array.from({ length: LEDGER_MAX_POINTS }, (_, t) => ({
      t: t + 1,
      assetRef: 'native',
      amount: String(t),
      decimals: 0,
    }));
    const merged = mergeLedger(
      { version: 1, points },
      { version: 1, points: [{ t: 0, assetRef: 'native', amount: '0', decimals: 0 }] },
    );
    expect(merged.points).toHaveLength(LEDGER_MAX_POINTS);
    expect(merged.points[0]?.t).toBe(1);
  });

  it('does not overwrite a foreign corrupt blob and retains a recovery copy', async () => {
    const storage = new MemoryStorage();
    const log = ledger(storage, 100);
    log.record([total('1')]);
    storage.setItem(LEDGER_STORAGE_KEY, '{broken');
    await log.flush();
    expect(storage.getItem(LEDGER_STORAGE_KEY)).toBe('{broken');
    expect(
      [...storage.values.keys()].some((key) => key.startsWith(`${LEDGER_STORAGE_KEY}.recovery.`)),
    ).toBe(true);
  });

  it('rejects conflicting contents for a previously committed record identity', async () => {
    const storage = new MemoryStorage();
    const log = ledger(storage, 100);
    log.record([total('1')]);
    await log.flush();
    const changed = loadLedger(storage);
    changed.points[0]!.amount = '9';
    storage.setItem(LEDGER_STORAGE_KEY, JSON.stringify(changed));
    log.record([total('2')], 200);
    await log.flush();
    expect(loadLedger(storage).points).toHaveLength(1);
    expect(log.getSnapshot().points).toHaveLength(2);
  });
});
