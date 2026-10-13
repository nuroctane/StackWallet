import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ACTIVITY_MAX_DAYS,
  ACTIVITY_STORAGE_KEY,
  ActivityLog,
  ActivityState,
  dayKey,
  loadActivity,
} from './activity.js';
import type { StorageLike } from './persist.js';

class MemoryStorage implements StorageLike {
  readonly map = new Map<string, string>();
  getItem(key: string) {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.map.set(key, value);
  }
  removeItem(key: string) {
    this.map.delete(key);
  }
}

const local = (y: number, m: number, d: number, h = 12) => new Date(y, m - 1, d, h).getTime();
const DAY = 86_400_000;

describe('dayKey', () => {
  it('uses the local calendar day and zero-pads', () => {
    expect(dayKey(local(2024, 3, 5))).toBe('2024-03-05');
    expect(dayKey(local(2024, 12, 31))).toBe('2024-12-31');
  });

  it('rolls over at local midnight, not UTC midnight', () => {
    const lastTick = new Date(2024, 2, 10, 23, 59, 59, 999).getTime();
    expect(dayKey(lastTick)).toBe('2024-03-10');
    expect(dayKey(lastTick + 1)).toBe('2024-03-11');
    expect(dayKey(new Date(2024, 2, 11, 0, 0, 0, 0).getTime())).toBe('2024-03-11');
  });
});

describe('ActivityLog', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('records counts per day and per kind', () => {
    let now = local(2024, 3, 5);
    const log = new ActivityLog(null, () => now);
    let notified = 0;
    log.subscribe(() => notified++);
    log.record('directory');
    log.record('directory', 2);
    log.record('balance');
    now = local(2024, 3, 6);
    log.record('layout');
    log.record('device', 0);
    log.record('device', -3);
    expect(notified).toBe(4);
    expect(log.getSnapshot().days).toEqual({
      '2024-03-05': { n: 4, kinds: { directory: 3, balance: 1 } },
      '2024-03-06': { n: 1, kinds: { layout: 1 } },
    });
  });

  it('series has weeks*7 entries, oldest first, aligned so the last entry is today', () => {
    const now = local(2024, 3, 10, 15);
    const log = new ActivityLog(null, () => now);
    log.record('ceremony', 2);
    const s = log.series(2);
    expect(s).toHaveLength(14);
    expect(s[13]?.dayKey).toBe('2024-03-10');
    expect(s[13]?.n).toBe(2);
    expect(s[0]?.dayKey).toBe('2024-02-26');
    for (let i = 0; i < s.length; i++) {
      const p = s[i]!;
      expect(dayKey(p.t)).toBe(p.dayKey);
      expect(new Date(p.t).getHours()).toBe(0);
      if (i > 0) expect(p.t - s[i - 1]!.t).toBeGreaterThanOrEqual(23 * 3_600_000);
      if (i !== 13) expect(p.n).toBe(0);
    }
    expect(log.series(0)).toEqual([]);
    expect(log.series(52)).toHaveLength(364);
  });

  it('series can be aligned to an explicit now', () => {
    const log = new ActivityLog(null, () => local(2024, 3, 10));
    const s = log.series(1, local(2023, 1, 1));
    expect(s.map((p) => p.dayKey)).toEqual([
      '2022-12-26',
      '2022-12-27',
      '2022-12-28',
      '2022-12-29',
      '2022-12-30',
      '2022-12-31',
      '2023-01-01',
    ]);
  });

  it('caps history at the newest ACTIVITY_MAX_DAYS days', () => {
    let now = local(2023, 1, 1);
    const log = new ActivityLog(null, () => now);
    for (let i = 0; i < ACTIVITY_MAX_DAYS + 5; i++) {
      log.record('balance');
      now += DAY;
    }
    const keys = Object.keys(log.getSnapshot().days).sort();
    expect(keys).toHaveLength(ACTIVITY_MAX_DAYS);
    expect(keys[0]).toBe(dayKey(local(2023, 1, 1) + 5 * DAY));
    expect(keys[keys.length - 1]).toBe(dayKey(now - DAY));
  });

  it('persists after the debounce and reloads', () => {
    const storage = new MemoryStorage();
    const now = local(2024, 3, 5);
    const log = new ActivityLog(storage, () => now, 500);
    log.record('directory');
    vi.advanceTimersByTime(499);
    expect(storage.getItem(ACTIVITY_STORAGE_KEY)).toBeNull();
    vi.advanceTimersByTime(1);
    const saved = ActivityState.parse(JSON.parse(storage.getItem(ACTIVITY_STORAGE_KEY)!));
    expect(saved.days['2024-03-05']?.n).toBe(1);

    log.record('device');
    log.flush();
    const reloaded = new ActivityLog(storage, () => now);
    expect(reloaded.getSnapshot()).toEqual(log.getSnapshot());
    expect(reloaded.series(1)[6]?.n).toBe(2);
  });

  it('retains dirty history through quota failures and retries without new events', () => {
    const storage = new MemoryStorage();
    const write = vi.spyOn(storage, 'setItem').mockImplementation(() => {
      throw new Error('quota');
    });
    const log = new ActivityLog(storage, () => local(2024, 3, 5), 500);
    log.record('transaction');
    vi.advanceTimersByTime(500 * 10);
    expect(write).toHaveBeenCalledTimes(3);
    expect(storage.getItem(ACTIVITY_STORAGE_KEY)).toBeNull();
    write.mockRestore();
    log.flush();
    expect(loadActivity(storage)).toEqual(log.getSnapshot());
    expect(loadActivity(storage).days['2024-03-05']?.n).toBe(1);
  });

  it('automatically recovers after a transient storage failure', () => {
    const storage = new MemoryStorage();
    vi.spyOn(storage, 'setItem').mockImplementationOnce(() => {
      throw new Error('busy');
    });
    const log = new ActivityLog(storage, () => local(2024, 3, 5), 500);
    log.record('directory', 2);
    vi.advanceTimersByTime(1000);
    expect(loadActivity(storage)).toEqual(log.getSnapshot());
    expect(vi.getTimerCount()).toBe(0);
  });

  it('starts fresh from corrupt or invalid blobs without quarantining', () => {
    for (const bad of [
      '{nope',
      JSON.stringify({ version: 2 }),
      JSON.stringify({ version: 1, days: { x: 1 } }),
    ]) {
      const storage = new MemoryStorage();
      storage.setItem(ACTIVITY_STORAGE_KEY, bad);
      expect(loadActivity(storage)).toEqual({ version: 1, days: {}, events: [] });
      expect([...storage.map.keys()]).toEqual([ACTIVITY_STORAGE_KEY]);
    }
    expect(loadActivity(null)).toEqual({ version: 1, days: {}, events: [] });
  });
});
describe('individual event history', () => {
  it('preserves legacy terrain totals without fabricating old timestamps', () => {
    const storage = new MemoryStorage();
    storage.setItem(
      ACTIVITY_STORAGE_KEY,
      JSON.stringify({ version: 1, days: { '2024-03-05': { n: 3, kinds: { directory: 3 } } } }),
    );
    const loaded = new ActivityLog(storage, () => local(2024, 3, 6));
    expect(loaded.getSnapshot().events).toEqual([]);
    expect(loaded.getSnapshot().days['2024-03-05']?.n).toBe(3);
    loaded.record('layout');
    loaded.flush();
    expect(new ActivityLog(storage).getSnapshot().events).toEqual([
      { atMs: local(2024, 3, 6), kind: 'layout', count: 1 },
    ]);
  });
  it('retains bounded timestamped entries while keeping aggregate counts in parity', () => {
    const log = new ActivityLog(null, () => local(2024, 3, 6));
    for (let i = 0; i < 1005; i++) log.record('directory', 2);
    expect(log.getSnapshot().events).toHaveLength(1000);
    expect(log.getSnapshot().days['2024-03-06']?.n).toBe(2010);
    log.record('transaction', 4);
    expect(log.getSnapshot().events[0]).toMatchObject({ kind: 'transaction', count: 4 });
    log.record('layout', 1.5);
    expect(log.getSnapshot().days['2024-03-06']?.n).toBe(2014);
    log.flush();
  });
});
