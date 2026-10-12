import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { NativeTotal } from '../store/totals.js';
import {
  LEDGER_DEDUPE_MS,
  LEDGER_MAX_POINTS,
  LEDGER_STORAGE_KEY,
  LedgerState,
  formatLedgerAmount,
  loadLedger,
  TotalsLedger,
  toUnits,
} from './ledger.js';
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

const total = (over: Partial<NativeTotal> = {}): NativeTotal => ({
  assetRef: 'eip155:1/slip44:60',
  symbol: 'ETH',
  decimals: 18,
  amount: '1000000000000000000',
  accounts: 1,
  incomplete: false,
  disputed: false,
  ...over,
});

describe('toUnits', () => {
  it('converts base units with 18 decimals and keeps whole units exact', () => {
    expect(toUnits('1000000000000000000', 18)).toBe(1);
    expect(toUnits('1500000000000000000', 18)).toBe(1.5);
    expect(toUnits('123456789000000000000000000', 18)).toBe(123_456_789);
    expect(toUnits('0', 18)).toBe(0);
    expect(toUnits('12345678', 8)).toBe(0.12345678);
    expect(toUnits('abc', 18)).toBeNaN();
  });
});

describe('exact ledger readouts', () => {
  it('retains fractional base units lost by the plotting approximation', () => {
    expect(toUnits('1000000000000000001', 18)).toBe(1);
    expect(formatLedgerAmount('1000000000000000001', 18)).toBe('1.000000000000000001');
    expect(formatLedgerAmount('9007199254740993', 0)).toBe('9007199254740993');
    expect(formatLedgerAmount('1', 77)).toBe(`0.${'0'.repeat(76)}1`);
  });

  it('normalizes zeros without rounding and rejects malformed quantities', () => {
    expect(formatLedgerAmount('0000', 18)).toBe('0');
    expect(formatLedgerAmount('000123400', 6)).toBe('0.1234');
    expect(formatLedgerAmount('12345678', 8)).toBe('0.12345678');
    expect(formatLedgerAmount('abc', 18)).toBe('unavailable');
    expect(formatLedgerAmount('1', -1)).toBe('unavailable');
    expect(formatLedgerAmount('1', 1.5)).toBe('unavailable');
  });
});

describe('TotalsLedger', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('skips incomplete totals and repeats of the same amount inside the dedupe window', () => {
    let now = 1_000_000;
    const ledger = new TotalsLedger(null, () => now);
    let notified = 0;
    ledger.subscribe(() => notified++);

    ledger.record([
      total(),
      total({ assetRef: 'bip122:000/slip44:0', symbol: 'BTC', decimals: 8, incomplete: true }),
    ]);
    expect(ledger.getSnapshot().points).toHaveLength(1);
    expect(notified).toBe(1);

    now += LEDGER_DEDUPE_MS - 1;
    ledger.record([total()]);
    expect(ledger.getSnapshot().points).toHaveLength(1);
    expect(notified).toBe(1);

    ledger.record([total({ amount: '2000000000000000000' })]);
    expect(ledger.getSnapshot().points).toHaveLength(2);

    now += LEDGER_DEDUPE_MS;
    ledger.record([total({ amount: '2000000000000000000' })]);
    expect(ledger.getSnapshot().points).toHaveLength(3);

    ledger.record([total({ amount: '1.5' })]);
    expect(ledger.getSnapshot().points).toHaveLength(3);
  });

  it('dedupes per asset, not globally', () => {
    const ledger = new TotalsLedger(null, () => 5_000);
    ledger.record([total()]);
    ledger.record([
      total({
        assetRef: 'solana:main/slip44:501',
        symbol: 'SOL',
        decimals: 9,
        amount: '1000000000',
      }),
    ]);
    expect(ledger.getSnapshot().points).toHaveLength(2);
    expect(ledger.assets()).toEqual([
      { assetRef: 'eip155:1/slip44:60', symbol: 'ETH' },
      { assetRef: 'solana:main/slip44:501', symbol: 'SOL' },
    ]);
  });

  it('caps at LEDGER_MAX_POINTS by dropping the oldest', () => {
    let now = 0;
    const ledger = new TotalsLedger(null, () => now);
    for (let i = 0; i < LEDGER_MAX_POINTS + 10; i++) {
      now += LEDGER_DEDUPE_MS;
      ledger.record([total({ amount: String(i) })]);
    }
    const points = ledger.getSnapshot().points;
    expect(points).toHaveLength(LEDGER_MAX_POINTS);
    expect(points[0]?.amount).toBe('10');
    expect(points[points.length - 1]?.amount).toBe(String(LEDGER_MAX_POINTS + 9));
  });

  it('seriesFor converts amounts and filters by asset and time', () => {
    let now = 10_000;
    const ledger = new TotalsLedger(null, () => now);
    ledger.record([total({ amount: '1000000000000000000' })]);
    now += LEDGER_DEDUPE_MS;
    ledger.record([
      total({ amount: '2500000000000000000' }),
      total({ assetRef: 'x', symbol: 'X', decimals: 0, amount: '7' }),
    ]);
    expect(ledger.seriesFor('eip155:1/slip44:60')).toEqual([
      { t: 10_000, v: 1 },
      { t: 10_000 + LEDGER_DEDUPE_MS, v: 2.5 },
    ]);
    expect(ledger.seriesFor('eip155:1/slip44:60', 10_001)).toEqual([
      { t: 10_000 + LEDGER_DEDUPE_MS, v: 2.5 },
    ]);
    expect(ledger.seriesFor('x')).toEqual([{ t: 10_000 + LEDGER_DEDUPE_MS, v: 7 }]);
    expect(ledger.seriesFor('missing')).toEqual([]);
  });

  it('persists after the debounce and reloads', () => {
    const storage = new MemoryStorage();
    const ledger = new TotalsLedger(storage, () => 42, 500);
    ledger.record([total()]);
    vi.advanceTimersByTime(499);
    expect(storage.getItem(LEDGER_STORAGE_KEY)).toBeNull();
    vi.advanceTimersByTime(1);
    const saved = LedgerState.parse(JSON.parse(storage.getItem(LEDGER_STORAGE_KEY)!));
    expect(saved.points).toEqual([
      {
        t: 42,
        assetRef: 'eip155:1/slip44:60',
        amount: '1000000000000000000',
        decimals: 18,
        symbol: 'ETH',
      },
    ]);
    const reloaded = new TotalsLedger(storage, () => 43);
    expect(reloaded.getSnapshot()).toEqual(ledger.getSnapshot());
    expect(reloaded.seriesFor('eip155:1/slip44:60')).toEqual([{ t: 42, v: 1 }]);
  });

  it('starts fresh from corrupt or invalid blobs', () => {
    for (const bad of ['{nope', JSON.stringify({ version: 1, points: [{ t: 1 }] })]) {
      const storage = new MemoryStorage();
      storage.setItem(LEDGER_STORAGE_KEY, bad);
      expect(loadLedger(storage)).toEqual({ version: 1, points: [] });
    }
    expect(loadLedger(null)).toEqual({ version: 1, points: [] });
  });
});
