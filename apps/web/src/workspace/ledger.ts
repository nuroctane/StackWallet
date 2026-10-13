import { useSyncExternalStore } from 'react';
import { z } from 'zod';

import type { StorageLike } from '../store/persist.js';
import { createMetadataPersistence } from '../store/metadataPersistence.js';
import { mergeHistoryRecords } from './historyMerge.js';
import type { NativeTotal } from '../store/totals.js';

export const LEDGER_STORAGE_KEY = 'stackwallet.ledger.v1';
export const LEDGER_SAVE_DEBOUNCE_MS = 500;
export const LEDGER_MAX_POINTS = 5000;
/** A repeated identical total inside this window is noise from a refresh, not a new observation. */
export const LEDGER_DEDUPE_MS = 60_000;

export const LedgerPoint = z.object({
  id: z.string().uuid().optional(),
  t: z.number().int().nonnegative().safe(),
  assetRef: z.string().min(1),
  /** Base units as a decimal string so 18-decimal chains survive JSON. */
  amount: z.string().regex(/^\d+$/),
  decimals: z.number().int().min(0).max(77),
  symbol: z.string().optional(),
});
export type LedgerPoint = z.infer<typeof LedgerPoint>;

export const LedgerState = z.object({
  version: z.literal(1),
  points: LedgerPoint.array(),
});
export type LedgerState = z.infer<typeof LedgerState>;

export interface SeriesPoint {
  t: number;
  v: number;
}

export interface LedgerAsset {
  assetRef: string;
  symbol?: string;
}

export const emptyLedger = (): LedgerState => ({ version: 1, points: [] });

const capPoints = (points: readonly LedgerPoint[]): LedgerPoint[] =>
  points.length > LEDGER_MAX_POINTS ? points.slice(points.length - LEDGER_MAX_POINTS) : [...points];

export function mergeLedger(left: LedgerState, right: LedgerState): LedgerState {
  return {
    version: 1,
    points: capPoints(
      mergeHistoryRecords(left.points, right.points).sort(
        (a, b) => a.t - b.t || (a.id ?? '').localeCompare(b.id ?? ''),
      ),
    ),
  };
}

/**
 * Split the integer and fractional parts with bigint before converting so the
 * whole-unit part keeps full precision even when the base amount exceeds 2^53.
 */
export function toUnits(amount: string, decimals: number): number {
  if (!/^\d+$/.test(amount)) return Number.NaN;
  const base = 10n ** BigInt(decimals);
  const value = BigInt(amount);
  const whole = value / base;
  const frac = value % base;
  return Number(whole) + Number(frac) / Number(base);
}

/** Text readouts must retain base-unit precision independently of the plotting approximation. */
export function formatLedgerAmount(amount: string, decimals: number): string {
  if (!/^\d+$/.test(amount) || !Number.isInteger(decimals) || decimals < 0 || decimals > 77)
    return 'unavailable';
  const digits = amount.replace(/^0+(?=\d)/, '').padStart(decimals + 1, '0');
  if (decimals === 0) return digits;
  const whole = digits.slice(0, -decimals);
  const fraction = digits.slice(-decimals).replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : whole;
}

export function loadLedger(storage: StorageLike | null): LedgerState {
  if (!storage) return emptyLedger();
  let raw: string | null = null;
  try {
    raw = storage.getItem(LEDGER_STORAGE_KEY);
  } catch {
    return emptyLedger();
  }
  if (raw === null || raw === '') return emptyLedger();
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return emptyLedger();
  }
  const result = LedgerState.safeParse(parsed);
  // History is re-derivable from live balances, so a broken blob is dropped rather than kept.
  if (!result.success) return emptyLedger();
  return mergeLedger(emptyLedger(), result.data);
}

export function saveLedger(storage: StorageLike, state: LedgerState): boolean {
  try {
    storage.setItem(LEDGER_STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

export class TotalsLedger {
  private state: LedgerState;
  private readonly listeners = new Set<() => void>();
  private readonly persistence: ReturnType<typeof createMetadataPersistence<LedgerState>>;

  constructor(
    storage: StorageLike | null,
    private readonly now: () => number = () => Date.now(),
    debounceMs = LEDGER_SAVE_DEBOUNCE_MS,
  ) {
    this.state = loadLedger(storage);
    this.persistence = createMetadataPersistence({
      storage,
      key: LEDGER_STORAGE_KEY,
      name: 'balance history',
      debounceMs,
      retryMs: debounceMs,
      snapshot: this.getSnapshot,
      subscribe: this.subscribe,
      adopt: (state) => {
        this.state = state;
        for (const listener of this.listeners) listener();
      },
      parse: (raw) => LedgerState.parse(JSON.parse(raw)),
      merge: (_base, local, remote) => mergeLedger(local, remote),
    });
  }

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  readonly getSnapshot = (): LedgerState => this.state;

  /** Append one point per complete total; partial sums would draw false dips in the chart. */
  record(totals: readonly NativeTotal[], now = this.now()): void {
    if (!Number.isSafeInteger(now) || now < 0) return;
    const added: LedgerPoint[] = [];
    for (const total of totals) {
      if (total.incomplete || !/^\d+$/.test(total.amount)) continue;
      const last = this.lastFor(total.assetRef);
      if (last && last.amount === total.amount && now >= last.t && now - last.t < LEDGER_DEDUPE_MS)
        continue;
      const point = LedgerPoint.safeParse({
        id: crypto.randomUUID(),
        t: now,
        assetRef: total.assetRef,
        amount: total.amount,
        decimals: total.decimals,
        symbol: total.symbol,
      });
      if (point.success) added.push(point.data);
    }
    if (added.length === 0) return;
    const points = [...this.state.points, ...added];
    if ((this.state.points.at(-1)?.t ?? 0) > now) points.sort((a, b) => a.t - b.t);
    this.state = { version: 1, points: capPoints(points) };
    for (const l of this.listeners) l();
  }

  seriesFor(assetRef: string, sinceMs = 0): SeriesPoint[] {
    const out: SeriesPoint[] = [];
    for (const p of this.state.points) {
      if (p.assetRef !== assetRef || p.t < sinceMs) continue;
      out.push({ t: p.t, v: toUnits(p.amount, p.decimals) });
    }
    return out;
  }

  /** Assets in first-seen order, carrying the most recent symbol recorded for each. */
  assets(): LedgerAsset[] {
    const seen = new Map<string, LedgerAsset>();
    for (const p of this.state.points) {
      const entry = seen.get(p.assetRef) ?? { assetRef: p.assetRef };
      if (p.symbol !== undefined) entry.symbol = p.symbol;
      seen.set(p.assetRef, entry);
    }
    return [...seen.values()];
  }

  flush(): Promise<void> {
    return this.persistence.flush();
  }
  dispose(): Promise<void> {
    return this.persistence.dispose();
  }

  private lastFor(assetRef: string): LedgerPoint | undefined {
    for (let i = this.state.points.length - 1; i >= 0; i--) {
      const p = this.state.points[i] as LedgerPoint;
      if (p.assetRef === assetRef) return p;
    }
    return undefined;
  }
}

function safeStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${LEDGER_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

export const totalsLedger = new TotalsLedger(safeStorage());

export function useLedger(): LedgerState {
  return useSyncExternalStore(
    totalsLedger.subscribe,
    totalsLedger.getSnapshot,
    totalsLedger.getSnapshot,
  );
}
