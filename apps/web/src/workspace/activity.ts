import { useSyncExternalStore } from 'react';
import { z } from 'zod';

import type { StorageLike } from '../store/persist.js';
import { reportStorageSave } from '../store/storageStatus.js';

export const ACTIVITY_STORAGE_KEY = 'stackwallet.activity.v1';
export const ACTIVITY_SAVE_DEBOUNCE_MS = 500;
export const ACTIVITY_MAX_DAYS = 400;

export const ActivityKind = z.enum([
  'directory',
  'balance',
  'device',
  'layout',
  'ceremony',
  'transaction',
]);
export type ActivityKind = z.infer<typeof ActivityKind>;

const DayKey = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);

export const ActivityDayRecord = z.object({
  n: z.number().int().min(0),
  kinds: z.record(z.string(), z.number().int().min(0)),
});
export type ActivityDayRecord = z.infer<typeof ActivityDayRecord>;

export const ACTIVITY_MAX_EVENTS = 1000;
export const ActivityEvent = z.object({
  atMs: z.number().int().nonnegative().safe(),
  kind: ActivityKind,
  count: z.number().int().positive().safe(),
});
export type ActivityEvent = z.infer<typeof ActivityEvent>;

export const ActivityState = z.object({
  version: z.literal(1),
  days: z.record(DayKey, ActivityDayRecord),
  events: z.array(ActivityEvent).max(ACTIVITY_MAX_EVENTS).default([]),
});
export type ActivityState = z.infer<typeof ActivityState>;

export interface ActivityDay {
  dayKey: string;
  /** Local midnight that starts the day, in ms. */
  t: number;
  n: number;
}
export type ActivityPoint = ActivityDay;

export const emptyActivity = (): ActivityState => ({ version: 1, days: {}, events: [] });

const pad2 = (n: number) => String(n).padStart(2, '0');

/** Calendar day in the device's local zone; the terrain is about the user's days, not UTC's. */
export function dayKey(ms: number): string {
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

/** Day keys sort lexically in chronological order, so trimming is a sort and a slice. */
function capDays(days: Record<string, ActivityDayRecord>): Record<string, ActivityDayRecord> {
  const keys = Object.keys(days);
  if (keys.length <= ACTIVITY_MAX_DAYS) return days;
  keys.sort();
  const keep = new Set(keys.slice(keys.length - ACTIVITY_MAX_DAYS));
  const next: Record<string, ActivityDayRecord> = {};
  for (const k of keys) if (keep.has(k)) next[k] = days[k] as ActivityDayRecord;
  return next;
}

export function loadActivity(storage: StorageLike | null): ActivityState {
  if (!storage) return emptyActivity();
  let raw: string | null = null;
  try {
    raw = storage.getItem(ACTIVITY_STORAGE_KEY);
  } catch {
    return emptyActivity();
  }
  if (raw === null || raw === '') return emptyActivity();
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return emptyActivity();
  }
  const result = ActivityState.safeParse(parsed);
  // Activity is decoration, not trust state: an unreadable blob is simply dropped.
  if (!result.success) return emptyActivity();
  return { ...result.data, days: capDays(result.data.days) };
}

export function saveActivity(storage: StorageLike, state: ActivityState): boolean {
  try {
    storage.setItem(ACTIVITY_STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

export class ActivityLog {
  private state: ActivityState;
  private readonly listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private dirty = false;
  private saveFailures = 0;

  constructor(
    private readonly storage: StorageLike | null,
    private readonly now: () => number = () => Date.now(),
    private readonly debounceMs = ACTIVITY_SAVE_DEBOUNCE_MS,
  ) {
    this.state = loadActivity(storage);
  }

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  readonly getSnapshot = (): ActivityState => this.state;

  record(kind: ActivityKind, count = 1): void {
    if (!Number.isSafeInteger(count) || count <= 0) return;
    const atMs = this.now();
    const key = dayKey(atMs);
    const day = this.state.days[key] ?? { n: 0, kinds: {} };
    const next: ActivityDayRecord = {
      n: day.n + count,
      kinds: { ...day.kinds, [kind]: (day.kinds[kind] ?? 0) + count },
    };
    this.state = {
      ...this.state,
      days: capDays({ ...this.state.days, [key]: next }),
      events: [{ atMs, kind, count }, ...this.state.events].slice(0, ACTIVITY_MAX_EVENTS),
    };
    this.scheduleSave();
    for (const l of this.listeners) l();
  }

  /** One point per day, oldest first, ending on the day that contains `now`. */
  series(weeks: number, now = this.now()): ActivityDay[] {
    const total = Math.max(0, Math.floor(weeks)) * 7;
    const today = new Date(now);
    const out: ActivityDay[] = [];
    for (let i = total - 1; i >= 0; i--) {
      // Date arithmetic on the local calendar keeps DST days from shifting the grid.
      const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - i);
      const key = dayKey(d.getTime());
      out.push({ dayKey: key, t: d.getTime(), n: this.state.days[key]?.n ?? 0 });
    }
    return out;
  }

  flush(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    if (!this.dirty) return;
    const saved = this.storage !== null && saveActivity(this.storage, this.state);
    this.dirty = !saved;
    reportStorageSave(
      'activity history',
      saved,
      saved
        ? undefined
        : {
            filename: 'stackwallet-activity.json',
            text: JSON.stringify(this.state),
          },
    );
    if (saved) this.saveFailures = 0;
    else if (++this.saveFailures < 3 && this.storage)
      this.timer = setTimeout(() => this.flush(), this.debounceMs);
  }

  private scheduleSave(): void {
    this.dirty = true;
    this.saveFailures = 0;
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.flush(), this.debounceMs);
  }
}

function safeStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${ACTIVITY_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

export const activityLog = new ActivityLog(safeStorage());

if (typeof window !== 'undefined') {
  window.addEventListener('pagehide', () => activityLog.flush());
}

export function useActivity(): ActivityState {
  return useSyncExternalStore(
    activityLog.subscribe,
    activityLog.getSnapshot,
    activityLog.getSnapshot,
  );
}
