import { useSyncExternalStore } from 'react';
import { z } from 'zod';

import type { StorageLike } from '../store/persist.js';
import { createMetadataPersistence } from '../store/metadataPersistence.js';
import { mergeHistoryRecords } from './historyMerge.js';

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

const ActivityCounts = z.object({
  n: z.number().int().nonnegative().safe(),
  kinds: z.record(z.string(), z.number().int().nonnegative().safe()),
});
export const ActivityDayRecord = ActivityCounts.extend({
  sources: z.record(z.union([z.string().uuid(), z.literal('legacy')]), ActivityCounts).optional(),
});
export type ActivityDayRecord = z.infer<typeof ActivityDayRecord>;

export const ACTIVITY_MAX_EVENTS = 1000;
export const ActivityEvent = z.object({
  id: z.string().uuid().optional(),
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

const addCount = (a: number, b: number) => Math.min(Number.MAX_SAFE_INTEGER, a + b);
function countsFromSources(sources: NonNullable<ActivityDayRecord['sources']>): ActivityDayRecord {
  let n = 0;
  const kinds: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const count of Object.values(sources)) {
    n = addCount(n, count.n);
    for (const [kind, value] of Object.entries(count.kinds))
      kinds[kind] = addCount(kinds[kind] ?? 0, value);
  }
  return { n, kinds, sources };
}

/** Per-writer counters make replayed recovery copies idempotent after event retention expires. */
export function mergeActivity(left: ActivityState, right: ActivityState): ActivityState {
  const days: Record<string, ActivityDayRecord> = {};
  for (const state of [left, right]) {
    for (const [key, day] of Object.entries(state.days)) {
      const sources = { ...days[key]?.sources };
      for (const [id, counts] of Object.entries(
        day.sources ?? { legacy: { n: day.n, kinds: day.kinds } },
      )) {
        const previous = sources[id];
        const kinds = { ...previous?.kinds };
        for (const [kind, value] of Object.entries(counts.kinds))
          kinds[kind] = Math.max(kinds[kind] ?? 0, value);
        sources[id] = { n: Math.max(previous?.n ?? 0, counts.n), kinds };
      }
      days[key] = countsFromSources(sources);
    }
  }
  return {
    version: 1,
    days: capDays(days),
    events: mergeHistoryRecords(left.events, right.events)
      .sort((a, b) => b.atMs - a.atMs || (a.id ?? '').localeCompare(b.id ?? ''))
      .slice(0, ACTIVITY_MAX_EVENTS),
  };
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
  private readonly writerId = crypto.randomUUID();
  private readonly persistence: ReturnType<typeof createMetadataPersistence<ActivityState>>;

  constructor(
    storage: StorageLike | null,
    private readonly now: () => number = () => Date.now(),
    debounceMs = ACTIVITY_SAVE_DEBOUNCE_MS,
  ) {
    this.state = loadActivity(storage);
    this.persistence = createMetadataPersistence({
      storage,
      key: ACTIVITY_STORAGE_KEY,
      name: 'activity history',
      debounceMs,
      retryMs: debounceMs,
      snapshot: this.getSnapshot,
      subscribe: this.subscribe,
      adopt: (state) => {
        this.state = state;
        for (const listener of this.listeners) listener();
      },
      parse: (raw) => ActivityState.parse(JSON.parse(raw)),
      merge: (_base, local, remote) => mergeActivity(local, remote),
    });
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
    if (!Number.isSafeInteger(atMs) || atMs < 0 || !Number.isFinite(new Date(atMs).getTime()))
      return;
    const key = dayKey(atMs);
    const day = this.state.days[key] ?? { n: 0, kinds: {} };
    const sources = { ...(day.sources ?? { legacy: { n: day.n, kinds: day.kinds } }) };
    const own = sources[this.writerId] ?? { n: 0, kinds: {} };
    sources[this.writerId] = {
      n: addCount(own.n, count),
      kinds: { ...own.kinds, [kind]: addCount(own.kinds[kind] ?? 0, count) },
    };
    const next = countsFromSources(sources);
    this.state = {
      ...this.state,
      days: capDays({ ...this.state.days, [key]: next }),
      events: [{ id: crypto.randomUUID(), atMs, kind, count }, ...this.state.events].slice(
        0,
        ACTIVITY_MAX_EVENTS,
      ),
    };
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

  flush(): Promise<void> {
    return this.persistence.flush();
  }
  dispose(): Promise<void> {
    return this.persistence.dispose();
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

export function useActivity(): ActivityState {
  return useSyncExternalStore(
    activityLog.subscribe,
    activityLog.getSnapshot,
    activityLog.getSnapshot,
  );
}
