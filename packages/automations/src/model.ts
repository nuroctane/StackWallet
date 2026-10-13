import { z } from 'zod';

/**
 * Automations propose; they never sign. A due automation produces a
 * transfer proposal marked as an automation run, which waits in the approval
 * queue like any other: policy checks it in the core and a person approves
 * it with a fresh sign-in. Until a device holds a threshold share for the
 * automation (Phase 6 with TSS), there is no autonomous lane.
 */

export const MIN_INTERVAL_MS = 15 * 60 * 1000;
export const MAX_RUNS_KEPT = 500;

const Base = z.string().regex(/^\d{1,78}$/, 'base units');

export const Trigger = z.discriminatedUnion('kind', [
  /** Every `everyMs`, starting at `startAtMs`. */
  z.object({
    kind: z.literal('interval'),
    everyMs: z
      .number()
      .int()
      .min(MIN_INTERVAL_MS)
      .max(366 * 24 * 3600 * 1000),
    startAtMs: z.number().int(),
  }),
  /** Once a day at `minuteOfDay` UTC. */
  z.object({ kind: z.literal('daily'), minuteOfDay: z.number().int().min(0).max(1439) }),
  /** Whenever the balance of the asset rises above `above` (checked at most every 15 minutes). */
  z.object({ kind: z.literal('balanceAbove'), above: Base }),
]);
export type Trigger = z.infer<typeof Trigger>;

export const Action = z.discriminatedUnion('kind', [
  /** A fixed amount. */
  z.object({ kind: z.literal('transfer'), to: z.string().min(1).max(128), amount: Base }),
  /** Everything above `keep`. */
  z.object({ kind: z.literal('sweep'), to: z.string().min(1).max(128), keep: Base }),
]);
export type Action = z.infer<typeof Action>;

export const Automation = z.object({
  id: z.string().min(1).max(64),
  name: z.string().trim().min(1).max(60),
  enabled: z.boolean(),
  walletId: z.string().min(1).max(128),
  accountId: z.string().min(1).max(128),
  /** `${chainId}:native` or `${chainId}:erc20:0x…` */
  asset: z.string().min(1).max(200),
  trigger: Trigger,
  action: Action,
  createdAtMs: z.number().int(),
  lastRunAtMs: z.number().int().nullable(),
});
export type Automation = z.infer<typeof Automation>;

export const RunOutcome = z.enum(['proposed', 'skipped', 'failed']);
export const Run = z.object({
  id: z.string().min(1).max(64),
  automationId: z.string().min(1).max(64),
  atMs: z.number().int(),
  outcome: RunOutcome,
  txId: z.string().max(128).optional(),
  note: z.string().max(400),
});
export type Run = z.infer<typeof Run>;

export const AutomationState = z.object({
  version: z.literal(1),
  automations: Automation.array().max(200),
  runs: Run.array().max(MAX_RUNS_KEPT),
});
export type AutomationState = z.infer<typeof AutomationState>;

export const emptyAutomations = (): AutomationState => ({ version: 1, automations: [], runs: [] });

const DAY = 24 * 3600 * 1000;

/** When the automation next fires; `null` when it is disabled. */
export function nextRunAt(a: Automation): number | null {
  if (!a.enabled) return null;
  const t = a.trigger;
  if (t.kind === 'interval') {
    if (a.lastRunAtMs === null) return Math.max(t.startAtMs, a.createdAtMs);
    return a.lastRunAtMs + t.everyMs;
  }
  if (t.kind === 'daily') {
    const from = a.lastRunAtMs === null ? a.createdAtMs : a.lastRunAtMs + 60_000;
    const dayStart = Math.floor(from / DAY) * DAY;
    const today = dayStart + t.minuteOfDay * 60_000;
    return today >= from ? today : today + DAY;
  }
  // Balance triggers are checked on a floor cadence; the trigger decides at run time.
  return a.lastRunAtMs === null ? a.createdAtMs : a.lastRunAtMs + MIN_INTERVAL_MS;
}

export function due(state: AutomationState, now: number): Automation[] {
  return state.automations.filter((a) => {
    const at = nextRunAt(a);
    return at !== null && at <= now;
  });
}

/**
 * The amount to propose, or why nothing is proposed. `balance` is the
 * current balance of the asset in base units, or null if it is unknown;
 * an unknown balance never produces a sweep.
 */
export function plan(a: Automation, balance: string | null): { amount: string } | { skip: string } {
  if (a.trigger.kind === 'balanceAbove') {
    if (balance === null) return { skip: 'balance unknown' };
    if (BigInt(balance) <= BigInt(a.trigger.above))
      return { skip: 'balance not above the trigger' };
  }
  if (a.action.kind === 'transfer') {
    if (balance !== null && BigInt(balance) < BigInt(a.action.amount))
      return { skip: 'balance below the amount' };
    return { amount: a.action.amount };
  }
  if (balance === null) return { skip: 'balance unknown' };
  const excess = BigInt(balance) - BigInt(a.action.keep);
  if (excess <= 0n) return { skip: 'nothing above the amount to keep' };
  return { amount: excess.toString() };
}

/** Record a run and advance `lastRunAtMs`; keeps the newest runs only. */
export function recordRun(state: AutomationState, run: Run): AutomationState {
  return {
    ...state,
    automations: state.automations.map((a) =>
      a.id === run.automationId ? { ...a, lastRunAtMs: run.atMs } : a,
    ),
    runs: [...state.runs, run].slice(-MAX_RUNS_KEPT),
  };
}
