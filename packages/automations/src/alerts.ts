import { z } from 'zod';

import { Condition, evaluate, type Observation } from './conditions.js';

/**
 * Price alerts. An alert fires when its condition becomes true while armed,
 * then stays quiet until the condition has been seen false again and the
 * cooldown has passed, so a price hovering on the line notifies once rather
 * than on every check.
 */

export const ALERT_COOLDOWN_MS = 60 * 60_000;
export const MAX_ALERTS = 100;
export const MAX_ALERT_EVENTS = 300;

export const Alert = z.object({
  id: z.string().min(1).max(64),
  name: z.string().trim().min(1).max(60),
  enabled: z.boolean(),
  condition: Condition,
  armed: z.boolean(),
  createdAtMs: z.number().int(),
  lastFiredAtMs: z.number().int().nullable(),
});
export type Alert = z.infer<typeof Alert>;

export const AlertEvent = z.object({
  id: z.string().min(1).max(64),
  alertId: z.string().min(1).max(64),
  atMs: z.number().int(),
  usd: z.number().finite().nonnegative(),
  change24hPct: z.number().finite().nullable(),
});
export type AlertEvent = z.infer<typeof AlertEvent>;

export const AlertState = z.object({
  version: z.literal(1),
  alerts: Alert.array().max(MAX_ALERTS),
  events: AlertEvent.array().max(MAX_ALERT_EVENTS),
});
export type AlertState = z.infer<typeof AlertState>;

export const emptyAlerts = (): AlertState => ({ version: 1, alerts: [], events: [] });

export function alertCoins(state: AlertState): string[] {
  return [...new Set(state.alerts.filter((a) => a.enabled).map((a) => a.condition.coinId))].sort();
}

export function checkAlerts(
  state: AlertState,
  observe: (coinId: string) => Observation | undefined,
  now: number,
  newId: () => string,
): { state: AlertState; fired: AlertEvent[] } {
  const fired: AlertEvent[] = [];
  let changed = false;
  const alerts = state.alerts.map((a) => {
    if (!a.enabled) return a;
    const obs = observe(a.condition.coinId);
    const verdict = evaluate(a.condition, obs, now);
    if (verdict === 'true' && a.armed && obs) {
      changed = true;
      fired.push({
        id: newId(),
        alertId: a.id,
        atMs: now,
        usd: obs.usd,
        change24hPct: obs.change24hPct,
      });
      return { ...a, armed: false, lastFiredAtMs: now };
    }
    const cooled = a.lastFiredAtMs === null || now - a.lastFiredAtMs >= ALERT_COOLDOWN_MS;
    if (verdict === 'false' && !a.armed && cooled) {
      changed = true;
      return { ...a, armed: true };
    }
    return a;
  });
  if (!changed) return { state, fired };
  return {
    state: { ...state, alerts, events: [...state.events, ...fired].slice(-MAX_ALERT_EVENTS) },
    fired,
  };
}
