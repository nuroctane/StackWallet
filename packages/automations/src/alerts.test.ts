import { describe, expect, it } from 'vitest';

import { ALERT_COOLDOWN_MS, checkAlerts, emptyAlerts, type AlertState } from './alerts.js';
import { Condition, STALE_AFTER_MS, evaluate, type Observation } from './conditions.js';

const obs = (usd: number, at = 0, extra: Partial<Observation> = {}): Observation => ({
  usd,
  change24hPct: 0,
  fetchedAtMs: at,
  confidence: 'single',
  ...extra,
});

describe('conditions', () => {
  const above = Condition.parse({ kind: 'price', coinId: 'bitcoin', op: 'above', usd: 100 });

  it('is unknown without a fresh, undisputed price', () => {
    expect(evaluate(above, undefined, 0)).toBe('unknown');
    expect(evaluate(above, obs(200, 0), STALE_AFTER_MS + 1)).toBe('unknown');
    expect(evaluate(above, obs(200, 0, { confidence: 'divergent' }), 0)).toBe('unknown');
    expect(evaluate(above, obs(200), 0)).toBe('true');
    expect(evaluate(above, obs(100), 0)).toBe('false');
  });

  it('reads the 24h change and treats a missing one as unknown', () => {
    const drop = Condition.parse({
      kind: 'change24h',
      coinId: 'bitcoin',
      op: 'below',
      percent: -5,
    });
    expect(evaluate(drop, obs(1, 0, { change24hPct: -6 }), 0)).toBe('true');
    expect(evaluate(drop, obs(1, 0, { change24hPct: -4 }), 0)).toBe('false');
    expect(evaluate(drop, obs(1, 0, { change24hPct: null }), 0)).toBe('unknown');
  });

  it('rejects malformed conditions', () => {
    expect(() => Condition.parse({ kind: 'price', coinId: '../x', op: 'above', usd: 1 })).toThrow();
    expect(() => Condition.parse({ kind: 'price', coinId: 'x', op: 'above', usd: 0 })).toThrow();
  });
});

describe('alerts', () => {
  const base = (): AlertState => ({
    ...emptyAlerts(),
    alerts: [
      {
        id: 'a',
        name: 'btc high',
        enabled: true,
        condition: { kind: 'price', coinId: 'bitcoin', op: 'above', usd: 100 },
        armed: true,
        createdAtMs: 0,
        lastFiredAtMs: null,
      },
    ],
  });
  let n = 0;
  const id = () => `e${++n}`;

  it('fires once, re-arms only after the line is uncrossed and the cooldown passes', () => {
    let s = base();
    let r = checkAlerts(s, () => obs(150, 1), 1, id);
    expect(r.fired).toHaveLength(1);
    s = r.state;
    r = checkAlerts(s, () => obs(160, 2), 2, id);
    expect(r.fired).toHaveLength(0);
    r = checkAlerts(s, () => obs(90, 3), 3, id);
    expect(r.state.alerts[0]?.armed).toBe(false);
    const later = 1 + ALERT_COOLDOWN_MS;
    s = checkAlerts(s, () => obs(90, later), later, id).state;
    expect(s.alerts[0]?.armed).toBe(true);
    r = checkAlerts(s, () => obs(150, later + 1), later + 1, id);
    expect(r.fired).toHaveLength(1);
    expect(r.state.events).toHaveLength(2);
  });

  it('does nothing on unknown prices or disabled alerts', () => {
    const s = base();
    expect(checkAlerts(s, () => undefined, 1, id).state).toBe(s);
    const off = { ...s, alerts: s.alerts.map((a) => ({ ...a, enabled: false })) };
    expect(checkAlerts(off, () => obs(500, 1), 1, id).fired).toHaveLength(0);
  });
});
