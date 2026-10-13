import { describe, expect, it } from 'vitest';

import { Automation, due, emptyAutomations, nextRunAt, plan, recordRun } from './model.js';

const DAY = 86_400_000;
const base = {
  id: 'a',
  name: 'rent',
  enabled: true,
  walletId: 'w',
  accountId: 'acc',
  asset: 'eip155:11155111:native',
  createdAtMs: 10 * DAY + 5,
  lastRunAtMs: null,
} as const;

describe('automations', () => {
  it('schedules intervals, daily times and balance checks', () => {
    const every = Automation.parse({
      ...base,
      trigger: { kind: 'interval', everyMs: DAY, startAtMs: 0 },
      action: { kind: 'transfer', to: '0xabc', amount: '5' },
    });
    expect(nextRunAt(every)).toBe(base.createdAtMs);
    expect(nextRunAt({ ...every, lastRunAtMs: 20 * DAY })).toBe(21 * DAY);
    expect(nextRunAt({ ...every, enabled: false })).toBeNull();

    const daily = Automation.parse({ ...every, trigger: { kind: 'daily', minuteOfDay: 60 } });
    expect(nextRunAt(daily)).toBe(10 * DAY + 3_600_000);
    expect(nextRunAt({ ...daily, lastRunAtMs: 10 * DAY + 3_600_000 })).toBe(11 * DAY + 3_600_000);
    expect(() =>
      Automation.parse({ ...every, trigger: { kind: 'interval', everyMs: 1000, startAtMs: 0 } }),
    ).toThrow();
  });

  it('plans transfers and sweeps and never sweeps blind', () => {
    const sweep = Automation.parse({
      ...base,
      trigger: { kind: 'balanceAbove', above: '100' },
      action: { kind: 'sweep', to: '0xabc', keep: '40' },
    });
    expect(plan(sweep, '150')).toEqual({ amount: '110' });
    expect(plan(sweep, '90')).toEqual({ skip: 'balance not above the trigger' });
    expect(plan(sweep, null)).toEqual({ skip: 'balance unknown' });
    const fixed = Automation.parse({
      ...base,
      trigger: { kind: 'interval', everyMs: DAY, startAtMs: 0 },
      action: { kind: 'transfer', to: '0xabc', amount: '5' },
    });
    expect(plan(fixed, '4')).toEqual({ skip: 'balance below the amount' });
    expect(plan(fixed, null)).toEqual({ amount: '5' });
  });

  it('records runs and drops what is no longer due', () => {
    const a = Automation.parse({
      ...base,
      trigger: { kind: 'interval', everyMs: DAY, startAtMs: 0 },
      action: { kind: 'transfer', to: '0xabc', amount: '5' },
    });
    let s = { ...emptyAutomations(), automations: [a] };
    expect(due(s, base.createdAtMs).map((x) => x.id)).toEqual(['a']);
    s = recordRun(s, {
      id: 'r',
      automationId: 'a',
      atMs: base.createdAtMs,
      outcome: 'proposed',
      note: '',
    });
    expect(due(s, base.createdAtMs + 1)).toEqual([]);
    expect(due(s, base.createdAtMs + DAY).map((x) => x.id)).toEqual(['a']);
  });
});
