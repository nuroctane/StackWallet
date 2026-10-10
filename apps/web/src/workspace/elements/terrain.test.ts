import { describe, expect, it } from 'vitest';

import { computeGeometry, hitTest, levelFor, toCells } from './TerrainElement.js';

const days = (ns: number[]) =>
  ns.map((n, i) => ({ dayKey: `2026-01-${String(i + 1).padStart(2, '0')}`, t: i * 86_400_000, n }));

describe('levelFor', () => {
  it('maps zero to the floor and the max to the top level', () => {
    expect(levelFor(0, 10)).toBe(0);
    expect(levelFor(10, 10)).toBe(4);
    expect(levelFor(1, 10)).toBe(1);
    expect(levelFor(5, 10)).toBe(3);
  });
  it('treats a single-event max as full height', () => {
    expect(levelFor(1, 1)).toBe(4);
  });
});

describe('toCells', () => {
  it('fills weeks column-major with seven weekdays', () => {
    const cells = toCells(days([1, 2, 3, 4, 5, 6, 7, 8]));
    expect(cells[0]).toMatchObject({ week: 0, day: 0, n: 1 });
    expect(cells[6]).toMatchObject({ week: 0, day: 6, n: 7 });
    expect(cells[7]).toMatchObject({ week: 1, day: 0, n: 8 });
  });
});

describe('computeGeometry + hitTest', () => {
  it('keeps the cell size within bounds and finds the hovered column', () => {
    const cells = toCells(days(Array.from({ length: 28 }, (_, i) => (i === 10 ? 9 : 1))));
    const g = computeGeometry(cells, 400, 220);
    expect(g.cell).toBeGreaterThanOrEqual(2);
    expect(g.cell).toBeLessThanOrEqual(14);
    expect(g.maxCount).toBe(9);
    // Probe the projected top of cell 10 and expect to hit it.
    const c = cells[10]!;
    const h = Math.max(1.5, (c.n / g.maxCount) * g.maxH);
    const x = g.ox + (c.week - c.day) * g.cell * 0.9;
    const y = g.oy + (c.week + c.day) * g.cell * 0.5 - h + g.cell * 0.5;
    expect(hitTest(cells, g, x, y)).toBe(c);
    expect(hitTest(cells, g, -1000, -1000)).toBeNull();
  });
});
