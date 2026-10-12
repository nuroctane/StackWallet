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
import { HOME_CAMERA, moveCamera, pinchCamera, project, zoomCamera } from './TerrainElement.js';

describe('terrain navigation', () => {
  it('turns and tilts on drag while shift-drag pans without changing orientation', () => {
    const turned = moveCamera(HOME_CAMERA, 60, 20);
    expect(turned.yaw).not.toBe(HOME_CAMERA.yaw);
    expect(turned.tilt).toBeGreaterThan(HOME_CAMERA.tilt);
    expect(turned.panX).toBe(0);
    const panned = moveCamera(turned, -10, 5, true);
    expect(panned.yaw).toBe(turned.yaw);
    expect(panned.panX).toBe(-10);
    expect(panned.panY).toBe(5);
  });
  it('pinches about the finger midpoint and handles coincident fingers without invalid geometry', () => {
    const next = pinchCamera(HOME_CAMERA, { x: 100, y: 0 }, { x: 200, y: 0 }, { x: 0, y: 0 });
    expect(next.zoom).toBe(2);
    expect(next.panX).toBe(50);
    expect(pinchCamera(HOME_CAMERA, { x: 0, y: 0 }, { x: 1, y: 1 }, { x: 0, y: 0 }).zoom).toBe(1);
    expect(zoomCamera(HOME_CAMERA, 100).zoom).toBe(4);
    expect(zoomCamera(HOME_CAMERA, 0.001).zoom).toBe(0.5);
  });
  it('fits and hit-tests a rotated terrain in a minimum-size pane', () => {
    const cells = toCells(days([0, 0, 10, 0, 0, 0, 0]));
    for (const yaw of [0, Math.PI / 4, Math.PI, Math.PI * 1.5]) {
      const g = computeGeometry(cells, 240, 120, { ...HOME_CAMERA, yaw });
      const c = cells[2]!;
      const p = project(c.week + 0.5, c.day + 0.5, g.maxH, g);
      expect(p.x).toBeGreaterThanOrEqual(0);
      expect(p.x).toBeLessThanOrEqual(240);
      expect(p.y).toBeGreaterThanOrEqual(0);
      expect(p.y).toBeLessThanOrEqual(120);
      expect(hitTest(cells, g, p.x, p.y)).toBe(c);
    }
  });
});
