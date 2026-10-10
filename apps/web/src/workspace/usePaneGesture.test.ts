import { describe, expect, it } from 'vitest';

import { PANE_MIN_H, PANE_MIN_W } from './schema.js';
import type { Rect } from './store.js';
import {
  applyGesture,
  clampToCanvas,
  snapGesture,
  type Handle,
  type MinSize,
} from './usePaneGesture.js';

const start: Rect = { x: 100, y: 200, w: 400, h: 300 };
const min: MinSize = { w: 240, h: 120 };

describe('applyGesture', () => {
  it('moves without changing size', () => {
    expect(applyGesture(start, 'move', 15, -25)).toEqual({ x: 115, y: 175, w: 400, h: 300 });
  });

  it('keeps the opposite edge fixed for every edge handle', () => {
    expect(applyGesture(start, 'e', 30, 99)).toEqual({ x: 100, y: 200, w: 430, h: 300 });
    expect(applyGesture(start, 'w', 30, 99)).toEqual({ x: 130, y: 200, w: 370, h: 300 });
    expect(applyGesture(start, 's', 99, 40)).toEqual({ x: 100, y: 200, w: 400, h: 340 });
    expect(applyGesture(start, 'n', 99, 40)).toEqual({ x: 100, y: 240, w: 400, h: 260 });
  });

  it('combines both axes for corner handles', () => {
    expect(applyGesture(start, 'se', 10, 20)).toEqual({ x: 100, y: 200, w: 410, h: 320 });
    expect(applyGesture(start, 'nw', 10, 20)).toEqual({ x: 110, y: 220, w: 390, h: 280 });
    expect(applyGesture(start, 'ne', 10, 20)).toEqual({ x: 100, y: 220, w: 410, h: 280 });
    expect(applyGesture(start, 'sw', 10, 20)).toEqual({ x: 110, y: 200, w: 390, h: 320 });
  });

  it.each<Handle>(['n', 's', 'e', 'w', 'ne', 'nw', 'se', 'sw'])(
    'pins the dragged edge at the minimum size for %s',
    (handle) => {
      const r = applyGesture(start, handle, -1000, -1000, min);
      const r2 = applyGesture(start, handle, 1000, 1000, min);
      for (const out of [r, r2]) {
        expect(out.w).toBeGreaterThanOrEqual(min.w);
        expect(out.h).toBeGreaterThanOrEqual(min.h);
      }
      // Whatever happens, the edge opposite the handle never moves.
      if (!handle.includes('w')) expect(r.x).toBe(start.x);
      if (!handle.includes('e')) expect(r.x + r.w).toBe(start.x + start.w);
      if (!handle.includes('n')) expect(r.y).toBe(start.y);
      if (!handle.includes('s')) expect(r.y + r.h).toBe(start.y + start.h);
    },
  );

  it('clamps a left-edge shrink so the right edge stays put', () => {
    const r = applyGesture(start, 'w', 1000, 0, min);
    expect(r).toEqual({ x: 260, y: 200, w: 240, h: 300 });
  });

  it('clamps a top-edge shrink so the bottom edge stays put', () => {
    const r = applyGesture(start, 'n', 0, 1000, min);
    expect(r).toEqual({ x: 100, y: 380, w: 400, h: 120 });
  });

  it('defaults to the schema minimums', () => {
    const r = applyGesture(start, 'se', -5000, -5000);
    expect(r.w).toBe(PANE_MIN_W);
    expect(r.h).toBe(PANE_MIN_H);
  });
});

describe('snapGesture', () => {
  const neighbour: Rect = { x: 600, y: 0, w: 200, h: 200 };

  it('snaps a move to the grid when nothing is near', () => {
    expect(snapGesture({ x: 101, y: 203, w: 400, h: 300 }, [], 'move')).toEqual({
      x: 104,
      y: 200,
      w: 400,
      h: 300,
    });
  });

  it('snaps the dragged right edge to a neighbour minus the gutter', () => {
    const live = { x: 100, y: 200, w: 495, h: 300 };
    const r = snapGesture(live, [neighbour], 'e');
    expect(r.x + r.w).toBe(neighbour.x - 8);
    expect(r.x).toBe(100);
  });

  it('snaps the dragged left edge and keeps the right edge fixed', () => {
    const live = { x: 805, y: 200, w: 300, h: 300 };
    const r = snapGesture(live, [neighbour], 'w');
    expect(r.x).toBe(neighbour.x + neighbour.w + 8);
    expect(r.x + r.w).toBe(1105);
  });

  it('refuses a snap that would violate the minimum size', () => {
    const live = { x: 805, y: 200, w: 240, h: 300 };
    const r = snapGesture(live, [neighbour], 'w', { w: 240, h: 120 });
    expect(r).toEqual(live);
  });

  it('leaves the top edge alone on a south resize', () => {
    const r = snapGesture({ x: 100, y: 203, w: 400, h: 301 }, [], 's');
    expect(r.y).toBe(203);
    expect(r.y + r.h).toBe(504);
  });
});

describe('clampToCanvas', () => {
  it('pulls a rect back inside the origin without moving the far edges', () => {
    expect(clampToCanvas({ x: -20, y: -10, w: 400, h: 300 })).toEqual({
      x: 0,
      y: 0,
      w: 380,
      h: 290,
    });
  });

  it('leaves in-bounds rects unchanged', () => {
    expect(clampToCanvas(start)).toEqual(start);
  });
});
