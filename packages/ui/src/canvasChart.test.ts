import { describe, expect, it } from 'vitest';

import { nearestPoint, niceTicks, scaleLinear } from './CanvasChart.js';

describe('scaleLinear', () => {
  it('maps domain endpoints onto range endpoints', () => {
    const s = scaleLinear([0, 10], [100, 200]);
    expect(s(0)).toBe(100);
    expect(s(10)).toBe(200);
    expect(s(5)).toBe(150);
  });

  it('supports an inverted range for y axes', () => {
    const s = scaleLinear([0, 1], [300, 0]);
    expect(s(0)).toBe(300);
    expect(s(1)).toBe(0);
    expect(s(0.25)).toBe(225);
  });

  it('extrapolates outside the domain', () => {
    expect(scaleLinear([0, 10], [0, 100])(-5)).toBe(-50);
  });

  it('collapses a zero-width domain onto the range midpoint', () => {
    const s = scaleLinear([7, 7], [0, 100]);
    expect(s(7)).toBe(50);
    expect(s(123)).toBe(50);
  });
});

describe('niceTicks', () => {
  it('returns round steps inside the domain', () => {
    expect(niceTicks(0, 100, 5)).toEqual([0, 20, 40, 60, 80, 100]);
  });

  it('picks 1-2-5 steps for awkward spans', () => {
    expect(niceTicks(3, 47, 5)).toEqual([10, 20, 30, 40]);
    expect(niceTicks(0, 7, 4)).toEqual([0, 2, 4, 6]);
  });

  it('handles fractional domains without float noise', () => {
    expect(niceTicks(0, 1, 5)).toEqual([0, 0.2, 0.4, 0.6, 0.8, 1]);
    expect(niceTicks(0.1, 0.35, 4)).toEqual([0.1, 0.15, 0.2, 0.25, 0.3, 0.35]);
  });

  it('handles negative ranges', () => {
    expect(niceTicks(-50, 50, 4)).toEqual([-40, -20, 0, 20, 40]);
    expect(niceTicks(-50, 50, 5)).toEqual([-40, -20, 0, 20, 40]);
  });

  it('returns the single value for a flat domain', () => {
    expect(niceTicks(4, 4, 5)).toEqual([4]);
  });

  it('swaps a reversed domain', () => {
    expect(niceTicks(100, 0, 5)).toEqual([0, 20, 40, 60, 80, 100]);
  });

  it('is empty for a non-finite domain or zero count', () => {
    expect(niceTicks(Number.NaN, 1, 5)).toEqual([]);
    expect(niceTicks(0, Number.POSITIVE_INFINITY, 5)).toEqual([]);
    expect(niceTicks(0, 10, 0)).toEqual([]);
  });

  it('never explodes for huge or tiny magnitudes', () => {
    expect(niceTicks(0, 5e9, 5)).toEqual([0, 1e9, 2e9, 3e9, 4e9, 5e9]);
    expect(niceTicks(0, 5e-6, 5).length).toBeGreaterThan(2);
  });
});

describe('nearestPoint', () => {
  const pts = [10, 20, 30, 40, 50].map((t) => ({ t, v: t * 2 }));

  it('returns -1 for no points', () => {
    expect(nearestPoint([], 5)).toBe(-1);
  });

  it('finds exact matches', () => {
    expect(nearestPoint(pts, 30)).toBe(2);
    expect(nearestPoint(pts, 10)).toBe(0);
    expect(nearestPoint(pts, 50)).toBe(4);
  });

  it('snaps to the closer neighbour', () => {
    expect(nearestPoint(pts, 24)).toBe(1);
    expect(nearestPoint(pts, 26)).toBe(2);
  });

  it('breaks ties toward the earlier point', () => {
    expect(nearestPoint(pts, 25)).toBe(1);
  });

  it('clamps outside the range', () => {
    expect(nearestPoint(pts, -100)).toBe(0);
    expect(nearestPoint(pts, 999)).toBe(4);
  });

  it('works for a single point', () => {
    expect(nearestPoint([{ t: 5, v: 1 }], 42)).toBe(0);
  });
});
