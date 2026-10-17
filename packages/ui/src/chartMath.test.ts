import { describe, expect, it } from 'vitest';

import {
  decimateCandles,
  decimateLine,
  logTicks,
  visibleSlice,
  type Point,
} from './CanvasChart.js';
import { bollinger, ema, heikinAshi, macd, rsi, sma, toPoints } from './chartIndicators.js';
import {
  clampViewport,
  fitViewport,
  minGapOf,
  panViewport,
  spanOf,
  zoomViewport,
} from './chartViewport.js';

describe('viewport math', () => {
  const MIN = 1_000_000;
  const MAX = 2_000_000;

  it('fits the data with air on the right', () => {
    const v = fitViewport(MIN, MAX);
    expect(v).not.toBeNull();
    expect(v!.t0).toBe(MIN);
    expect(v!.t1).toBeGreaterThan(MAX);
  });

  it('zooms around the anchor, not the center', () => {
    const v = { t0: 0, t1: 100_000_000 };
    const zoomed = zoomViewport(v, 0.5, 0.25, -1e12, 1e12, 1);
    expect(zoomed.t0).toBeCloseTo(12_500_000);
    expect(zoomed.t1).toBeCloseTo(62_500_000);
    // The data point under the cursor stays under the cursor.
    const before = 100_000_000 * 0.25;
    expect(zoomed.t0 + spanOf(zoomed) * 0.25).toBeCloseTo(before);
  });

  it('refuses to zoom past the minimum span', () => {
    const v = { t0: 0, t1: 10_000 };
    const z = zoomViewport(v, 0.000001, 0.5, -1e12, 1e12, 5_000);
    expect(spanOf(z)).toBeGreaterThanOrEqual(5_000);
  });

  it('refuses to zoom out past four data spans', () => {
    const v = { t0: MIN, t1: MAX };
    const z = zoomViewport(v, 100, 0.5, MIN, MAX, 1);
    expect(spanOf(z)).toBeLessThanOrEqual((MAX - MIN) * 4);
  });

  it('pans but cannot leave the data behind entirely', () => {
    const v = { t0: MIN, t1: MAX };
    const panned = panViewport(v, 1e12, MIN, MAX, 1);
    expect(panned.t0).toBeLessThanOrEqual(MAX + spanOf(panned) * 0.85);
    const back = panViewport(v, -1e12, MIN, MAX, 1);
    expect(back.t1).toBeGreaterThanOrEqual(MIN - spanOf(back) * 0.85);
  });

  it('clamps a degenerate window open', () => {
    const v = clampViewport({ t0: 5, t1: 5 }, 0, 10, 60_000);
    expect(v.t1 - v.t0).toBe(60_000);
  });

  it('finds the smallest observation gap', () => {
    expect(minGapOf([0, 100, 150, 400])).toBe(50);
    expect(minGapOf([])).toBe(60_000);
  });
});

describe('sma', () => {
  it('averages the trailing window and warms up with nulls', () => {
    expect(sma([1, 2, 3, 4], 3)).toEqual([null, null, 2, 3]);
  });
  it('stays null when the input is shorter than the period', () => {
    expect(sma([1, 2], 5)).toEqual([null, null]);
  });
});

describe('ema', () => {
  it('seeds on the SMA and follows with the standard multiplier', () => {
    const values = [1, 2, 3, 4, 5];
    const out = ema(values, 3);
    expect(out[0]).toBeNull();
    expect(out[1]).toBeNull();
    expect(out[2]).toBeCloseTo(2);
    const k = 2 / 4;
    expect(out[3]).toBeCloseTo(4 * k + 2 * (1 - k));
    expect(out[4]).toBeCloseTo(5 * k + (4 * k + 2 * (1 - k)) * (1 - k));
  });
});

describe('bollinger', () => {
  it('centers on the SMA with two population deviations', () => {
    const values = [2, 4, 4, 4, 5, 5, 7, 9];
    const { mid, upper, lower } = bollinger(values, 8, 2);
    // Classic textbook window: mean 5, population sd 2.
    expect(mid[7]).toBeCloseTo(5);
    expect(upper[7]).toBeCloseTo(9);
    expect(lower[7]).toBeCloseTo(1);
  });

  it('has zero-width bands on a flat window', () => {
    const { mid, upper, lower } = bollinger([3, 3, 3, 3], 3);
    expect(mid[3]).toBeCloseTo(3);
    expect(upper[3]).toBeCloseTo(3);
    expect(lower[3]).toBeCloseTo(3);
  });
});

describe('rsi', () => {
  it('is 100 when every move is up', () => {
    const out = rsi([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], 14);
    expect(out[14]).toBeCloseTo(100);
  });

  it('matches the Wilder walk on mixed data', () => {
    // Alternating +1/-1 closes: the seed window balances exactly at 50, and
    // Wilder smoothing keeps later values hovering around it.
    const closes = [1];
    for (let i = 1; i <= 20; i++) closes.push(i % 2 === 1 ? 2 : 1);
    const out = rsi(closes, 14);
    expect(out[14]).toBeCloseTo(50);
    expect(out[20]).toBeGreaterThan(48);
    expect(out[20]).toBeLessThan(52);
  });

  it('warms up with nulls', () => {
    expect(rsi([1, 2, 3], 14)).toEqual([null, null, null]);
  });
});

describe('macd', () => {
  it('produces a histogram equal to macd minus signal', () => {
    const closes: number[] = [];
    for (let i = 0; i < 60; i++) closes.push(100 + Math.sin(i / 3) * 10 + i * 0.1);
    const { macd: m, signal: s, histogram: h } = macd(closes);
    for (let i = 0; i < closes.length; i++) {
      if (h[i] !== null) expect(h[i]).toBeCloseTo((m[i] as number) - (s[i] as number));
    }
    expect(h.filter((v) => v !== null).length).toBeGreaterThan(0);
  });

  it('is all null when there is not enough data', () => {
    const { histogram } = macd([1, 2, 3], 12, 26, 9);
    expect(histogram).toEqual([null, null, null]);
  });
});

describe('heikinAshi', () => {
  it('averages the four prices for the close and chains opens', () => {
    const out = heikinAshi([
      { t: 0, o: 10, h: 12, l: 9, v: 11 },
      { t: 1, o: 11, h: 14, l: 10, v: 13 },
    ]);
    expect(out[0]!.v).toBeCloseTo((10 + 12 + 9 + 11) / 4);
    expect(out[0]!.o).toBeCloseTo((10 + 11) / 2);
    expect(out[1]!.o).toBeCloseTo((out[0]!.o! + out[0]!.v) / 2);
    expect(out[1]!.h).toBeGreaterThanOrEqual(out[1]!.o!);
    expect(out[1]!.l).toBeLessThanOrEqual(out[1]!.o!);
  });
});

describe('toPoints', () => {
  it('drops warmup nulls and keeps timestamps', () => {
    expect(toPoints([10, 20, 30], [null, 2, 3])).toEqual([
      { t: 20, v: 2 },
      { t: 30, v: 3 },
    ]);
  });
});

describe('visibleSlice', () => {
  const pts: Point[] = [0, 10, 20, 30, 40].map((t) => ({ t, v: t }));

  it('includes one neighbour on each side for line continuity', () => {
    expect(visibleSlice(pts, 10, 30)).toEqual([0, 4]);
    expect(visibleSlice(pts, 11, 29)).toEqual([1, 3]);
  });

  it('returns an empty range when the window misses the data', () => {
    expect(visibleSlice(pts, 100, 200)).toEqual([1, 0]);
    expect(visibleSlice([], 0, 1)).toEqual([1, 0]);
  });
});

describe('decimateLine', () => {
  it('keeps every point when under the budget', () => {
    const pts: Point[] = [0, 1, 2].map((t) => ({ t, v: t }));
    expect(decimateLine(pts, 0, 2, 10)).toHaveLength(3);
  });

  it('preserves spikes through bucketing', () => {
    const pts: Point[] = [];
    for (let i = 0; i < 1000; i++) pts.push({ t: i, v: i === 517 ? 10_000 : 50 });
    const out = decimateLine(pts, 0, 999, 50);
    expect(out.length).toBeLessThanOrEqual(50 * 4);
    expect(Math.max(...out.map((p) => p.v))).toBe(10_000);
  });
});

describe('decimateCandles', () => {
  it('merges buckets preserving open, close, and the extremes', () => {
    const pts: Point[] = [
      { t: 0, o: 10, h: 11, l: 9, v: 10.5 },
      { t: 1, o: 10.5, h: 20, l: 10, v: 12 },
      { t: 2, o: 12, h: 13, l: 2, v: 8 },
      { t: 3, o: 8, h: 9, l: 7, v: 8.5 },
    ];
    const out = decimateCandles(pts, 0, 3, 2);
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({ o: 10, h: 20, l: 9, v: 12 });
    expect(out[1]).toMatchObject({ o: 12, h: 13, l: 2, v: 8.5 });
  });
});

describe('logTicks', () => {
  it('places 1-2-5 mantissas per decade', () => {
    expect(logTicks(10, 100, 10)).toEqual([10, 20, 50, 100]);
  });

  it('collapses to single mantissas over many decades', () => {
    const ticks = logTicks(0.01, 100_000, 4);
    expect(ticks).toEqual([0.01, 0.1, 1, 10, 100, 1000, 10_000, 100_000]);
  });

  it('rejects a non-positive domain', () => {
    expect(logTicks(0, 10, 5)).toEqual([]);
  });
});
