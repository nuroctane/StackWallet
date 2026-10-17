/**
 * Pure viewport math for interactive charts: the visible time window is a
 * value, and every gesture is a function of it. The canvas component owns no
 * gesture logic beyond calling these and scheduling a redraw.
 */

export interface Viewport {
  t0: number;
  t1: number;
}

/** How far past the data edges the window may travel, as a share of its span. */
const OVERSCROLL = 0.85;
/** Zooming in stops at this many milliseconds of span. */
const HARD_MIN_SPAN = 60_000;

export function spanOf(v: Viewport): number {
  return v.t1 - v.t0;
}

/** A window over all data with a little air on the right, TradingView-style. */
export function fitViewport(minT: number, maxT: number): Viewport | null {
  if (!Number.isFinite(minT) || !Number.isFinite(maxT)) return null;
  if (maxT < minT) [minT, maxT] = [maxT, minT];
  const span = Math.max(maxT - minT, HARD_MIN_SPAN);
  return { t0: maxT - span, t1: maxT + span * 0.06 };
}

/**
 * Zoom by `factor` (smaller = closer) keeping the data point at `anchorFrac`
 * (0..1 across the plot) under the cursor. The window is clamped so it can
 * never collapse to nothing or drift off the data entirely.
 */
export function zoomViewport(
  v: Viewport,
  factor: number,
  anchorFrac: number,
  dataMin: number,
  dataMax: number,
  minSpan: number,
): Viewport {
  const clamped = Math.min(0.995, Math.max(0.005, factor));
  const frac = Math.min(1, Math.max(0, anchorFrac));
  const anchor = v.t0 + spanOf(v) * frac;
  const next: Viewport = {
    t0: anchor - (anchor - v.t0) * clamped,
    t1: anchor + (v.t1 - anchor) * clamped,
  };
  return clampViewport(next, dataMin, dataMax, minSpan);
}

export function panViewport(
  v: Viewport,
  deltaT: number,
  dataMin: number,
  dataMax: number,
  minSpan: number,
): Viewport {
  return clampViewport({ t0: v.t0 + deltaT, t1: v.t1 + deltaT }, dataMin, dataMax, minSpan);
}

/**
 * Keep the span above `minSpan` and keep at least a sliver of the window over
 * the data: the user may scroll whitespace into view to wait for new candles,
 * but never lose the series completely.
 */
export function clampViewport(
  v: Viewport,
  dataMin: number,
  dataMax: number,
  minSpan: number,
): Viewport {
  let span = spanOf(v);
  const floor = Math.max(HARD_MIN_SPAN, minSpan);
  if (span < floor) {
    const mid = (v.t0 + v.t1) / 2;
    v = { t0: mid - floor / 2, t1: mid + floor / 2 };
    span = floor;
  }
  const dataSpan = Math.max(0, dataMax - dataMin);
  const maxSpan = Math.max(dataSpan * 4, floor);
  if (span > maxSpan) {
    const mid = (v.t0 + v.t1) / 2;
    v = { t0: mid - maxSpan / 2, t1: mid + maxSpan / 2 };
    span = maxSpan;
  }
  if (!Number.isFinite(dataSpan) || dataMax < dataMin) return v;
  const slack = span * OVERSCROLL;
  if (v.t0 > dataMax + slack) {
    v = { t0: dataMax + slack - span, t1: dataMax + slack };
  } else if (v.t1 < dataMin - slack) {
    v = { t0: dataMin - slack, t1: dataMin - slack + span };
  }
  return v;
}

/** The smallest gap between observations, the natural zoom floor. */
export function minGapOf(times: readonly number[]): number {
  let min = Infinity;
  for (let i = 1; i < times.length; i++) {
    const dt = (times[i] as number) - (times[i - 1] as number);
    if (dt > 0 && dt < min) min = dt;
  }
  return Number.isFinite(min) ? min : HARD_MIN_SPAN;
}
