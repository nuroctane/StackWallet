import {
  useCallback,
  useEffect,
  useRef,
  type PointerEvent as ReactPointerEvent,
  type KeyboardEvent,
} from 'react';

import {
  clampViewport,
  fitViewport,
  minGapOf,
  panViewport,
  spanOf,
  zoomViewport,
  type Viewport,
} from './chartViewport.js';
import { useThemeEpoch } from './theme/apply.js';

export interface Point {
  t: number;
  /** The close for candle series. */
  v: number;
  /** Open, high and low; read only by candle-style series. */
  o?: number;
  h?: number;
  l?: number;
}

export type SeriesKind = 'line' | 'area' | 'step' | 'bars' | 'candles' | 'hollow' | 'ohlc';

export interface Series {
  id: string;
  label: string;
  points: readonly Point[];
  kind?: SeriesKind;
  /** Any CSS color; `var(--sw-*)` strings are resolved from the canvas at draw time. */
  color?: string;
  /** Line dash pattern for line-family kinds. */
  dash?: readonly number[];
}

export interface ChartPadding {
  top?: number;
  right?: number;
  bottom?: number;
  left?: number;
}

export interface CanvasChartProps {
  series: readonly Series[];
  /** CSS px; the backing store is scaled by the device pixel ratio. */
  width: number;
  height: number;
  yFormat?: (v: number) => string;
  /** Crosshair timestamp chip. */
  tFormat?: (t: number) => string;
  /** X tick labels. */
  axisFormat?: (t: number) => string;
  padding?: ChartPadding;
  gridlines?: boolean;
  /** Right-axis pill showing the last value of `series[0]`. */
  lastValuePill?: boolean;
  className?: string;
  ariaLabel: string;
  onHover?: (t: number | null) => void;
  /** Balance quantities cannot go below zero; generic signed charts retain their domain. */
  nonnegative?: boolean;
  /**
   * Companion series drawn on the same scales but excluded from the y domain,
   * so a Bollinger band never stretches the axis. Drawn after `series`.
   */
  overlays?: readonly Series[];
  /** Wheel zoom, drag pan, pinch and double-click reset. */
  interactive?: boolean;
  /** Controlled visible window; omit to fit the data, `null` releases to fit. */
  viewport?: Viewport | null;
  onViewportChange?: (v: Viewport) => void;
  /** Fires when the window reaches a data edge, for history backfill. */
  onEdgeReach?: (side: 'left' | 'right') => void;
  logScale?: boolean;
  /** Controlled crosshair; pass the same value to stacked panes to sync them. */
  hoverT?: number | null;
  /** Changing it refits an uncontrolled viewport (e.g. a new coin was picked). */
  resetKey?: string | number;
}

export const SERIES_RAMP: readonly string[] = ['#d8d8d8', '#a0a0a0', '#777777', '#555555'];

const EMPTY_SERIES: readonly Series[] = [];
const LINE_WIDTH = 1.25;
const CHIP_H = 16;
const CHIP_PAD = 4;

/** Linear map from `domain` to `range`; a zero-width domain lands on the range midpoint. */
export function scaleLinear(
  domain: readonly [number, number],
  range: readonly [number, number],
): (v: number) => number {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const span = d1 - d0;
  if (span === 0) {
    const mid = (r0 + r1) / 2;
    return () => mid;
  }
  const k = (r1 - r0) / span;
  return (v: number) => r0 + (v - d0) * k;
}

/** Roughly `count` round-number ticks inside `[min, max]` (1-2-5 steps). */
export function niceTicks(min: number, max: number, count: number): number[] {
  if (!Number.isFinite(min) || !Number.isFinite(max) || count <= 0) return [];
  if (min > max) [min, max] = [max, min];
  if (min === max) return [min];
  const step = niceStep((max - min) / count);
  // The epsilon keeps a boundary that is a tick (0.1 / 0.05) from falling off through
  // float error; rounding each tick to the step's precision avoids 0.30000000000000004.
  const first = Math.ceil(min / step - 1e-9) * step;
  const last = Math.floor(max / step + 1e-9) * step;
  const digits = Math.max(0, -Math.floor(Math.log10(step)) + 1);
  const n = Math.floor((last - first) / step + 0.5) + 1;
  const out: number[] = [];
  for (let i = 0; i < n && i < 100; i++) {
    out.push(Number((first + i * step).toFixed(digits)));
  }
  return out;
}

// Geometric-mean thresholds (as d3 uses) land nearer the requested count than hard 1-2-5 cutoffs.
function niceStep(raw: number): number {
  const mag = 10 ** Math.floor(Math.log10(raw));
  const r = raw / mag;
  if (r >= 7.071) return 10 * mag;
  if (r >= 3.162) return 5 * mag;
  if (r >= 1.414) return 2 * mag;
  return mag;
}

/** 1-2-5 ticks per decade for a positive log domain. */
export function logTicks(min: number, max: number, count: number): number[] {
  if (!(min > 0) || !(max > 0) || count <= 0) return [];
  const lo = Math.floor(Math.log10(min));
  const hi = Math.ceil(Math.log10(max));
  const decades = Math.max(1, hi - lo);
  const mantissas = decades > count ? [1] : decades * 5 >= count ? [1, 5] : [1, 2, 5];
  const out: number[] = [];
  for (let d = lo; d <= hi; d++) {
    for (const m of mantissas) {
      const v = m * 10 ** d;
      if (v >= min && v <= max) out.push(v);
    }
    if (out.length >= 100) break;
  }
  return out;
}

/** Index of the point whose `t` is closest to `t`; `-1` when empty. Points must be sorted by `t`. */
export function nearestPoint(points: readonly Point[], t: number): number {
  const n = points.length;
  if (n === 0) return -1;
  let lo = 0;
  let hi = n - 1;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((points[mid] as Point).t < t) lo = mid + 1;
    else hi = mid;
  }
  if (lo === 0) return 0;
  const a = points[lo - 1] as Point;
  const b = points[lo] as Point;
  return t - a.t <= b.t - t ? lo - 1 : lo;
}

/**
 * Inclusive index range of points inside `[t0, t1]`, widened by one point on
 * each side so lines continue cleanly to the plot edge. `[1, 0]` when empty.
 */
export function visibleSlice(
  points: readonly Point[],
  t0: number,
  t1: number,
): readonly [number, number] {
  const n = points.length;
  if (n === 0) return [1, 0];
  let lo = 0;
  let hi = n;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((points[mid] as Point).t < t0) lo = mid + 1;
    else hi = mid;
  }
  let rLo = 0;
  let rHi = n;
  while (rLo < rHi) {
    const mid = (rLo + rHi) >>> 1;
    if ((points[mid] as Point).t <= t1) rLo = mid + 1;
    else rHi = mid;
  }
  if (lo >= rLo) return [1, 0];
  return [Math.max(0, lo - 1), Math.min(n - 1, rLo)];
}

/**
 * Reduce a dense slice to at most ~`maxPts` points without losing the
 * envelope: each bucket contributes its first, extreme-by-order and last
 * values, so spikes survive decimation.
 */
export function decimateLine(
  points: readonly Point[],
  lo: number,
  hi: number,
  maxPts: number,
): Point[] {
  const count = hi - lo + 1;
  if (count <= 0) return [];
  if (count <= maxPts) return points.slice(lo, hi + 1);
  const bucket = count / maxPts;
  const out: Point[] = [];
  for (let b = 0; b < maxPts; b++) {
    const from = lo + Math.floor(b * bucket);
    const to = Math.min(hi, lo + Math.floor((b + 1) * bucket) - 1);
    if (from > to) continue;
    let minI = from;
    let maxI = from;
    for (let i = from + 1; i <= to; i++) {
      const v = (points[i] as Point).v;
      if (v < (points[minI] as Point).v) minI = i;
      if (v > (points[maxI] as Point).v) maxI = i;
    }
    out.push(points[from] as Point);
    if (minI !== from && minI !== to) out.push(points[minI] as Point);
    if (maxI !== from && maxI !== to && maxI !== minI) out.push(points[maxI] as Point);
    if (to !== from) out.push(points[to] as Point);
  }
  return out;
}

/** Merge dense candles into buckets of consecutive points, preserving OHLC. */
export function decimateCandles(
  points: readonly Point[],
  lo: number,
  hi: number,
  maxCandles: number,
): Point[] {
  const count = hi - lo + 1;
  if (count <= 0) return [];
  if (count <= maxCandles) return points.slice(lo, hi + 1);
  const bucket = Math.ceil(count / maxCandles);
  const out: Point[] = [];
  for (let from = lo; from <= hi; from += bucket) {
    const to = Math.min(hi, from + bucket - 1);
    const first = points[from] as Point;
    let h = first.h ?? Math.max(first.o ?? first.v, first.v);
    let l = first.l ?? Math.min(first.o ?? first.v, first.v);
    for (let i = from + 1; i <= to; i++) {
      const p = points[i] as Point;
      h = Math.max(h, p.h ?? Math.max(p.o ?? p.v, p.v));
      l = Math.min(l, p.l ?? Math.min(p.o ?? p.v, p.v));
    }
    const last = points[to] as Point;
    out.push({ t: first.t, o: first.o ?? first.v, h, l, v: last.v });
  }
  return out;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAY = 86_400_000;

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

function fmtHM(t: number): string {
  const d = new Date(t);
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

function fmtMD(t: number): string {
  const d = new Date(t);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

function fmtMDHM(t: number): string {
  return `${fmtMD(t)} ${fmtHM(t)}`;
}

function fmtMY(t: number): string {
  const d = new Date(t);
  return `${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

const numberFormat = new Intl.NumberFormat(undefined, { maximumSignificantDigits: 5 });

function defaultYFormat(v: number): string {
  return numberFormat.format(v);
}

interface Palette {
  ink: string;
  muted: string;
  faint: string;
  edge: string;
  edgeStrong: string;
  warm: string;
  danger: string;
  surface: string;
  paper: string;
  font: string;
}

function readPalette(canvas: HTMLCanvasElement): Palette {
  const cs = getComputedStyle(canvas);
  const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback;
  return {
    ink: v('--sw-ink', '#f2f2f2'),
    muted: v('--sw-muted', '#a0a0a0'),
    faint: v('--sw-faint', '#777777'),
    edge: v('--sw-edge', 'rgb(255 255 255 / 12%)'),
    edgeStrong: v('--sw-edge-strong', 'rgb(255 255 255 / 30%)'),
    warm: v('--sw-warm', '#e2c27b'),
    danger: v('--sw-danger', '#ff453a'),
    surface: v('--sw-surface', '#141414'),
    paper: v('--sw-paper', '#050505'),
    font: `10px ${cs.fontFamily || 'ui-monospace, monospace'}`,
  };
}

/** The theme's series ramp, falling back to the night glass grays outside a themed DOM. */
function rampColor(index: number, cs: CSSStyleDeclaration): string {
  const slot = index % SERIES_RAMP.length;
  return cs.getPropertyValue(`--sw-chart-${slot + 1}`).trim() || (SERIES_RAMP[slot] as string);
}

function resolveColor(color: string | undefined, index: number, cs: CSSStyleDeclaration): string {
  if (!color) return rampColor(index, cs);
  if (color.startsWith('var(')) {
    const name = color.slice(4, -1).split(',')[0]?.trim() ?? '';
    const resolved = cs.getPropertyValue(name).trim();
    if (resolved) return resolved;
    return rampColor(index, cs);
  }
  return color;
}

/** Everything the overlay and gestures need to map pixels → data without React state. */
interface Layout {
  left: number;
  right: number;
  top: number;
  bottom: number;
  x: (t: number) => number;
  y: (v: number) => number;
  tMin: number;
  tMax: number;
  hasData: boolean;
  primaryColor: string;
}

interface DragState {
  pointerId: number;
  startX: number;
  startViewport: Viewport;
  moved: boolean;
}

function prepareCanvas(
  canvas: HTMLCanvasElement,
  width: number,
  height: number,
): CanvasRenderingContext2D | null {
  const dpr = Math.min(typeof devicePixelRatio === 'number' ? devicePixelRatio : 1, 2);
  const w = Math.round(width * dpr);
  const h = Math.round(height * dpr);
  if (canvas.width !== w) canvas.width = w;
  if (canvas.height !== h) canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  return ctx;
}

function drawChip(
  ctx: CanvasRenderingContext2D,
  text: string,
  x: number,
  y: number,
  fill: string,
  stroke: string | null,
  ink: string,
): void {
  const w = Math.ceil(ctx.measureText(text).width) + CHIP_PAD * 2;
  ctx.fillStyle = fill;
  ctx.beginPath();
  ctx.roundRect(x, y, w, CHIP_H, 3);
  ctx.fill();
  if (stroke) {
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1;
    ctx.stroke();
  }
  ctx.fillStyle = ink;
  ctx.textAlign = 'left';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, x + CHIP_PAD, y + CHIP_H / 2 + 0.5);
}

function chipWidth(ctx: CanvasRenderingContext2D, text: string): number {
  return Math.ceil(ctx.measureText(text).width) + CHIP_PAD * 2;
}

function seriesExtent(series: readonly Series[]): { tMin: number; tMax: number } | null {
  let tMin = Infinity;
  let tMax = -Infinity;
  for (const s of series) {
    const n = s.points.length;
    if (n === 0) continue;
    tMin = Math.min(tMin, (s.points[0] as Point).t);
    tMax = Math.max(tMax, (s.points[n - 1] as Point).t);
  }
  return Number.isFinite(tMin) ? { tMin, tMax } : null;
}

/**
 * Two stacked canvases: the data layer redraws only when the series shape,
 * size or viewport changes; the overlay draws the crosshair on pointer moves
 * and never re-renders React. Colors are read from the CSS tokens at draw
 * time so the chart follows the theme without props.
 *
 * With `interactive` the visible window is a viewport value: the wheel zooms
 * around the cursor, dragging pans, pinching zooms, double-click refits, and
 * the y domain follows whatever the window shows. Dense slices are decimated
 * per pixel column, so a million-point history draws as fast as a hundred.
 */
export function CanvasChart({
  series,
  width,
  height,
  yFormat = defaultYFormat,
  tFormat,
  axisFormat,
  padding,
  gridlines = true,
  lastValuePill = true,
  className = '',
  ariaLabel,
  onHover,
  nonnegative = false,
  overlays = EMPTY_SERIES,
  interactive = false,
  viewport,
  onViewportChange,
  onEdgeReach,
  logScale = false,
  hoverT: hoverProp,
  resetKey,
}: CanvasChartProps) {
  const dataRef = useRef<HTMLCanvasElement>(null);
  const themeEpoch = useThemeEpoch();
  const overlayRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const layout = useRef<Layout | null>(null);
  const palette = useRef<Palette | null>(null);
  const hoverT = useRef<number | null>(null);
  // The live window. `null` means "fit the data"; a value means the user (or
  // a controlling parent) placed the window deliberately.
  const windowRef = useRef<Viewport | null>(viewport ?? null);
  const extentRef = useRef<{ tMin: number; tMax: number } | null>(null);
  const minSpanRef = useRef(60_000);
  const dragRef = useRef<DragState | null>(null);
  const pinchRef = useRef<{ d0: number; start: Viewport; anchorFrac: number } | null>(null);
  const pointersRef = useRef(new Map<number, number>());
  const rafRef = useRef(0);
  const edgeRef = useRef<{ left: boolean; right: boolean }>({ left: false, right: false });

  // Formatters and callbacks are read through refs so a new inline lambda per render
  // does not force a full data redraw.
  const fmt = useRef({ yFormat, tFormat, axisFormat, onHover, onViewportChange, onEdgeReach });
  fmt.current = { yFormat, tFormat, axisFormat, onHover, onViewportChange, onEdgeReach };
  const seriesRef = useRef(series);
  seriesRef.current = series;
  const overlaysRef = useRef(overlays);
  overlaysRef.current = overlays;
  const interactiveRef = useRef(interactive);
  interactiveRef.current = interactive;
  const logRef = useRef(logScale);
  logRef.current = logScale;

  const padTop = padding?.top ?? 8;
  const padRight = padding?.right ?? 56;
  const padBottom = padding?.bottom ?? 20;
  const padLeft = padding?.left ?? 4;

  const drawOverlay = useCallback(
    (t: number | null) => {
      const canvas = overlayRef.current;
      const L = layout.current;
      const P = palette.current;
      if (!canvas || !L || !P) return;
      const ctx = prepareCanvas(canvas, width, height);
      if (!ctx) return;
      if (t === null || !L.hasData) return;
      const primary = seriesRef.current[0];
      if (!primary) return;
      const idx = nearestPoint(primary.points, t);
      if (idx < 0) return;
      const p = primary.points[idx] as Point;
      if (p.t < L.tMin || p.t > L.tMax) return;
      const x = Math.round(L.x(p.t)) + 0.5;
      const y = Math.round(L.y(p.v)) + 0.5;

      ctx.font = P.font;
      ctx.lineWidth = 1;
      ctx.strokeStyle = P.muted;

      ctx.setLineDash([1, 3]);
      ctx.beginPath();
      ctx.moveTo(x, L.top);
      ctx.lineTo(x, L.bottom);
      ctx.stroke();

      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(L.left, y);
      ctx.lineTo(L.right, y);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = L.primaryColor;
      ctx.beginPath();
      ctx.arc(x, y, 2.5, 0, Math.PI * 2);
      ctx.fill();

      const tf = fmt.current.tFormat ?? fmtMDHM;
      const tText = tf(p.t);
      const tw = chipWidth(ctx, tText);
      const tx = Math.max(0, Math.min(width - tw, x - tw / 2));
      drawChip(ctx, tText, tx, L.bottom + 2, P.surface, P.edgeStrong, P.ink);

      const vText = fmt.current.yFormat(p.v);
      const vy = Math.max(0, Math.min(height - CHIP_H, y - CHIP_H / 2));
      const vx = Math.max(0, Math.min(width - chipWidth(ctx, vText), L.right + 2));
      drawChip(ctx, vText, vx, vy, P.surface, P.edgeStrong, P.ink);
    },
    [width, height],
  );

  const drawData = useCallback(() => {
    const canvas = dataRef.current;
    if (!canvas) return;
    const ctx = prepareCanvas(canvas, width, height);
    if (!ctx) return;
    const cs = getComputedStyle(canvas);
    const P = readPalette(canvas);
    palette.current = P;
    const all = seriesRef.current;
    const ovl = overlaysRef.current;

    const left = padLeft;
    const top = padTop;
    const bottom = height - padBottom;

    const extent = seriesExtent(all);
    extentRef.current = extent;
    const primary = all[0];
    if (primary) {
      const times: number[] = [];
      const step = Math.max(1, Math.floor(primary.points.length / 400));
      for (let i = 0; i < primary.points.length; i += step)
        times.push((primary.points[i] as Point).t);
      minSpanRef.current = Math.max(2 * minGapOf(times), 1);
    }

    // The visible window: the explicit viewport when there is one, else the
    // full extent. Interactive charts get a little air on the right.
    let tMin: number;
    let tMax: number;
    const w = windowRef.current;
    if (w && extent) {
      tMin = w.t0;
      tMax = w.t1;
    } else if (extent) {
      if (interactiveRef.current) {
        const fit = fitViewport(extent.tMin, extent.tMax);
        tMin = fit?.t0 ?? extent.tMin;
        tMax = fit?.t1 ?? extent.tMax;
      } else {
        tMin = extent.tMin;
        tMax = extent.tMax;
      }
    } else {
      tMin = 0;
      tMax = 1;
    }
    const hasData = extent !== null;

    // The y domain follows the visible slice of every price series; overlays
    // ride along without stretching it.
    let vMin = Infinity;
    let vMax = -Infinity;
    if (hasData) {
      for (const s of all) {
        const [lo, hi] = visibleSlice(s.points, tMin, tMax);
        if (lo > hi) continue;
        if (s.kind === 'bars') {
          vMin = Math.min(vMin, 0);
          vMax = Math.max(vMax, 0);
        }
        for (let i = lo; i <= hi; i++) {
          const p = s.points[i] as Point;
          const candle = s.kind === 'candles' || s.kind === 'hollow' || s.kind === 'ohlc';
          const loV = candle ? Math.min(p.v, p.l ?? p.v, p.o ?? p.v) : p.v;
          const hiV = candle ? Math.max(p.v, p.h ?? p.v, p.o ?? p.v) : p.v;
          if (loV < vMin) vMin = loV;
          if (hiV > vMax) vMax = hiV;
        }
      }
    }
    const hasVisible = Number.isFinite(vMin);
    if (!hasVisible) {
      // Window over empty space: keep the last full-range scale so the axes
      // stay meaningful instead of collapsing to a fake 0..1.
      if (hasData) {
        for (const s of all) {
          for (const p of s.points) {
            const candle = s.kind === 'candles' || s.kind === 'hollow' || s.kind === 'ohlc';
            const loV = candle ? Math.min(p.v, p.l ?? p.v, p.o ?? p.v) : p.v;
            const hiV = candle ? Math.max(p.v, p.h ?? p.v, p.o ?? p.v) : p.v;
            if (loV < vMin) vMin = loV;
            if (hiV > vMax) vMax = hiV;
          }
        }
      }
      if (!Number.isFinite(vMin)) {
        vMin = 0;
        vMax = 1;
      }
    }
    if (logRef.current) {
      vMin = Math.max(vMin, Number.MIN_VALUE);
      if (vMax <= vMin) vMax = vMin * 10;
    } else if (vMin === vMax) {
      const bump = vMin === 0 ? 1 : Math.abs(vMin) * 0.05;
      vMin -= bump;
      vMax += bump;
    }
    if (nonnegative && !logRef.current) vMin = Math.max(0, vMin);

    const project = logRef.current ? Math.log10 : (v: number) => v;
    ctx.font = P.font;
    const tickCount = Math.max(2, Math.min(5, Math.floor(height / 45)));
    const yTicks = logRef.current
      ? logTicks(vMin, vMax, tickCount)
      : niceTicks(vMin, vMax, tickCount);
    const labelWidth = Math.max(
      0,
      ...yTicks.map((v) => ctx.measureText(fmt.current.yFormat(v)).width),
    );
    const right = Math.max(
      left + 1,
      width - Math.min(width * 0.45, Math.max(padRight, labelWidth + 12)),
    );
    // Breathing room so extremes never sit on the plot edge.
    const vPad = logRef.current ? 0 : (vMax - vMin) * 0.06;
    const domLo = logRef.current
      ? project(vMin)
      : nonnegative
        ? Math.max(0, vMin - vPad)
        : vMin - vPad;
    const domHi = logRef.current ? project(vMax) : vMax + vPad;
    const x = scaleLinear([tMin, tMax], [left, right]);
    const yRaw = scaleLinear([domLo, domHi], [bottom, top]);
    const y = logRef.current ? (v: number) => yRaw(project(Math.max(v, vMin))) : yRaw;
    const primaryColor = resolveColor(primary?.color, 0, cs);
    layout.current = { left, right, top, bottom, x, y, tMin, tMax, hasData, primaryColor };

    ctx.font = P.font;
    ctx.lineWidth = 1;

    // Axes hairlines.
    ctx.strokeStyle = P.edge;
    ctx.beginPath();
    ctx.moveTo(left, bottom + 0.5);
    ctx.lineTo(right, bottom + 0.5);
    ctx.moveTo(right + 0.5, top);
    ctx.lineTo(right + 0.5, bottom);
    ctx.stroke();

    if (!hasData) return;

    ctx.fillStyle = P.faint;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    for (const v of yTicks) {
      const yy = Math.round(y(v)) + 0.5;
      ctx.fillText(fmt.current.yFormat(v), right + 6, yy, Math.max(1, width - right - 8));
    }

    const span = tMax - tMin;
    const xCount = Math.max(2, Math.min(8, Math.floor((right - left) / 90)));
    const af =
      fmt.current.axisFormat ?? (span < 2 * DAY ? fmtHM : span < 120 * DAY ? fmtMD : fmtMY);
    ctx.textBaseline = 'top';
    for (let i = 0; i < xCount; i++) {
      const t = span === 0 ? tMin : tMin + (span * i) / (xCount - 1);
      const xx = Math.round(x(t)) + 0.5;
      if (gridlines) {
        ctx.strokeStyle = P.edge;
        ctx.setLineDash([1, 3]);
        ctx.beginPath();
        ctx.moveTo(xx, top);
        ctx.lineTo(xx, bottom);
        ctx.stroke();
        ctx.setLineDash([]);
      }
      ctx.fillStyle = P.faint;
      ctx.textAlign = i === 0 ? 'left' : i === xCount - 1 ? 'right' : 'center';
      ctx.fillText(af(t), xx, bottom + 6);
      if (span === 0) break;
    }

    ctx.save();
    ctx.beginPath();
    ctx.rect(left, top - 1, right - left, bottom - top + 2);
    ctx.clip();
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.lineWidth = LINE_WIDTH;

    const plotW = right - left;

    const drawSeries = (s: Series, si: number) => {
      const pts = s.points;
      if (pts.length === 0) return;
      const color = resolveColor(s.color, si, cs);
      const kind = s.kind ?? 'line';
      const [lo, hi] = visibleSlice(pts, tMin, tMax);
      if (lo > hi) return;

      if (kind === 'bars') {
        const base = y(0);
        const maxBars = Math.max(8, Math.floor(plotW));
        const count = hi - lo + 1;
        // Dense bars merge by peak, so a volume spike survives decimation.
        const bucket = count > maxBars ? count / maxBars : 1;
        const bw = Math.max(1, plotW / Math.min(count, maxBars) - 1);
        ctx.fillStyle = color;
        for (let b = 0; b < Math.min(count, maxBars); b++) {
          const from = lo + Math.floor(b * bucket);
          const to = Math.min(hi, lo + Math.floor((b + 1) * bucket) - 1);
          if (from > to) continue;
          let p = pts[from] as Point;
          for (let i = from + 1; i <= to; i++) {
            if ((pts[i] as Point).v > p.v) p = pts[i] as Point;
          }
          const px = x(p.t) - bw / 2;
          const py = y(p.v);
          ctx.fillRect(px, Math.min(py, base), bw, Math.max(1, Math.abs(base - py)));
        }
        return;
      }

      if (kind === 'candles' || kind === 'hollow' || kind === 'ohlc') {
        // Monochrome by design: direction is encoded by fill, never by the
        // danger role's colour.
        const maxCandles = Math.max(8, Math.floor(plotW / 2));
        const slice = decimateCandles(pts, lo, hi, maxCandles);
        const bw = Math.max(1, Math.min(12, (plotW / slice.length) * 0.7));
        ctx.lineWidth = 1;
        ctx.strokeStyle = color;
        for (const p of slice) {
          const o = p.o ?? p.v;
          const cx = Math.round(x(p.t)) + 0.5;
          ctx.beginPath();
          ctx.moveTo(cx, y(p.h ?? Math.max(o, p.v)));
          ctx.lineTo(cx, y(p.l ?? Math.min(o, p.v)));
          ctx.stroke();
          if (kind === 'ohlc') {
            const oy = y(o);
            const cy = y(p.v);
            ctx.beginPath();
            ctx.moveTo(cx - bw / 2, oy);
            ctx.lineTo(cx, oy);
            ctx.moveTo(cx, cy);
            ctx.lineTo(cx + bw / 2, cy);
            ctx.stroke();
            continue;
          }
          const bodyTop = y(Math.max(o, p.v));
          const bodyH = Math.max(1, y(Math.min(o, p.v)) - bodyTop);
          const bx = cx - bw / 2;
          const up = p.v >= o;
          const filled = kind === 'hollow' ? !up : up;
          if (filled) {
            ctx.fillStyle = color;
            ctx.fillRect(bx, bodyTop, bw, bodyH);
          } else {
            ctx.fillStyle = P.paper;
            ctx.fillRect(bx, bodyTop, bw, bodyH);
            ctx.strokeRect(bx, bodyTop, bw, bodyH);
          }
        }
        ctx.lineWidth = LINE_WIDTH;
        return;
      }

      const slice = decimateLine(pts, lo, hi, Math.max(16, Math.floor(plotW * 2)));
      ctx.beginPath();
      let started = false;
      const trace = () => {
        started = false;
        ctx.beginPath();
        for (let i = 0; i < slice.length; i++) {
          const p = slice[i] as Point;
          if (!Number.isFinite(p.v)) {
            started = false;
            continue;
          }
          const px = x(p.t);
          const py = y(p.v);
          if (started) {
            if (kind === 'step' && i > 0) ctx.lineTo(px, y((slice[i - 1] as Point).v));
            ctx.lineTo(px, py);
          } else {
            ctx.moveTo(px, py);
            started = true;
          }
        }
      };
      trace();
      if (kind === 'area') {
        const firstX = x((slice[0] as Point).t);
        const lastX = x((slice[slice.length - 1] as Point).t);
        ctx.save();
        ctx.lineTo(lastX, bottom);
        ctx.lineTo(firstX, bottom);
        ctx.closePath();
        ctx.globalAlpha = 0.12;
        ctx.fillStyle = color;
        ctx.fill();
        ctx.restore();
        trace();
      }
      ctx.strokeStyle = color;
      if (s.dash) ctx.setLineDash([...s.dash]);
      ctx.stroke();
      if (s.dash) ctx.setLineDash([]);
    };

    all.forEach(drawSeries);
    ovl.forEach((s, i) => drawSeries(s, all.length + i));
    ctx.restore();

    if (lastValuePill && primary && primary.points.length > 0) {
      const last = primary.points[primary.points.length - 1] as Point;
      if (last.t >= tMin - span) {
        const py = Math.max(0, Math.min(height - CHIP_H, Math.round(y(last.v)) - CHIP_H / 2));
        ctx.font = P.font;
        const text = fmt.current.yFormat(last.v);
        drawChip(
          ctx,
          text,
          Math.max(0, Math.min(width - chipWidth(ctx, text), right + 2)),
          py,
          primaryColor,
          null,
          P.paper,
        );
      }
    }

    // Keep the crosshair aligned to the fresh data if the pointer is still over the chart.
    drawOverlay(hoverT.current);

    // Tell the parent when the window runs out of history so it can fetch more.
    if (extent && interactiveRef.current) {
      const nearLeft = tMin <= extent.tMin + span * 0.02;
      const nearRight = tMax >= extent.tMax - span * 0.02;
      if (nearLeft && !edgeRef.current.left) fmt.current.onEdgeReach?.('left');
      if (nearRight && !edgeRef.current.right) fmt.current.onEdgeReach?.('right');
      edgeRef.current = { left: nearLeft, right: nearRight };
    }
  }, [
    width,
    height,
    padTop,
    padRight,
    padBottom,
    padLeft,
    gridlines,
    lastValuePill,
    nonnegative,
    drawOverlay,
  ]);

  const scheduleDraw = useCallback(() => {
    if (rafRef.current) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = 0;
      drawData();
    });
  }, [drawData]);

  /** Move the window; used by every gesture. Honours a controlling parent. */
  const applyViewport = useCallback(
    (next: Viewport) => {
      const extent = extentRef.current;
      if (!extent) return;
      const clamped = clampViewport(next, extent.tMin, extent.tMax, minSpanRef.current);
      windowRef.current = clamped;
      fmt.current.onViewportChange?.(clamped);
      scheduleDraw();
    },
    [scheduleDraw],
  );

  // Cheap identity of the data: a change in count, span or last value means a redraw;
  // intermediate edits that keep those equal are not expected from append-only feeds.
  const signature = [...series, ...overlays]
    .map((s) => {
      const n = s.points.length;
      const first = n > 0 ? (s.points[0] as Point).t : 0;
      const last = n > 0 ? (s.points[n - 1] as Point) : null;
      return `${s.id}:${s.kind ?? 'line'}:${s.color ?? ''}:${n}:${first}:${last?.t ?? 0}:${last?.v ?? 0}`;
    })
    .join('|');

  // A controlling parent owns the window; mirror it and redraw.
  const viewportKey = viewport ? `${viewport.t0}:${viewport.t1}` : viewport === null ? 'fit' : '';
  useEffect(() => {
    if (viewport !== undefined) windowRef.current = viewport ?? null;
  }, [viewportKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    windowRef.current = viewport === undefined ? null : (viewport ?? null);
    edgeRef.current = { left: false, right: false };
  }, [resetKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    drawData();
  }, [signature, themeEpoch, drawData, viewportKey, logScale]);

  // Wheel zoom needs a non-passive listener; React's onWheel is passive since 17.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el || !interactive) return;
    const onWheel = (e: WheelEvent) => {
      const extent = extentRef.current;
      const L = layout.current;
      if (!extent || !L) return;
      e.preventDefault();
      const base = windowRef.current ?? {
        t0: extent.tMin,
        t1: Math.max(extent.tMax, extent.tMin + 1),
      };
      const anchorFrac = (e.offsetX - L.left) / Math.max(1, L.right - L.left);
      const factor = Math.exp(e.deltaY * 0.0016);
      applyViewport(
        zoomViewport(base, factor, anchorFrac, extent.tMin, extent.tMax, minSpanRef.current),
      );
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [interactive, applyViewport]);

  useEffect(() => () => cancelAnimationFrame(rafRef.current), []);

  // A parent-controlled crosshair draws without a pointer over this pane.
  useEffect(() => {
    if (hoverProp === undefined) return;
    if (hoverProp === hoverT.current) return;
    hoverT.current = hoverProp;
    drawOverlay(hoverProp);
  }, [hoverProp, drawOverlay]);

  const anchorFromEvent = (clientX: number): number => {
    const L = layout.current;
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!L || !rect) return 0.5;
    return (clientX - rect.left - L.left) / Math.max(1, L.right - L.left);
  };

  const onPointerDown = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    if (!interactive) {
      onPointerMove(e);
      return;
    }
    e.currentTarget.setPointerCapture(e.pointerId);
    pointersRef.current.set(e.pointerId, e.clientX);
    if (pointersRef.current.size === 2) {
      const [a, b] = [...pointersRef.current.values()] as [number, number];
      const extent = extentRef.current;
      if (extent) {
        const base = windowRef.current ?? { t0: extent.tMin, t1: extent.tMax };
        pinchRef.current = {
          d0: Math.max(1, Math.abs(a - b)),
          start: base,
          anchorFrac: anchorFromEvent(e.clientX),
        };
      }
      dragRef.current = null;
      return;
    }
    const extent = extentRef.current;
    if (!extent) return;
    dragRef.current = {
      pointerId: e.pointerId,
      startX: e.clientX,
      startViewport: windowRef.current ?? {
        t0: extent.tMin,
        t1: Math.max(extent.tMax, extent.tMin + 1),
      },
      moved: false,
    };
  };

  const onPointerMove = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    const L = layout.current;
    if (!L || !L.hasData) return;

    if (pointersRef.current.has(e.pointerId)) pointersRef.current.set(e.pointerId, e.clientX);

    const pinch = pinchRef.current;
    if (pinch && pointersRef.current.size >= 2) {
      const [a, b] = [...pointersRef.current.values()] as [number, number];
      const extent = extentRef.current;
      if (extent) {
        const factor = pinch.d0 / Math.max(1, Math.abs(a - b));
        applyViewport(
          zoomViewport(
            pinch.start,
            factor,
            pinch.anchorFrac,
            extent.tMin,
            extent.tMax,
            minSpanRef.current,
          ),
        );
      }
      return;
    }

    const drag = dragRef.current;
    if (drag && drag.pointerId === e.pointerId) {
      const dx = e.clientX - drag.startX;
      if (!drag.moved && Math.abs(dx) < 3) return;
      drag.moved = true;
      const plotW = L.right - L.left;
      if (plotW > 0) {
        const extent = extentRef.current;
        if (extent) {
          const deltaT = (-dx / plotW) * spanOf(drag.startViewport);
          applyViewport(
            panViewport(drag.startViewport, deltaT, extent.tMin, extent.tMax, minSpanRef.current),
          );
        }
      }
      return;
    }

    // Plain hover: snap the crosshair to the nearest observation.
    const px = e.nativeEvent.offsetX;
    const span = L.tMax - L.tMin;
    const plotW = L.right - L.left;
    const t =
      plotW <= 0
        ? L.tMin
        : L.tMin + ((Math.max(L.left, Math.min(L.right, px)) - L.left) / plotW) * span;
    const primary = seriesRef.current[0];
    if (!primary) return;
    const idx = nearestPoint(primary.points, t);
    if (idx < 0) return;
    const snapped = (primary.points[idx] as Point).t;
    if (snapped === hoverT.current) return;
    hoverT.current = snapped;
    drawOverlay(snapped);
    fmt.current.onHover?.(snapped);
  };

  const onPointerUp = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    pointersRef.current.delete(e.pointerId);
    if (pinchRef.current && pointersRef.current.size < 2) pinchRef.current = null;
    if (dragRef.current?.pointerId === e.pointerId) dragRef.current = null;
  };

  const onDoubleClick = () => {
    if (!interactive) return;
    const extent = extentRef.current;
    if (!extent) return;
    const fit = fitViewport(extent.tMin, extent.tMax);
    if (!fit) return;
    windowRef.current = fit;
    fmt.current.onViewportChange?.(fit);
    scheduleDraw();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (interactive && extentRef.current) {
      const extent = extentRef.current;
      const base = windowRef.current ?? { t0: extent.tMin, t1: extent.tMax };
      if (e.key === '+' || e.key === '=') {
        e.preventDefault();
        applyViewport(zoomViewport(base, 0.8, 0.5, extent.tMin, extent.tMax, minSpanRef.current));
        return;
      }
      if (e.key === '-') {
        e.preventDefault();
        applyViewport(zoomViewport(base, 1.25, 0.5, extent.tMin, extent.tMax, minSpanRef.current));
        return;
      }
      if (e.key === '0') {
        e.preventDefault();
        onDoubleClick();
        return;
      }
    }
    const points = seriesRef.current[0]?.points ?? [];
    if (!points.length) return;
    const current =
      hoverT.current === null ? points.length - 1 : nearestPoint(points, hoverT.current);
    let next = current;
    const step = e.shiftKey ? 10 : 1;
    if (e.key === 'ArrowLeft') next -= step;
    else if (e.key === 'ArrowRight') next += step;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = points.length - 1;
    else return;
    e.preventDefault();
    const point = points[Math.max(0, Math.min(points.length - 1, next))];
    if (!point) return;
    hoverT.current = point.t;
    drawOverlay(point.t);
    fmt.current.onHover?.(point.t);
  };

  const gestureHint = interactive ? ' Scroll to zoom, drag to pan, double-click to refit.' : '';
  return (
    <div
      ref={wrapRef}
      role="group"
      tabIndex={0}
      aria-label={`${ariaLabel}. Tap or move to inspect. Left and right arrows select observations; Home and End select first and latest.${gestureHint}`}
      onKeyDown={onKeyDown}
      className={`relative block select-none ${className}`}
      style={{ width, height }}
    >
      <canvas
        aria-hidden
        ref={dataRef}
        className="absolute inset-0 block"
        style={{ width, height }}
      />
      <canvas
        ref={overlayRef}
        aria-hidden
        className={`absolute inset-0 block ${interactive ? 'touch-none' : 'touch-pan-y'}`}
        style={{
          width,
          height,
          cursor: interactive ? 'crosshair' : undefined,
        }}
        onPointerMove={onPointerMove}
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onDoubleClick={onDoubleClick}
      />
    </div>
  );
}
