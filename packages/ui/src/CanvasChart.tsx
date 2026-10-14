import { useCallback, useEffect, useRef, type PointerEvent, type KeyboardEvent } from 'react';

import { useThemeEpoch } from './theme/apply.js';

export interface Point {
  t: number;
  /** The close for candle series. */
  v: number;
  /** Open, high and low; read only by `candles` series. */
  o?: number;
  h?: number;
  l?: number;
}

export interface Series {
  id: string;
  label: string;
  points: readonly Point[];
  kind?: 'line' | 'area' | 'bars' | 'candles';
  /** Any CSS color; `var(--sw-*)` strings are resolved from the canvas at draw time. */
  color?: string;
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
}

export const SERIES_RAMP: readonly string[] = ['#d8d8d8', '#a0a0a0', '#777777', '#555555'];

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

/** Everything the overlay needs to map pointer → data without touching React state. */
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

/**
 * Two stacked canvases: the data layer redraws only when the series shape or size changes;
 * the overlay draws the crosshair on pointer moves and never re-renders React. Colors are
 * read from the CSS tokens at draw time so the chart follows the theme without props.
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
}: CanvasChartProps) {
  const dataRef = useRef<HTMLCanvasElement>(null);
  const themeEpoch = useThemeEpoch();
  const overlayRef = useRef<HTMLCanvasElement>(null);
  const layout = useRef<Layout | null>(null);
  const palette = useRef<Palette | null>(null);
  const hoverT = useRef<number | null>(null);

  // Formatters and callbacks are read through refs so a new inline lambda per render
  // does not force a full data redraw.
  const fmt = useRef({ yFormat, tFormat, axisFormat, onHover });
  fmt.current = { yFormat, tFormat, axisFormat, onHover };
  const seriesRef = useRef(series);
  seriesRef.current = series;

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

  // Cheap identity of the data: a change in count, span or last value means a redraw;
  // intermediate edits that keep those equal are not expected from append-only feeds.
  const signature = series
    .map((s) => {
      const n = s.points.length;
      const first = n > 0 ? (s.points[0] as Point).t : 0;
      const last = n > 0 ? (s.points[n - 1] as Point) : null;
      return `${s.id}:${s.kind ?? 'line'}:${s.color ?? ''}:${n}:${first}:${last?.t ?? 0}:${last?.v ?? 0}`;
    })
    .join('|');

  useEffect(() => {
    const canvas = dataRef.current;
    if (!canvas) return;
    const ctx = prepareCanvas(canvas, width, height);
    if (!ctx) return;
    const cs = getComputedStyle(canvas);
    const P = readPalette(canvas);
    palette.current = P;

    const left = padLeft;
    const top = padTop;
    const bottom = height - padBottom;

    let tMin = Infinity;
    let tMax = -Infinity;
    let vMin = Infinity;
    let vMax = -Infinity;
    for (const s of series) {
      const n = s.points.length;
      if (n === 0) continue;
      tMin = Math.min(tMin, (s.points[0] as Point).t);
      tMax = Math.max(tMax, (s.points[n - 1] as Point).t);
      if (s.kind === 'bars') {
        vMin = Math.min(vMin, 0);
        vMax = Math.max(vMax, 0);
      }
      for (let i = 0; i < n; i++) {
        const p = s.points[i] as Point;
        const lo = s.kind === 'candles' ? Math.min(p.v, p.l ?? p.v) : p.v;
        const hi = s.kind === 'candles' ? Math.max(p.v, p.h ?? p.v) : p.v;
        if (lo < vMin) vMin = lo;
        if (hi > vMax) vMax = hi;
      }
    }
    const hasData = Number.isFinite(tMin) && Number.isFinite(vMin);
    if (hasData && vMin === vMax) {
      const bump = vMin === 0 ? 1 : Math.abs(vMin) * 0.05;
      vMin -= bump;
      vMax += bump;
    }
    if (nonnegative && hasData) vMin = Math.max(0, vMin);
    ctx.font = P.font;
    const yTicks = niceTicks(vMin, vMax, Math.max(2, Math.min(5, Math.floor(height / 45))));
    const labelWidth = Math.max(
      0,
      ...yTicks.map((v) => ctx.measureText(fmt.current.yFormat(v)).width),
    );
    const right = Math.max(
      left + 1,
      width - Math.min(width * 0.45, Math.max(padRight, labelWidth + 12)),
    );
    // Breathing room so extremes never sit on the plot edge.
    const vPad = hasData ? (vMax - vMin) * 0.06 : 0;
    const x = scaleLinear([tMin, tMax], [left, right]);
    const y = scaleLinear(
      [nonnegative ? Math.max(0, vMin - vPad) : vMin - vPad, vMax + vPad],
      [bottom, top],
    );
    const primary = series[0];
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
    const af = fmt.current.axisFormat ?? (span < 2 * DAY ? fmtHM : fmtMD);
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

    series.forEach((s, si) => {
      const pts = s.points;
      const n = pts.length;
      if (n === 0) return;
      const color = resolveColor(s.color, si, cs);
      const kind = s.kind ?? 'line';

      if (kind === 'bars') {
        const base = y(0);
        const bw = Math.max(1, (right - left) / n - 1);
        ctx.fillStyle = color;
        for (let i = 0; i < n; i++) {
          const p = pts[i] as Point;
          const px = x(p.t) - bw / 2;
          const py = y(p.v);
          ctx.fillRect(px, Math.min(py, base), bw, Math.max(1, Math.abs(base - py)));
        }
        return;
      }

      if (kind === 'candles') {
        // Monochrome by design: a rising candle is filled, a falling one is hollow, so
        // direction never borrows the danger role's colour.
        const bw = Math.max(1, Math.min(12, ((right - left) / n) * 0.7));
        ctx.lineWidth = 1;
        for (let i = 0; i < n; i++) {
          const p = pts[i] as Point;
          const o = p.o ?? p.v;
          const cx = Math.round(x(p.t)) + 0.5;
          ctx.strokeStyle = color;
          ctx.beginPath();
          ctx.moveTo(cx, y(p.h ?? Math.max(o, p.v)));
          ctx.lineTo(cx, y(p.l ?? Math.min(o, p.v)));
          ctx.stroke();
          const bodyTop = y(Math.max(o, p.v));
          const bodyH = Math.max(1, y(Math.min(o, p.v)) - bodyTop);
          const bx = cx - bw / 2;
          if (p.v >= o) {
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

      ctx.beginPath();
      let started = false;
      for (let i = 0; i < n; i++) {
        const p = pts[i] as Point;
        if (!Number.isFinite(p.v)) {
          started = false;
          continue;
        }
        const px = x(p.t);
        const py = y(p.v);
        if (started) ctx.lineTo(px, py);
        else {
          ctx.moveTo(px, py);
          started = true;
        }
      }
      if (kind === 'area') {
        const firstX = x((pts[0] as Point).t);
        const lastX = x((pts[n - 1] as Point).t);
        ctx.save();
        ctx.lineTo(lastX, bottom);
        ctx.lineTo(firstX, bottom);
        ctx.closePath();
        ctx.globalAlpha = 0.12;
        ctx.fillStyle = color;
        ctx.fill();
        ctx.restore();
        // Re-trace the stroke so the closing edges of the fill do not get outlined.
        ctx.beginPath();
        started = false;
        for (let i = 0; i < n; i++) {
          const p = pts[i] as Point;
          if (!Number.isFinite(p.v)) {
            started = false;
            continue;
          }
          const px = x(p.t);
          const py = y(p.v);
          if (started) ctx.lineTo(px, py);
          else {
            ctx.moveTo(px, py);
            started = true;
          }
        }
      }
      ctx.strokeStyle = color;
      ctx.stroke();
    });
    ctx.restore();

    if (lastValuePill && primary && primary.points.length > 0) {
      const last = primary.points[primary.points.length - 1] as Point;
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

    // Keep the crosshair aligned to the fresh data if the pointer is still over the chart.
    drawOverlay(hoverT.current);
    // `series` is read through the signature on purpose: a new array with the same shape
    // (the common case for live feeds re-slicing a buffer) must not trigger a redraw.
  }, [
    signature,
    themeEpoch,
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

  const onPointerMove = useCallback(
    (e: PointerEvent<HTMLCanvasElement>) => {
      const L = layout.current;
      if (!L || !L.hasData) return;
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
    },
    [drawOverlay],
  );

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
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

  return (
    <div
      role="group"
      tabIndex={0}
      aria-label={`${ariaLabel}. Tap or move to inspect. Left and right arrows select observations; Home and End select first and latest.`}
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
        className="absolute inset-0 block touch-pan-y"
        style={{ width, height }}
        onPointerMove={onPointerMove}
        onPointerDown={onPointerMove}
      />
    </div>
  );
}
