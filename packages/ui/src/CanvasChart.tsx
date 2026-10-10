import { useCallback, useEffect, useRef, type PointerEvent } from 'react';

export interface Point {
  t: number;
  v: number;
}

export interface Series {
  id: string;
  label: string;
  points: readonly Point[];
  kind?: 'line' | 'area' | 'bars';
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

function resolveColor(color: string | undefined, index: number, cs: CSSStyleDeclaration): string {
  if (!color) return SERIES_RAMP[index % SERIES_RAMP.length] as string;
  if (color.startsWith('var(')) {
    const name = color.slice(4, -1).split(',')[0]?.trim() ?? '';
    const resolved = cs.getPropertyValue(name).trim();
    if (resolved) return resolved;
    return SERIES_RAMP[index % SERIES_RAMP.length] as string;
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
}: CanvasChartProps) {
  const dataRef = useRef<HTMLCanvasElement>(null);
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
      drawChip(ctx, vText, L.right + 2, vy, P.surface, P.edgeStrong, P.ink);
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
    const right = width - padRight;
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
        const v = (s.points[i] as Point).v;
        if (v < vMin) vMin = v;
        if (v > vMax) vMax = v;
      }
    }
    const hasData = Number.isFinite(tMin) && Number.isFinite(vMin);
    if (hasData && vMin === vMax) {
      const bump = vMin === 0 ? 1 : Math.abs(vMin) * 0.05;
      vMin -= bump;
      vMax += bump;
    }
    // Breathing room so extremes never sit on the plot edge.
    const vPad = hasData ? (vMax - vMin) * 0.06 : 0;
    const x = scaleLinear([tMin, tMax], [left, right]);
    const y = scaleLinear([vMin - vPad, vMax + vPad], [bottom, top]);
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

    const yTicks = niceTicks(vMin, vMax, 5);
    ctx.fillStyle = P.faint;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    for (const v of yTicks) {
      const yy = Math.round(y(v)) + 0.5;
      ctx.fillText(fmt.current.yFormat(v), right + 6, yy);
    }

    const span = tMax - tMin;
    const xCount = Math.max(4, Math.min(8, Math.floor((right - left) / 90)));
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
      drawChip(ctx, fmt.current.yFormat(last.v), right + 2, py, primaryColor, null, P.paper);
    }

    // Keep the crosshair aligned to the fresh data if the pointer is still over the chart.
    drawOverlay(hoverT.current);
    // `series` is read through the signature on purpose: a new array with the same shape
    // (the common case for live feeds re-slicing a buffer) must not trigger a redraw.
  }, [
    signature,
    width,
    height,
    padTop,
    padRight,
    padBottom,
    padLeft,
    gridlines,
    lastValuePill,
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

  const onPointerLeave = useCallback(() => {
    if (hoverT.current === null) return;
    hoverT.current = null;
    drawOverlay(null);
    fmt.current.onHover?.(null);
  }, [drawOverlay]);

  return (
    <div
      role="img"
      aria-label={ariaLabel}
      className={`relative block select-none ${className}`}
      style={{ width, height }}
    >
      <canvas ref={dataRef} className="absolute inset-0 block" style={{ width, height }} />
      <canvas
        ref={overlayRef}
        className="absolute inset-0 block touch-none"
        style={{ width, height }}
        onPointerMove={onPointerMove}
        onPointerLeave={onPointerLeave}
        onPointerCancel={onPointerLeave}
      />
    </div>
  );
}
