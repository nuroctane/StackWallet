import { useEffect, useMemo, useRef, useState } from 'react';

import { useThemeEpoch } from '@stackwallet/ui';

import { useActivity, activityLog, type ActivityDay } from '../activity.js';
import type { ElementBodyProps } from './types.js';

/** Night-glass ramp: five grays from the panel colour up to the neutral success ink. */
const LEVEL_GRAYS = ['#1b1b1b', '#3a3a3a', '#5e5e5e', '#8a8a8a', '#d8d8d8'];
const LEVEL_TOKENS = [
  '--sw-terrain-0',
  '--sw-terrain-1',
  '--sw-terrain-2',
  '--sw-terrain-3',
  '--sw-terrain-4',
];
const LABEL_TOP = 22;
const MARGIN = 8;

export interface TerrainCell {
  week: number;
  day: number;
  n: number;
  t: number;
  dayKey: string;
}

export function levelFor(count: number, max: number): number {
  if (count <= 0) return 0;
  if (max <= 1) return 4;
  const t = count / max;
  if (t < 0.25) return 1;
  if (t < 0.5) return 2;
  if (t < 0.75) return 3;
  return 4;
}

/** Arrange a day series oldest→newest into week columns and weekday rows. */
export function toCells(days: readonly ActivityDay[]): TerrainCell[] {
  const cells: TerrainCell[] = [];
  for (let i = 0; i < days.length; i++) {
    const d = days[i] as ActivityDay;
    cells.push({ week: Math.floor(i / 7), day: i % 7, n: d.n, t: d.t, dayKey: d.dayKey });
  }
  return cells;
}

export interface TerrainCamera {
  yaw: number;
  tilt: number;
  zoom: number;
  panX: number;
  panY: number;
}
export const HOME_CAMERA: TerrainCamera = { yaw: Math.PI / 4, tilt: 1, zoom: 1, panX: 0, panY: 0 };
export function moveCamera(c: TerrainCamera, dx: number, dy: number, pan = false): TerrainCamera {
  return pan
    ? { ...c, panX: c.panX + dx, panY: c.panY + dy }
    : { ...c, yaw: c.yaw - dx * 0.008, tilt: Math.max(0.3, Math.min(1.6, c.tilt + dy * 0.008)) };
}
export function zoomCamera(c: TerrainCamera, factor: number): TerrainCamera {
  return { ...c, zoom: Math.max(0.5, Math.min(4, c.zoom * factor)) };
}
export function pinchCamera(
  c: TerrainCamera,
  previous: { x: number; y: number },
  next: { x: number; y: number },
  other: { x: number; y: number },
): TerrainCamera {
  const before = Math.hypot(previous.x - other.x, previous.y - other.y);
  const after = Math.hypot(next.x - other.x, next.y - other.y);
  return zoomCamera(
    moveCamera(c, (next.x - previous.x) / 2, (next.y - previous.y) / 2, true),
    before > 1 ? after / before : 1,
  );
}

interface Geometry {
  cell: number;
  ox: number;
  oy: number;
  maxH: number;
  maxCount: number;
  ax: number;
  ay: number;
  bx: number;
  by: number;
}

export function project(w: number, d: number, h: number, g: Geometry) {
  return { x: g.ox + (w * g.ax + d * g.bx) * g.cell, y: g.oy + (w * g.ay + d * g.by) * g.cell - h };
}

export function computeGeometry(
  cells: readonly TerrainCell[],
  cssW: number,
  cssH: number,
  camera: TerrainCamera = HOME_CAMERA,
): Geometry {
  const maxWeek = cells.reduce((m, c) => Math.max(m, c.week), 0);
  const maxDay = 6;
  const maxCount = cells.reduce((m, c) => Math.max(m, c.n), 1);
  const availW = cssW - MARGIN * 2;
  const availH = cssH - LABEL_TOP - MARGIN;
  const cell = Math.max(
    2,
    Math.min(14, availW / (maxWeek + maxDay + 4) / 0.9, availH / (maxWeek + maxDay + 6) / 0.55),
  );
  const maxH = cell * 5.5;
  const g: Geometry = {
    cell,
    ox: 0,
    oy: 0,
    maxH,
    maxCount,
    ax: Math.cos(camera.yaw) * Math.SQRT2 * 0.9,
    bx: -Math.sin(camera.yaw) * Math.SQRT2 * 0.9,
    ay: Math.sin(camera.yaw) * Math.SQRT2 * 0.5 * camera.tilt,
    by: Math.cos(camera.yaw) * Math.SQRT2 * 0.5 * camera.tilt,
  };

  // Measure the projected bounding box at the origin, then centre it.
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  const sample = (w: number, d: number, h: number) => {
    const pts = [
      [0, 0],
      [1, 0],
      [1, 1],
      [0, 1],
    ].flatMap(([dw, dd]) => [project(w + dw!, d + dd!, 0, g), project(w + dw!, d + dd!, h, g)]);
    for (const p of pts) {
      minX = Math.min(minX, p.x);
      maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y);
      maxY = Math.max(maxY, p.y);
    }
  };
  sample(0, 0, maxH);
  sample(maxWeek, 0, maxH);
  sample(0, maxDay, maxH);
  sample(maxWeek, maxDay, maxH);
  const bw = maxX - minX || 1;
  const bh = maxY - minY || 1;
  const fit = Math.min(1, Math.max(1, availW) / bw, Math.max(1, availH) / bh) * camera.zoom;
  g.cell *= fit;
  g.maxH *= fit;
  g.ox = (cssW - bw * fit) / 2 - minX * fit + camera.panX;
  g.oy = LABEL_TOP + (availH - bh * fit) / 2 - minY * fit + camera.panY;
  return g;
}

function heightFor(n: number, g: Geometry): number {
  return Math.max(1.5, (n / g.maxCount) * g.maxH);
}

export function drawTerrain(
  ctx: CanvasRenderingContext2D,
  cells: readonly TerrainCell[],
  g: Geometry,
  cssW: number,
  cssH: number,
  colors: {
    paper: string;
    faint: string;
    warm: string;
    ink: string;
    font: string;
    levels?: readonly string[];
  },
  hovered: TerrainCell | null,
  todayKey: string,
) {
  ctx.clearRect(0, 0, cssW, cssH);
  const sorted = cells.slice().sort((a, b) => (a.week - b.week) * g.ay + (a.day - b.day) * g.by);
  for (const c of sorted) {
    const h = heightFor(c.n, g);
    const levels = colors.levels ?? LEVEL_GRAYS;
    const col =
      hovered === c || c.dayKey === todayKey ? colors.warm : levels[levelFor(c.n, g.maxCount)]!;
    const corners = [
      [0, 0],
      [1, 0],
      [1, 1],
      [0, 1],
    ].map(([w, d]) => project(c.week + w!, c.day + d!, 0, g));
    const face = (points: { x: number; y: number }[], color: string) => {
      ctx.fillStyle = color;
      ctx.beginPath();
      points.forEach((p, i) => (i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y)));
      ctx.closePath();
      ctx.fill();
    };
    for (let i = 0; i < 4; i++) {
      const a = corners[i]!;
      const b = corners[(i + 1) % 4]!;
      const midY = (a.y + b.y) / 2;
      const centerY = corners.reduce((sum, p) => sum + p.y, 0) / 4;
      // Hide far faces as the camera crosses each side of the terrain.
      if (midY >= centerY)
        face([a, b, { x: b.x, y: b.y - h }, { x: a.x, y: a.y - h }], shade(col, i % 2 ? -45 : -28));
    }
    face(
      corners.map((p) => ({ x: p.x, y: p.y - h })),
      col,
    );
  }

  ctx.font = `500 10px ${colors.font}`;
  ctx.textBaseline = 'alphabetic';
  // Readouts live in wrapping DOM text so narrow canvases cannot clip their labels.
  if (hovered) {
    ctx.fillStyle = colors.ink;
    const label = `${hovered.dayKey} · ${hovered.n}`;
    ctx.fillText(label, cssW - MARGIN - ctx.measureText(label).width, cssH - 6);
  }
}

/** Nearest cell by projected top-face centre; cheap enough to run per pointermove. */
export function hitTest(
  cells: readonly TerrainCell[],
  g: Geometry,
  px: number,
  py: number,
): TerrainCell | null {
  let best: TerrainCell | null = null;
  let bestD = (g.cell * 1.2) ** 2;
  for (const c of cells) {
    const top = project(c.week + 0.5, c.day + 0.5, heightFor(c.n, g), g);
    const cx = top.x;
    const cy = top.y;
    const d = (cx - px) ** 2 + (cy - py) ** 2;
    if (d < bestD) {
      bestD = d;
      best = c;
    }
  }
  return best;
}

function shade(hex: string, delta: number): string {
  // Themes may carry an alpha pair; the extrusion faces are always drawn opaque.
  const n = parseInt(hex.slice(1, 7), 16);
  const r = Math.max(0, Math.min(255, ((n >> 16) & 255) + delta));
  const gch = Math.max(0, Math.min(255, ((n >> 8) & 255) + delta));
  const b = Math.max(0, Math.min(255, (n & 255) + delta));
  return `rgb(${r},${gch},${b})`;
}

export function TerrainElement({ pane, width, height }: ElementBodyProps) {
  const themeEpoch = useThemeEpoch();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const activity = useActivity();
  const weeks = clampWeeks(Number(pane.props['weeks'] ?? 26));
  const [camera, setCamera] = useState<TerrainCamera>(HOME_CAMERA);
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const [hovered, setHovered] = useState<TerrainCell | null>(null);
  const [focused, setFocused] = useState(false);

  const cells = useMemo(() => toCells(activityLog.series(weeks)), [activity, weeks]);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const zoom = (e: WheelEvent) => {
      e.preventDefault();
      setCamera((c) => zoomCamera(c, Math.exp(-Math.max(-200, Math.min(200, e.deltaY)) * 0.003)));
    };
    canvas.addEventListener('wheel', zoom, { passive: false });
    return () => canvas.removeEventListener('wheel', zoom);
  }, []);
  const geometry = useMemo(
    () =>
      width > 0 && height > 0
        ? computeGeometry(cells, width, Math.max(1, height - 64), camera)
        : null,
    [cells, width, height, camera],
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !geometry) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    if (
      canvas.width !== Math.floor(width * dpr) ||
      canvas.height !== Math.floor(Math.max(1, height - 64) * dpr)
    ) {
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(Math.max(1, height - 64) * dpr);
    }
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const cs = getComputedStyle(canvas);
    const colors = {
      paper: cs.getPropertyValue('--sw-paper').trim(),
      faint: cs.getPropertyValue('--sw-faint').trim(),
      warm: cs.getPropertyValue('--sw-warm').trim() || '#e2c27b',
      ink: cs.getPropertyValue('--sw-ink').trim(),
      font: cs.fontFamily,
      levels: LEVEL_TOKENS.map(
        (t, i) => cs.getPropertyValue(t).trim() || (LEVEL_GRAYS[i] as string),
      ),
    };
    const todayKey = cells.length > 0 ? (cells[cells.length - 1] as TerrainCell).dayKey : '';
    drawTerrain(ctx, cells, geometry, width, Math.max(1, height - 64), colors, hovered, todayKey);
  }, [cells, geometry, width, height, hovered, themeEpoch]);

  const release = (id: number) => pointers.current.delete(id);
  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto">
      <div className="flex shrink-0 flex-wrap items-center gap-2 px-2 py-1 text-[10px] text-faint">
        <span className="flex-1">drag: turn / tilt · shift-drag: pan · pinch: zoom</span>
        <button
          type="button"
          className="sw-pressable px-2 py-1"
          onClick={() => {
            setCamera(HOME_CAMERA);
            setHovered(null);
          }}
        >
          reset view
        </button>
      </div>
      <canvas
        ref={canvasRef}
        style={{
          width,
          height: Math.max(1, height - 64),
          display: 'block',
          touchAction: 'none',
          cursor: 'grab',
        }}
        tabIndex={0}
        data-camera={JSON.stringify(camera)}
        aria-label="Workspace activity terrain. Local app events, not wallet transactions. Drag to turn and tilt, shift-drag to pan, two fingers to pan and zoom. Arrow keys turn and tilt, plus and minus zoom, brackets select days, Home resets."
        role="img"
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onDoubleClick={() => setCamera(HOME_CAMERA)}
        onKeyDown={(e) => {
          let next = camera;
          if (e.key === 'Home') next = HOME_CAMERA;
          else if (e.key === '+' || e.key === '=') next = zoomCamera(camera, 1.2);
          else if (e.key === '-') next = zoomCamera(camera, 1 / 1.2);
          else if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) {
            const dx = e.key === 'ArrowLeft' ? -20 : e.key === 'ArrowRight' ? 20 : 0;
            const dy = e.key === 'ArrowUp' ? -15 : e.key === 'ArrowDown' ? 15 : 0;
            next = moveCamera(camera, dx, dy, e.shiftKey);
          } else if (e.key === '[' || e.key === ']') {
            const current = hovered ? cells.indexOf(hovered) : cells.length - 1;
            setHovered(
              cells[Math.max(0, Math.min(cells.length - 1, current + (e.key === '[' ? -1 : 1)))] ??
                null,
            );
          } else return;
          e.preventDefault();
          e.stopPropagation();
          setCamera(next);
        }}
        onPointerDown={(e) => {
          if (e.button !== 0) return;
          e.currentTarget.focus();
          e.currentTarget.setPointerCapture(e.pointerId);
          if (geometry) {
            const rect = e.currentTarget.getBoundingClientRect();
            setHovered(hitTest(cells, geometry, e.clientX - rect.left, e.clientY - rect.top));
          }
          pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
        }}
        onPointerUp={(e) => release(e.pointerId)}
        onPointerCancel={(e) => release(e.pointerId)}
        onLostPointerCapture={(e) => release(e.pointerId)}
        onPointerMove={(e) => {
          const previous = pointers.current.get(e.pointerId);
          if (previous) {
            const other = [...pointers.current.entries()].find(([id]) => id !== e.pointerId)?.[1];
            const dx = e.clientX - previous.x;
            const dy = e.clientY - previous.y;
            pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
            if (other) {
              setCamera((c) => pinchCamera(c, previous, { x: e.clientX, y: e.clientY }, other));
            } else setCamera((c) => moveCamera(c, dx, dy, e.shiftKey));
          }
          if (!geometry) return;
          const rect = e.currentTarget.getBoundingClientRect();
          setHovered(hitTest(cells, geometry, e.clientX - rect.left, e.clientY - rect.top));
        }}
        onPointerLeave={() => {
          if (!pointers.current.size) setHovered(null);
        }}
      />
      <div
        className="shrink-0 px-2 py-1 text-[11px] break-words text-muted"
        aria-live={focused ? 'polite' : 'off'}
      >
        {hovered
          ? hovered.dayKey + ' · ' + hovered.n + ' local events'
          : 'Local workspace events · use brackets to inspect any day'}
        <span className="block text-faint">
          {cells.reduce((sum, c) => sum + c.n, 0).toLocaleString()} local events · {cells.length}{' '}
          days
        </span>
      </div>
    </div>
  );
}

function clampWeeks(n: number): number {
  if (!Number.isFinite(n)) return 26;
  return Math.max(4, Math.min(57, Math.round(n)));
}
