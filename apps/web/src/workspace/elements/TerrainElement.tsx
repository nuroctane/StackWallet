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

interface Geometry {
  cell: number;
  ox: number;
  oy: number;
  maxH: number;
  maxCount: number;
}

function project(w: number, d: number, h: number, g: Geometry) {
  return { x: g.ox + (w - d) * g.cell * 0.9, y: g.oy + (w + d) * g.cell * 0.5 - h };
}

export function computeGeometry(
  cells: readonly TerrainCell[],
  cssW: number,
  cssH: number,
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
  const g: Geometry = { cell, ox: 0, oy: 0, maxH, maxCount };

  // Measure the projected bounding box at the origin, then centre it.
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  const sample = (w: number, d: number, h: number) => {
    const base = project(w, d, 0, g);
    const top = project(w, d, h, g);
    const pts = [
      base,
      top,
      { x: base.x + cell * 0.9, y: base.y + cell * 0.5 },
      { x: base.x - cell * 0.9, y: base.y + cell * 0.5 },
      { x: top.x + cell * 0.9, y: top.y + cell * 0.5 },
      { x: top.x - cell * 0.9, y: top.y + cell * 0.5 },
      { x: base.x, y: base.y + cell },
    ];
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
  g.ox = (cssW - bw) / 2 - minX;
  g.oy = LABEL_TOP + (availH - bh) / 2 - minY;
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
  const sorted = cells.slice().sort((a, b) => a.week + a.day - (b.week + b.day));
  for (const c of sorted) {
    const h = heightFor(c.n, g);
    const { x, y } = project(c.week, c.day, 0, g);
    const top = project(c.week, c.day, h, g);
    const isHot = hovered === c || c.dayKey === todayKey;
    const levels = colors.levels ?? LEVEL_GRAYS;
    const col = isHot ? colors.warm : (levels[levelFor(c.n, g.maxCount)] as string);
    const half = g.cell * 0.5;
    const wide = g.cell * 0.9;

    ctx.fillStyle = shade(col, -28);
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x + wide, y + half);
    ctx.lineTo(x + wide, y + half - h);
    ctx.lineTo(x, y - h);
    ctx.closePath();
    ctx.fill();

    ctx.fillStyle = shade(col, -45);
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x - wide, y + half);
    ctx.lineTo(x - wide, y + half - h);
    ctx.lineTo(x, y - h);
    ctx.closePath();
    ctx.fill();

    ctx.fillStyle = col;
    ctx.beginPath();
    ctx.moveTo(top.x, top.y);
    ctx.lineTo(top.x + wide, top.y + half);
    ctx.lineTo(top.x, top.y + g.cell);
    ctx.lineTo(top.x - wide, top.y + half);
    ctx.closePath();
    ctx.fill();
  }

  ctx.font = `500 10px ${colors.font}`;
  ctx.textBaseline = 'alphabetic';
  const total = cells.reduce((s, c) => s + c.n, 0);
  ctx.fillStyle = colors.faint;
  ctx.fillText(`activity · ${cells.length} days`, MARGIN, 13);
  const right = `${total.toLocaleString()} events`;
  ctx.fillText(right, cssW - MARGIN - ctx.measureText(right).width, 13);
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
    const top = project(c.week, c.day, heightFor(c.n, g), g);
    const cx = top.x;
    const cy = top.y + g.cell * 0.5;
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
  const [hovered, setHovered] = useState<TerrainCell | null>(null);

  const cells = useMemo(() => toCells(activityLog.series(weeks)), [activity, weeks]);
  const geometry = useMemo(
    () => (width > 0 && height > 0 ? computeGeometry(cells, width, height) : null),
    [cells, width, height],
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !geometry) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(height * dpr)) {
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
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
    drawTerrain(ctx, cells, geometry, width, height, colors, hovered, todayKey);
  }, [cells, geometry, width, height, hovered, themeEpoch]);

  return (
    <canvas
      ref={canvasRef}
      style={{ width, height, display: 'block' }}
      aria-label="Local activity terrain"
      role="img"
      onPointerMove={(e) => {
        if (!geometry) return;
        const rect = e.currentTarget.getBoundingClientRect();
        const hit = hitTest(cells, geometry, e.clientX - rect.left, e.clientY - rect.top);
        if (hit !== hovered) setHovered(hit);
      }}
      onPointerLeave={() => setHovered(null)}
    />
  );
}

function clampWeeks(n: number): number {
  if (!Number.isFinite(n)) return 26;
  return Math.max(4, Math.min(57, Math.round(n)));
}
