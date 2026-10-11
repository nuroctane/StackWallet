import { isLight, mix, withAlpha } from './color.js';
import { NUR_PRESETS, type NurPalette } from './nurPresets.js';

/**
 * Every colour StackWallet paints with. Each key becomes `--color-<key>` (read
 * by Tailwind utilities) and `--sw-<key>` (read by plain CSS and canvases), so
 * a theme is nothing more than a full assignment of these.
 */
export const THEME_TOKENS = [
  'paper',
  'surface',
  'elevated',
  'hover',
  'sheen',
  'grid',
  'ink',
  'muted',
  'faint',
  'edge',
  'edge-strong',
  'warm',
  'accent-2',
  'accent-3',
  'ok',
  'danger',
  'danger-soft',
  'chart-1',
  'chart-2',
  'chart-3',
  'chart-4',
  'terrain-0',
  'terrain-1',
  'terrain-2',
  'terrain-3',
  'terrain-4',
] as const;

export type ThemeToken = (typeof THEME_TOKENS)[number];
export type ThemeTokens = Record<ThemeToken, string>;

export interface TokenMeta {
  label: string;
  hint: string;
}

export const TOKEN_META: Record<ThemeToken, TokenMeta> = {
  paper: { label: 'paper', hint: 'canvas and page background' },
  surface: { label: 'surface', hint: 'panel fill' },
  elevated: { label: 'elevated', hint: 'cards, menus, popovers' },
  hover: { label: 'hover', hint: 'hover fill on rows and buttons' },
  sheen: { label: 'sheen', hint: 'glass top highlight' },
  grid: { label: 'grid', hint: 'canvas grid lines' },
  ink: { label: 'ink', hint: 'primary text' },
  muted: { label: 'muted', hint: 'secondary text' },
  faint: { label: 'faint', hint: 'labels and tertiary text' },
  edge: { label: 'edge', hint: 'hairline borders' },
  'edge-strong': { label: 'edge strong', hint: 'focus ring, selected edge' },
  warm: { label: 'accent', hint: 'selection, totals, pending counts' },
  'accent-2': { label: 'accent 2', hint: 'name-service names, links' },
  'accent-3': { label: 'accent 3', hint: 'imported provenance, secondary highlights' },
  ok: { label: 'ok', hint: 'success and healthy state' },
  danger: { label: 'danger', hint: 'destructive, exposed keys, signing danger' },
  'danger-soft': { label: 'danger glass', hint: 'fill behind danger state' },
  'chart-1': { label: 'series 1', hint: 'first chart series' },
  'chart-2': { label: 'series 2', hint: 'second chart series' },
  'chart-3': { label: 'series 3', hint: 'third chart series' },
  'chart-4': { label: 'series 4', hint: 'fourth chart series' },
  'terrain-0': { label: 'terrain 0', hint: 'activity: no events' },
  'terrain-1': { label: 'terrain 1', hint: 'activity: low' },
  'terrain-2': { label: 'terrain 2', hint: 'activity: medium' },
  'terrain-3': { label: 'terrain 3', hint: 'activity: high' },
  'terrain-4': { label: 'terrain 4', hint: 'activity: peak' },
};

export const TOKEN_GROUPS: readonly { name: string; tokens: readonly ThemeToken[] }[] = [
  { name: 'surfaces', tokens: ['paper', 'surface', 'elevated', 'hover', 'sheen', 'grid'] },
  { name: 'text', tokens: ['ink', 'muted', 'faint'] },
  { name: 'edges', tokens: ['edge', 'edge-strong'] },
  {
    name: 'signals',
    tokens: ['warm', 'accent-2', 'accent-3', 'ok', 'danger', 'danger-soft'],
  },
  { name: 'charts', tokens: ['chart-1', 'chart-2', 'chart-3', 'chart-4'] },
  { name: 'terrain', tokens: ['terrain-0', 'terrain-1', 'terrain-2', 'terrain-3', 'terrain-4'] },
];

export interface ThemePreset {
  id: string;
  name: string;
  description: string;
  family: 'stackwallet' | 'nur' | 'custom';
  tokens: ThemeTokens;
}

/** The house theme, kept byte-for-byte with docs/DESIGN.md. */
export const NIGHT_GLASS: ThemeTokens = {
  paper: '#050505',
  surface: '#141414',
  elevated: '#1b1b1b',
  hover: '#ffffff12',
  sheen: '#ffffff17',
  grid: '#ffffff08',
  ink: '#f2f2f2',
  muted: '#a0a0a0',
  faint: '#777777',
  edge: '#ffffff1f',
  'edge-strong': '#ffffff4d',
  warm: '#e2c27b',
  'accent-2': '#d8d8d8',
  'accent-3': '#a0a0a0',
  ok: '#d8d8d8',
  danger: '#ff453a',
  'danger-soft': '#ff453a38',
  'chart-1': '#d8d8d8',
  'chart-2': '#a0a0a0',
  'chart-3': '#777777',
  'chart-4': '#555555',
  'terrain-0': '#1b1b1b',
  'terrain-1': '#3a3a3a',
  'terrain-2': '#5e5e5e',
  'terrain-3': '#8a8a8a',
  'terrain-4': '#d8d8d8',
};

export const DEFAULT_PRESET_ID = 'night-glass';

/**
 * Map a NurCLI palette onto StackWallet's roles. Translucent roles are derived
 * from the ink at the same strengths night glass uses, so hairlines and hover
 * fills read the same on every ground.
 */
export function tokensFromNur(p: NurPalette): ThemeTokens {
  const light = isLight(p.bg);
  return {
    paper: p.bg,
    surface: p.surface,
    elevated: p.surface2,
    hover: withAlpha(p.fg, light ? 0.06 : 0.07),
    sheen: withAlpha(light ? '#ffffff' : p.fg, light ? 0.5 : 0.09),
    grid: withAlpha(p.fg, light ? 0.05 : 0.03),
    ink: p.fg,
    muted: p.muted,
    faint: p.faint,
    edge: withAlpha(p.fg, light ? 0.14 : 0.12),
    'edge-strong': withAlpha(p.fg, light ? 0.36 : 0.3),
    warm: p.nurGold,
    'accent-2': p.mdH2,
    'accent-3': p.mdH3,
    ok: p.success,
    danger: p.error,
    'danger-soft': withAlpha(p.error, 0.22),
    'chart-1': mix(p.fg, p.bg, 0.12),
    'chart-2': p.muted,
    'chart-3': p.faint,
    'chart-4': mix(p.faint, p.bg, 0.35),
    'terrain-0': p.surface2,
    'terrain-1': mix(p.surface2, p.fg, 0.18),
    'terrain-2': mix(p.surface2, p.fg, 0.36),
    'terrain-3': mix(p.surface2, p.fg, 0.56),
    'terrain-4': mix(p.surface2, p.fg, 0.82),
  };
}

function splitLabel(label: string): { name: string; description: string } {
  const i = label.indexOf(' - ');
  return i < 0
    ? { name: label, description: '' }
    : { name: label.slice(0, i), description: label.slice(i + 3) };
}

export const BUILTIN_PRESETS: readonly ThemePreset[] = [
  {
    id: DEFAULT_PRESET_ID,
    name: 'Night Glass',
    description: 'stark black, white glass, hairline edges',
    family: 'stackwallet',
    tokens: NIGHT_GLASS,
  },
  ...NUR_PRESETS.map((p) => ({
    id: `nur-${p.id}`,
    ...splitLabel(p.label),
    family: 'nur' as const,
    tokens: tokensFromNur(p.palette),
  })),
];

export function isLightTheme(tokens: Pick<ThemeTokens, 'paper'>): boolean {
  return isLight(tokens.paper);
}
