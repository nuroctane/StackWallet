import type { SVGProps } from 'react';

/**
 * Hairline glyphs drawn on a 12-unit grid with a 1.25 stroke so they sit on
 * the same optical weight as the monospace labels beside them. Everything is
 * `currentColor`: a glyph never brings its own colour, the tag does.
 */
type Glyph = readonly string[];

/** Glyphs a user may put on their own tags. */
export const TAG_ICON_GLYPHS = {
  dot: ['M6 4.5a1.5 1.5 0 1 1 0 3a1.5 1.5 0 1 1 0-3z'],
  ring: ['M6 2.5a3.5 3.5 0 1 1 0 7a3.5 3.5 0 1 1 0-7z'],
  square: ['M3 3h6v6H3z'],
  diamond: ['M6 2l4 4-4 4-4-4z'],
  triangle: ['M6 2.5l4 7H2z'],
  hexagon: ['M6 1.8l3.6 2.1v4.2L6 10.2 2.4 8.1V3.9z'],
  star: ['M6 1.8l1.25 2.6 2.85.4-2.07 2 .5 2.83L6 8.3 3.47 9.63l.5-2.83-2.07-2 2.85-.4z'],
  spark: ['M6 1.5v9M1.5 6h9M3 3l6 6M9 3l-6 6'],
  bolt: ['M6.8 1.5L3 6.8h3l-.8 3.7L9 5.2H6z'],
  flame: [
    'M6 10.5c2 0 3.3-1.3 3.3-3.1C9.3 5.2 6.8 4 6.6 1.5 5 2.8 4.9 4.3 5.2 5.4 4.4 5 4 4.2 4 3.6 3 4.6 2.7 5.9 2.7 7.4c0 1.8 1.3 3.1 3.3 3.1z',
  ],
  leaf: ['M2.5 9.5C2.5 5 5 2.5 9.5 2.5c0 4.5-2.5 7-7 7z', 'M2.5 9.5l4-4'],
  snow: ['M6 1.5v9M2.1 3.75l7.8 4.5M2.1 8.25l7.8-4.5'],
  moon: ['M9.5 7.6A4 4 0 0 1 4.4 2.5a4 4 0 1 0 5.1 5.1z'],
  sun: [
    'M6 4.2a1.8 1.8 0 1 1 0 3.6a1.8 1.8 0 1 1 0-3.6z',
    'M6 1v1.2M6 9.8V11M1 6h1.2M9.8 6H11M2.5 2.5l.85.85M8.65 8.65l.85.85M2.5 9.5l.85-.85M8.65 3.35l.85-.85',
  ],
  flag: ['M3 10.5V1.8M3 2h5.5l-1 2 1 2H3'],
  bookmark: ['M3.5 1.8h5v8.7L6 8.6l-2.5 1.9z'],
  pin: ['M6 10.5s3.2-3.1 3.2-5.5a3.2 3.2 0 0 0-6.4 0c0 2.4 3.2 5.5 3.2 5.5z', 'M6 4.2v.1'],
  anchor: [
    'M6 3.5v7M4 5h4M2.5 7.2c0 1.9 1.6 3.3 3.5 3.3s3.5-1.4 3.5-3.3',
    'M6 1.5a1 1 0 1 1 0 2a1 1 0 1 1 0-2z',
  ],
  compass: ['M6 1.5a4.5 4.5 0 1 1 0 9a4.5 4.5 0 1 1 0-9z', 'M7.6 4.4L6.6 6.6 4.4 7.6l1-2.2z'],
  cube: ['M6 1.5l4 2.2v4.6L6 10.5 2 8.3V3.7z', 'M2 3.7l4 2.2 4-2.2M6 5.9v4.6'],
  layers: ['M6 2l4.5 2.3L6 6.6 1.5 4.3z', 'M1.5 6.5L6 8.8l4.5-2.3', 'M1.5 8.6L6 10.9l4.5-2.3'],
  coin: [
    'M6 1.5a4.5 4.5 0 1 1 0 9a4.5 4.5 0 1 1 0-9z',
    'M6 3.5v5M4.6 4.6h2.1a.9.9 0 0 1 0 1.4H5.3a.9.9 0 0 0 0 1.4h2.1',
  ],
  chart: ['M1.5 10.5h9', 'M2.5 8l2.5-2.5 2 1.5 3-4'],
  clock: ['M6 1.5a4.5 4.5 0 1 1 0 9a4.5 4.5 0 1 1 0-9z', 'M6 3.5V6l1.8 1.2'],
  hash: ['M4.5 1.8L3.5 10.2M8.5 1.8l-1 8.4M2 4.3h8.3M1.7 7.7H10'],
  at: [
    'M6 4.2a1.8 1.8 0 1 1 0 3.6a1.8 1.8 0 1 1 0-3.6z',
    'M7.8 6v.8c0 1.6 2.7 1.6 2.7-.8A4.5 4.5 0 1 0 8.3 9.9',
  ],
  link: [
    'M5 7L7 5',
    'M5.6 3.4l.9-.9a2.1 2.1 0 0 1 3 3l-.9.9',
    'M6.4 8.6l-.9.9a2.1 2.1 0 0 1-3-3l.9-.9',
  ],
  heart: ['M6 10S1.5 7.4 1.5 4.6A2.3 2.3 0 0 1 6 3.5a2.3 2.3 0 0 1 4.5 1.1C10.5 7.4 6 10 6 10z'],
  target: ['M6 1.5a4.5 4.5 0 1 1 0 9a4.5 4.5 0 1 1 0-9z', 'M6 4a2 2 0 1 1 0 4a2 2 0 1 1 0-4z'],
  crown: ['M1.8 9.5h8.4M2 8l-.5-5 2.8 2.2L6 2l1.7 3.2L10.5 3 10 8z'],
  wave: ['M1.5 6c1.1-1.6 2.2-1.6 3 0s1.9 1.6 3 0 2.2-1.6 3 0'],
  grid: ['M2 2h3v3H2zM7 2h3v3H7zM2 7h3v3H2zM7 7h3v3H7z'],
} as const satisfies Record<string, Glyph>;

export type TagIconId = keyof typeof TAG_ICON_GLYPHS;
export const TAG_ICON_IDS = Object.keys(TAG_ICON_GLYPHS) as TagIconId[];

/**
 * Glyphs reserved for core-derived security tags. None of them is in the user
 * set, so a user tag can never borrow the look of an attestation.
 */
export const SECURITY_GLYPHS = {
  lock: ['M3 5.5h6v4.8H3z', 'M4.3 5.5V4a1.7 1.7 0 0 1 3.4 0v1.5'],
  exposed: ['M6 1.8l4.6 8.2H1.4z', 'M6 4.8v2.4M6 8.4v.1'],
  exported: ['M5 2.5H2.5v7h7V7', 'M6.5 5.5l4-4M7.5 1.5h3v3'],
  imported: ['M7 2.5h2.5v7h-7V7', 'M10.5 1.5l-4 4M3.5 5.5h3v-3'],
  approvals: ['M3 5.5h6v4.8H3z', 'M4.3 5.5V4a1.7 1.7 0 0 1 3.3-.5'],
  local: ['M6 3a3 3 0 1 1 0 6a3 3 0 1 1 0-6z', 'M1.5 1.5l9 9'],
  watch: [
    'M1.2 6S3 2.8 6 2.8 10.8 6 10.8 6 9 9.2 6 9.2 1.2 6 1.2 6z',
    'M6 4.8a1.2 1.2 0 1 1 0 2.4a1.2 1.2 0 1 1 0-2.4z',
  ],
} as const satisfies Record<string, Glyph>;

export type SecurityGlyphId = keyof typeof SECURITY_GLYPHS;

const FILLED: ReadonlySet<string> = new Set(['dot']);

function Svg({
  glyph,
  filled,
  size,
  ...rest
}: { glyph: Glyph; filled: boolean; size: number } & Omit<SVGProps<SVGSVGElement>, 'children'>) {
  return (
    <svg
      viewBox="0 0 12 12"
      width={size}
      height={size}
      aria-hidden
      focusable="false"
      fill={filled ? 'currentColor' : 'none'}
      stroke="currentColor"
      strokeWidth={1.25}
      strokeLinecap="round"
      strokeLinejoin="round"
      {...rest}
    >
      {glyph.map((d, i) => (
        <path key={i} d={d} />
      ))}
    </svg>
  );
}

export function isTagIconId(value: unknown): value is TagIconId {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(TAG_ICON_GLYPHS, value);
}

export function TagIcon({
  icon,
  size = 10,
  ...rest
}: { icon: TagIconId; size?: number } & Omit<SVGProps<SVGSVGElement>, 'children'>) {
  const glyph = TAG_ICON_GLYPHS[icon];
  return <Svg glyph={glyph} filled={FILLED.has(icon)} size={size} {...rest} />;
}

export function SecurityGlyph({
  glyph,
  size = 10,
  ...rest
}: { glyph: SecurityGlyphId; size?: number } & Omit<SVGProps<SVGSVGElement>, 'children'>) {
  return <Svg glyph={SECURITY_GLYPHS[glyph]} filled={false} size={size} {...rest} />;
}
