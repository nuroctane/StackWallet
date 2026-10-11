/**
 * Colour math for the theme engine. Everything is stored as `#rrggbb` or
 * `#rrggbbaa` so a theme serialises to plain strings that CSS reads directly.
 */

export interface Rgba {
  r: number;
  g: number;
  b: number;
  /** 0..1 */
  a: number;
}

export interface Hsva {
  /** 0..360 */
  h: number;
  /** 0..1 */
  s: number;
  /** 0..1 */
  v: number;
  /** 0..1 */
  a: number;
}

const HEX_RE = /^#?([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;

export function isHexColor(s: string): boolean {
  return HEX_RE.test(s.trim());
}

export function parseHex(input: string): Rgba | null {
  const m = HEX_RE.exec(input.trim());
  if (!m) return null;
  let h = m[1]!.toLowerCase();
  if (h.length <= 4) h = [...h].map((c) => c + c).join('');
  const n = (i: number) => parseInt(h.slice(i, i + 2), 16);
  return { r: n(0), g: n(2), b: n(4), a: h.length === 8 ? n(6) / 255 : 1 };
}

const byte = (n: number) => Math.round(Math.min(255, Math.max(0, n)));
const hex2 = (n: number) => byte(n).toString(16).padStart(2, '0');

/** Opaque colours drop the alpha pair so presets stay readable. */
export function formatHex({ r, g, b, a }: Rgba): string {
  const base = `#${hex2(r)}${hex2(g)}${hex2(b)}`;
  return a >= 1 ? base : `${base}${hex2(a * 255)}`;
}

/** Normalises any accepted hex spelling to the canonical stored form. */
export function normalizeHex(input: string): string | null {
  const c = parseHex(input);
  return c ? formatHex(c) : null;
}

export function withAlpha(hex: string, a: number): string {
  const c = parseHex(hex) ?? { r: 0, g: 0, b: 0, a: 1 };
  return formatHex({ ...c, a: Math.min(1, Math.max(0, a)) });
}

/** Straight RGB interpolation, matching NurCLI's `lerp` so derived ramps agree. */
export function mix(a: string, b: string, t: number): string {
  const x = parseHex(a) ?? { r: 0, g: 0, b: 0, a: 1 };
  const y = parseHex(b) ?? { r: 0, g: 0, b: 0, a: 1 };
  const k = Math.min(1, Math.max(0, t));
  return formatHex({
    r: x.r + (y.r - x.r) * k,
    g: x.g + (y.g - x.g) * k,
    b: x.b + (y.b - x.b) * k,
    a: x.a + (y.a - x.a) * k,
  });
}

export function rgbToHsv({ r, g, b, a }: Rgba): Hsva {
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const d = max - min;
  let h = 0;
  if (d > 0) {
    if (max === rn) h = ((gn - bn) / d) % 6;
    else if (max === gn) h = (bn - rn) / d + 2;
    else h = (rn - gn) / d + 4;
    h *= 60;
    if (h < 0) h += 360;
  }
  return { h, s: max === 0 ? 0 : d / max, v: max, a };
}

export function hsvToRgb({ h, s, v, a }: Hsva): Rgba {
  const hh = (((h % 360) + 360) % 360) / 60;
  const c = v * s;
  const x = c * (1 - Math.abs((hh % 2) - 1));
  const m = v - c;
  const [r, g, b] =
    hh < 1
      ? [c, x, 0]
      : hh < 2
        ? [x, c, 0]
        : hh < 3
          ? [0, c, x]
          : hh < 4
            ? [0, x, c]
            : hh < 5
              ? [x, 0, c]
              : [c, 0, x];
  return { r: (r + m) * 255, g: (g + m) * 255, b: (b + m) * 255, a };
}

/** Composite `fg` over an opaque `bg`; contrast is only meaningful on what the eye sees. */
export function flatten(fg: string, bg: string): Rgba {
  const f = parseHex(fg) ?? { r: 0, g: 0, b: 0, a: 1 };
  const b = parseHex(bg) ?? { r: 0, g: 0, b: 0, a: 1 };
  return {
    r: f.r * f.a + b.r * (1 - f.a),
    g: f.g * f.a + b.g * (1 - f.a),
    b: f.b * f.a + b.b * (1 - f.a),
    a: 1,
  };
}

export function relativeLuminance({ r, g, b }: Rgba): number {
  const ch = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
}

/** WCAG contrast of `fg` drawn on `bg` (alpha composited onto `bg`). */
export function contrastRatio(fg: string, bg: string): number {
  const back = flatten(bg, '#000000');
  const front = flatten(fg, formatHex(back));
  const l1 = relativeLuminance(front);
  const l2 = relativeLuminance(back);
  const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
}

export function isLight(hex: string): boolean {
  return relativeLuminance(flatten(hex, '#000000')) > 0.4;
}
