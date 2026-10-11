import { describe, expect, it } from 'vitest';

import {
  contrastRatio,
  formatHex,
  hsvToRgb,
  mix,
  normalizeHex,
  parseHex,
  rgbToHsv,
  withAlpha,
} from './theme/color.js';
import { NUR_PRESETS } from './theme/nurPresets.js';
import { BUILTIN_PRESETS, NIGHT_GLASS, THEME_TOKENS, tokensFromNur } from './theme/tokens.js';

describe('colour math', () => {
  it('parses every hex spelling and formats canonically', () => {
    expect(parseHex('#fff')).toEqual({ r: 255, g: 255, b: 255, a: 1 });
    expect(normalizeHex('ABC')).toBe('#aabbcc');
    expect(normalizeHex('#11223380')).toBe('#11223380');
    expect(normalizeHex('#112233ff')).toBe('#112233');
    expect(normalizeHex('red')).toBeNull();
    expect(normalizeHex('#12345')).toBeNull();
  });

  it('round-trips through HSV across the spectrum', () => {
    for (const hex of [
      '#ff0000',
      '#00ff00',
      '#0000ff',
      '#123456',
      '#fedcba',
      '#808080',
      '#000000',
    ]) {
      expect(formatHex(hsvToRgb(rgbToHsv(parseHex(hex)!)))).toBe(hex);
    }
  });

  it('mixes like NurCLI lerp and applies alpha', () => {
    expect(mix('#000000', '#ffffff', 0.5)).toBe('#808080');
    expect(withAlpha('#ff453a', 0.22)).toBe('#ff453a38');
  });

  it('computes WCAG contrast, compositing translucent ink', () => {
    expect(contrastRatio('#ffffff', '#000000')).toBeCloseTo(21, 0);
    expect(contrastRatio('#777777', '#777777')).toBeCloseTo(1, 5);
    expect(contrastRatio('#ffffff00', '#000000')).toBeCloseTo(1, 5);
  });
});

describe('presets', () => {
  it('ships night glass plus all 41 NurCLI themes with unique ids', () => {
    expect(NUR_PRESETS).toHaveLength(41);
    expect(BUILTIN_PRESETS).toHaveLength(42);
    expect(new Set(BUILTIN_PRESETS.map((p) => p.id)).size).toBe(42);
    expect(BUILTIN_PRESETS[0]!.tokens).toBe(NIGHT_GLASS);
  });

  it('assigns every token a canonical colour in every preset', () => {
    for (const p of BUILTIN_PRESETS) {
      for (const t of THEME_TOKENS)
        expect(normalizeHex(p.tokens[t]), `${p.id}.${t}`).toBe(p.tokens[t]);
    }
  });

  it('maps the Nur gold spine onto the accent', () => {
    const gold = NUR_PRESETS.find((p) => p.id === 'gold')!;
    const t = tokensFromNur(gold.palette);
    expect(t.warm).toBe('#e8b923');
    expect(t.paper).toBe('#0b0e12');
    expect(t.danger).toBe(gold.palette.error);
  });

  it('keeps body text legible on every built-in preset', () => {
    for (const p of BUILTIN_PRESETS) {
      expect(contrastRatio(p.tokens.ink, p.tokens.paper), p.id).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(p.tokens.ink, p.tokens.surface), p.id).toBeGreaterThanOrEqual(4.5);
    }
  });
});
