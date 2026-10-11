import { NIGHT_GLASS } from '@stackwallet/ui';
import { describe, expect, it } from 'vitest';

import {
  THEME_STORAGE_KEY,
  ThemeStore,
  defaultThemeState,
  loadTheme,
  resolveForLayout,
  resolveSpec,
  type ThemeScope,
} from './theme.js';

function memStorage(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init));
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    map: m,
  };
}

const G: ThemeScope = { kind: 'global' };
const L: ThemeScope = { kind: 'layout', id: 'home' };

function store() {
  let n = 0;
  return new ThemeStore(defaultThemeState(), null, 0, () => `id${++n}`);
}

describe('theme store', () => {
  it('defaults to night glass everywhere', () => {
    const s = store();
    expect(resolveForLayout(s.getSnapshot(), 'home')).toEqual(NIGHT_GLASS);
  });

  it('layouts follow the global theme until they get their own', () => {
    const s = store();
    s.setPreset(G, 'nur-gold');
    expect(resolveForLayout(s.getSnapshot(), 'home').warm).toBe('#e8b923');
    s.detachLayout('home');
    s.setPreset(L, 'nur-matrix');
    s.setPreset(G, 'night-glass');
    expect(resolveForLayout(s.getSnapshot(), 'home').warm).not.toBe(NIGHT_GLASS.warm);
    expect(resolveForLayout(s.getSnapshot(), 'other')).toEqual(NIGHT_GLASS);
    s.resetScope(L);
    expect(resolveForLayout(s.getSnapshot(), 'home')).toEqual(NIGHT_GLASS);
  });

  it('overrides single tokens and resets them', () => {
    const s = store();
    s.setToken(G, 'warm', '#12AB34');
    expect(resolveSpec(s.getSnapshot(), s.getSnapshot().global).warm).toBe('#12ab34');
    s.setToken(G, 'warm', 'not a colour');
    expect(s.getSnapshot().global.overrides.warm).toBe('#12ab34');
    s.resetToken(G, 'warm');
    expect(s.getSnapshot().global.overrides).toEqual({});
  });

  it('ignores unknown presets', () => {
    const s = store();
    s.setPreset(G, 'nope');
    expect(s.getSnapshot().global.preset).toBe('night-glass');
  });

  it('saves, exports and re-imports a custom theme', () => {
    const s = store();
    s.setToken(G, 'paper', '#101010');
    const id = s.saveCustom(G, 'mine');
    expect(id).toBe('custom-id1');
    expect(s.getSnapshot().global).toEqual({ preset: 'custom-id1', overrides: {} });
    const json = s.exportScope(G, 'mine');
    const r = s.importTheme(L, json);
    expect(r).toEqual({ ok: true, name: 'mine' });
    expect(resolveForLayout(s.getSnapshot(), 'home').paper).toBe('#101010');
    expect(s.importTheme(L, '{"x":1}').ok).toBe(false);
    s.deleteCustom('custom-id1');
    expect(resolveSpec(s.getSnapshot(), s.getSnapshot().global)).toEqual(NIGHT_GLASS);
  });

  it('prunes themes of deleted layouts', () => {
    const s = store();
    s.detachLayout('a');
    s.detachLayout('b');
    s.pruneLayouts(['a']);
    expect(Object.keys(s.getSnapshot().layouts)).toEqual(['a']);
  });
});

describe('theme persistence', () => {
  it('round-trips and quarantines a corrupt blob', () => {
    const st = memStorage();
    const s = new ThemeStore(defaultThemeState(), st, 0);
    s.setPreset(G, 'nur-nord');
    s.flush();
    expect(loadTheme(st).state.global.preset).toBe('nur-nord');

    const bad = memStorage({
      [THEME_STORAGE_KEY]: '{"version":1,"global":{"preset":"x","overrides":{"warm":"red"}}}',
    });
    const r = loadTheme(bad, () => 7);
    expect(r.quarantinedKey).toBe(`${THEME_STORAGE_KEY}.corrupt-7`);
    expect(r.state).toEqual(defaultThemeState());
    expect(bad.map.has(THEME_STORAGE_KEY)).toBe(false);
  });
});
