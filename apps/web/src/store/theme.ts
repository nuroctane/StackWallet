import { useSyncExternalStore } from 'react';
import {
  BUILTIN_PRESETS,
  DEFAULT_PRESET_ID,
  NIGHT_GLASS,
  THEME_TOKENS,
  normalizeHex,
  type ThemePreset,
  type ThemeToken,
  type ThemeTokens,
} from '@stackwallet/ui';
import { z } from 'zod';

import type { StorageLike } from './persist.js';

export const THEME_STORAGE_KEY = 'stackwallet.theme.v1';
export const THEME_SAVE_DEBOUNCE_MS = 200;
export const MAX_CUSTOM_THEMES = 64;
export const MAX_RECENT_COLORS = 12;
const MAX_LAYOUT_THEMES = 64;

const ThemeTokenKey = z.enum(THEME_TOKENS);

/** Stored colours are always canonical hex; anything else is refused at parse time. */
export const HexColor = z
  .string()
  .max(9)
  .refine((s) => normalizeHex(s) === s, 'expected canonical #rrggbb or #rrggbbaa');

const Overrides = z.partialRecord(ThemeTokenKey, HexColor);

export const ThemeSpec = z.object({
  preset: z.string().min(1).max(80),
  overrides: Overrides.default({}),
});
export type ThemeSpec = z.infer<typeof ThemeSpec>;

const FullTokens = z.object(
  Object.fromEntries(THEME_TOKENS.map((t) => [t, HexColor])) as Record<ThemeToken, typeof HexColor>,
);

export const CustomTheme = z.object({
  id: z.string().regex(/^custom-[a-z0-9-]{1,64}$/),
  name: z.string().trim().min(1).max(40),
  tokens: FullTokens,
});
export type CustomTheme = z.infer<typeof CustomTheme>;

export const ThemeState = z.object({
  version: z.literal(1),
  global: ThemeSpec,
  /** Layout id -> its own theme. A layout without an entry follows the global theme. */
  layouts: z
    .record(z.string().min(1).max(80), ThemeSpec)
    .refine((r) => Object.keys(r).length <= MAX_LAYOUT_THEMES, 'too many layout themes'),
  custom: CustomTheme.array().max(MAX_CUSTOM_THEMES),
  recent: HexColor.array().max(MAX_RECENT_COLORS),
});
export type ThemeState = z.infer<typeof ThemeState>;

/** Portable theme for copy/paste between instances. Partial token sets fill from night glass. */
export const ThemeExport = z.object({
  stackwalletTheme: z.literal(1),
  name: z.string().trim().min(1).max(40),
  tokens: Overrides,
});
export type ThemeExport = z.infer<typeof ThemeExport>;

export type ThemeScope = { kind: 'global' } | { kind: 'layout'; id: string };

export function defaultThemeState(): ThemeState {
  return {
    version: 1,
    global: { preset: DEFAULT_PRESET_ID, overrides: {} },
    layouts: {},
    custom: [],
    recent: [],
  };
}

export function presetsFor(state: ThemeState): ThemePreset[] {
  return [
    ...BUILTIN_PRESETS,
    ...state.custom.map((c) => ({
      id: c.id,
      name: c.name,
      description: 'your theme',
      family: 'custom' as const,
      tokens: c.tokens,
    })),
  ];
}

export function findPreset(state: ThemeState, id: string): ThemePreset | undefined {
  return presetsFor(state).find((p) => p.id === id);
}

/** A spec naming a preset that no longer exists (deleted custom theme) falls back to night glass. */
export function resolveSpec(state: ThemeState, spec: ThemeSpec): ThemeTokens {
  const base = findPreset(state, spec.preset)?.tokens ?? NIGHT_GLASS;
  return { ...base, ...spec.overrides };
}

export function specFor(state: ThemeState, scope: ThemeScope): ThemeSpec {
  if (scope.kind === 'layout') return state.layouts[scope.id] ?? state.global;
  return state.global;
}

export function resolveForLayout(state: ThemeState, layoutId: string | null): ThemeTokens {
  return resolveSpec(
    state,
    layoutId ? specFor(state, { kind: 'layout', id: layoutId }) : state.global,
  );
}

export function loadTheme(
  storage: StorageLike | null,
  now = () => Date.now(),
): { state: ThemeState; quarantinedKey?: string } {
  if (!storage) return { state: defaultThemeState() };
  let raw: string | null = null;
  try {
    raw = storage.getItem(THEME_STORAGE_KEY);
  } catch {
    return { state: defaultThemeState() };
  }
  if (raw === null || raw === '') return { state: defaultThemeState() };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  const result = parsed === undefined ? undefined : ThemeState.safeParse(parsed);
  if (result?.success) return { state: result.data };
  const quarantinedKey = `${THEME_STORAGE_KEY}.corrupt-${now()}`;
  try {
    storage.setItem(quarantinedKey, raw);
    storage.removeItem(THEME_STORAGE_KEY);
  } catch {
    // Storage blocked: the default theme still renders.
  }
  return { state: defaultThemeState(), quarantinedKey };
}

export function saveTheme(storage: StorageLike, state: ThemeState): boolean {
  try {
    storage.setItem(THEME_STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

export class ThemeStore {
  private state: ThemeState;
  private readonly listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    initial: ThemeState,
    private readonly storage: StorageLike | null,
    private readonly debounceMs = THEME_SAVE_DEBOUNCE_MS,
    private readonly newId: () => string = () =>
      globalThis.crypto?.randomUUID?.().slice(0, 18) ?? Math.random().toString(36).slice(2, 14),
  ) {
    this.state = initial;
  }

  readonly subscribe = (l: () => void): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getSnapshot = (): ThemeState => this.state;

  flush(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.storage) saveTheme(this.storage, this.state);
  }

  private commit(next: ThemeState): void {
    this.state = next;
    for (const l of this.listeners) l();
    if (!this.storage) return;
    // Colour drags commit many times per second; disk only needs the last one.
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      if (this.storage) saveTheme(this.storage, this.state);
    }, this.debounceMs);
  }

  private writeSpec(scope: ThemeScope, spec: ThemeSpec): void {
    if (scope.kind === 'global') {
      this.commit({ ...this.state, global: spec });
      return;
    }
    this.commit({ ...this.state, layouts: { ...this.state.layouts, [scope.id]: spec } });
  }

  /** True when the layout carries its own theme rather than following the global one. */
  hasOwn(scope: ThemeScope): boolean {
    return scope.kind === 'global' || scope.id in this.state.layouts;
  }

  setPreset(scope: ThemeScope, presetId: string): void {
    if (!findPreset(this.state, presetId)) return;
    this.writeSpec(scope, { preset: presetId, overrides: {} });
  }

  setToken(scope: ThemeScope, token: ThemeToken, value: string): void {
    const hex = normalizeHex(value);
    if (!hex) return;
    const spec = specFor(this.state, scope);
    this.writeSpec(scope, { ...spec, overrides: { ...spec.overrides, [token]: hex } });
  }

  resetToken(scope: ThemeScope, token: ThemeToken): void {
    const spec = specFor(this.state, scope);
    if (!(token in spec.overrides)) return;
    const overrides = { ...spec.overrides };
    delete overrides[token];
    this.writeSpec(scope, { ...spec, overrides });
  }

  /** Layout scope: go back to following the global theme. Global scope: back to night glass. */
  resetScope(scope: ThemeScope): void {
    if (scope.kind === 'global') {
      this.writeSpec(scope, { preset: DEFAULT_PRESET_ID, overrides: {} });
      return;
    }
    if (!(scope.id in this.state.layouts)) return;
    const layouts = { ...this.state.layouts };
    delete layouts[scope.id];
    this.commit({ ...this.state, layouts });
  }

  /** Give a layout its own copy of whatever it currently shows, ready for edits. */
  detachLayout(layoutId: string): void {
    if (layoutId in this.state.layouts) return;
    this.writeSpec({ kind: 'layout', id: layoutId }, structuredClone(this.state.global));
  }

  /** Drop themes for layouts that were deleted. */
  pruneLayouts(liveIds: readonly string[]): void {
    const live = new Set(liveIds);
    const stale = Object.keys(this.state.layouts).filter((id) => !live.has(id));
    if (stale.length === 0) return;
    const layouts = { ...this.state.layouts };
    for (const id of stale) delete layouts[id];
    this.commit({ ...this.state, layouts });
  }

  /** Save the scope's resolved colours as a named theme and point the scope at it. */
  saveCustom(scope: ThemeScope, name: string): string | null {
    const trimmed = name.trim().slice(0, 40);
    if (!trimmed || this.state.custom.length >= MAX_CUSTOM_THEMES) return null;
    const id = `custom-${this.newId()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '')}`;
    const tokens = resolveSpec(this.state, specFor(this.state, scope));
    const next: ThemeState = {
      ...this.state,
      custom: [...this.state.custom, { id, name: trimmed, tokens }],
    };
    this.state = next;
    this.writeSpec(scope, { preset: id, overrides: {} });
    return id;
  }

  deleteCustom(id: string): void {
    if (!this.state.custom.some((c) => c.id === id)) return;
    this.commit({ ...this.state, custom: this.state.custom.filter((c) => c.id !== id) });
  }

  exportScope(scope: ThemeScope, name: string): string {
    const payload: ThemeExport = {
      stackwalletTheme: 1,
      name: name.trim().slice(0, 40) || 'theme',
      tokens: resolveSpec(this.state, specFor(this.state, scope)),
    };
    return JSON.stringify(payload);
  }

  /** Parse a pasted theme, store it as a custom theme and apply it to `scope`. */
  importTheme(
    scope: ThemeScope,
    text: string,
  ): { ok: true; name: string } | { ok: false; error: string } {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return { ok: false, error: 'not JSON' };
    }
    const r = ThemeExport.safeParse(parsed);
    if (!r.success) return { ok: false, error: 'not a StackWallet theme' };
    if (this.state.custom.length >= MAX_CUSTOM_THEMES) {
      return { ok: false, error: `at most ${MAX_CUSTOM_THEMES} saved themes` };
    }
    const id = `custom-${this.newId()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '')}`;
    const tokens: ThemeTokens = { ...NIGHT_GLASS, ...r.data.tokens };
    this.state = {
      ...this.state,
      custom: [...this.state.custom, { id, name: r.data.name, tokens }],
    };
    this.writeSpec(scope, { preset: id, overrides: {} });
    return { ok: true, name: r.data.name };
  }

  pushRecent(value: string): void {
    const hex = normalizeHex(value);
    if (!hex) return;
    const recent = [hex, ...this.state.recent.filter((c) => c !== hex)].slice(0, MAX_RECENT_COLORS);
    this.commit({ ...this.state, recent });
  }
}

function safeStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${THEME_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

const loaded = loadTheme(safeStorage());
export const themeStore = new ThemeStore(loaded.state, safeStorage());
export const themeQuarantinedKey: string | undefined = loaded.quarantinedKey;

if (typeof window !== 'undefined') {
  window.addEventListener('pagehide', () => themeStore.flush());
}

export function useThemeState(): ThemeState {
  return useSyncExternalStore(themeStore.subscribe, themeStore.getSnapshot, themeStore.getSnapshot);
}
