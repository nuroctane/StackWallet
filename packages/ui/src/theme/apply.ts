import { useSyncExternalStore } from 'react';

import { isLightTheme, THEME_TOKENS, type ThemeTokens } from './tokens.js';

let epoch = 0;
const listeners = new Set<() => void>();

/**
 * Writes a resolved theme onto `target` (the document root by default). Both
 * the Tailwind `--color-*` and the plain `--sw-*` names are set so utilities,
 * stylesheets and canvases all pick it up in the same frame.
 */
export function applyTheme(tokens: ThemeTokens, target?: HTMLElement): void {
  const el = target ?? (typeof document !== 'undefined' ? document.documentElement : null);
  if (!el) return;
  for (const key of THEME_TOKENS) {
    const value = tokens[key];
    el.style.setProperty(`--color-${key}`, value);
    el.style.setProperty(`--sw-${key}`, value);
  }
  const light = isLightTheme(tokens);
  el.style.setProperty('color-scheme', light ? 'light' : 'dark');
  el.dataset['swScheme'] = light ? 'light' : 'dark';
  epoch += 1;
  for (const l of listeners) l();
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

const getEpoch = () => epoch;

/**
 * Bumps every time a theme is applied. Canvas painters read colours from CSS at
 * draw time, so they include this in their redraw dependencies.
 */
export function useThemeEpoch(): number {
  return useSyncExternalStore(subscribe, getEpoch, getEpoch);
}

/** Read a token from computed style with a fallback for non-DOM environments. */
export function readToken(name: string, fallback: string, from?: Element): string {
  if (typeof window === 'undefined' || typeof getComputedStyle !== 'function') return fallback;
  const el = from ?? document.documentElement;
  const v = getComputedStyle(el).getPropertyValue(name).trim();
  return v || fallback;
}
