import { useCallback, useSyncExternalStore } from 'react';

function subscribe(query: string, onChange: () => void): () => void {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return () => undefined;
  }
  const mql = window.matchMedia(query);
  mql.addEventListener('change', onChange);
  return () => mql.removeEventListener('change', onChange);
}

function read(query: string): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
  return window.matchMedia(query).matches;
}

/** Reactive `matchMedia`; `false` wherever the API is missing (tests, SSR). */
export function useMediaQuery(query: string): boolean {
  const sub = useCallback((onChange: () => void) => subscribe(query, onChange), [query]);
  const get = useCallback(() => read(query), [query]);
  return useSyncExternalStore(sub, get, () => false);
}
