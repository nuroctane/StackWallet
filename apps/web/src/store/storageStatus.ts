import { useSyncExternalStore } from 'react';

const failures = new Set<string>();
const listeners = new Set<() => void>();
let snapshot = '';

export function reportStorageSave(name: string, ok: boolean): void {
  if (ok) failures.delete(name);
  else failures.add(name);
  const next = [...failures].sort().join(', ');
  if (next === snapshot) return;
  snapshot = next;
  for (const listener of listeners) listener();
}

export function useStorageFailures(): string {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    () => snapshot,
    () => '',
  );
}
