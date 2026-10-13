import { useSyncExternalStore } from 'react';

const failures = new Set<string>();
const recoveryCopies = new Map<string, { filename: string; text: string }>();
const listeners = new Set<() => void>();
let snapshot = '';

export function reportStorageSave(
  name: string,
  ok: boolean,
  recovery?: { filename: string; text: string },
): void {
  if (ok) {
    failures.delete(name);
    recoveryCopies.delete(name);
  } else {
    failures.add(name);
    if (recovery) recoveryCopies.set(name, recovery);
  }
  const next = [...failures].sort().join(', ');
  if (next === snapshot) return;
  snapshot = next;
  for (const listener of listeners) listener();
}

export function downloadStorageRecovery(): void {
  if (recoveryCopies.size === 0) return;
  const text = JSON.stringify(
    {
      stackwalletRecoveries: 1,
      copies: [...recoveryCopies.values()].map((copy) => ({
        filename: copy.filename,
        data: JSON.parse(copy.text) as unknown,
      })),
    },
    null,
    2,
  );
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'stackwallet-recovery.json';
  a.hidden = true;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
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
