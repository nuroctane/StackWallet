import type { StorageLike } from './persist.js';

const writers = new WeakMap<StorageLike, Map<string, Promise<unknown>>>();

export async function withStorageWriter<T>(
  storage: StorageLike,
  key: string,
  op: () => T | Promise<T>,
): Promise<T> {
  if (typeof navigator !== 'undefined' && navigator.locks)
    return navigator.locks.request(key, async () => op());
  if (typeof window !== 'undefined' && storage === window.localStorage)
    throw new Error(
      'This browser cannot coordinate local writes. Use a browser with Web Locks support.',
    );
  let queue = writers.get(storage);
  if (!queue) {
    queue = new Map();
    writers.set(storage, queue);
  }
  const pending = (queue.get(key) ?? Promise.resolve()).catch(() => undefined).then(op);
  queue.set(key, pending);
  return pending;
}
