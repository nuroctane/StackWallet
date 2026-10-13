import type { StorageLike } from './persist.js';
import { MetadataConflict } from './metadataMerge.js';
import { reportStorageSave } from './storageStatus.js';
import { withStorageWriter } from './storageWriter.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export function createMetadataPersistence<T>(options: {
  storage: StorageLike | null;
  key: string;
  name: string;
  debounceMs: number;
  snapshot: () => T;
  subscribe: (callback: () => void) => () => void;
  adopt: (state: T) => void;
  parse: (raw: string) => T;
  merge: (base: T, local: T, remote: T, bootstrap: boolean) => T;
}) {
  const { storage, key, name } = options;
  let base = options.snapshot();
  let committed: string | null = null;
  try {
    committed = storage?.getItem(key) ?? null;
  } catch {
    /* Retain the local copy if reads are blocked. */
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  let dirty = false,
    disposed = false,
    adopting = false,
    failures = 0;
  let recoveryKey: string | undefined;
  const recoveries = new Set<string>();
  const hash = (text: string) => bytesToHex(sha256(new TextEncoder().encode(text)));
  try {
    if (storage?.key && storage.length !== undefined)
      for (let i = 0; i < storage.length; i++) {
        const candidate = storage.key(i);
        if (!candidate?.startsWith(`${key}.recovery.`) || candidate.endsWith('.applied')) continue;
        const raw = storage.getItem(candidate);
        if (raw && storage.getItem(`${candidate}.applied`) !== hash(raw)) recoveries.add(candidate);
      }
  } catch {
    /* Canonical metadata still works when recovery enumeration is blocked. */
  }
  const archive = (reason: string) => {
    let remote: unknown;
    try {
      const raw = storage?.getItem(key);
      remote = raw ? (JSON.parse(raw) as unknown) : null;
    } catch {
      remote = null;
    }
    let text = JSON.stringify({
      stackwalletRecovery: 1,
      source: name,
      reason,
      base,
      local: options.snapshot(),
      remote,
      bootstrap: committed === null,
    });
    try {
      if (dirty || recoveries.size === 0) {
        recoveryKey ??= `${key}.recovery.${crypto.randomUUID()}`;
        storage?.setItem(recoveryKey, text);
      }
      if (recoveries.size > 0) {
        text = JSON.stringify({
          stackwalletRecoveries: 1,
          source: name,
          reason,
          copies: [...recoveries].map((id) => ({ key: id, text: storage?.getItem(id) })),
          ...(dirty ? { current: JSON.parse(text) as unknown } : {}),
        });
      }
    } catch {
      /* The download remains available when browser storage is full. */
    }
    reportStorageSave(name, false, { filename: `stackwallet-${name}-recovery.json`, text });
  };
  const flush = async () => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    try {
      if (!storage) {
        if (dirty) throw new Error('Local storage is unavailable');
        return;
      }
      await withStorageWriter(storage, key, () => {
        const raw = storage.getItem(key);
        if (raw === committed && !dirty && recoveries.size === 0) return;
        if (raw === null && committed !== null)
          throw new MetadataConflict('Saved metadata was removed in another tab');
        const local = options.snapshot();
        let next =
          raw !== committed && raw !== null
            ? options.merge(base, local, options.parse(raw), committed === null)
            : local;
        const applied: Array<{ key: string; hash: string }> = [];
        for (const recovery of recoveries) {
          const text = storage.getItem(recovery);
          if (!text) continue;
          const digest = hash(text);
          if (storage.getItem(`${recovery}.applied`) === digest) continue;
          const saved = JSON.parse(text) as Record<string, unknown>;
          if (saved.stackwalletRecovery !== 1 || saved.source !== name)
            throw new MetadataConflict('Unrecognized metadata recovery');
          next = options.merge(
            options.parse(JSON.stringify(saved.base)),
            options.parse(JSON.stringify(saved.local)),
            next,
            saved.bootstrap === true,
          );
          applied.push({ key: recovery, hash: digest });
        }
        const encoded = JSON.stringify(next);
        const write = dirty || applied.length > 0;
        if (write) storage.setItem(key, encoded);
        committed = write ? encoded : raw;
        base = next;
        dirty = false;
        failures = 0;
        adopting = true;
        try {
          options.adopt(next);
        } finally {
          adopting = false;
        }
        for (const copy of applied) {
          try {
            storage.setItem(`${copy.key}.applied`, copy.hash);
          } catch {
            /* Reapplying an unchanged recovery is idempotent. */
          }
        }
        recoveries.clear();
        if (recoveryKey) {
          try {
            storage.removeItem(recoveryKey);
            recoveryKey = undefined;
          } catch {
            /* Recovery copies may safely outlive a successful save. */
          }
        }
        reportStorageSave(name, true);
      });
    } catch (err) {
      archive(err instanceof Error ? err.message : String(err));
      if (dirty && !(err instanceof MetadataConflict) && !disposed && ++failures < 3)
        timer = setTimeout(() => void flush(), 5_000);
    }
  };
  const unsubscribe = options.subscribe(() => {
    if (adopting) return;
    dirty = true;
    failures = 0;
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(() => void flush(), options.debounceMs);
  });
  const sync = () => {
    void flush();
  };
  const pagehide = () => {
    if (dirty) archive('The page closed before its coordinated save finished');
    void flush();
  };
  const storageEvent = (event: StorageEvent) => {
    if ((event.key === key || event.key === null) && event.storageArea === storage) sync();
  };
  if (typeof window !== 'undefined') {
    window.addEventListener('focus', sync);
    window.addEventListener('pagehide', pagehide);
    window.addEventListener('storage', storageEvent);
  }
  if (recoveries.size > 0) timer = setTimeout(sync, 0);
  return {
    flush,
    async dispose() {
      disposed = true;
      unsubscribe();
      if (typeof window !== 'undefined') {
        window.removeEventListener('focus', sync);
        window.removeEventListener('pagehide', pagehide);
        window.removeEventListener('storage', storageEvent);
      }
      await flush();
    },
  };
}
