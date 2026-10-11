import { useSyncExternalStore } from 'react';
import type { ChainRegistry } from '@stackwallet/chains';
import type { Account, Wallet } from '@stackwallet/core-client';
import {
  defaultNameServices,
  displayName,
  NameRecord,
  resolveAccountNames,
  sortRecords,
  type NameService,
} from '@stackwallet/names';
import { z } from 'zod';

import type { StorageLike } from './persist.js';

export const NAMES_STORAGE_KEY = 'stackwallet.names.v1';
/** Names change rarely; a few hours keeps lookups off the hot path without going stale for long. */
export const NAMES_TTL_MS = 6 * 60 * 60 * 1000;
/** A failed service is retried sooner than a clean miss. */
export const NAMES_RETRY_MS = 10 * 60 * 1000;
const MAX_ENTRIES = 5000;
const CONCURRENCY = 3;

const Entry = z.object({
  records: NameRecord.array().max(16),
  checkedAtMs: z.number().int(),
  failed: z.array(z.string().max(16)).max(8).default([]),
});
type Entry = z.infer<typeof Entry>;

const NamesState = z.object({
  version: z.literal(1),
  /** `${family}:${address}`; names belong to an address, not to one chain's account row. */
  entries: z
    .record(z.string().max(200), Entry)
    .refine((r) => Object.keys(r).length <= MAX_ENTRIES, 'too many entries'),
});
type NamesState = z.infer<typeof NamesState>;

export function nameKey(a: Pick<Account, 'family' | 'address'>): string {
  // EVM addresses are case-insensitive; one entry per address across checksum spellings.
  return `${a.family}:${a.family === 'evm' ? a.address.toLowerCase() : a.address}`;
}

function load(storage: StorageLike | null): NamesState {
  const empty: NamesState = { version: 1, entries: {} };
  if (!storage) return empty;
  try {
    const raw = storage.getItem(NAMES_STORAGE_KEY);
    if (!raw) return empty;
    const r = NamesState.safeParse(JSON.parse(raw));
    // A cache: an unreadable blob is simply rebuilt from the network.
    return r.success ? r.data : empty;
  } catch {
    return empty;
  }
}

export class NamesStore {
  private state: NamesState;
  private readonly listeners = new Set<() => void>();
  private readonly inflight = new Set<string>();
  private queue: Account[] = [];
  private running = 0;
  private services: NameService[] | null = null;

  constructor(
    private readonly storage: StorageLike | null,
    private readonly now: () => number = Date.now,
  ) {
    this.state = load(storage);
  }

  readonly subscribe = (l: () => void): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getSnapshot = (): NamesState => this.state;

  configure(registry: ChainRegistry, services?: NameService[]): void {
    this.services = services ?? defaultNameServices({ registry, now: this.now });
  }

  entry(a: Pick<Account, 'family' | 'address'>): Entry | undefined {
    return this.state.entries[nameKey(a)];
  }

  private stale(a: Account, force: boolean): boolean {
    if (force) return true;
    const e = this.entry(a);
    if (!e) return true;
    const age = this.now() - e.checkedAtMs;
    return age > NAMES_TTL_MS || (e.failed.length > 0 && age > NAMES_RETRY_MS);
  }

  /** Queue lookups for accounts whose cached answer is missing or old. */
  ensure(accounts: readonly Account[], force = false): void {
    if (!this.services) return;
    const seen = new Set<string>();
    for (const a of accounts) {
      const k = nameKey(a);
      if (seen.has(k) || this.inflight.has(k) || !this.stale(a, force)) continue;
      seen.add(k);
      this.inflight.add(k);
      this.queue.push(a);
    }
    this.pump();
  }

  private pump(): void {
    while (this.running < CONCURRENCY && this.queue.length > 0) {
      const a = this.queue.shift()!;
      this.running += 1;
      void this.resolveOne(a).finally(() => {
        this.running -= 1;
        this.inflight.delete(nameKey(a));
        this.pump();
      });
    }
  }

  private async resolveOne(a: Account): Promise<void> {
    const services = this.services;
    if (!services) return;
    const out = await resolveAccountNames(services, {
      family: a.family,
      chainId: a.chainId,
      address: a.address,
    });
    this.write(nameKey(a), {
      records: out.records.slice(0, 16),
      checkedAtMs: this.now(),
      failed: out.failed.slice(0, 8),
    });
  }

  private write(key: string, entry: Entry): void {
    let entries = { ...this.state.entries, [key]: entry };
    const keys = Object.keys(entries);
    if (keys.length > MAX_ENTRIES) {
      const oldest = keys.sort((x, y) => entries[x]!.checkedAtMs - entries[y]!.checkedAtMs);
      entries = Object.fromEntries(
        oldest.slice(keys.length - MAX_ENTRIES).map((k) => [k, entries[k]!]),
      );
    }
    this.state = { version: 1, entries };
    if (this.storage) {
      try {
        this.storage.setItem(NAMES_STORAGE_KEY, JSON.stringify(this.state));
      } catch {
        // Cache only; a full disk costs a refetch next load.
      }
    }
    for (const l of this.listeners) l();
  }
}

/** Every verified name on any of `accounts`, best first. */
export function namesFor(state: NamesState, accounts: readonly Account[]): NameRecord[] {
  const out: NameRecord[] = [];
  const seen = new Set<string>();
  for (const a of accounts) {
    const k = nameKey(a);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(...(state.entries[k]?.records ?? []));
  }
  return sortRecords(out);
}

export interface WalletLabel {
  /** What the wallet is shown as. */
  text: string;
  /** The verified name behind `text`, when it is one. */
  record: NameRecord | null;
  /** The user's own tag, always kept and shown alongside a resolved name. */
  tag: string;
}

export function walletLabel(
  state: NamesState,
  wallet: Pick<Wallet, 'id' | 'name'>,
  accounts: readonly Account[],
): WalletLabel {
  const record = displayName(
    namesFor(
      state,
      accounts.filter((a) => a.walletId === wallet.id),
    ),
  );
  return { text: record ? record.name : wallet.name, record, tag: wallet.name };
}

function safeStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${NAMES_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

export const namesStore = new NamesStore(safeStorage());

export function useNames(): NamesState {
  return useSyncExternalStore(namesStore.subscribe, namesStore.getSnapshot, namesStore.getSnapshot);
}
