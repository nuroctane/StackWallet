import { useCallback, useEffect, useMemo, useSyncExternalStore } from 'react';
import type { Account } from '@stackwallet/core-client';
import type { ChainRegistry, Holding } from '@stackwallet/chains';

import { useRegistry } from './RegistryContext.js';
import { useTokens } from './tokens.js';

export const BALANCE_STALE_MS = 60_000;

export interface BalanceEntry {
  holdings: Holding[];
  /** 0 until the first fetch settles. */
  fetchedAtMs: number;
  error?: string;
  loading: boolean;
}

export type BalanceSnapshot = ReadonlyMap<string, BalanceEntry>;

export function balanceKey(chainId: string, address: string): string {
  return `${chainId}|${address}`;
}

export interface BalanceSource {
  adapterFor: ChainRegistry['adapterFor'];
}

export class BalanceCache {
  private snapshot: Map<string, BalanceEntry> = new Map();
  private readonly inflight = new Map<string, Promise<void>>();
  private readonly listeners = new Set<() => void>();
  private readonly now: () => number;
  private readonly staleMs: number;
  private generation = 0;

  constructor(options: { now?: () => number; staleMs?: number } = {}) {
    this.now = options.now ?? (() => Date.now());
    this.staleMs = options.staleMs ?? BALANCE_STALE_MS;
  }

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  readonly getSnapshot = (): BalanceSnapshot => this.snapshot;

  get(chainId: string, address: string): BalanceEntry | undefined {
    return this.snapshot.get(balanceKey(chainId, address));
  }

  invalidate(): void {
    this.generation++;
    this.snapshot = new Map();
    for (const l of this.listeners) l();
  }

  isStale(key: string): boolean {
    const entry = this.snapshot.get(key);
    if (!entry) return true;
    return this.now() - entry.fetchedAtMs >= this.staleMs;
  }

  private set(key: string, entry: BalanceEntry): void {
    const next = new Map(this.snapshot);
    next.set(key, entry);
    this.snapshot = next;
    for (const l of this.listeners) l();
  }

  /**
   * Fetch unless fresh. Concurrent callers for the same key share one promise,
   * and errors land in the entry rather than rejecting, so a flaky RPC can never
   * unwind a React tree.
   */
  ensure(
    source: BalanceSource,
    account: Pick<Account, 'chainId' | 'address'>,
    options: { force?: boolean } = {},
  ): Promise<void> {
    const key = balanceKey(account.chainId, account.address);
    const pending = this.inflight.get(key);
    if (pending) {
      // A forced refresh during a fetch must still produce a fresh read, or
      // "Refresh" silently resolves with the result of the older request.
      if (!options.force) return pending;
      const chained = pending.then(() => this.ensure(source, account, { force: true }));
      this.inflight.set(key, chained);
      return chained;
    }
    if (!options.force && !this.isStale(key)) return Promise.resolve();

    const prev = this.snapshot.get(key);
    const generation = this.generation;
    this.set(key, {
      holdings: prev?.holdings ?? [],
      fetchedAtMs: prev?.fetchedAtMs ?? 0,
      loading: true,
    });

    // Deferred one microtask so a synchronous throw from `adapterFor` cannot
    // reach `finally` before the in-flight entry is registered below.
    const run = Promise.resolve().then(async () => {
      try {
        const adapter = source.adapterFor(account.chainId);
        const holdings = await adapter.getBalances(account.address, account.chainId);
        if (generation === this.generation)
          this.set(key, { holdings, fetchedAtMs: this.now(), loading: false });
      } catch (err) {
        if (generation === this.generation)
          this.set(key, {
            holdings: prev?.holdings ?? [],
            fetchedAtMs: this.now(),
            error: errorMessage(err),
            loading: false,
          });
      } finally {
        this.inflight.delete(key);
      }
      if (generation !== this.generation) await this.ensure(source, account);
    });
    this.inflight.set(key, run);
    return run;
  }

  refresh(source: BalanceSource, accounts: readonly Pick<Account, 'chainId' | 'address'>[]) {
    return Promise.all(accounts.map((a) => this.ensure(source, a, { force: true }))).then(
      () => undefined,
    );
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message || err.name;
  return String(err);
}

export const balanceCache = new BalanceCache();

export interface BalancesView {
  byAccount: ReadonlyMap<string, BalanceEntry | undefined>;
  loading: boolean;
  refresh: () => Promise<void>;
}

export function useBalances(accounts: readonly Account[]): BalancesView {
  const registry = useRegistry();
  const tokens = useTokens();
  const snapshot = useSyncExternalStore(
    balanceCache.subscribe,
    balanceCache.getSnapshot,
    balanceCache.getSnapshot,
  );
  // Includes the account id because `byAccount` is indexed by it.
  const keys = accounts.map((a) => `${a.id}|${balanceKey(a.chainId, a.address)}`).join('\n');

  useEffect(() => {
    const tick = () => {
      for (const a of accounts) void balanceCache.ensure(registry, a);
    };
    tick();
    const id = setInterval(tick, BALANCE_STALE_MS);
    return () => clearInterval(id);
    // `keys` stands in for `accounts`, whose array identity changes on every render.
  }, [keys, registry, tokens]);

  const refresh = useCallback(() => balanceCache.refresh(registry, accounts), [keys, registry]);

  const byAccount = useMemo(() => {
    const map = new Map<string, BalanceEntry | undefined>();
    for (const a of accounts) map.set(a.id, snapshot.get(balanceKey(a.chainId, a.address)));
    return map;
  }, [keys, snapshot]);

  const loading = accounts.some(
    (a) => snapshot.get(balanceKey(a.chainId, a.address))?.loading === true,
  );

  return { byAccount, loading, refresh };
}
