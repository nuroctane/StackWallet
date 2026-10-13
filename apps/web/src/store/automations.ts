import { useSyncExternalStore } from 'react';
import {
  Automation,
  AutomationState,
  due,
  emptyAutomations,
  plan,
  recordRun,
  type Run,
} from '@stackwallet/automations';
import type { ChainRegistry } from '@stackwallet/chains';

import { vault } from '../core/bridge.js';
import { balanceCache } from './balances.js';
import { directory } from './persist.js';
import type { StorageLike } from './persist.js';
import { proposeSend } from './txs.js';

/**
 * Automation definitions and run history (metadata, no secrets) in local
 * storage, and the scheduler that runs due ones while the app is open. A run
 * only ever proposes: the approval queue still needs a person to sign.
 */
export const AUTOMATIONS_KEY = 'stackwallet.automations.v1';
export const TICK_MS = 30_000;

export class AutomationStore {
  private state: AutomationState;
  private listeners = new Set<() => void>();
  private running = false;
  quarantinedKey: string | undefined;

  constructor(
    private readonly storage: StorageLike | null,
    private readonly now: () => number = Date.now,
    private readonly newId: () => string = () => crypto.randomUUID(),
  ) {
    this.state = emptyAutomations();
    let raw: string | null = null;
    try {
      raw = storage?.getItem(AUTOMATIONS_KEY) ?? null;
      if (raw) this.state = AutomationState.parse(JSON.parse(raw));
    } catch {
      if (raw) {
        this.quarantinedKey = `${AUTOMATIONS_KEY}.corrupt-${this.now()}`;
        try {
          storage?.setItem(this.quarantinedKey, raw);
        } catch {
          // Kept in memory only.
        }
      }
    }
  }

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  getSnapshot = () => this.state;

  private commit(next: AutomationState): void {
    this.state = AutomationState.parse(next);
    try {
      this.storage?.setItem(AUTOMATIONS_KEY, JSON.stringify(this.state));
    } catch {
      // The in-memory state still drives this session.
    }
    for (const l of this.listeners) l();
  }

  add(
    input: Omit<Automation, 'id' | 'createdAtMs' | 'lastRunAtMs'>,
  ): { ok: true; value: string } | { ok: false; error: string } {
    const parsed = Automation.safeParse({
      ...input,
      id: this.newId(),
      createdAtMs: this.now(),
      lastRunAtMs: null,
    });
    if (!parsed.success) return { ok: false, error: parsed.error.issues[0]?.message ?? 'invalid' };
    this.commit({ ...this.state, automations: [...this.state.automations, parsed.data] });
    return { ok: true, value: parsed.data.id };
  }

  setEnabled(id: string, enabled: boolean): void {
    this.commit({
      ...this.state,
      automations: this.state.automations.map((a) => (a.id === id ? { ...a, enabled } : a)),
    });
  }

  remove(id: string): void {
    this.commit({ ...this.state, automations: this.state.automations.filter((a) => a.id !== id) });
  }

  record(run: Run): void {
    this.commit(recordRun(this.state, run));
  }

  /** Propose every due automation once. Skips everything while the vault is locked. */
  async runDue(registry: ChainRegistry): Promise<number> {
    if (this.running || vault.getSnapshot().status.kind !== 'unlocked') return 0;
    this.running = true;
    let n = 0;
    try {
      for (const a of due(this.state, this.now())) {
        n += 1;
        const runId = this.newId();
        const base = { id: runId, automationId: a.id, atMs: this.now() };
        const account = directory.getSnapshot().accounts.find((x) => x.id === a.accountId);
        if (!account) {
          this.record({ ...base, outcome: 'failed', note: 'account no longer exists' });
          continue;
        }
        let balance: string | null = null;
        try {
          await balanceCache.ensure(registry, account, { force: true });
          const h = balanceCache
            .get(account.chainId, account.address)
            ?.holdings.find((x) => x.assetRef.toLowerCase() === a.asset.toLowerCase());
          balance = h && !h.error ? h.amount : null;
        } catch {
          balance = null;
        }
        const p = plan(a, balance);
        if ('skip' in p) {
          this.record({ ...base, outcome: 'skipped', note: p.skip });
          continue;
        }
        const r = await proposeSend(registry, {
          account,
          to: a.action.to,
          asset: a.asset,
          amount: p.amount,
          by: { kind: 'automation', automationId: a.id, runId },
        });
        this.record(
          r.ok
            ? {
                ...base,
                outcome: 'proposed',
                txId: r.value.id,
                note:
                  r.value.state === 'awaiting'
                    ? 'waiting for approval'
                    : `policy: ${r.value.state}`,
              }
            : { ...base, outcome: 'failed', note: r.error.slice(0, 400) },
        );
      }
    } finally {
      this.running = false;
    }
    return n;
  }
}

function safeStorage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export const automationStore = new AutomationStore(safeStorage());

export function useAutomations(): AutomationState {
  return useSyncExternalStore(
    automationStore.subscribe,
    automationStore.getSnapshot,
    automationStore.getSnapshot,
  );
}

/** Start the scheduler; returns the stop function. */
export function startAutomations(registry: ChainRegistry): () => void {
  const tick = () => void automationStore.runDue(registry);
  tick();
  const id = setInterval(tick, TICK_MS);
  return () => clearInterval(id);
}
