import { useSyncExternalStore } from 'react';
import {
  Alert,
  AlertState,
  alertCoins,
  checkAlerts,
  emptyAlerts,
  type AlertEvent,
  type Condition,
} from '@stackwallet/automations';

import type { StorageLike } from './persist.js';
import { priceStore } from './prices.js';

/**
 * Price alerts in local storage, checked while the app is open. Firing only
 * notifies: an alert never proposes or signs anything.
 */
export const ALERTS_KEY = 'stackwallet.alerts.v1';
export const ALERT_TICK_MS = 60_000;

export class AlertStore {
  private state: AlertState = emptyAlerts();
  private listeners = new Set<() => void>();
  private firedListeners = new Set<(e: AlertEvent, a: Alert) => void>();

  constructor(
    private readonly storage: StorageLike | null,
    private readonly now: () => number = Date.now,
    private readonly newId: () => string = () => crypto.randomUUID(),
  ) {
    try {
      const raw = storage?.getItem(ALERTS_KEY);
      if (raw) {
        const parsed = AlertState.safeParse(JSON.parse(raw));
        if (parsed.success) this.state = parsed.data;
      }
    } catch {
      // Unreadable storage: start empty for this session.
    }
  }

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  getSnapshot = () => this.state;

  onFired(l: (e: AlertEvent, a: Alert) => void): () => void {
    this.firedListeners.add(l);
    return () => {
      this.firedListeners.delete(l);
    };
  }

  private commit(next: AlertState): void {
    this.state = AlertState.parse(next);
    try {
      this.storage?.setItem(ALERTS_KEY, JSON.stringify(this.state));
    } catch {
      // Kept in memory only.
    }
    for (const l of this.listeners) l();
  }

  add(name: string, condition: Condition): { ok: true } | { ok: false; error: string } {
    const parsed = Alert.safeParse({
      id: this.newId(),
      name: name.trim() || 'alert',
      enabled: true,
      condition,
      // Armed from the start: an alert created while the line is already crossed fires
      // on the first check, which is what the person setting it expects to learn.
      armed: true,
      createdAtMs: this.now(),
      lastFiredAtMs: null,
    });
    if (!parsed.success) return { ok: false, error: parsed.error.issues[0]?.message ?? 'invalid' };
    if (this.state.alerts.length >= 100) return { ok: false, error: 'too many alerts' };
    this.commit({ ...this.state, alerts: [...this.state.alerts, parsed.data] });
    return { ok: true };
  }

  setEnabled(id: string, enabled: boolean): void {
    this.commit({
      ...this.state,
      alerts: this.state.alerts.map((a) => (a.id === id ? { ...a, enabled, armed: true } : a)),
    });
  }

  remove(id: string): void {
    this.commit({
      ...this.state,
      alerts: this.state.alerts.filter((a) => a.id !== id),
      events: this.state.events.filter((e) => e.alertId !== id),
    });
  }

  async check(): Promise<AlertEvent[]> {
    const coins = alertCoins(this.state);
    if (coins.length === 0) return [];
    await priceStore.want(coins);
    const r = checkAlerts(this.state, (id) => priceStore.get(id), this.now(), this.newId);
    if (r.state !== this.state) this.commit(r.state);
    for (const e of r.fired) {
      const a = this.state.alerts.find((x) => x.id === e.alertId);
      if (a) for (const l of this.firedListeners) l(e, a);
    }
    return r.fired;
  }
}

function safeStorage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export const alertStore = new AlertStore(safeStorage());

export function useAlerts(): AlertState {
  return useSyncExternalStore(alertStore.subscribe, alertStore.getSnapshot, alertStore.getSnapshot);
}

/** Browser notifications are optional and local; nothing is pushed from a server (D3). */
export function desktopNotify(title: string, body: string): void {
  try {
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted')
      new Notification(title, { body, silent: false });
  } catch {
    // Some embedded webviews expose Notification but refuse construction.
  }
}

export function startAlerts(): () => void {
  const tick = () => void alertStore.check();
  tick();
  const id = setInterval(tick, ALERT_TICK_MS);
  return () => clearInterval(id);
}
