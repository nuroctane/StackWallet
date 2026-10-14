import { useId, useState, type FormEvent } from 'react';
import { Condition, describeCondition, evaluate } from '@stackwallet/automations';
import { Button, Field, Input, Select } from '@stackwallet/ui';

import { relativeTime } from '../../../lib/format.js';
import { alertStore, useAlerts } from '../../../store/alerts.js';
import { useMarketSettings } from '../../../store/market.js';
import { usePrices } from '../../../store/prices.js';
import type { ElementBodyProps } from '../types.js';
import { fmtPct, fmtUsd, SourcesPanel, useCoinOptions } from './shared.js';

/**
 * Price alerts: checked every minute while StackWallet is open, shown as a
 * toast and, if allowed, a browser notification. They notify only.
 */
export function AlertsElement(_: ElementBodyProps) {
  const state = useAlerts();
  const coins = useCoinOptions();
  const settings = useMarketSettings();
  const quote = usePrices(state.alerts.map((a) => a.condition.coinId));
  const [adding, setAdding] = useState(false);
  const now = Date.now();
  const symbol = (id: string) => coins.find((c) => c.id === id)?.symbol ?? id;

  return (
    <div className="flex h-full min-h-0 flex-col gap-2 overflow-auto p-3 text-[12px]">
      <p className="text-faint">
        Checked every minute while StackWallet is open. An alert only notifies; it never proposes or
        signs. A missing, stale or disputed price never fires one.
      </p>
      {!settings.coingecko && !settings.defillama && (
        <p className="text-danger">All market sources are off, so no alert can fire.</p>
      )}
      <NotificationPermission />
      {state.alerts.length === 0 && !adding && <p className="text-faint">No alerts.</p>}
      <ul className="flex flex-col divide-y divide-edge">
        {state.alerts.map((a) => {
          const q = quote(a.condition.coinId);
          const verdict = evaluate(a.condition, q, now);
          const status = !a.enabled
            ? 'paused'
            : verdict === 'unknown'
              ? 'no usable price'
              : !a.armed
                ? `fired ${ago(a.lastFiredAtMs, now)} · re-arms after the line is uncrossed`
                : 'armed';
          return (
            <li key={a.id} className="flex items-start justify-between gap-2 py-2">
              <span className="flex min-w-0 flex-col">
                <span className="text-ink">{a.name}</span>
                <span className="text-muted">
                  {describeCondition(a.condition, symbol(a.condition.coinId))}
                  {q
                    ? ` · now ${a.condition.kind === 'price' ? fmtUsd(q.usd) : fmtPct(q.change24hPct)}`
                    : ''}
                </span>
                <span className="text-faint">{status}</span>
              </span>
              <span className="flex shrink-0 gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => alertStore.setEnabled(a.id, !a.enabled)}
                >
                  {a.enabled ? 'Pause' : 'Resume'}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => alertStore.remove(a.id)}>
                  Remove
                </Button>
              </span>
            </li>
          );
        })}
      </ul>
      {adding ? (
        <AddAlert onDone={() => setAdding(false)} />
      ) : (
        <Button size="sm" onClick={() => setAdding(true)} className="self-start">
          + alert
        </Button>
      )}
      {state.events.length > 0 && (
        <details>
          <summary className="cursor-pointer text-faint">Fired · {state.events.length}</summary>
          <ol className="mt-1 flex flex-col gap-1 text-muted tabular-nums">
            {[...state.events]
              .reverse()
              .slice(0, 50)
              .map((e) => {
                const a = state.alerts.find((x) => x.id === e.alertId);
                return (
                  <li key={e.id} className="flex justify-between gap-2">
                    <span className="truncate">{a?.name ?? 'removed alert'}</span>
                    <span>
                      {fmtUsd(e.usd)} · {new Date(e.atMs).toLocaleString()}
                    </span>
                  </li>
                );
              })}
          </ol>
        </details>
      )}
      <SourcesPanel />
    </div>
  );
}

function ago(atMs: number | null, now: number): string {
  if (atMs === null) return '';
  const rel = relativeTime(atMs, now);
  return rel === 'now' ? 'just now' : `${rel} ago`;
}

function NotificationPermission() {
  const supported = typeof Notification !== 'undefined';
  const [perm, setPerm] = useState(supported ? Notification.permission : 'denied');
  if (!supported) return null;
  if (perm === 'granted') return <p className="text-faint">Browser notifications are on.</p>;
  if (perm === 'denied')
    return (
      <p className="text-faint">
        Browser notifications are blocked for this site; alerts show inside StackWallet only.
      </p>
    );
  return (
    <Button
      size="sm"
      variant="ghost"
      className="self-start"
      onClick={() => void Notification.requestPermission().then(setPerm)}
    >
      Allow browser notifications
    </Button>
  );
}

function AddAlert({ onDone }: { onDone: () => void }) {
  const coins = useCoinOptions();
  const ids = { name: useId(), coin: useId(), kind: useId(), op: useId(), value: useId() };
  const [name, setName] = useState('');
  const [coinId, setCoinId] = useState(coins[0]?.id ?? '');
  const [kind, setKind] = useState<'price' | 'change24h'>('price');
  const [op, setOp] = useState<'above' | 'below'>('above');
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const n = Number(value);
    const parsed = Condition.safeParse(
      kind === 'price' ? { kind, coinId, op, usd: n } : { kind, coinId, op, percent: n },
    );
    if (!value.trim() || !parsed.success) {
      setError(parsed.success ? 'Enter a value' : (parsed.error.issues[0]?.message ?? 'invalid'));
      return;
    }
    const sym = coins.find((c) => c.id === coinId)?.symbol ?? coinId;
    const r = alertStore.add(
      (name.trim() || describeCondition(parsed.data, sym)).slice(0, 60),
      parsed.data,
    );
    if (!r.ok) {
      setError(r.error);
      return;
    }
    // Check now rather than at the next tick, so an alert whose line is already crossed
    // reports straight away.
    void alertStore.check();
    onDone();
  };

  if (coins.length === 0)
    return (
      <p className="text-faint">
        Watch a coin first (watchlist element) or hold a mainnet coin; alerts pick from those.
      </p>
    );
  return (
    <form onSubmit={submit} className="flex flex-col gap-2 rounded-sw-sm border border-edge p-3">
      <Field label="Coin" htmlFor={ids.coin}>
        <Select id={ids.coin} value={coinId} onChange={(e) => setCoinId(e.target.value)}>
          {coins.map((c) => (
            <option key={c.id} value={c.id}>
              {c.symbol} · {c.name}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="When" htmlFor={ids.kind}>
        <Select id={ids.kind} value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
          <option value="price">Price (USD)</option>
          <option value="change24h">24h change (%)</option>
        </Select>
      </Field>
      <Field label="Is" htmlFor={ids.op}>
        <Select id={ids.op} value={op} onChange={(e) => setOp(e.target.value as typeof op)}>
          <option value="above">above</option>
          <option value="below">below</option>
        </Select>
      </Field>
      <Field label={kind === 'price' ? 'USD' : 'Percent (e.g. -5)'} htmlFor={ids.value}>
        <Input
          id={ids.value}
          value={value}
          inputMode="decimal"
          onChange={(e) => setValue(e.target.value)}
        />
      </Field>
      <Field label="Name (optional)" htmlFor={ids.name}>
        <Input
          id={ids.name}
          value={name}
          maxLength={60}
          onChange={(e) => setName(e.target.value)}
        />
      </Field>
      {error && <p className="text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" size="sm" variant="ghost" onClick={onDone}>
          Cancel
        </Button>
        <Button type="submit" size="sm" variant="primary">
          Save
        </Button>
      </div>
    </form>
  );
}
