import { useId, useState, type FormEvent } from 'react';
import { nextRunAt, type Action, type Trigger } from '@stackwallet/automations';
import { shortAddress } from '@stackwallet/chains';
import { Button, Field, Input, Select } from '@stackwallet/ui';

import { findChain } from '../../lib/chains.js';
import { parseUnits, relativeTime } from '../../lib/format.js';
import { canSendFrom } from '../../lib/sendable.js';
import { automationStore, useAutomations } from '../../store/automations.js';
import { useDirectory } from '../../store/persist.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { ElementBodyProps } from './types.js';

/**
 * Scheduled and balance-triggered transfers. Every run is a proposal in the
 * approval queue; nothing is signed without the person at a device.
 */
export function AutomationsElement(_: ElementBodyProps) {
  const state = useAutomations();
  const now = Date.now();
  const [adding, setAdding] = useState(false);
  return (
    <div className="flex h-full min-h-0 flex-col gap-3 overflow-auto p-3 text-[12px]">
      <p className="text-faint">
        Runs while StackWallet is open and the vault unlocked. Each run proposes a transfer into the
        approval queue; you approve and sign it there.
      </p>
      {state.automations.length === 0 && !adding && <p className="text-faint">No automations.</p>}
      <ul className="flex flex-col divide-y divide-edge">
        {state.automations.map((a) => {
          const next = nextRunAt(a);
          const last = [...state.runs].reverse().find((r) => r.automationId === a.id);
          return (
            <li key={a.id} className="flex items-start justify-between gap-2 py-2">
              <span className="flex min-w-0 flex-col">
                <span className="text-ink">{a.name}</span>
                <span className="text-faint">
                  {describe(a.trigger, a.action)}
                  {next !== null
                    ? ` · next ${next <= now ? 'now' : `in ${relativeTime(now, next)}`}`
                    : ' · paused'}
                </span>
                {last && (
                  <span className={last.outcome === 'failed' ? 'text-danger' : 'text-muted'}>
                    last: {last.outcome} · {last.note} · {relativeTime(last.atMs, now)} ago
                  </span>
                )}
              </span>
              <span className="flex shrink-0 gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => automationStore.setEnabled(a.id, !a.enabled)}
                >
                  {a.enabled ? 'Pause' : 'Resume'}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => automationStore.remove(a.id)}>
                  Remove
                </Button>
              </span>
            </li>
          );
        })}
      </ul>
      {adding ? (
        <AddAutomation onDone={() => setAdding(false)} />
      ) : (
        <Button size="sm" onClick={() => setAdding(true)} className="self-start">
          + automation
        </Button>
      )}
    </div>
  );
}

function describe(t: Trigger, a: Action): string {
  const when =
    t.kind === 'interval'
      ? `every ${Math.round(t.everyMs / 3_600_000)}h`
      : t.kind === 'daily'
        ? `daily ${String(Math.floor(t.minuteOfDay / 60)).padStart(2, '0')}:${String(t.minuteOfDay % 60).padStart(2, '0')} UTC`
        : `when balance > ${t.above}`;
  const what = a.kind === 'transfer' ? `send ${a.amount}` : `sweep above ${a.keep}`;
  return `${when} · ${what} (base units) to ${a.to.slice(0, 10)}…`;
}

function AddAutomation({ onDone }: { onDone: () => void }) {
  const state = useDirectory();
  const registry = useRegistry();
  const ids = {
    name: useId(),
    account: useId(),
    trigger: useId(),
    every: useId(),
    to: useId(),
    amount: useId(),
  };
  const single = new Map(
    state.wallets.filter((w) => w.kind === 'single').map((w) => [w.id, w] as const),
  );
  const accounts = state.accounts.filter((a) => canSendFrom(a, single.get(a.walletId)));
  const [name, setName] = useState('');
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? '');
  const [trigger, setTrigger] = useState<'interval' | 'daily' | 'balanceAbove'>('interval');
  const [every, setEvery] = useState('24');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [error, setError] = useState<string | null>(null);
  const account = accounts.find((a) => a.id === accountId);
  const chain = account ? findChain(registry, account.chainId) : undefined;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!account || !chain) return;
    const units = parseUnits(amount, chain.nativeAsset.decimals);
    if (units === null) {
      setError('Amount has too many decimals');
      return;
    }
    const t: Trigger =
      trigger === 'interval'
        ? {
            kind: 'interval',
            everyMs: Math.round(Number(every) * 3_600_000),
            startAtMs: Date.now(),
          }
        : trigger === 'daily'
          ? {
              kind: 'daily',
              minuteOfDay: Math.max(0, Math.min(1439, Math.round(Number(every) * 60))),
            }
          : { kind: 'balanceAbove', above: units };
    const r = automationStore.add({
      name: name.trim() || 'automation',
      enabled: true,
      walletId: account.walletId,
      accountId: account.id,
      asset: `${account.chainId}:native`,
      trigger: t,
      action:
        trigger === 'balanceAbove'
          ? { kind: 'sweep', to: to.trim(), keep: units }
          : { kind: 'transfer', to: to.trim(), amount: units },
    });
    if (!r.ok) setError(r.error);
    else onDone();
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-2 rounded-sw-sm border border-edge p-3">
      <Field label="Name" htmlFor={ids.name}>
        <Input
          id={ids.name}
          value={name}
          maxLength={60}
          onChange={(e) => setName(e.target.value)}
        />
      </Field>
      <Field label="From" htmlFor={ids.account}>
        <Select id={ids.account} value={accountId} onChange={(e) => setAccountId(e.target.value)}>
          {accounts.map((a) => (
            <option key={a.id} value={a.id}>
              {findChain(registry, a.chainId)?.name ?? a.chainId} · {shortAddress(a.address, 10, 4)}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="When" htmlFor={ids.trigger}>
        <Select
          id={ids.trigger}
          value={trigger}
          onChange={(e) => setTrigger(e.target.value as typeof trigger)}
        >
          <option value="interval">Every N hours</option>
          <option value="daily">Daily at an hour (UTC)</option>
          <option value="balanceAbove">
            When the balance rises above the amount (sweep the rest)
          </option>
        </Select>
      </Field>
      {trigger !== 'balanceAbove' && (
        <Field
          label={trigger === 'interval' ? 'Hours (at least 0.25)' : 'Hour of day, UTC'}
          htmlFor={ids.every}
        >
          <Input
            id={ids.every}
            value={every}
            inputMode="decimal"
            onChange={(e) => setEvery(e.target.value)}
          />
        </Field>
      )}
      <Field label="To" htmlFor={ids.to}>
        <Input id={ids.to} value={to} spellCheck={false} onChange={(e) => setTo(e.target.value)} />
      </Field>
      <Field
        label={
          trigger === 'balanceAbove'
            ? `Keep (${chain?.nativeAsset.symbol ?? ''})`
            : `Amount (${chain?.nativeAsset.symbol ?? ''})`
        }
        htmlFor={ids.amount}
      >
        <Input
          id={ids.amount}
          value={amount}
          inputMode="decimal"
          onChange={(e) => setAmount(e.target.value)}
        />
      </Field>
      {error && <p className="text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" size="sm" variant="ghost" onClick={onDone}>
          Cancel
        </Button>
        <Button
          type="submit"
          size="sm"
          variant="primary"
          disabled={!account || !to.trim() || !amount.trim()}
        >
          Save
        </Button>
      </div>
    </form>
  );
}
