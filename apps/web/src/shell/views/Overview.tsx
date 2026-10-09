import type { ReactNode } from 'react';
import type { WalletKind } from '@stackwallet/core-client';
import { Badge, Button } from '@stackwallet/ui';

import { findChain, listChains } from '../../lib/chains.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { DirectoryState } from '../../store/schema.js';
import { chainIdsInUse, countByKind } from '../../store/selectors.js';
import { useShell } from '../ShellContext.js';

const KIND_ORDER: WalletKind[] = ['watch', 'tss', 'single', 'hardware'];
const KIND_TITLE: Record<WalletKind, string> = {
  watch: 'Watch-only',
  tss: 'Threshold',
  single: 'Single key',
  hardware: 'Hardware',
};

export function Overview({ state }: { state: DirectoryState }) {
  const registry = useRegistry();
  const shell = useShell();
  const counts = countByKind(state);
  const total = state.wallets.length;
  const inUse = chainIdsInUse(state);
  const available = listChains(registry);

  return (
    <div className="flex flex-col gap-5 p-5">
      <section className="grid grid-cols-2 gap-3 min-[900px]:grid-cols-4">
        {KIND_ORDER.map((kind) => (
          <div key={kind} className="sw-elevated flex flex-col gap-1 px-4 py-3">
            <div className="text-[11px] font-semibold tracking-[0.12em] text-faint uppercase">
              {KIND_TITLE[kind]}
            </div>
            <div className="text-[22px] font-semibold tracking-[-0.01em] text-ink">
              {counts[kind]}
            </div>
          </div>
        ))}
      </section>

      <section className="grid gap-3 min-[900px]:grid-cols-2">
        <div className="sw-elevated flex flex-col">
          <header className="flex items-center justify-between border-b border-edge px-4 py-2.5">
            <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
              Chains in use
            </h3>
            <span className="text-[11px] text-faint">
              {inUse.length} of {available.length} available
            </span>
          </header>
          {inUse.length === 0 ? (
            <p className="px-4 py-3 text-[12px] text-faint">
              {total === 0 ? 'No accounts yet.' : 'Accounts exist but none reference a chain.'}
            </p>
          ) : (
            <ul className="divide-y divide-edge">
              {inUse.map((chainId) => {
                const info = findChain(registry, chainId);
                const n = state.accounts.filter((a) => a.chainId === chainId).length;
                return (
                  <li key={chainId} className="flex h-9 items-center gap-3 px-4">
                    <span className="flex-1 truncate text-ink">{info?.name ?? chainId}</span>
                    {info?.testnet && <Badge>testnet</Badge>}
                    <span className="w-16 text-right text-muted">
                      {n} {n === 1 ? 'acct' : 'accts'}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
          {available.length === 0 && (
            <p className="border-t border-edge px-4 py-2.5 text-[11px] text-faint">
              No chain adapters loaded. Balances and address checks are unavailable.
            </p>
          )}
        </div>

        <div className="sw-elevated flex flex-col">
          <header className="border-b border-edge px-4 py-2.5">
            <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
              Getting started
            </h3>
          </header>
          <ol className="divide-y divide-edge">
            <Step
              n={1}
              title="Add a watch wallet"
              body="Follow any address on any supported chain. Read-only, nothing to sign."
              badge={<Badge tone="ok">now</Badge>}
              action={
                <Button size="sm" onClick={() => shell.openDialog({ kind: 'watch' })}>
                  Add
                </Button>
              }
            />
            <Step
              n={2}
              title="Pair a device and create a TSS wallet"
              body="Threshold keys split across your devices. No single party ever holds the key."
              badge={<Badge>phase 1</Badge>}
            />
            <Step
              n={3}
              title="Attach an automation"
              body="Schedules and triggers run as their own signing party and still need a human share."
              badge={<Badge>phase 6</Badge>}
            />
          </ol>
        </div>
      </section>
    </div>
  );
}

function Step({
  n,
  title,
  body,
  badge,
  action,
}: {
  n: number;
  title: string;
  body: string;
  badge: ReactNode;
  action?: ReactNode;
}) {
  return (
    <li className="flex items-start gap-3 px-4 py-3">
      <span className="w-4 pt-0.5 text-faint">{n}</span>
      <div className="flex flex-1 flex-col gap-0.5">
        <div className="flex items-center gap-2">
          <span className="text-ink">{title}</span>
          {badge}
        </div>
        <p className="text-[12px] text-faint">{body}</p>
      </div>
      {action}
    </li>
  );
}
