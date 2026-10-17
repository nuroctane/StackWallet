import type { ReactNode } from 'react';
import type { WalletKind } from '@stackwallet/core-client';
import { Badge, Button } from '@stackwallet/ui';

import { vault } from '../../core/bridge.js';
import { useVaultView } from '../../core/vault.js';
import { findChain, listChains } from '../../lib/chains.js';
import { useBalances } from '../../store/balances.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { DirectoryState } from '../../store/schema.js';
import { chainIdsInUse, countByKind } from '../../store/selectors.js';
import { useShell } from '../ShellContext.js';
import { TotalsStrip } from './TotalsStrip.js';

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
      <GettingStarted state={state} />
      {total > 0 && <TotalsStrip accounts={state.accounts} label="All holdings" />}
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
              More ways to hold keys
            </h3>
          </header>
          <ul className="divide-y divide-edge">
            <Step
              title="Bring a browser wallet"
              body="MetaMask, Rabby and other extensions share their addresses to watch here. They keep their keys; nothing is signed."
              action={
                <Button size="sm" onClick={() => shell.openDialog({ kind: 'connect' })}>
                  Add wallet…
                </Button>
              }
            />
            <Step
              title="Watch an address"
              body="Follow any address on any supported chain. Read-only, nothing to sign."
              action={
                <Button size="sm" onClick={() => shell.openDialog({ kind: 'watch' })}>
                  Watch…
                </Button>
              }
            />
            <Step
              title="Connect a Ledger"
              body="The device signs EVM transactions; the key never reaches this browser."
              action={
                <Button size="sm" onClick={() => shell.openDialog({ kind: 'hardwareWallet' })}>
                  Ledger…
                </Button>
              }
            />
            <Step
              title="Shared wallet across two devices"
              body="A threshold key split between devices. No single device ever holds the key."
              action={
                <Button
                  size="sm"
                  onClick={() =>
                    shell.openDialog({ kind: 'threshold', target: { mode: 'create' } })
                  }
                >
                  Shared…
                </Button>
              }
            />
          </ul>
        </div>
      </section>
    </div>
  );
}

/**
 * The first-run path from nothing to a signed transfer. Hidden once every step is done so a
 * returning user sees their numbers first.
 */
function GettingStarted({ state }: { state: DirectoryState }) {
  const shell = useShell();
  const view = useVaultView(vault);
  const balances = useBalances(state.accounts);
  const status = view.status.kind;
  const vaultReady = status === 'unlocked';
  const keyed = state.wallets.find((w) => w.kind !== 'watch');
  const funded = state.accounts.some((a) =>
    balances.byAccount.get(a.id)?.holdings.some((h) => !h.error && !/^0*$/.test(h.amount)),
  );
  const sent = (view.ledger?.txs.length ?? 0) > 0;
  if (vaultReady && keyed && funded && sent) return null;

  const vaultStep =
    status === 'absent'
      ? { label: 'Create vault…', done: false }
      : status === 'locked'
        ? { label: 'Unlock…', done: false }
        : { label: '', done: status === 'unlocked' };

  return (
    <section className="sw-elevated flex flex-col">
      <header className="border-b border-edge px-4 py-2.5">
        <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
          Getting started
        </h3>
      </header>
      <ol className="divide-y divide-edge">
        <Step
          n={1}
          done={vaultStep.done}
          title={status === 'locked' ? 'Unlock your vault' : 'Create your vault'}
          body="One passphrase encrypts every key on this device. It never leaves the device, and there is no reset."
          action={
            !vaultStep.done &&
            vaultStep.label && (
              <Button
                size="sm"
                variant="primary"
                onClick={() => shell.openDialog({ kind: 'vault' })}
              >
                {vaultStep.label}
              </Button>
            )
          }
        />
        <Step
          n={2}
          done={!!keyed}
          title="Create a wallet"
          body="A new recovery phrase is generated inside the core and sealed in the vault. You can also restore one you already have."
          action={
            !keyed && (
              <Button
                size="sm"
                variant={vaultStep.done ? 'primary' : 'ghost'}
                onClick={() =>
                  shell.openDialog(vaultReady ? { kind: 'newWallet' } : { kind: 'vault' })
                }
              >
                New wallet…
              </Button>
            )
          }
        />
        <Step
          n={3}
          done={funded}
          title="Receive coins"
          body="Share an address or QR code. Most testnet accounts link to a free faucet."
          action={
            keyed &&
            !funded && (
              <Button
                size="sm"
                onClick={() => shell.openDialog({ kind: 'receive', walletId: keyed.id })}
              >
                Receive…
              </Button>
            )
          }
        />
        <Step
          n={4}
          done={sent}
          title="Send"
          body="The core checks every transfer against its intent and your policies, then it waits in the approval queue for your passphrase."
          action={
            keyed &&
            !sent && (
              <Button
                size="sm"
                onClick={() => shell.openDialog({ kind: 'send', walletId: keyed.id })}
              >
                Send…
              </Button>
            )
          }
        />
      </ol>
    </section>
  );
}

function Step({
  n,
  done,
  title,
  body,
  action,
}: {
  n?: number;
  done?: boolean;
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <li className="flex items-start gap-3 px-4 py-3">
      {n !== undefined && <span className="w-4 pt-0.5 text-faint">{n}</span>}
      <div className="flex flex-1 flex-col gap-0.5">
        <div className="flex items-center gap-2">
          <span className={done ? 'text-muted' : 'text-ink'}>{title}</span>
          {done && <Badge tone="ok">done</Badge>}
        </div>
        <p className="text-[12px] text-faint">{body}</p>
      </div>
      {action}
    </li>
  );
}
