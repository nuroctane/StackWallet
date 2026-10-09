import { useEffect, useRef, useState } from 'react';
import type { Account, Wallet } from '@stackwallet/core-client';
import type { ChainInfo } from '@stackwallet/chains';
import { Badge, Button, Kbd, useToasts } from '@stackwallet/ui';

import { explorerAddressUrl, FAMILY_LABEL, findChain } from '../../lib/chains.js';
import { formatUnits, shortAddress } from '../../lib/format.js';
import { useBalances, type BalanceEntry } from '../../store/balances.js';
import { directory } from '../../store/persist.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { DirectoryState } from '../../store/schema.js';
import { accountsOf, kindLabel, pathTo } from '../../store/selectors.js';
import { Breadcrumb } from '../Breadcrumb.js';
import { isTypingTarget, useShell } from '../ShellContext.js';

export function WalletView({ state, wallet }: { state: DirectoryState; wallet: Wallet }) {
  const shell = useShell();
  const toasts = useToasts();
  const registry = useRegistry();
  const path = pathTo(state, wallet.id);
  const accounts = accountsOf(state, wallet.id);
  const balances = useBalances(accounts);
  const [renaming, setRenaming] = useState(false);

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key !== 'F2' || isTypingTarget(e.target)) return;
      if (e.target instanceof HTMLElement && e.target.closest('[role="tree"]')) return;
      e.preventDefault();
      setRenaming(true);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const commitRename = (name: string) => {
    setRenaming(false);
    if (name.trim() === '' || name.trim() === wallet.name) return;
    const result = directory.renameNode(wallet.id, name);
    if (!result.ok) toasts.push(result.error, 'danger');
  };

  const copy = async (address: string) => {
    try {
      await navigator.clipboard.writeText(address);
      toasts.push('Address copied');
    } catch {
      toasts.push('Clipboard unavailable', 'danger');
    }
  };

  return (
    <div className="flex flex-col gap-5 p-5">
      <div className="flex flex-col gap-2">
        <Breadcrumb path={path} leaf={wallet.name} />
        <div className="flex flex-wrap items-center gap-3">
          {renaming ? (
            <NameInput
              initial={wallet.name}
              onCommit={commitRename}
              onCancel={() => setRenaming(false)}
            />
          ) : (
            <button
              type="button"
              onClick={() => setRenaming(true)}
              title="Rename (F2)"
              className="sw-pressable -mx-1 rounded-sw-sm px-1 text-left text-[22px] font-semibold tracking-[-0.01em] text-ink"
            >
              {wallet.name}
            </button>
          )}
          <Badge>{kindLabel(wallet)}</Badge>
          {wallet.tags.map((t) => (
            <Badge key={t} tone="ok">
              {t}
            </Badge>
          ))}
        </div>
        {wallet.kind === 'watch' && (
          <p className="text-[12px] text-faint">
            Watch-only: StackWallet can read this address but cannot sign for it.
          </p>
        )}
      </div>

      <section className="sw-elevated flex flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
          <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
            Accounts
          </h3>
          <div className="flex items-center gap-2 text-[11px] text-faint">
            <span>
              {accounts.length} {accounts.length === 1 ? 'account' : 'accounts'}
            </span>
            <Button
              size="sm"
              variant="ghost"
              disabled={accounts.length === 0 || balances.loading}
              onClick={() => void balances.refresh()}
            >
              {balances.loading ? 'refreshing…' : 'refresh'}
            </Button>
          </div>
        </header>
        {accounts.length === 0 ? (
          <p className="px-4 py-3 text-[12px] text-faint">No accounts on this wallet yet.</p>
        ) : (
          <ul className="divide-y divide-edge">
            {accounts.map((a) => (
              <AccountRow
                key={a.id}
                account={a}
                info={findChain(registry, a.chainId)}
                entry={balances.byAccount.get(a.id)}
                onCopy={() => void copy(a.address)}
              />
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-3 rounded-sw border border-edge p-4">
        <div className="flex flex-col gap-1">
          <h3 className="text-[11px] font-semibold tracking-[0.12em] text-danger uppercase">
            Danger zone
          </h3>
          <p className="text-[12px] text-faint">
            Removes this wallet and its accounts from this device. Nothing on-chain changes
            {wallet.kind === 'watch' ? '; the address keeps existing without you.' : '.'}
          </p>
        </div>
        <div>
          <Button
            variant="danger"
            size="sm"
            onClick={() => shell.openDialog({ kind: 'deleteWallet', walletId: wallet.id })}
          >
            Delete wallet
          </Button>
        </div>
      </section>
    </div>
  );
}

function AccountRow({
  account,
  info,
  entry,
  onCopy,
}: {
  account: Account;
  info: ChainInfo | undefined;
  entry: BalanceEntry | undefined;
  onCopy: () => void;
}) {
  const explorer = info ? explorerAddressUrl(info, account.address) : undefined;
  const native =
    info && entry ? entry.holdings.find((h) => h.assetRef === info.nativeAsset.ref) : undefined;
  const others = entry ? entry.holdings.filter((h) => h.assetRef !== info?.nativeAsset.ref) : [];

  return (
    <li className="flex flex-col gap-2 px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <div className="flex items-center gap-2">
            <span className="text-ink">{info?.name ?? account.chainId}</span>
            <span className="text-[10px] tracking-[0.06em] text-faint uppercase">
              {FAMILY_LABEL[account.family]}
            </span>
            {info?.testnet && <Badge>testnet</Badge>}
            {account.label && <span className="text-[12px] text-muted">{account.label}</span>}
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onCopy}
              title={`${account.address} (click to copy)`}
              className="sw-pressable -mx-1 rounded-sw-sm px-1 font-mono text-[12px] text-muted"
            >
              {shortAddress(account.address)}
            </button>
            {explorer && (
              <a
                href={explorer}
                target="_blank"
                rel="noreferrer noopener"
                className="sw-pressable rounded-sw-sm px-1 text-[11px] text-faint underline decoration-edge underline-offset-2"
              >
                explorer
              </a>
            )}
          </div>
        </div>
        <div className="text-right tabular-nums">
          <BalanceCell info={info} entry={entry} native={native?.amount} />
        </div>
      </div>
      {others.length > 0 && (
        <ul className="flex flex-col gap-1 border-t border-edge pt-2 text-[11px]">
          {others.map((h) => (
            <li key={h.assetRef} className="flex items-center justify-between gap-3">
              <span className="truncate font-mono text-faint">{h.assetRef}</span>
              <span className="text-muted">
                {h.amount} <span className="text-faint">base units</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

function BalanceCell({
  info,
  entry,
  native,
}: {
  info: ChainInfo | undefined;
  entry: BalanceEntry | undefined;
  native: string | undefined;
}) {
  if (!info) return <span className="text-[12px] text-faint">no chain adapter</span>;
  if (!entry || (entry.loading && entry.fetchedAtMs === 0)) {
    return <span className="text-faint">…</span>;
  }
  if (entry.error) {
    return (
      <div className="flex flex-col items-end">
        <span className="text-faint">unavailable</span>
        <span className="max-w-[28ch] truncate text-[11px] text-faint" title={entry.error}>
          {entry.error}
        </span>
      </div>
    );
  }
  return (
    <div className="flex flex-col items-end">
      <span className="text-ink">
        {formatUnits(native ?? '0', info.nativeAsset.decimals)}{' '}
        <span className="text-muted">{info.nativeAsset.symbol}</span>
      </span>
      <span className="text-[11px] text-faint">{entry.loading ? 'refreshing…' : 'native'}</span>
    </div>
  );
}

function NameInput({
  initial,
  onCommit,
  onCancel,
}: {
  initial: string;
  onCommit: (name: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(initial);
  const done = useRef(false);
  const finish = (commit: boolean) => {
    if (done.current) return;
    done.current = true;
    if (commit) onCommit(value);
    else onCancel();
  };
  return (
    <span className="flex items-center gap-2">
      <input
        autoFocus
        aria-label="Wallet name"
        value={value}
        maxLength={80}
        onChange={(e) => setValue(e.target.value)}
        onFocus={(e) => e.target.select()}
        onBlur={() => finish(true)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') finish(true);
          else if (e.key === 'Escape') finish(false);
        }}
        className="h-9 min-w-[16ch] rounded-sw-sm border border-edge-strong bg-paper px-2 font-mono text-[22px] font-semibold tracking-[-0.01em] text-ink outline-none"
      />
      <span className="flex items-center gap-1 text-[11px] text-faint">
        <Kbd>↵</Kbd> save <Kbd>esc</Kbd> cancel
      </span>
    </span>
  );
}
