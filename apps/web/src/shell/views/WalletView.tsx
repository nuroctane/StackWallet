import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import type { Account, Wallet } from '@stackwallet/core-client';
import { shortAddress, type ChainInfo, type Holding } from '@stackwallet/chains';
import { Badge, Button, Kbd, useToasts } from '@stackwallet/ui';

import { explorerAddressUrl, FAMILY_LABEL, findChain } from '../../lib/chains.js';
import { formatUnits, relativeTime } from '../../lib/format.js';
import { useBalances, type BalanceEntry } from '../../store/balances.js';
import { directory } from '../../store/persist.js';
import { MAX_TAG_LENGTH, MAX_TAGS } from '../../store/reducers.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { DirectoryState } from '../../store/schema.js';
import { accountsOf, kindLabel, pathTo } from '../../store/selectors.js';
import { Breadcrumb } from '../Breadcrumb.js';
import { isTypingTarget, useShell } from '../ShellContext.js';
import { WalletTags } from '../ProvenanceTags.js';
import { nameTitle, useWalletLabel } from '../WalletName.js';
import { KeysSection } from './KeysSection.js';
import { CollectiblesGrid } from './CollectiblesGrid.js';
import { NamesSection } from './NamesSection.js';
import { TransactionsSection } from './TransactionsSection.js';

const CLOCK_TICK_MS = 10_000;

export function WalletView({ state, wallet }: { state: DirectoryState; wallet: Wallet }) {
  const shell = useShell();
  const toasts = useToasts();
  const registry = useRegistry();
  const path = pathTo(state, wallet.id);
  const accounts = accountsOf(state, wallet.id);
  const balances = useBalances(accounts);
  const [renaming, setRenaming] = useState(false);
  const now = useNow(CLOCK_TICK_MS);
  const label = useWalletLabel(wallet);

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

  const rows = useMemo(
    () => buildRows(accounts, balances.byAccount, (id) => findChain(registry, id)),
    [accounts, balances.byAccount, registry],
  );

  return (
    <div className="flex flex-col gap-5 p-5">
      <div className="flex flex-col gap-2">
        <Breadcrumb path={path} leaf={label.text} />
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
              title={label.record ? `${nameTitle(label)} · F2 renames your tag` : 'Rename (F2)'}
              className={`sw-pressable -mx-1 min-w-0 truncate rounded-sw-sm px-1 text-left text-[22px] font-semibold tracking-[-0.01em] ${label.record ? 'text-accent-2' : 'text-ink'}`}
            >
              {label.text}
            </button>
          )}
          <Badge>{kindLabel(wallet)}</Badge>
          <WalletTags wallet={wallet} />
          <span className="flex-1" />
          <Button
            size="sm"
            variant="ghost"
            title="Move to another folder (m in the tree)"
            onClick={() => shell.openDialog({ kind: 'move', walletId: wallet.id })}
          >
            Move…
          </Button>
        </div>
        {label.record && (
          <p className="text-[12px] text-faint">
            your tag <span className="text-muted">{wallet.name}</span>
            {label.record.nonAscii && (
              <span className="ml-2 text-danger">
                this name uses non-ASCII characters; check it is the one you expect
              </span>
            )}
          </p>
        )}
        <TagEditor wallet={wallet} />
        {wallet.kind === 'watch' && (
          <p className="text-[12px] text-faint">
            Watch-only: StackWallet can read this address but cannot sign for it.
          </p>
        )}
      </div>

      <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
        <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
          <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
            Holdings
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
            <Button size="sm" variant="ghost" onClick={() => shell.openDialog({ kind: 'tokens' })}>
              Tokens…
            </Button>
          </div>
        </header>
        {accounts.length === 0 ? (
          <p className="px-4 py-3 text-[12px] text-faint">No accounts on this wallet yet.</p>
        ) : (
          <div className="max-h-[56vh] overflow-auto">
            <table className="w-full border-collapse text-[12px]">
              <thead className="sticky top-0 z-10 bg-elevated text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
                <tr className="h-9 border-b border-edge">
                  <th className="px-4 text-left font-semibold">Chain</th>
                  <th className="px-2 text-left font-semibold">Address</th>
                  <th className="px-2 text-left font-semibold">Asset</th>
                  <th className="px-2 text-right font-semibold">Balance</th>
                  <th className="px-2 text-left font-semibold" title="How many RPC endpoints agree">
                    Source
                  </th>
                  <th className="px-4 text-right font-semibold" title="Time since last read">
                    Age
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {rows.map((row) => (
                  <HoldingRow
                    key={row.key}
                    row={row}
                    now={now}
                    onCopy={() => void copy(row.account.address)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {wallet.kind === 'single' && <KeysSection wallet={wallet} />}

      <TransactionsSection wallet={wallet} />

      <NamesSection accounts={accounts} />

      <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
        <header className="border-b border-edge px-4 py-2.5">
          <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
            Collectibles
          </h3>
        </header>
        <CollectiblesGrid accounts={accounts} />
      </section>

      <section className="flex flex-col gap-3 rounded-sw border border-edge p-4">
        <div className="flex flex-col gap-1">
          <h3 className="text-[11px] font-semibold tracking-[0.12em] text-danger uppercase">
            Danger zone
          </h3>
          <p className="text-[12px] text-faint">
            Removes this wallet and its accounts from this device. Nothing on-chain changes
            {wallet.kind === 'watch'
              ? '; the address keeps existing without you.'
              : wallet.kind === 'single'
                ? '. The key stays sealed in the vault, so restoring the phrase later finds it again.'
                : '.'}
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

function useNow(tickMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), tickMs);
    return () => clearInterval(id);
  }, [tickMs]);
  return now;
}

interface HoldingRowData {
  key: string;
  account: Account;
  info: ChainInfo | undefined;
  entry: BalanceEntry | undefined;
  /** Missing while the first fetch is pending, the fetch failed or no adapter exists. */
  holding: Holding | undefined;
  native: boolean;
}

/**
 * One row per holding, native first. An account with nothing fetched yet
 * still gets a row so the chain and address are visible while it loads.
 */
function buildRows(
  accounts: readonly Account[],
  byAccount: ReadonlyMap<string, BalanceEntry | undefined>,
  lookup: (chainId: string) => ChainInfo | undefined,
): HoldingRowData[] {
  const rows: HoldingRowData[] = [];
  for (const account of accounts) {
    const info = lookup(account.chainId);
    const entry = byAccount.get(account.id);
    const nativeRef = info?.nativeAsset.ref;
    const fetched = entry && !entry.error && entry.fetchedAtMs > 0;
    if (!info || !fetched) {
      rows.push({ key: account.id, account, info, entry, holding: undefined, native: true });
      continue;
    }
    const native = entry.holdings.find((h) => h.assetRef === nativeRef) ?? {
      assetRef: nativeRef ?? '',
      amount: '0',
      updatedAtMs: entry.fetchedAtMs,
    };
    rows.push({
      key: `${account.id}|${native.assetRef}`,
      account,
      info,
      entry,
      holding: native,
      native: true,
    });
    for (const h of entry.holdings) {
      if (h.assetRef === nativeRef) continue;
      rows.push({
        key: `${account.id}|${h.assetRef}`,
        account,
        info,
        entry,
        holding: h,
        native: false,
      });
    }
  }
  return rows;
}

function HoldingRow({
  row,
  now,
  onCopy,
}: {
  row: HoldingRowData;
  now: number;
  onCopy: () => void;
}) {
  const { account, info, entry, holding } = row;
  const explorer = info ? explorerAddressUrl(info, account.address) : undefined;
  const loading = !entry || (entry.loading && entry.fetchedAtMs === 0);

  let balance: string;
  let balanceClass = 'text-ink';
  const asset = row.native
    ? (info?.nativeAsset.symbol ?? '—')
    : (holding?.metadata?.symbol ?? holding?.assetRef ?? '—');
  if (!info) {
    balance = 'no adapter';
    balanceClass = 'text-faint';
  } else if (entry?.error || holding?.error) {
    balance = 'unavailable';
    balanceClass = 'text-faint';
  } else if (loading || !holding) {
    balance = '…';
    balanceClass = 'text-faint';
  } else if (row.native) {
    balance = formatUnits(holding.amount, info.nativeAsset.decimals);
  } else {
    balance = holding.metadata
      ? formatUnits(holding.amount, holding.metadata.decimals)
      : holding.amount;
  }

  return (
    <tr className="h-9 hover:bg-hover">
      <td
        className="max-w-[16ch] truncate px-4 whitespace-nowrap"
        title={`${info?.name ?? account.chainId} · ${FAMILY_LABEL[account.family]}`}
      >
        <span className="text-ink">{info?.name ?? account.chainId}</span>
        {info?.testnet && <Badge className="ml-2">testnet</Badge>}
      </td>
      <td className="px-2 whitespace-nowrap">
        <button
          type="button"
          onClick={onCopy}
          title={`${account.address} (click to copy)`}
          className="sw-pressable -mx-1 rounded-sw-sm px-1 font-mono text-muted"
        >
          {shortAddress(account.address)}
        </button>
        {explorer && (
          <a
            href={explorer}
            target="_blank"
            rel="noreferrer noopener"
            aria-label="Open in explorer"
            title="Open in explorer"
            className="sw-pressable ml-0.5 inline-flex h-5 w-5 items-center justify-center rounded-sw-sm text-faint"
          >
            ↗
          </a>
        )}
      </td>
      <td
        className={`max-w-[18ch] truncate px-2 ${row.native ? 'text-muted' : 'font-mono text-[11px] text-faint'}`}
        title={holding?.assetRef ?? asset}
      >
        {asset}
      </td>
      <td
        className={`px-2 text-right font-mono tabular-nums ${balanceClass}`}
        title={holding?.error ?? entry?.error}
      >
        {balance}
        {!row.native && !holding?.metadata && (
          <span className="ml-1 text-[10px] text-faint">base</span>
        )}
      </td>
      <td className="px-2 whitespace-nowrap">
        <Verified holding={holding} info={info} native={row.native} />
      </td>
      <td className="px-4 text-right whitespace-nowrap text-faint tabular-nums">
        {holding ? relativeTime(holding.updatedAtMs, now) : entry?.error ? 'failed' : ''}
      </td>
    </tr>
  );
}

function Verified({
  holding,
  info,
  native,
}: {
  holding: Holding | undefined;
  info: ChainInfo | undefined;
  native: boolean;
}) {
  const p = holding?.provenance;
  if (!holding || !p) return <span className="text-faint">—</span>;
  if (p.kind === 'agreed') {
    return (
      <span className="text-muted" title={p.endpoints.join('\n')}>
        2 rpc
      </span>
    );
  }
  if (p.kind === 'single') {
    return (
      <span className="text-faint" title={p.endpoint}>
        1 rpc
      </span>
    );
  }
  const other = holding.metadata
    ? `${formatUnits(p.other, holding.metadata.decimals)} ${holding.metadata.symbol}`
    : native && info
      ? `${formatUnits(p.other, info.nativeAsset.decimals)} ${info.nativeAsset.symbol}`
      : `${p.other} base`;
  return (
    <span
      className="text-danger"
      title={`Second endpoint reported ${other}\n${p.endpoints.join('\n')}`}
    >
      mismatch
    </span>
  );
}

function TagEditor({ wallet }: { wallet: Wallet }) {
  const toasts = useToasts();
  const [draft, setDraft] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const full = wallet.tags.length >= MAX_TAGS;

  const report = (result: { ok: boolean; error?: string }) => {
    if (!result.ok && result.error) toasts.push(result.error, 'danger');
  };

  const add = () => {
    const tag = draft.trim();
    if (tag === '') return;
    const result = directory.addTag(wallet.id, tag);
    report(result);
    if (result.ok) setDraft('');
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      add();
    } else if (e.key === 'Backspace' && draft === '') {
      const last = wallet.tags[wallet.tags.length - 1];
      if (last) report(directory.removeTag(wallet.id, last));
    } else if (e.key === 'Escape') {
      setDraft('');
    }
  };

  return (
    <div
      role="group"
      aria-label="Tags"
      className="flex min-h-7 flex-wrap items-center gap-1.5"
      onClick={() => inputRef.current?.focus()}
    >
      {wallet.tags.map((t) => (
        <span
          key={t}
          className="inline-flex h-5 items-center gap-1 rounded-sw-sm border border-edge pl-1.5 text-[10px] font-medium tracking-[0.08em] text-ok uppercase"
        >
          {t}
          <button
            type="button"
            aria-label={`Remove tag ${t}`}
            onClick={(e) => {
              e.stopPropagation();
              report(directory.removeTag(wallet.id, t));
            }}
            className="sw-pressable flex h-5 w-5 items-center justify-center rounded-sw-sm text-faint hover:text-ink"
          >
            ×
          </button>
        </span>
      ))}
      <input
        ref={inputRef}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={onKeyDown}
        onBlur={add}
        disabled={full}
        maxLength={MAX_TAG_LENGTH}
        placeholder={full ? `${MAX_TAGS} tags max` : wallet.tags.length === 0 ? 'add tag' : '+'}
        aria-label="Add tag"
        spellCheck={false}
        autoComplete="off"
        className="h-5 min-w-[6ch] flex-1 basis-[6ch] bg-transparent px-1 font-mono text-[11px] text-muted outline-none placeholder:text-faint disabled:cursor-not-allowed"
      />
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
