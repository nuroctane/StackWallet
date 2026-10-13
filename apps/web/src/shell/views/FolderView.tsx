import { useMemo } from 'react';
import type { Folder, Wallet } from '@stackwallet/core-client';
import { Badge, Button, EmptyState } from '@stackwallet/ui';

import { FAMILY_LABEL, findChain } from '../../lib/chains.js';
import { formatUnits } from '../../lib/format.js';
import { useBalances, type BalanceEntry } from '../../store/balances.js';
import { vault } from '../../core/bridge.js';
import { useVaultView } from '../../core/vault.js';
import { directory } from '../../store/persist.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { DirectoryState } from '../../store/schema.js';
import {
  childFolders,
  descendantWallets,
  kindLabel,
  pathTo,
  walletFamilies,
  walletsIn,
} from '../../store/selectors.js';
import { Breadcrumb } from '../Breadcrumb.js';
import { useShell } from '../ShellContext.js';
import { SetTags } from '../ProvenanceTags.js';
import { WalletName } from '../WalletName.js';
import { TotalsStrip } from './TotalsStrip.js';

export function FolderView({ state, folder }: { state: DirectoryState; folder: Folder }) {
  const shell = useShell();
  const registry = useRegistry();
  const path = pathTo(state, folder.id);
  const subfolders = childFolders(state, folder.id);
  const wallets = walletsIn(state, folder.id);
  const nested = descendantWallets(state, folder.id);
  const accounts = useMemo(() => {
    const ids = new Set(wallets.map((w) => w.id));
    return state.accounts.filter((a) => ids.has(a.walletId));
  }, [state.accounts, wallets]);
  const nestedAccounts = useMemo(() => {
    const ids = new Set(nested.map((w) => w.id));
    return state.accounts.filter((a) => ids.has(a.walletId));
  }, [state.accounts, nested]);
  const balances = useBalances(accounts);
  // Re-render when export keys change; the button shows whether one is set.
  useVaultView(vault);

  return (
    <div className="flex flex-col gap-5 p-5">
      <div className="flex flex-col gap-2">
        <Breadcrumb path={path.slice(0, -1)} leaf={folder.name} />
        <SetTags folderId={folder.id} />
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-[22px] font-semibold tracking-[-0.01em]">{folder.name}</h1>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => shell.openDialog({ kind: 'folder', parentId: folder.id })}
            >
              + folder
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => shell.openDialog({ kind: 'newWallet', folderId: folder.id })}
            >
              + wallet
            </Button>
            <Button
              size="sm"
              onClick={() => shell.openDialog({ kind: 'watch', folderId: folder.id })}
            >
              + watch
            </Button>
            {folder.parentId === null && (
              <Button
                size="sm"
                variant="ghost"
                title="Open a directory or wallet sealed for this device"
                onClick={() => shell.openDialog({ kind: 'importSet' })}
              >
                Import…
              </Button>
            )}
            <Button
              size="sm"
              variant="ghost"
              title="The key every export from this directory needs: its wallets one by one, or the directory as a whole"
              onClick={() =>
                shell.openDialog({ kind: 'exportKey', scope: 'folder', id: folder.id })
              }
            >
              {vault.hasExportKey('folder', folder.id) ? 'Directory key ✓' : 'Directory key…'}
            </Button>
            {folder.parentId !== null && (
              <Button
                size="sm"
                variant="ghost"
                title="Seal this directory, its wallets and their layouts for a paired device"
                onClick={() => shell.openDialog({ kind: 'transferSet', folderId: folder.id })}
              >
                Export directory…
              </Button>
            )}
          </div>
        </div>
      </div>

      <section className="grid grid-cols-2 gap-3 min-[900px]:grid-cols-[auto_auto_minmax(0,1fr)]">
        <Stat label="Subfolders" value={subfolders.length} />
        <Stat
          label="Wallets"
          value={nested.length}
          hint={
            nested.length !== wallets.length
              ? `${wallets.length} here · ${nested.length - wallets.length} nested`
              : undefined
          }
        />
        <TotalsStrip accounts={nestedAccounts} className="col-span-2 min-[900px]:col-span-1" />
      </section>

      {subfolders.length > 0 && (
        <section className="flex flex-wrap gap-2">
          {subfolders.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => directory.reveal(f.id)}
              className="sw-pressable sw-elevated flex h-8 items-center gap-2 px-3 text-muted"
            >
              <span className="text-ink">{f.name}</span>
              <span className="text-[11px] text-faint">
                {descendantWallets(state, f.id).length}
              </span>
            </button>
          ))}
        </section>
      )}

      <section className="sw-elevated overflow-hidden">
        {wallets.length === 0 ? (
          <EmptyState
            title="No wallets in this folder"
            description="Add a watch-only address here or move a wallet in from the tree."
            action={
              <Button
                size="sm"
                onClick={() => shell.openDialog({ kind: 'watch', folderId: folder.id })}
              >
                Add watch wallet
              </Button>
            }
          />
        ) : (
          <div className="max-h-[60vh] overflow-auto">
            <table className="w-full border-collapse text-[12px]">
              <thead className="sticky top-0 z-10 bg-elevated text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
                <tr className="h-9 border-b border-edge">
                  <th className="px-4 text-left font-semibold">Name</th>
                  <th className="px-3 text-left font-semibold">Kind</th>
                  <th className="px-3 text-left font-semibold">Chains</th>
                  <th className="px-4 text-right font-semibold">Balance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {wallets.map((w) => (
                  <WalletRow
                    key={w.id}
                    state={state}
                    wallet={w}
                    balances={balances.byAccount}
                    registry={registry}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: number; hint?: string | undefined }) {
  return (
    <div className="sw-elevated flex min-w-[7rem] flex-col gap-1 px-4 py-3">
      <div className="text-[11px] font-semibold tracking-[0.12em] text-faint uppercase">
        {label}
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-[18px] font-semibold tracking-[-0.01em] text-ink">{value}</span>
        {hint && <span className="text-[11px] text-faint">{hint}</span>}
      </div>
    </div>
  );
}

function WalletRow({
  state,
  wallet,
  balances,
  registry,
}: {
  state: DirectoryState;
  wallet: Wallet;
  balances: ReadonlyMap<string, BalanceEntry | undefined>;
  registry: ReturnType<typeof useRegistry>;
}) {
  const accounts = state.accounts.filter((a) => a.walletId === wallet.id);
  const families = walletFamilies(state, wallet.id);
  const first = accounts[0];
  const entry = first ? balances.get(first.id) : undefined;
  const info = first ? findChain(registry, first.chainId) : undefined;
  const native =
    entry && info ? entry.holdings.find((h) => h.assetRef === info.nativeAsset.ref) : undefined;

  let balanceText = '—';
  if (entry?.error) balanceText = 'unavailable';
  else if (entry?.loading && entry.fetchedAtMs === 0) balanceText = '…';
  else if (native && info) {
    balanceText = `${formatUnits(native.amount, info.nativeAsset.decimals)} ${info.nativeAsset.symbol}`;
  } else if (entry && entry.fetchedAtMs > 0 && info) {
    balanceText = `0 ${info.nativeAsset.symbol}`;
  }

  return (
    <tr
      className="h-9 cursor-pointer hover:bg-hover focus-visible:bg-hover"
      onClick={() => directory.reveal(wallet.id)}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter') directory.reveal(wallet.id);
      }}
    >
      <td data-label="Name" className="truncate px-4 text-ink">
        <WalletName wallet={wallet} className="max-w-full" />
      </td>
      <td data-label="Kind" className="px-3">
        <Badge>{kindLabel(wallet)}</Badge>
      </td>
      <td data-label="Chains" className="px-3 text-[10px] tracking-[0.06em] text-faint uppercase">
        {families.map((f) => FAMILY_LABEL[f]).join(' · ') || '—'}
      </td>
      <td
        data-label="Balance"
        className={`px-4 text-right tabular-nums ${entry?.error ? 'text-faint' : 'text-muted'}`}
        title={entry?.error}
      >
        {balanceText}
        {accounts.length > 1 && <span className="text-faint"> +{accounts.length - 1}</span>}
      </td>
    </tr>
  );
}
