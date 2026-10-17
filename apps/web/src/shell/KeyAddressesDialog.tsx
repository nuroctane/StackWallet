import { useMemo, useState } from 'react';
import type { ChainInfo } from '@stackwallet/chains';
import type { Account, Wallet } from '@stackwallet/core-client';
import { Badge, Button, Dialog, useToasts } from '@stackwallet/ui';

import { explorerAddressUrl, FAMILY_LABEL, findChain } from '../lib/chains.js';
import { signsAtPath, type KeySibling } from '../lib/key-siblings.js';
import { directory, useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { useKeySiblings } from './KeyLinks.js';
import { useWalletLabel } from './WalletName.js';

/**
 * Every address one key owns across chain families. The list comes from the
 * stored public key alone, so it works with a locked vault and for hardware
 * wallets; adding a row to the wallet reuses the same derivation path, which
 * is why only single-key wallets get the button.
 */
export function KeyAddressesDialog({
  open,
  accountId,
  onClose,
}: {
  open: boolean;
  accountId?: string | undefined;
  onClose: () => void;
}) {
  const state = useDirectory();
  const account = state.accounts.find((a) => a.id === accountId);
  const wallet = account ? state.wallets.find((w) => w.id === account.walletId) : undefined;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Same key, other chains"
      meta="one secret, one owner everywhere"
      width="w-[min(92vw,640px)]"
    >
      {account && wallet ? <Body account={account} wallet={wallet} /> : null}
    </Dialog>
  );
}

function Body({ account, wallet }: { account: Account; wallet: Wallet }) {
  const registry = useRegistry();
  const toasts = useToasts();
  const label = useWalletLabel(wallet);
  const rows = useKeySiblings(account);
  const [showTestnets, setShowTestnets] = useState(false);
  const source = findChain(registry, account.chainId);
  const visible = useMemo(
    () => rows.filter((r) => showTestnets || !r.testnet),
    [rows, showTestnets],
  );
  const testnetRows = rows.filter((r) => r.testnet).length;
  const canAdd = wallet.kind === 'single' && !!account.derivationPath;

  const copy = (text: string) =>
    void navigator.clipboard
      .writeText(text)
      .then(() => toasts.push('Address copied'))
      .catch(() => toasts.push('Clipboard unavailable', 'danger'));

  const add = (row: KeySibling, chain: ChainInfo) => {
    const r = directory.addKeyedAccount({
      walletId: wallet.id,
      chainId: chain.chainId,
      address: row.address,
      derivationPath: account.derivationPath ?? '',
      publicKeyHex: account.publicKeyHex,
    });
    if (!r.ok) {
      toasts.push(r.error, 'danger');
      return;
    }
    toasts.push(`Added ${chain.name} to ${label.text}`);
  };

  return (
    <div className="flex flex-col gap-4 p-4 text-[12px]">
      <div className="flex flex-col gap-1">
        <p className="text-muted">
          <span className="text-ink">{label.text}</span> · {source?.name ?? account.chainId}
          {account.label ? ` · ${account.label}` : ''}
        </p>
        <p className="font-mono break-all text-faint select-all">{account.address}</p>
        <p className="text-[11px] text-faint">
          {account.derivationPath ? (
            <>
              key <span className="font-mono">{account.derivationPath}</span> ·{' '}
            </>
          ) : null}
          the private key behind this address also controls every address below.
        </p>
      </div>

      {visible.length === 0 ? (
        <p className="text-faint">
          {rows.length === 0
            ? 'This key is specific to its chain family; no other family derives an account from it.'
            : 'Only testnets share this key. Show testnets to see them.'}
        </p>
      ) : (
        <div className="max-h-[52vh] overflow-auto rounded-sw-sm border border-edge">
          <table className="w-full border-collapse">
            <thead className="sticky top-0 z-10 bg-elevated text-[10px] font-semibold tracking-[0.12em] text-muted uppercase">
              <tr className="h-8 border-b border-edge">
                <th className="px-3 text-left font-semibold">Family</th>
                <th className="px-2 text-left font-semibold">Address</th>
                <th className="px-3 text-right font-semibold">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {visible.map((row) => (
                <SiblingRow
                  key={`${row.family}|${row.address}`}
                  row={row}
                  canAdd={canAdd}
                  path={account.derivationPath ?? ''}
                  onCopy={() => copy(row.address)}
                  onAdd={(chain) => add(row, chain)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex items-center justify-between gap-3">
        <label className="flex items-center gap-2 text-[11px] text-faint">
          <input
            type="checkbox"
            checked={showTestnets}
            onChange={(e) => setShowTestnets(e.target.checked)}
            disabled={testnetRows === 0}
          />
          show testnets{testnetRows > 0 ? ` (${testnetRows})` : ''}
        </label>
        <p className="text-right text-[11px] text-faint">
          {canAdd
            ? 'Adding a chain reuses this key; the account signs with the same vault entry. Rows marked watch receive only, because that family signs testnet transfers from its own coin-type-1 path.'
            : wallet.kind === 'hardware'
              ? 'Hardware apps pin each chain to its own path, so these are shown, not added.'
              : 'Shown for reference; this wallet kind does not derive extra accounts.'}
        </p>
      </div>
    </div>
  );
}

function SiblingRow({
  row,
  canAdd,
  path,
  onCopy,
  onAdd,
}: {
  row: KeySibling;
  canAdd: boolean;
  path: string;
  onCopy: () => void;
  onAdd: (chain: ChainInfo) => void;
}) {
  const first = row.chains.find((c) => !row.heldOn.includes(c.chainId)) ?? row.chains[0]!;
  const [chainId, setChainId] = useState(first.chainId);
  const chain = row.chains.find((c) => c.chainId === chainId) ?? first;
  const held = row.heldOn.includes(chain.chainId);
  const signs = !chain.testnet || signsAtPath(chain, path);
  const explorer = explorerAddressUrl(chain, row.address);
  const names = row.chains.map((c) => c.name);
  return (
    <tr className="hover:bg-hover">
      <td className="max-w-[16ch] px-3 py-1.5 align-top whitespace-nowrap">
        <div className="text-ink">{FAMILY_LABEL[row.family]}</div>
        <div className="truncate text-[10px] text-faint" title={names.join(', ')}>
          {row.chains.length === 1 ? names[0] : `${names[0]} +${row.chains.length - 1}`}
        </div>
        {row.testnet && <Badge className="mt-0.5">testnet</Badge>}
        {row.heldOn.length > 0 && (
          <div className="text-[10px] text-faint">
            in wallet{row.heldOn.length > 1 ? ` ×${row.heldOn.length}` : ''}
          </div>
        )}
      </td>
      <td className="px-2 py-1.5 align-top">
        <button
          type="button"
          onClick={onCopy}
          title="Click to copy"
          className="sw-pressable -mx-1 rounded-sw-sm px-1 text-left font-mono text-[11px] break-all text-muted"
        >
          {row.address}
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
      <td className="px-3 py-1.5 text-right align-top whitespace-nowrap">
        {canAdd && (
          <span className="inline-flex items-center gap-1">
            {row.chains.length > 1 && (
              <select
                aria-label={`Which ${FAMILY_LABEL[row.family]} chain to add`}
                value={chainId}
                onChange={(e) => setChainId(e.target.value)}
                className="h-6 max-w-[16ch] rounded-sw-sm border border-edge bg-paper px-1 font-mono text-[11px] text-muted outline-none focus:border-edge-strong"
              >
                {row.chains.map((c) => (
                  <option key={c.chainId} value={c.chainId}>
                    {c.name}
                    {row.heldOn.includes(c.chainId) ? ' · in wallet' : ''}
                  </option>
                ))}
              </select>
            )}
            <Button
              size="sm"
              variant="ghost"
              disabled={held}
              title={
                signs
                  ? undefined
                  : `${chain.name} signs only from a coin-type-1 path; this account would receive and watch, not send.`
              }
              onClick={() => onAdd(chain)}
            >
              {held ? 'added' : signs ? 'add' : 'add (watch)'}
            </Button>
          </span>
        )}
      </td>
    </tr>
  );
}
