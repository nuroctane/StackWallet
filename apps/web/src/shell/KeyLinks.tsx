import { useMemo } from 'react';
import type { Account } from '@stackwallet/core-client';

import { FAMILY_LABEL } from '../lib/chains.js';
import { keySiblings, siblingsHint, type KeySibling } from '../lib/key-siblings.js';
import { useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { accountsOf } from '../store/selectors.js';
import { useShell } from './ShellContext.js';

/** Sibling rows for one account, decorated with which of them the wallet already holds. */
export function useKeySiblings(account: Account | undefined): KeySibling[] {
  const registry = useRegistry();
  const state = useDirectory();
  const holders = useMemo(
    () => (account ? accountsOf(state, account.walletId) : []),
    [state, account],
  );
  return useMemo(
    () => (account ? keySiblings(registry, account, holders) : []),
    [registry, account, holders],
  );
}

/**
 * One sentence under an address: which other families the key reaches, with
 * a link to the full list when the account exists in the directory.
 */
export function KeyReach({
  account,
  className = '',
}: {
  account: Account | (Pick<Account, 'family' | 'publicKeyHex' | 'chainId'> & { id?: undefined });
  className?: string;
}) {
  const shell = useShell();
  const registry = useRegistry();
  const rows = useMemo(() => keySiblings(registry, account), [registry, account]);
  const main = rows.filter((r) => !r.testnet);
  const families = [...new Set(main.map((r) => r.family))];
  if (families.length === 0) return null;
  const shown = families.slice(0, 5).map((f) => FAMILY_LABEL[f]);
  const more = families.length - shown.length;
  return (
    <p className={`text-[11px] text-faint ${className}`}>
      The same key owns addresses on{' '}
      <span className="text-muted">
        {shown.join(', ')}
        {more > 0 ? ` +${more}` : ''}
      </span>
      .{' '}
      {account.id ? (
        <button
          type="button"
          onClick={() => shell.openDialog({ kind: 'keyAddresses', accountId: account.id })}
          className="sw-pressable text-muted underline"
        >
          show them
        </button>
      ) : null}
    </p>
  );
}

/** `KeyLinksHint` for places that only carry the account id. */
export function KeyLinksById({ accountId, className }: { accountId: string; className?: string }) {
  const state = useDirectory();
  const account = state.accounts.find((a) => a.id === accountId);
  return account ? <KeyLinksHint account={account} className={className ?? ''} /> : null;
}

/**
 * The hover hint next to an address: how many other families this key owns an
 * address on, with the first few spelled out in the tooltip. Click opens the
 * full list. Renders nothing for keys that are specific to their family.
 */
export function KeyLinksHint({
  account,
  className = '',
}: {
  account: Account;
  className?: string;
}) {
  const shell = useShell();
  const rows = useKeySiblings(account);
  const hint = siblingsHint(rows);
  if (!hint) return null;
  const families = new Set(rows.filter((r) => !r.testnet).map((r) => r.family)).size;
  return (
    <button
      type="button"
      title={hint}
      aria-label={`Same key on ${families} other chain families; show addresses`}
      onClick={(e) => {
        e.stopPropagation();
        shell.openDialog({ kind: 'keyAddresses', accountId: account.id });
      }}
      className={`sw-pressable inline-flex h-5 shrink-0 items-center gap-0.5 rounded-sw-sm border border-edge px-1 font-mono text-[10px] text-faint hover:border-edge-strong hover:text-muted ${className}`}
    >
      <span aria-hidden>⇄</span>
      {families}
    </button>
  );
}
