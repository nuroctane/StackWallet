import { useMemo } from 'react';
import type { Account } from '@stackwallet/core-client';

import { findChain } from '../../lib/chains.js';
import { formatUnits } from '../../lib/format.js';
import { useBalances } from '../../store/balances.js';
import { useRegistry } from '../../store/RegistryContext.js';
import { aggregateNative } from '../../store/totals.js';

const MAX_ASSETS = 6;

/**
 * Per-native-asset totals for a set of accounts. Subscribing to balances here
 * also keeps every listed account warm in the cache, so a folder opened after
 * its wallets have been viewed shows numbers immediately.
 */
export function TotalsStrip({
  accounts,
  label = 'Holdings',
  className = '',
}: {
  accounts: readonly Account[];
  label?: string;
  className?: string;
}) {
  const registry = useRegistry();
  const balances = useBalances(accounts);
  const totals = useMemo(
    () => aggregateNative(accounts, balances.byAccount, (id) => findChain(registry, id)),
    [accounts, balances.byAccount, registry],
  );
  const shown = totals.slice(0, MAX_ASSETS);
  const hidden = totals.length - shown.length;
  const disputed = totals.some((t) => t.disputed);
  const partial = !disputed && totals.some((t) => t.incomplete);

  return (
    <div className={`sw-elevated flex min-w-0 flex-col gap-1 px-4 py-3 ${className}`}>
      <div className="flex items-center gap-2 text-[11px] font-semibold tracking-[0.12em] text-faint uppercase">
        <span>{label}</span>
        {disputed && (
          <span
            className="font-normal tracking-normal text-danger normal-case"
            title="Two endpoints reported different balances for at least one account; this is a floor."
          >
            disputed
          </span>
        )}
        {partial && (
          <span
            className="font-normal tracking-normal normal-case"
            title="Some balances are missing, failed or stale; this is a floor."
          >
            partial
          </span>
        )}
        {balances.loading && (
          <span className="font-normal tracking-normal normal-case">refreshing…</span>
        )}
      </div>
      {accounts.length === 0 ? (
        <div className="text-[13px] text-faint">No accounts</div>
      ) : shown.length === 0 ? (
        <div className="text-[13px] text-faint">No known chains</div>
      ) : (
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-[16px] font-semibold tracking-[-0.01em] text-ink tabular-nums">
          {shown.map((t, i) => (
            <span key={t.assetRef} className="flex items-baseline gap-1 whitespace-nowrap">
              {i > 0 && (
                <span aria-hidden className="font-normal text-faint">
                  ·
                </span>
              )}
              <span title={`${t.accounts} ${t.accounts === 1 ? 'account' : 'accounts'}`}>
                {formatUnits(t.amount, t.decimals, 4)}{' '}
                <span className="text-[13px] font-medium text-muted">{t.symbol}</span>
              </span>
            </span>
          ))}
          {hidden > 0 && <span className="text-[12px] font-normal text-faint">+{hidden} more</span>}
        </div>
      )}
    </div>
  );
}
