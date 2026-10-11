import { useEffect, useMemo, useState } from 'react';
import { shortAddress } from '@stackwallet/chains';
import { VirtualTable, type Column } from '@stackwallet/ui';

import { findChain } from '../../lib/chains.js';
import { formatUnits, relativeTime } from '../../lib/format.js';
import { useBalances, type BalanceEntry } from '../../store/balances.js';
import { useNames, walletLabel } from '../../store/names.js';
import { directory, useDirectory } from '../../store/persist.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { ElementBodyProps } from './types.js';

const CLOCK_TICK_MS = 10_000;
const HEADER_H = 28;

export interface HoldingRow {
  key: string;
  accountId: string;
  walletId: string;
  wallet: string;
  chainId: string;
  chain: string;
  address: string;
  symbol: string;
  amount: string;
  decimals: number;
  fetchedAtMs: number;
  loading: boolean;
  error?: string;
  zero: boolean;
}

export function buildHoldingRows(
  accounts: readonly { id: string; walletId: string; chainId: string; address: string }[],
  walletName: (id: string) => string,
  entry: (accountId: string) => BalanceEntry | undefined,
  chain: (
    chainId: string,
  ) => { name: string; nativeAsset: { ref: string; symbol: string; decimals: number } } | undefined,
): HoldingRow[] {
  const rows: HoldingRow[] = [];
  for (const a of accounts) {
    const info = chain(a.chainId);
    const e = entry(a.id);
    const native = info ? e?.holdings.find((h) => h.assetRef === info.nativeAsset.ref) : undefined;
    const amount = native?.amount ?? '0';
    const row: HoldingRow = {
      key: a.id,
      accountId: a.id,
      walletId: a.walletId,
      wallet: walletName(a.walletId),
      chainId: a.chainId,
      chain: info?.name ?? a.chainId,
      address: a.address,
      symbol: info?.nativeAsset.symbol ?? '?',
      amount,
      decimals: info?.nativeAsset.decimals ?? 0,
      fetchedAtMs: e?.fetchedAtMs ?? 0,
      loading: e?.loading ?? false,
      zero: /^0*$/.test(amount),
    };
    if (e?.error) row.error = e.error;
    rows.push(row);
  }
  return rows.sort((x, y) => x.wallet.localeCompare(y.wallet) || x.chain.localeCompare(y.chain));
}

export function HoldingsElement({ pane, height }: ElementBodyProps) {
  const state = useDirectory();
  const registry = useRegistry();
  const balances = useBalances(state.accounts);
  const names = useNames();
  const hideZero = pane.props['hideZero'] === true;
  const chainFilter = typeof pane.props['chainId'] === 'string' ? pane.props['chainId'] : '';
  const now = useNow(CLOCK_TICK_MS);

  const rows = useMemo(() => {
    const labels = new Map(
      state.wallets.map((w) => [w.id, walletLabel(names, w, state.accounts).text]),
    );
    const all = buildHoldingRows(
      state.accounts,
      (id) => labels.get(id) ?? '?',
      (id) => balances.byAccount.get(id),
      (id) => findChain(registry, id),
    );
    return all.filter((r) => (!hideZero || !r.zero) && (!chainFilter || r.chainId === chainFilter));
  }, [state.accounts, state.wallets, balances.byAccount, registry, hideZero, chainFilter, names]);

  const columns = useMemo<Column<HoldingRow>[]>(
    () => [
      { key: 'wallet', header: 'wallet', width: 'minmax(72px,1.2fr)', render: (r) => r.wallet },
      {
        key: 'chain',
        header: 'chain',
        width: 'minmax(64px,1fr)',
        render: (r) => <span className="text-muted">{r.chain}</span>,
      },
      {
        key: 'address',
        header: 'address',
        width: 'minmax(96px,1.4fr)',
        render: (r) => <span className="text-muted">{shortAddress(r.address)}</span>,
      },
      {
        key: 'balance',
        header: 'balance',
        width: 'minmax(100px,1fr)',
        align: 'right',
        render: (r) =>
          r.error ? (
            <span className="text-danger" title={r.error}>
              error
            </span>
          ) : r.fetchedAtMs === 0 ? (
            <span className="text-faint">··</span>
          ) : (
            <span className={r.zero ? 'text-faint' : 'text-ink'}>
              {formatUnits(r.amount, r.decimals)} <span className="text-faint">{r.symbol}</span>
            </span>
          ),
      },
      {
        key: 'age',
        header: 'age',
        width: 44,
        align: 'right',
        render: (r) => (
          <span className="text-faint">
            {r.loading ? '…' : r.fetchedAtMs === 0 ? '' : relativeTime(r.fetchedAtMs, now)}
          </span>
        ),
      },
    ],
    [now],
  );

  const bodyHeight = Math.max(0, height - HEADER_H);
  return (
    <VirtualTable
      ariaLabel="Holdings"
      rows={rows}
      columns={columns}
      rowKey={(r) => r.key}
      height={bodyHeight + HEADER_H}
      density="normal"
      selectedKey={state.ui.selectedId}
      onRowClick={(r) => directory.reveal(r.walletId)}
      rowAge={(r) =>
        now - r.fetchedAtMs < 2_000 ? 0 : now - r.fetchedAtMs < 6_000 ? 1 : undefined
      }
      emptyLabel={state.accounts.length === 0 ? 'no accounts yet' : 'nothing matches the filter'}
    />
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
