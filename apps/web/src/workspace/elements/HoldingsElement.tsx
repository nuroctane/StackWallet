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
  assetRef: string;
  metadataKnown: boolean;
  hasAmount: boolean;
  provenance: string;
  amount: string;
  decimals: number;
  fetchedAtMs: number;
  loading: boolean;
  error?: string;
  notice?: string;
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
      assetRef: info?.nativeAsset.ref ?? a.chainId + ':native',
      metadataKnown: !!info,
      hasAmount: !!native,
      provenance: native?.provenance
        ? JSON.stringify(native.provenance, null, 2)
        : 'Unverified / unavailable',
      amount,
      decimals: info?.nativeAsset.decimals ?? 0,
      fetchedAtMs: e?.fetchedAtMs ?? 0,
      loading: e?.loading ?? false,
      zero: !!native && !e?.error && !native.error && /^0*$/.test(amount),
    };
    const readError = e?.error ?? native?.error;
    if (readError) row.error = readError;
    rows.push(row);
    for (const holding of e?.holdings ?? []) {
      if (holding.assetRef === info?.nativeAsset.ref) continue;
      rows.push({
        ...row,
        key: `${a.id}|${holding.assetRef}`,
        amount: holding.amount,
        symbol: holding.metadata?.symbol ?? holding.assetRef,
        assetRef: holding.assetRef,
        metadataKnown: !!holding.metadata,
        hasAmount: !holding.error,
        provenance: holding.provenance
          ? JSON.stringify(holding.provenance, null, 2)
          : 'Unverified / unavailable',
        decimals: holding.metadata?.decimals ?? 0,
        zero: !holding.error && /^0*$/.test(holding.amount),
        ...(holding.error ? { error: holding.error } : {}),
        ...(holding.notice ? { notice: holding.notice } : {}),
      });
    }
  }
  return rows.sort((x, y) => x.wallet.localeCompare(y.wallet) || x.chain.localeCompare(y.chain));
}

export function HoldingsElement({ pane, width, height }: ElementBodyProps) {
  const [readable, setReadable] = useState(false);
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
        render: (r) => (
          <span className="text-muted" title={r.address}>
            {shortAddress(r.address)}
          </span>
        ),
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
              {r.metadataKnown ? formatUnits(r.amount, r.decimals) : r.amount + ' base units'}{' '}
              <span className="text-faint">{r.symbol}</span>
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

  if (width < 640 || readable)
    return (
      <div className="h-full overflow-auto p-3 text-[12px]" aria-label="Holdings">
        {width >= 640 && (
          <button
            type="button"
            className="sw-pressable mb-2 min-h-8 text-muted underline"
            onClick={() => setReadable(false)}
          >
            Return to table
          </button>
        )}
        {rows.length === 0 && (
          <p className="text-faint">
            {state.accounts.length === 0 ? 'no accounts yet' : 'nothing matches the filter'}
          </p>
        )}
        {rows.map((r) => (
          <details key={r.key} className="border-b border-edge py-2">
            <summary className="cursor-pointer break-words leading-relaxed">
              <span className="text-ink">{r.wallet}</span> · {r.chain}
              <span className="block text-muted">
                {r.error
                  ? 'Read failed · expand for details'
                  : r.fetchedAtMs === 0
                    ? 'Not yet read'
                    : (r.metadataKnown
                        ? formatUnits(r.amount, r.decimals)
                        : r.amount + ' base units') +
                      ' ' +
                      r.symbol}
              </span>
            </summary>
            <dl className="mt-2 space-y-2 text-[11px]">
              <div>
                <dt className="text-faint">Asset reference</dt>
                <dd className="select-text break-all">{r.assetRef}</dd>
              </div>
              <div>
                <dt className="text-faint">Balance source</dt>
                <dd className="select-text whitespace-pre-wrap break-all">{r.provenance}</dd>
              </div>
              <div>
                <dt className="text-faint">Account address</dt>
                <dd className="select-text break-all">{r.address}</dd>
              </div>
              <div>
                <dt className="text-faint">Chain ID</dt>
                <dd className="select-text break-all">{r.chainId}</dd>
              </div>
              <div>
                <dt className="text-faint">Base units</dt>
                <dd className="select-text break-all">{r.hasAmount ? r.amount : 'Unknown'}</dd>
              </div>
              <div>
                <dt className="text-faint">Last read</dt>
                <dd>
                  {r.fetchedAtMs ? new Date(r.fetchedAtMs).toLocaleString() : 'Never'}
                  {r.loading ? ' · refreshing' : ''}
                </dd>
              </div>
              {r.error && (
                <div>
                  <dt className="text-faint">Error</dt>
                  <dd className="break-words text-danger">{r.error}</dd>
                </div>
              )}
              {r.notice && (
                <div>
                  <dt className="text-faint">Balance coverage</dt>
                  <dd className="break-words text-muted">{r.notice}</dd>
                </div>
              )}
            </dl>
            <button
              type="button"
              className="sw-pressable mt-2 min-h-8 text-muted underline"
              onClick={() => directory.reveal(r.walletId)}
            >
              Open wallet
            </button>
          </details>
        ))}
      </div>
    );

  const bodyHeight = Math.max(0, height - HEADER_H - 32);
  return (
    <div className="h-full">
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
      <button
        type="button"
        className="sw-pressable h-8 w-full border-t border-edge px-3 text-left text-[11px] text-muted"
        onClick={() => setReadable(true)}
      >
        Read full holding details
      </button>
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
