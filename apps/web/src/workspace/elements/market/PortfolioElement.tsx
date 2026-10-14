import { useEffect, useMemo, useState } from 'react';
import {
  allocation,
  fetchHistory,
  formatUsd,
  HISTORY_DAYS,
  valueSeries,
  type HistoryDays,
  type PricePoint,
} from '@stackwallet/market';
import { CanvasChart, Select, type Series } from '@stackwallet/ui';

import { findChain } from '../../../lib/chains.js';
import { useBalances } from '../../../store/balances.js';
import { marketClient, useMarketSettings } from '../../../store/market.js';
import { useDirectory } from '../../../store/persist.js';
import { usePrices } from '../../../store/prices.js';
import { useRegistry } from '../../../store/RegistryContext.js';
import { aggregateNative } from '../../../store/totals.js';
import { useLedger } from '../../ledger.js';
import { useElementSize } from '../../useElementSize.js';
import { compact } from '../LedgerElement.js';
import type { ElementBodyProps } from '../types.js';
import { coinIdForAssetRef, fmtPct, fmtUsd, SourcesPanel } from './shared.js';

const DAY = 86_400_000;

/**
 * Value over time from this device's own balance snapshots × public price
 * history, plus today's allocation. Only coin ids leave the device; the
 * holdings never do.
 */
export function PortfolioElement({ pane, setProps }: ElementBodyProps) {
  const registry = useRegistry();
  const state = useDirectory();
  const ledger = useLedger();
  const settings = useMarketSettings();
  const balances = useBalances(state.accounts);
  const rawDays = Number(pane.props['days'] ?? 30);
  const days: HistoryDays = (HISTORY_DAYS as readonly number[]).includes(rawDays)
    ? (rawDays as HistoryDays)
    : 30;
  const [stageRef, stage] = useElementSize<HTMLDivElement>();
  const [history, setHistory] = useState<Map<string, PricePoint[]>>(new Map());
  const [errors, setErrors] = useState<string[]>([]);
  const [hoverT, setHoverT] = useState<number | null>(null);

  const totals = useMemo(
    () => aggregateNative(state.accounts, balances.byAccount, (id) => findChain(registry, id)),
    [state.accounts, balances.byAccount, registry],
  );
  const holdings = useMemo(
    () =>
      totals.map((t) => ({
        assetRef: t.assetRef,
        symbol: t.symbol,
        amount: t.amount,
        decimals: t.decimals,
        coinId: coinIdForAssetRef(registry, t.assetRef),
      })),
    [totals, registry],
  );
  const coinFor = useMemo(() => {
    const cache = new Map<string, string | null>();
    return (ref: string) => {
      if (!cache.has(ref)) cache.set(ref, coinIdForAssetRef(registry, ref));
      return cache.get(ref) ?? null;
    };
  }, [registry]);
  const historyCoins = useMemo(
    () =>
      [
        ...new Set(ledger.points.map((p) => coinFor(p.assetRef)).filter((x): x is string => !!x)),
      ].sort(),
    [ledger, coinFor],
  );
  const coinKey = historyCoins.join(',');

  const quote = usePrices(holdings.map((h) => h.coinId).filter((x): x is string => !!x));
  const alloc = allocation(holdings, (id) => quote(id)?.usd);

  useEffect(() => {
    if (!settings.coingecko || !coinKey) return;
    let live = true;
    void (async () => {
      const next = new Map<string, PricePoint[]>();
      const errs: string[] = [];
      // One coin at a time: the client spaces CoinGecko requests anyway.
      for (const id of coinKey.split(',')) {
        try {
          next.set(id, await fetchHistory(marketClient, id, days));
        } catch (err) {
          errs.push(`${id}: ${err instanceof Error ? err.message : String(err)}`);
        }
        if (!live) return;
      }
      setHistory(next);
      setErrors(errs);
    })();
    return () => {
      live = false;
    };
  }, [coinKey, days, settings.coingecko]);

  const now = Date.now();
  const value = useMemo(
    () =>
      valueSeries(
        ledger.points,
        coinFor,
        history,
        { sinceMs: now - days * DAY, untilMs: now },
        days <= 1 ? 30 * 60_000 : days <= 90 ? 3 * 3600_000 : 2 * DAY,
      ),
    // `now` moves every render; the window only needs to follow the data and range.
    [ledger, coinFor, history, days],
  );

  const series = useMemo<Series[]>(() => {
    // Gaps inside the range break the line; trailing gaps are trimmed so the
    // last-value pill always reads a real value.
    const pts = value.points.map((p) => ({ t: p.t, v: p.complete ? p.usd : Number.NaN }));
    while (pts.length > 0 && !Number.isFinite(pts.at(-1)?.v)) pts.pop();
    while (pts.length > 0 && !Number.isFinite(pts[0]?.v)) pts.shift();
    return [
      {
        id: `portfolio:${days}`,
        label: 'portfolio',
        kind: 'area',
        color: 'var(--sw-warm)',
        points: pts,
      },
    ];
  }, [value, days]);
  const complete = value.points.filter((p) => p.complete);
  const firstV = complete[0]?.usd;
  const lastV = complete.at(-1)?.usd;
  const change = firstV && lastV !== undefined ? ((lastV - firstV) / firstV) * 100 : null;
  const hovered = value.points.find((p) => p.t === hoverT);
  const gaps = value.points.length - complete.length;

  return (
    <div className="grid h-full grid-rows-[auto_minmax(90px,1fr)_auto] overflow-auto text-[11px]">
      <header className="flex flex-col gap-1 px-3 py-2">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <span className="text-[16px] font-semibold text-ink tabular-nums">
            {alloc.totalMicros > 0n ? `≈ ${formatUsd(alloc.totalMicros)}` : 'No priced holdings'}
          </span>
          <Select
            aria-label="Range"
            value={String(days)}
            onChange={(e) => setProps({ days: Number(e.target.value) })}
          >
            {HISTORY_DAYS.map((d) => (
              <option key={d} value={d}>
                {d === 1 ? '24h' : `${d}d`}
              </option>
            ))}
          </Select>
        </div>
        <p role="status" aria-live="polite" className="text-muted tabular-nums">
          {hovered
            ? `${new Date(hovered.t).toLocaleString()} · ${hovered.complete ? fmtUsd(hovered.usd) : 'no price for every held asset at this moment'}`
            : complete.length > 1
              ? `${days === 1 ? '24h' : `${days}d`} change ${fmtPct(change)} (holdings and price together)`
              : 'Value history fills in from balance snapshots recorded on this device.'}
        </p>
        <p className="text-faint">
          {gaps > 0 ? `${gaps} moments without a usable price are left blank · ` : ''}
          {value.unpricedAssets.length > 0
            ? `${value.unpricedAssets.length} testnet or unknown assets have no value · `
            : ''}
          snapshots × CoinGecko history, computed here
        </p>
        {!settings.coingecko && (
          <p className="text-faint">Value history needs CoinGecko, which is turned off below.</p>
        )}
        {errors.map((e) => (
          <p key={e} className="text-danger">
            {e}
          </p>
        ))}
      </header>
      <div ref={stageRef} className="relative min-h-[90px] min-w-0">
        {complete.length > 0 && stage.width > 0 && stage.height > 0 && (
          <div className="absolute inset-0">
            <CanvasChart
              key={`portfolio:${days}`}
              ariaLabel="Portfolio value over time"
              series={series}
              width={stage.width}
              height={stage.height}
              yFormat={(v) => `$${compact(v)}`}
              onHover={setHoverT}
              nonnegative
              gridlines
              lastValuePill
            />
          </div>
        )}
      </div>
      <footer className="flex flex-col gap-1 px-3 py-2">
        {alloc.rows.length > 0 && (
          <ul aria-label="Allocation" className="flex flex-col gap-1">
            {alloc.rows.map((r) => (
              <li key={r.assetRef} className="grid grid-cols-[64px_1fr_auto] items-center gap-2">
                <span className="truncate text-ink">{r.symbol}</span>
                <span className="h-1.5 rounded-full bg-edge">
                  <span
                    className="block h-full rounded-full bg-[var(--sw-ink)]"
                    style={{ width: `${Math.max(1, r.share * 100)}%` }}
                  />
                </span>
                <span className="text-muted tabular-nums">
                  {(r.share * 100).toFixed(1)}% · {formatUsd(r.usdMicros)}
                </span>
              </li>
            ))}
          </ul>
        )}
        {alloc.unpriced.length > 0 && (
          <p className="text-faint">Unpriced: {[...new Set(alloc.unpriced)].join(', ')}</p>
        )}
        <SourcesPanel />
      </footer>
    </div>
  );
}
