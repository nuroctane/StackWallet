import { useEffect, useMemo, useState } from 'react';
import { CanvasChart, type Series } from '@stackwallet/ui';

import { listChains } from '../../lib/chains.js';
import { useRegistry } from '../../store/RegistryContext.js';
import {
  formatLedgerAmount,
  LEDGER_MAX_POINTS,
  totalsLedger,
  toUnits,
  useLedger,
} from '../ledger.js';
import { useElementSize } from '../useElementSize.js';
import type { ElementBodyProps } from './types.js';

export const RANGES: Record<string, number> = {
  '24h': 24 * 3600_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
  '1y': 365 * 86_400_000,
  all: Number.POSITIVE_INFINITY,
};

export function LedgerElement({ pane }: ElementBodyProps) {
  const ledger = useLedger();
  const registry = useRegistry();
  const requestedRange = typeof pane.props['range'] === 'string' ? pane.props['range'] : '30d';
  const range = requestedRange in RANGES ? requestedRange : '30d';
  const span = RANGES[range] ?? RANGES['30d'];
  const [stageRef, stage] = useElementSize<HTMLDivElement>();
  const [selectedT, setSelectedT] = useState<number | null>(null);
  const [shown, setShown] = useState(100);
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(timer);
  }, []);

  const assets = useMemo(() => totalsLedger.assets(), [ledger]);
  const requested = typeof pane.props['assetRef'] === 'string' ? pane.props['assetRef'] : '';
  const assetRef = assets.some((a) => a.assetRef === requested)
    ? requested
    : (assets[0]?.assetRef ?? '');

  const chain = listChains(registry).find((c) => c.nativeAsset.ref === assetRef);
  const symbol =
    chain?.nativeAsset.symbol ?? assets.find((a) => a.assetRef === assetRef)?.symbol ?? assetRef;
  useEffect(() => {
    setSelectedT(null);
    setShown(100);
  }, [assetRef, range]);

  const observations = useMemo(() => {
    const since = Number.isFinite(span) ? now - (span as number) : 0;
    return ledger.points.filter((p) => p.assetRef === assetRef && p.t >= since);
  }, [ledger, assetRef, span, now]);
  const lastObserved = ledger.points.findLast((p) => p.assetRef === assetRef);
  const selected = observations.find((p) => p.t === selectedT) ?? observations.at(-1);

  const series = useMemo<Series[]>(() => {
    if (!assetRef) return [];
    const points = observations.map((p) => ({ t: p.t, v: toUnits(p.amount, p.decimals) }));
    return [{ id: assetRef, label: symbol, points, kind: 'area', color: 'var(--sw-warm)' }];
  }, [observations, assetRef, symbol]);

  if (assets.length === 0) {
    return (
      <p className="p-4 text-[12px] text-faint">
        Balance history fills in as balances load. Totals are recorded locally on every complete
        refresh; nothing leaves this device.
      </p>
    );
  }

  const points = series[0]?.points ?? [];
  return (
    <div className="grid h-full grid-rows-[auto_minmax(100px,1fr)_auto] overflow-auto">
      <header className="space-y-1 px-3 py-2 text-[11px] text-muted [overflow-wrap:anywhere]">
        <p>
          {symbol} · {chain?.name ?? assetRef} · {range} · local native balance snapshots
        </p>
        <p className="text-faint">
          {lastObserved
            ? `Last observed ${new Date(lastObserved.t).toLocaleString()}${now - lastObserved.t > 300_000 ? ' · older than 5 minutes' : ''}`
            : 'No observation yet'}
        </p>
        <p role="status" aria-live="polite" aria-atomic="true">
          {selected
            ? `${new Date(selected.t).toLocaleString()} · ${formatLedgerAmount(selected.amount, selected.decimals)} ${symbol}`
            : 'No snapshots in this range. Choose a wider range in settings or complete a balance refresh.'}
        </p>
        <p className="text-faint">Tap to inspect · ← / → select · Home / End first / latest</p>
      </header>
      <div ref={stageRef} className="relative min-h-[100px] min-w-0">
        {points.length > 0 && stage.width > 0 && stage.height > 0 && (
          <div className="absolute inset-0">
            <CanvasChart
              key={`${assetRef}:${range}`}
              ariaLabel={symbol + ' total over time'}
              series={series}
              width={stage.width}
              height={stage.height}
              yFormat={compact}
              onHover={setSelectedT}
              nonnegative
              gridlines
              lastValuePill
            />
          </div>
        )}
      </div>
      <details className="px-3 py-2 text-[11px]">
        <summary className="min-h-11 cursor-pointer py-3 text-muted">
          Read balance snapshots · {points.length} points
        </summary>
        <p className="my-2 break-all text-faint">
          {assetRef} · Only complete successful refreshes are recorded; unavailable refreshes are
          not observations. Keeps the latest {LEDGER_MAX_POINTS} snapshots across all assets on this
          device.
        </p>
        <ol className="space-y-2">
          {observations
            .slice()
            .reverse()
            .slice(0, shown)
            .map((p) => (
              <li key={p.t} className="flex flex-wrap justify-between gap-2 break-all text-muted">
                <time>{new Date(p.t).toLocaleString()}</time>
                <span>
                  {formatLedgerAmount(p.amount, p.decimals)} {symbol}
                </span>
              </li>
            ))}
        </ol>
        {observations.length > shown && (
          <button
            type="button"
            className="sw-pressable mt-2 min-h-11 rounded-sw-sm border border-edge px-3 text-muted"
            onClick={() => setShown((n) => n + 100)}
          >
            Read next {Math.min(100, observations.length - shown)} snapshots
          </button>
        )}
      </details>
    </div>
  );
}

export function compact(v: number): string {
  const abs = Math.abs(v);
  if (abs >= 1e9) return `${(v / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `${(v / 1e6).toFixed(2)}M`;
  if (abs >= 1e3) return `${(v / 1e3).toFixed(2)}k`;
  if (abs >= 1) return v.toFixed(2);
  if (abs === 0) return '0';
  return v.toPrecision(3);
}
