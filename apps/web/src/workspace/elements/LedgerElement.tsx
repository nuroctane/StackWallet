import { useMemo } from 'react';
import { CanvasChart, type Series } from '@stackwallet/ui';

import { listChains } from '../../lib/chains.js';
import { useRegistry } from '../../store/RegistryContext.js';
import { totalsLedger, useLedger } from '../ledger.js';
import type { ElementBodyProps } from './types.js';

export const RANGES: Record<string, number> = {
  '24h': 24 * 3600_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
  '1y': 365 * 86_400_000,
  all: Number.POSITIVE_INFINITY,
};

export function LedgerElement({ pane, width, height }: ElementBodyProps) {
  const ledger = useLedger();
  const registry = useRegistry();
  const range = typeof pane.props['range'] === 'string' ? pane.props['range'] : '30d';
  const span = RANGES[range] ?? RANGES['30d'];

  const assets = useMemo(() => totalsLedger.assets(), [ledger]);
  const requested = typeof pane.props['assetRef'] === 'string' ? pane.props['assetRef'] : '';
  const assetRef = assets.some((a) => a.assetRef === requested)
    ? requested
    : (assets[0]?.assetRef ?? '');

  const symbol = useMemo(() => {
    for (const c of listChains(registry))
      if (c.nativeAsset.ref === assetRef) return c.nativeAsset.symbol;
    return assetRef.split(':').pop() ?? assetRef;
  }, [registry, assetRef]);

  const series = useMemo<Series[]>(() => {
    if (!assetRef) return [];
    const since = Number.isFinite(span as number) ? Date.now() - (span as number) : undefined;
    const points = totalsLedger.seriesFor(assetRef, since);
    return [{ id: assetRef, label: symbol, points, kind: 'area', color: 'var(--sw-warm)' }];
  }, [ledger, assetRef, span, symbol]);

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
    <div className="h-full overflow-auto">
      <CanvasChart
        ariaLabel={symbol + ' total over time'}
        series={series}
        width={width}
        height={Math.max(80, height - 36)}
        yFormat={(v) => compact(v) + ' ' + symbol}
        gridlines
        lastValuePill
      />
      <details className="px-3 py-2 text-[11px]">
        <summary className="cursor-pointer text-muted">
          Read balance snapshots · {points.length} points
        </summary>
        <p className="my-2 break-all text-faint">
          {assetRef} · {range} · local snapshots
        </p>
        <ol className="space-y-2">
          {points
            .slice()
            .reverse()
            .map((p) => (
              <li key={p.t} className="flex flex-wrap justify-between gap-2 break-all text-muted">
                <time>{new Date(p.t).toLocaleString()}</time>
                <span>
                  {p.v.toLocaleString(undefined, { maximumFractionDigits: 20 })} {symbol}
                </span>
              </li>
            ))}
        </ol>
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
