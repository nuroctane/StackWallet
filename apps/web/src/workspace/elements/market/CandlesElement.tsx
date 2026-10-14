import { useEffect, useMemo, useState } from 'react';
import { CANDLE_DAYS, fetchCandles, type CandleDays, type CandleSet } from '@stackwallet/market';
import { CanvasChart, Select, type Series } from '@stackwallet/ui';

import { marketClient, useMarketSettings } from '../../../store/market.js';
import { useElementSize } from '../../useElementSize.js';
import type { ElementBodyProps } from '../types.js';
import { fmtPct, fmtUsd, SourcesPanel, useCoinOptions } from './shared.js';

const REFRESH_MS = 5 * 60_000;

export function CandlesElement({ pane, setProps }: ElementBodyProps) {
  const coins = useCoinOptions();
  const settings = useMarketSettings();
  const requested = typeof pane.props['coinId'] === 'string' ? pane.props['coinId'] : '';
  const coinId = requested || coins[0]?.id || 'bitcoin';
  const rawDays = Number(pane.props['days'] ?? 30);
  const days: CandleDays = (CANDLE_DAYS as readonly number[]).includes(rawDays)
    ? (rawDays as CandleDays)
    : 30;
  const [set, setSet] = useState<CandleSet | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hoverT, setHoverT] = useState<number | null>(null);
  const [stageRef, stage] = useElementSize<HTMLDivElement>();

  useEffect(() => {
    if (!settings.coingecko) return;
    let live = true;
    const load = () =>
      fetchCandles(marketClient, coinId, days)
        .then((s) => {
          if (!live) return;
          setSet(s);
          setError(null);
        })
        .catch((err: unknown) => {
          if (live) setError(err instanceof Error ? err.message : String(err));
        });
    setSet(null);
    setHoverT(null);
    void load();
    const id = setInterval(() => void load(), REFRESH_MS);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, [coinId, days, settings.coingecko]);

  const series = useMemo<Series[]>(
    () =>
      set
        ? [
            {
              id: `${set.id}:${set.days}`,
              label: set.id,
              kind: 'candles',
              color: 'var(--sw-ink)',
              points: set.candles.map((c) => ({ t: c.t, v: c.c, o: c.o, h: c.h, l: c.l })),
            },
          ]
        : [],
    [set],
  );

  const candles = set?.candles ?? [];
  const first = candles[0];
  const last = candles.at(-1);
  const shown = candles.find((c) => c.t === hoverT) ?? last;
  const hi = candles.length ? Math.max(...candles.map((c) => c.h)) : null;
  const lo = candles.length ? Math.min(...candles.map((c) => c.l)) : null;
  const change = first && last && first.o > 0 ? ((last.c - first.o) / first.o) * 100 : null;
  const label = coins.find((c) => c.id === coinId)?.symbol ?? coinId;

  return (
    <div className="grid h-full grid-rows-[auto_minmax(100px,1fr)_auto] overflow-hidden text-[11px]">
      <header className="flex flex-col gap-1 px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <Select
            aria-label="Coin"
            value={coinId}
            onChange={(e) => setProps({ coinId: e.target.value })}
          >
            {!coins.some((c) => c.id === coinId) && <option value={coinId}>{coinId}</option>}
            {coins.map((c) => (
              <option key={c.id} value={c.id}>
                {c.symbol} · {c.name}
              </option>
            ))}
          </Select>
          <Select
            aria-label="Range"
            value={String(days)}
            onChange={(e) => setProps({ days: Number(e.target.value) })}
          >
            {CANDLE_DAYS.map((d) => (
              <option key={d} value={d}>
                {d === 1 ? '24h' : `${d}d`}
              </option>
            ))}
          </Select>
        </div>
        <p role="status" aria-live="polite" className="text-muted tabular-nums">
          {shown
            ? `${label} · ${new Date(shown.t).toLocaleString()} · O ${fmtUsd(shown.o)} H ${fmtUsd(shown.h)} L ${fmtUsd(shown.l)} C ${fmtUsd(shown.c)}`
            : error
              ? ''
              : settings.coingecko
                ? 'Loading candles…'
                : ''}
        </p>
        {hi !== null && lo !== null && (
          <p className="text-faint tabular-nums">
            range high {fmtUsd(hi)} · low {fmtUsd(lo)} · change {fmtPct(change)} · CoinGecko OHLC
            (USD)
            {set && set.dropped > 0 ? ` · ${set.dropped} inconsistent candles left out` : ''}
          </p>
        )}
        {!settings.coingecko && (
          <p className="text-faint">Candles come from CoinGecko, which is turned off below.</p>
        )}
        {error && <p className="text-danger">{error}</p>}
      </header>
      <div ref={stageRef} className="relative min-h-[100px] min-w-0">
        {candles.length > 0 && stage.width > 0 && stage.height > 0 && (
          <div className="absolute inset-0">
            <CanvasChart
              key={`${coinId}:${days}`}
              ariaLabel={`${label} candles, ${days} days`}
              series={series}
              width={stage.width}
              height={stage.height}
              yFormat={fmtUsd}
              onHover={setHoverT}
              gridlines
              lastValuePill
            />
          </div>
        )}
      </div>
      <div className="px-3 py-1">
        <SourcesPanel />
      </div>
    </div>
  );
}
