import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  CANDLE_DAYS,
  CHAINLINK_FEEDS,
  feedByKey,
  feedForCoinId,
  feedKey,
  fetchCandles,
  isStale,
  ticksToCandles,
  type CandleDays,
  type CandleSet,
  type ChainlinkFeed,
} from '@stackwallet/market';
import {
  bollinger,
  CanvasChart,
  ema,
  heikinAshi,
  macd,
  rsi,
  Select,
  sma,
  toPoints,
  type Point,
  type Series,
  type Viewport,
} from '@stackwallet/ui';

import type { Candle } from '@stackwallet/market';
import { chainlinkStore, useChainlinkSeries } from '../../../store/chainlink.js';
import { marketClient, useMarketSettings } from '../../../store/market.js';
import { useRegistry } from '../../../store/RegistryContext.js';
import { useElementSize } from '../../useElementSize.js';
import type { ElementBodyProps } from '../types.js';
import { fmtPct, fmtUsd, SourcesPanel, useCoinOptions } from './shared.js';

const REFRESH_GECKO_MS = 5 * 60_000;
const REFRESH_CHAINLINK_MS = 60_000;

type Source = 'coingecko' | 'chainlink';
type ChartType = 'candles' | 'hollow' | 'ohlc' | 'heikin' | 'line' | 'area' | 'step';
type IndicatorId = 'sma20' | 'ema50' | 'bb' | 'rsi' | 'macd';

const CHART_TYPES: readonly { id: ChartType; label: string }[] = [
  { id: 'candles', label: 'Candles' },
  { id: 'hollow', label: 'Hollow' },
  { id: 'ohlc', label: 'OHLC' },
  { id: 'heikin', label: 'Heikin Ashi' },
  { id: 'line', label: 'Line' },
  { id: 'area', label: 'Area' },
  { id: 'step', label: 'Step' },
];

const INDICATORS: readonly { id: IndicatorId; label: string; pane: boolean }[] = [
  { id: 'sma20', label: 'SMA 20', pane: false },
  { id: 'ema50', label: 'EMA 50', pane: false },
  { id: 'bb', label: 'BB 20·2', pane: false },
  { id: 'rsi', label: 'RSI 14', pane: true },
  { id: 'macd', label: 'MACD', pane: true },
];

const FRAMES = [
  { ms: 300_000, label: '5m' },
  { ms: 900_000, label: '15m' },
  { ms: 3_600_000, label: '1h' },
  { ms: 14_400_000, label: '4h' },
  { ms: 86_400_000, label: '1D' },
] as const;

const SUBPANE_HEIGHT = 88;

function parseIndicators(raw: unknown): IndicatorId[] {
  // Pane props are flat string/number/boolean values, so the set is stored
  // comma-separated.
  if (typeof raw !== 'string') return [];
  const known = new Set(INDICATORS.map((i) => i.id));
  return raw.split(',').filter((x): x is IndicatorId => known.has(x as IndicatorId));
}

/** Chainlink candles from the tick store; flat buckets repeat the carry price. */
function useChainlinkCandles(feed: ChainlinkFeed | null, frameMs: number) {
  const series = useChainlinkSeries(feed);
  useEffect(() => {
    if (!feed || !chainlinkStore.available) return;
    void chainlinkStore.sync(feed);
    const id = setInterval(() => void chainlinkStore.sync(feed), REFRESH_CHAINLINK_MS);
    return () => clearInterval(id);
  }, [feed]);
  const candles = useMemo(() => ticksToCandles(series.ticks, frameMs), [series.ticks, frameMs]);
  return { series, candles };
}

export function CandlesElement({ pane, setProps }: ElementBodyProps) {
  const coins = useCoinOptions();
  const settings = useMarketSettings();
  const registry = useRegistry();

  // Pane props, validated.
  const requested = typeof pane.props['coinId'] === 'string' ? pane.props['coinId'] : '';
  const coinId = requested || coins[0]?.id || 'bitcoin';
  const rawDays = Number(pane.props['days'] ?? 30);
  const days: CandleDays = (CANDLE_DAYS as readonly number[]).includes(rawDays)
    ? (rawDays as CandleDays)
    : 30;
  const feedKeyProp = typeof pane.props['feedKey'] === 'string' ? pane.props['feedKey'] : '';
  const rawFrame = Number(pane.props['frame'] ?? 3_600_000);
  const frameMs = FRAMES.some((f) => f.ms === rawFrame) ? rawFrame : 3_600_000;
  const rawType = typeof pane.props['chartType'] === 'string' ? pane.props['chartType'] : 'candles';
  const chartType: ChartType = CHART_TYPES.some((t) => t.id === rawType)
    ? (rawType as ChartType)
    : 'candles';
  const indicators = parseIndicators(pane.props['indicators']);
  const logScale = pane.props['log'] === true;
  const rawSource = pane.props['source'] === 'chainlink' ? 'chainlink' : 'coingecko';

  // The effective Chainlink feed: the pinned pair, else the freshest feed for
  // the selected coin, else mainnet ETH/USD so the pair picker always has a
  // live value to show.
  const feed = useMemo(() => {
    const pinned = feedKeyProp ? feedByKey(feedKeyProp) : undefined;
    return pinned ?? feedForCoinId(coinId) ?? feedByKey('eip155:1:ETH / USD') ?? null;
  }, [feedKeyProp, coinId]);
  const source: Source = rawSource;

  // --- CoinGecko path -------------------------------------------------------
  const [set, setSet] = useState<CandleSet | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (source !== 'coingecko' || !settings.coingecko) return;
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
    void load();
    const id = setInterval(() => void load(), REFRESH_GECKO_MS);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, [coinId, days, settings.coingecko, source]);

  // --- Chainlink path -------------------------------------------------------
  const { series: feedSeries, candles: feedCandles } = useChainlinkCandles(
    source === 'chainlink' ? feed : null,
    frameMs,
  );
  const clError = source === 'chainlink' ? feedSeries.error : null;

  // --- Unified candle model --------------------------------------------------
  const candles: readonly Candle[] = source === 'chainlink' ? feedCandles : (set?.candles ?? []);
  const times = useMemo(() => candles.map((c) => c.t), [candles]);
  const closes = useMemo(() => candles.map((c) => c.c), [candles]);

  // --- Shared viewport across the main chart and the indicator panes ---------
  const [viewport, setViewport] = useState<Viewport | null>(null);
  const [hoverT, setHoverT] = useState<number | null>(null);
  const viewKey = `${source}:${source === 'chainlink' ? (feed ? feedKey(feed) : '') : coinId}:${source === 'chainlink' ? frameMs : days}`;
  // A different pair, coin or timeframe starts from a fitted window.
  useEffect(() => {
    setViewport(null);
    setHoverT(null);
  }, [viewKey]);

  // Panning into unknown history pulls older data: another CoinGecko range
  // step, or another Chainlink page backwards.
  const lastBackfill = useRef(0);
  const onEdgeReach = useCallback(
    (side: 'left' | 'right') => {
      if (side !== 'left') return;
      const now = Date.now();
      if (now - lastBackfill.current < 2_000) return;
      lastBackfill.current = now;
      if (source === 'chainlink' && feed) {
        void chainlinkStore.backfill(feed);
      } else if (source === 'coingecko') {
        const i = CANDLE_DAYS.indexOf(days);
        const next = CANDLE_DAYS[i + 1];
        if (next !== undefined) setProps({ days: next });
      }
    },
    [source, feed, days, setProps],
  );

  // --- Indicators ------------------------------------------------------------
  const overlaySeries = useMemo(() => {
    const out: Series[] = [];
    if (indicators.includes('sma20'))
      out.push({
        id: 'sma20',
        label: 'SMA 20',
        kind: 'line',
        color: 'var(--sw-muted)',
        points: toPoints(times, sma(closes, 20)),
      });
    if (indicators.includes('ema50'))
      out.push({
        id: 'ema50',
        label: 'EMA 50',
        kind: 'line',
        color: 'var(--sw-faint)',
        dash: [4, 3],
        points: toPoints(times, ema(closes, 50)),
      });
    if (indicators.includes('bb')) {
      const band = bollinger(closes, 20, 2);
      out.push(
        {
          id: 'bb-u',
          label: 'BB upper',
          kind: 'line',
          color: 'var(--sw-faint)',
          dash: [1, 3],
          points: toPoints(times, band.upper),
        },
        {
          id: 'bb-l',
          label: 'BB lower',
          kind: 'line',
          color: 'var(--sw-faint)',
          dash: [1, 3],
          points: toPoints(times, band.lower),
        },
      );
    }
    return out;
  }, [indicators, times, closes]);

  const rsiSeries = useMemo(() => {
    if (!indicators.includes('rsi')) return null;
    return toPoints(times, rsi(closes, 14));
  }, [indicators, times, closes]);

  const macdSeries = useMemo(() => {
    if (!indicators.includes('macd')) return null;
    return macd(closes);
  }, [indicators, closes]);

  // --- Main chart series ------------------------------------------------------
  const points = useMemo<Point[]>(
    () => candles.map((c) => ({ t: c.t, v: c.c, o: c.o, h: c.h, l: c.l })),
    [candles],
  );
  const series = useMemo<Series[]>(() => {
    if (points.length === 0) return [];
    const base = { id: viewKey, label: viewKey };
    switch (chartType) {
      case 'line':
      case 'area':
      case 'step':
        return [{ ...base, kind: chartType, color: 'var(--sw-ink)', points }];
      case 'hollow':
        return [{ ...base, kind: 'hollow', color: 'var(--sw-ink)', points }];
      case 'ohlc':
        return [{ ...base, kind: 'ohlc', color: 'var(--sw-ink)', points }];
      case 'heikin':
        return [{ ...base, kind: 'candles', color: 'var(--sw-ink)', points: heikinAshi(points) }];
      default:
        return [{ ...base, kind: 'candles', color: 'var(--sw-ink)', points }];
    }
  }, [points, chartType, viewKey]);

  const [stageRef, stage] = useElementSize<HTMLDivElement>();
  const paneCount = (rsiSeries ? 1 : 0) + (macdSeries ? 1 : 0);
  const mainHeight = Math.max(100, stage.height - paneCount * (SUBPANE_HEIGHT + 6));

  // --- Header readout ----------------------------------------------------------
  const first = candles[0];
  const lastCandle = candles.at(-1);
  // The readout follows the drawn series, so a Heikin Ashi pane reads HA values.
  const shownPoint = points.find((p) => p.t === hoverT) ?? points.at(-1);
  const shownCandle =
    shownPoint !== undefined
      ? {
          t: shownPoint.t,
          o: shownPoint.o ?? shownPoint.v,
          h: shownPoint.h ?? shownPoint.v,
          l: shownPoint.l ?? shownPoint.v,
          c: shownPoint.v,
        }
      : undefined;
  const hi = candles.length ? Math.max(...candles.map((c) => c.h)) : null;
  const lo = candles.length ? Math.min(...candles.map((c) => c.l)) : null;
  const change =
    first && lastCandle && first.o > 0 ? ((lastCandle.c - first.o) / first.o) * 100 : null;
  const coinLabel = coins.find((c) => c.id === coinId)?.symbol ?? coinId;
  const label = source === 'chainlink' && feed ? feed.pair : coinLabel;
  const chainName = feed ? (registry.chainInfo(feed.chainId)?.name ?? feed.chainId) : null;

  const rsiAt = (t: number | null): number | null => {
    if (!rsiSeries || rsiSeries.length === 0) return null;
    const target = t ?? times.at(-1);
    if (target === undefined) return null;
    let best: Point | null = null;
    for (const p of rsiSeries) if (p.t <= target) best = p;
    return best?.v ?? null;
  };

  const lastTick = source === 'chainlink' ? feedSeries.ticks.at(-1) : null;
  const stale =
    source === 'chainlink' && feed && lastTick ? isStale(feed, lastTick.t, Date.now()) : false;
  const tickAgeMin = lastTick ? Math.max(0, Math.round((Date.now() - lastTick.t) / 60_000)) : null;

  const loading =
    candles.length === 0 &&
    !error &&
    !clError &&
    (source === 'coingecko'
      ? settings.coingecko
      : feedSeries.loading || feedSeries.ticks.length > 0);

  const toggleIndicator = (id: IndicatorId) => {
    const next = indicators.includes(id) ? indicators.filter((x) => x !== id) : [...indicators, id];
    setProps({ indicators: next.join(',') });
  };

  const macdTimes = times;
  const macdPanes = useMemo(() => {
    if (!macdSeries) return null;
    return {
      hist: toPoints(macdTimes, macdSeries.histogram),
      line: toPoints(macdTimes, macdSeries.macd),
      sig: toPoints(macdTimes, macdSeries.signal),
    };
  }, [macdSeries, macdTimes]);

  return (
    <div className="grid h-full grid-rows-[auto_minmax(100px,1fr)_auto] overflow-hidden text-[11px]">
      <header className="flex flex-col gap-1 px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <Select
            aria-label="Source"
            value={source}
            onChange={(e) => {
              const next = e.target.value === 'chainlink' ? 'chainlink' : 'coingecko';
              // An empty feedKey re-derives the pair from the selected coin.
              setProps(next === 'chainlink' ? { source: next } : { source: next, feedKey: '' });
            }}
          >
            <option value="coingecko">CoinGecko</option>
            <option value="chainlink">Chainlink on-chain</option>
          </Select>
          {source === 'coingecko' ? (
            <Select
              aria-label="Coin"
              value={coinId}
              onChange={(e) => setProps({ coinId: e.target.value, feedKey: '' })}
            >
              {!coins.some((c) => c.id === coinId) && <option value={coinId}>{coinId}</option>}
              {coins.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.symbol} · {c.name}
                  {feedForCoinId(c.id) ? ' ⛓' : ''}
                </option>
              ))}
            </Select>
          ) : (
            <Select
              aria-label="Chainlink pair"
              value={feed ? feedKey(feed) : ''}
              onChange={(e) => setProps({ feedKey: e.target.value })}
            >
              {feed && !feedByKey(feedKey(feed)) && (
                <option value={feedKey(feed)}>{feed.pair}</option>
              )}
              {[...new Set(CHAINLINK_FEEDS.map((f) => f.chainId))].map((cid) => (
                <optgroup key={cid} label={registry.chainInfo(cid)?.name ?? cid}>
                  {CHAINLINK_FEEDS.filter((f) => f.chainId === cid).map((f) => (
                    <option key={feedKey(f)} value={feedKey(f)}>
                      {f.pair}
                    </option>
                  ))}
                </optgroup>
              ))}
            </Select>
          )}
          {source === 'coingecko' ? (
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
          ) : (
            <Select
              aria-label="Timeframe"
              value={String(frameMs)}
              onChange={(e) => setProps({ frame: Number(e.target.value) })}
            >
              {FRAMES.map((f) => (
                <option key={f.ms} value={f.ms}>
                  {f.label}
                </option>
              ))}
            </Select>
          )}
          <Select
            aria-label="Chart type"
            value={chartType}
            onChange={(e) => setProps({ chartType: e.target.value })}
          >
            {CHART_TYPES.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          {INDICATORS.map((ind) => (
            <button
              key={ind.id}
              type="button"
              aria-pressed={indicators.includes(ind.id)}
              onClick={() => toggleIndicator(ind.id)}
              className={`border px-1.5 py-0.5 text-[10px] transition-colors ${
                indicators.includes(ind.id)
                  ? 'border-[var(--sw-edge-strong)] text-[var(--sw-ink)]'
                  : 'border-[var(--sw-edge)] text-[var(--sw-faint)] hover:text-[var(--sw-muted)]'
              }`}
            >
              {ind.label}
            </button>
          ))}
          <button
            type="button"
            aria-pressed={logScale}
            onClick={() => setProps({ log: !logScale })}
            className={`border px-1.5 py-0.5 text-[10px] transition-colors ${
              logScale
                ? 'border-[var(--sw-edge-strong)] text-[var(--sw-ink)]'
                : 'border-[var(--sw-edge)] text-[var(--sw-faint)] hover:text-[var(--sw-muted)]'
            }`}
          >
            log
          </button>
          <span className="text-faint">scroll to zoom · drag to pan · double-click to refit</span>
        </div>
        <p role="status" aria-live="polite" className="text-muted tabular-nums">
          {shownCandle
            ? `${label} · ${new Date(shownCandle.t).toLocaleString()} · O ${fmtUsd(shownCandle.o)} H ${fmtUsd(shownCandle.h)} L ${fmtUsd(shownCandle.l)} C ${fmtUsd(shownCandle.c)}`
            : error || clError
              ? ''
              : loading
                ? source === 'chainlink'
                  ? 'Reading rounds from the feed contract…'
                  : 'Loading candles…'
                : ''}
          {rsiSeries && rsiAt(hoverT) !== null ? ` · RSI ${rsiAt(hoverT)!.toFixed(1)}` : ''}
        </p>
        <p className="text-faint tabular-nums">
          {hi !== null && lo !== null && (
            <>
              range high {fmtUsd(hi)} · low {fmtUsd(lo)} · change {fmtPct(change)} ·{' '}
            </>
          )}
          {source === 'coingecko' ? (
            <>
              CoinGecko OHLC (USD)
              {set && set.dropped > 0 ? ` · ${set.dropped} inconsistent candles left out` : ''}
              {!settings.coingecko && ' · CoinGecko is turned off below'}
            </>
          ) : feed ? (
            <>
              Chainlink {feed.pair} on {chainName} · {feedSeries.ticks.length} rounds
              {feedSeries.exhausted ? ' (full history)' : ' · pan left for older'}
              {feed.heartbeatSec > 0
                ? ` · heartbeat ${feed.heartbeatSec >= 3600 ? `${Math.round(feed.heartbeatSec / 3600)}h` : `${Math.round(feed.heartbeatSec / 60)}m`}`
                : ''}
              {tickAgeMin !== null && (
                <span className={stale ? 'text-danger' : ''}>
                  {' '}
                  · updated {tickAgeMin}m ago{stale ? ' (stale)' : ''}
                </span>
              )}
            </>
          ) : (
            'No Chainlink feed covers this coin yet'
          )}
        </p>
        {source === 'coingecko' && !settings.coingecko && (
          <p className="text-faint">Candles come from CoinGecko, which is turned off below.</p>
        )}
        {source === 'chainlink' && !settings.chainlink && (
          <p className="text-faint">Chainlink reads are turned off below.</p>
        )}
        {source === 'chainlink' && !feed && (
          <p className="text-faint">Pick a pair above; {CHAINLINK_FEEDS.length} feeds are known.</p>
        )}
        {(error ?? clError) && <p className="text-danger">{error ?? clError}</p>}
      </header>
      <div ref={stageRef} className="relative min-h-[100px] min-w-0 overflow-hidden">
        {candles.length > 0 && stage.width > 0 && stage.height > 0 && (
          <div className="absolute inset-0 flex flex-col gap-1.5">
            <CanvasChart
              key={viewKey}
              ariaLabel={`${label} chart`}
              series={series}
              overlays={overlaySeries}
              width={stage.width}
              height={mainHeight}
              yFormat={fmtUsd}
              onHover={setHoverT}
              hoverT={hoverT}
              gridlines
              lastValuePill
              interactive
              viewport={viewport}
              onViewportChange={setViewport}
              onEdgeReach={onEdgeReach}
              logScale={logScale}
              resetKey={viewKey}
            />
            {rsiSeries && (
              <CanvasChart
                ariaLabel={`${label} RSI 14`}
                series={[
                  {
                    id: 'rsi',
                    label: 'RSI 14',
                    kind: 'line',
                    color: 'var(--sw-ink)',
                    points: rsiSeries,
                  },
                ]}
                overlays={[
                  {
                    id: 'rsi-70',
                    label: '70',
                    kind: 'line',
                    color: 'var(--sw-faint)',
                    dash: [1, 3],
                    points: guidePoints(times, 70),
                  },
                  {
                    id: 'rsi-30',
                    label: '30',
                    kind: 'line',
                    color: 'var(--sw-faint)',
                    dash: [1, 3],
                    points: guidePoints(times, 30),
                  },
                ]}
                width={stage.width}
                height={SUBPANE_HEIGHT}
                yFormat={(v) => v.toFixed(0)}
                onHover={setHoverT}
                hoverT={hoverT}
                gridlines={false}
                lastValuePill
                nonnegative
                interactive
                viewport={viewport}
                onViewportChange={setViewport}
                resetKey={viewKey}
              />
            )}
            {macdPanes && (
              <CanvasChart
                ariaLabel={`${label} MACD`}
                series={[
                  {
                    id: 'macd-h',
                    label: 'histogram',
                    kind: 'bars',
                    color: 'var(--sw-faint)',
                    points: macdPanes.hist,
                  },
                  {
                    id: 'macd-l',
                    label: 'MACD',
                    kind: 'line',
                    color: 'var(--sw-ink)',
                    points: macdPanes.line,
                  },
                  {
                    id: 'macd-s',
                    label: 'signal',
                    kind: 'line',
                    color: 'var(--sw-muted)',
                    dash: [4, 3],
                    points: macdPanes.sig,
                  },
                ]}
                width={stage.width}
                height={SUBPANE_HEIGHT}
                yFormat={(v) => v.toPrecision(3)}
                onHover={setHoverT}
                hoverT={hoverT}
                gridlines={false}
                lastValuePill={false}
                interactive
                viewport={viewport}
                onViewportChange={setViewport}
                resetKey={viewKey}
              />
            )}
          </div>
        )}
      </div>
      <div className="px-3 py-1">
        <SourcesPanel />
      </div>
    </div>
  );
}

/** Horizontal guide levels for a subpane, spanning the loaded range. */
function guidePoints(times: readonly number[], v: number): Point[] {
  const first = times[0];
  const last = times.at(-1);
  if (first === undefined || last === undefined || first === last) return [];
  return [
    { t: first, v },
    { t: last, v },
  ];
}
