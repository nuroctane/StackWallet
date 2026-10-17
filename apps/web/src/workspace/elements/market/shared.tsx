import { useEffect, useMemo } from 'react';
import type { ChainRegistry } from '@stackwallet/chains';
import { coinIdFor, SOURCE_LABEL, type MarketSource, type Quote } from '@stackwallet/market';

import { findChain } from '../../../lib/chains.js';
import { marketSettings, useMarketSettings, useWatchlist } from '../../../store/market.js';
import { useDirectory } from '../../../store/persist.js';
import { priceStore, usePriceErrors } from '../../../store/prices.js';
import { useRegistry } from '../../../store/RegistryContext.js';
import { elementDefaults } from '../../defaults.js';
import { workspace } from '../../persist.js';
import { getCanvasViewport } from '../../WorkspaceContext.js';

export interface CoinOption {
  id: string;
  symbol: string;
  name: string;
  held: boolean;
}

/** The market id of a native asset ref (`<chainId>:native`), or null for testnets and unknowns. */
export function coinIdForAssetRef(registry: ChainRegistry, assetRef: string): string | null {
  const chain = findChain(registry, assetRef.slice(0, assetRef.lastIndexOf(':')));
  return chain ? coinIdFor(chain) : null;
}

/** Mainnet native coins the directory holds, then the watchlist, deduplicated by id. */
export function useCoinOptions(): CoinOption[] {
  const state = useDirectory();
  const registry = useRegistry();
  const list = useWatchlist();
  return useMemo(() => {
    const out = new Map<string, CoinOption>();
    for (const a of state.accounts) {
      const chain = findChain(registry, a.chainId);
      const id = chain ? coinIdFor(chain) : null;
      if (chain && id && !out.has(id))
        out.set(id, {
          id,
          symbol: chain.nativeAsset.symbol,
          name: chain.name,
          held: true,
        });
    }
    for (const w of list)
      if (!out.has(w.id)) out.set(w.id, { id: w.id, symbol: w.symbol, name: w.name, held: false });
    return [...out.values()];
  }, [state.accounts, registry, list]);
}

const usd = (max: number) =>
  new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: max,
    minimumFractionDigits: Math.min(2, max),
  });
const USD2 = usd(2);
const USD4 = usd(4);
const USD8 = usd(8);

export function fmtUsd(v: number): string {
  if (!Number.isFinite(v)) return '—';
  const abs = Math.abs(v);
  return (abs >= 1 ? USD2 : abs >= 0.01 ? USD4 : USD8).format(v);
}

export function fmtPct(v: number | null): string {
  if (v === null || !Number.isFinite(v)) return '—';
  return `${v > 0 ? '+' : ''}${v.toFixed(2)}%`;
}

/** Source names, agreement and age of a quote; divergence is flagged, never hidden. */
export function QuoteProvenance({ quote, now }: { quote: Quote; now: number }) {
  const ageMin = Math.max(0, Math.round((now - quote.fetchedAtMs) / 60_000));
  const names = quote.sources.map((s) => SOURCE_LABEL[s.source]).join(' + ');
  const detail = quote.sources
    .map(
      (s) =>
        `${SOURCE_LABEL[s.source]} ${fmtUsd(s.usd)} @ ${new Date(s.observedAtMs).toLocaleTimeString()}`,
    )
    .join('\n');
  return (
    <span title={detail} className="whitespace-nowrap text-faint">
      {names}
      {quote.confidence === 'divergent' ? (
        <span className="text-danger"> · sources differ {quote.spreadPct.toFixed(1)}%</span>
      ) : quote.confidence === 'agreed' ? (
        ' · agree'
      ) : (
        ''
      )}
      {ageMin >= 1 ? ` · ${ageMin}m` : ''}
    </span>
  );
}

const SOURCES: readonly MarketSource[] = ['coingecko', 'defillama', 'chainlink'];

const SOURCE_NOTE: Readonly<Record<MarketSource, string>> = {
  coingecko: 'prices, 24h change, candles, history and search',
  defillama: 'second price for a cross-check',
  chainlink: 'on-chain oracle prices and candle history through your EVM endpoints',
};

/**
 * Which providers may be contacted. Turning one off stops every request to it
 * at once; cached quotes are dropped so nothing shown still claims it.
 */
export function SourcesPanel() {
  const settings = useMarketSettings();
  const errors = usePriceErrors();
  return (
    <details className="text-[11px]">
      <summary className="cursor-pointer py-1 text-faint">
        Market data sources ·{' '}
        {SOURCES.filter((s) => settings[s])
          .map((s) => SOURCE_LABEL[s])
          .join(', ') || 'all off'}
      </summary>
      <div className="mt-1 flex flex-col gap-1 text-muted">
        <p className="text-faint">
          Requests go straight from this device to the provider and name coins only, never your
          addresses. The provider still learns which coins you look at.
        </p>
        {SOURCES.map((s) => (
          <label key={s} className="flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={settings[s]}
              onChange={(e) => {
                marketSettings.toggle(s, e.target.checked);
                priceStore.clear();
              }}
              className="accent-[var(--sw-ink)]"
            />
            {SOURCE_LABEL[s]} <span className="text-faint">· {SOURCE_NOTE[s]}</span>
          </label>
        ))}
        {errors.map((e) => (
          <p key={e.source} className="text-danger">
            {SOURCE_LABEL[e.source]}: {e.message}
          </p>
        ))}
      </div>
    </details>
  );
}

/** Re-ask for quotes on a clock while mounted so open market views stay current. */
export function useQuoteRefresh(ids: readonly string[], everyMs = 60_000): void {
  const key = [...new Set(ids)].sort().join(',');
  useEffect(() => {
    if (!key) return;
    const id = setInterval(() => void priceStore.want(key.split(',')), everyMs);
    return () => clearInterval(id);
  }, [key, everyMs]);
}

/** Point an open candles pane at a coin, or open one. */
export function showCandles(coinId: string): void {
  const existing = workspace.findPane('candles');
  if (existing) {
    workspace.setProps(existing.id, { coinId });
    workspace.raise(existing.id);
    workspace.focus(existing.id);
    return;
  }
  const size = elementDefaults.candles;
  workspace.addPane(
    { kind: 'candles', props: { coinId, days: 30 }, w: size.w, h: size.h },
    getCanvasViewport(),
  );
}
