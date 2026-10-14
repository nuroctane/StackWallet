import { useState, type FormEvent } from 'react';
import { searchAssets, type AssetHit } from '@stackwallet/market';
import { Button, Input } from '@stackwallet/ui';

import { marketClient, useMarketSettings, watchlist } from '../../../store/market.js';
import { usePrices } from '../../../store/prices.js';
import type { ElementBodyProps } from '../types.js';
import {
  fmtPct,
  fmtUsd,
  QuoteProvenance,
  showCandles,
  SourcesPanel,
  useCoinOptions,
  useQuoteRefresh,
} from './shared.js';

export function WatchlistElement(_: ElementBodyProps) {
  const coins = useCoinOptions();
  const ids = coins.map((c) => c.id);
  const quote = usePrices(ids);
  useQuoteRefresh(ids);
  const settings = useMarketSettings();
  const now = Date.now();
  const anySource = settings.coingecko || settings.defillama;

  return (
    <div className="flex h-full min-h-0 flex-col gap-2 overflow-auto p-3 text-[12px]">
      {!anySource && (
        <p className="text-faint">All market sources are off; no prices are fetched.</p>
      )}
      {coins.length === 0 ? (
        <p className="text-faint">
          No mainnet coins held and nothing watched. Search below to watch a coin. Testnet coins
          have no market price.
        </p>
      ) : (
        <table className="w-full table-fixed border-collapse tabular-nums">
          <thead className="text-left text-[11px] text-faint">
            <tr>
              <th className="w-[30%] py-1 font-normal">asset</th>
              <th className="w-[22%] py-1 text-right font-normal">price</th>
              <th className="w-[16%] py-1 text-right font-normal">24h</th>
              <th className="py-1 pl-3 font-normal">source</th>
              <th className="w-[72px] py-1" />
            </tr>
          </thead>
          <tbody className="divide-y divide-edge">
            {coins.map((c) => {
              const q = quote(c.id);
              return (
                <tr key={c.id}>
                  <td className="truncate py-1.5" title={`${c.name} · ${c.id}`}>
                    <span className="text-ink">{c.symbol}</span>{' '}
                    <span className="text-faint">{c.held ? 'held' : c.name}</span>
                  </td>
                  <td className="py-1.5 text-right text-ink">{q ? fmtUsd(q.usd) : '—'}</td>
                  <td className="py-1.5 text-right text-muted">
                    {q ? `${(q.change24hPct ?? 0) < 0 ? '▼' : '▲'} ${fmtPct(q.change24hPct)}` : '—'}
                  </td>
                  <td className="truncate py-1.5 pl-3">
                    {q ? (
                      <QuoteProvenance quote={q} now={now} />
                    ) : (
                      <span className="text-faint">no quote</span>
                    )}
                  </td>
                  <td className="py-1.5 text-right">
                    <span className="flex justify-end gap-1">
                      <Button size="sm" variant="ghost" onClick={() => showCandles(c.id)}>
                        chart
                      </Button>
                      {!c.held && (
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-label={`Stop watching ${c.symbol}`}
                          onClick={() => watchlist.remove(c.id)}
                        >
                          ×
                        </Button>
                      )}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <Search disabled={!settings.coingecko} watched={new Set(ids)} />
      <SourcesPanel />
    </div>
  );
}

function Search({ disabled, watched }: { disabled: boolean; watched: ReadonlySet<string> }) {
  const [query, setQuery] = useState('');
  const [hits, setHits] = useState<AssetHit[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setHits(await searchAssets(marketClient, query));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (disabled)
    return <p className="text-faint">Search needs CoinGecko, which is turned off below.</p>;
  return (
    <div className="flex flex-col gap-1">
      <form onSubmit={submit} className="flex gap-2">
        <Input
          aria-label="Search coins"
          placeholder="search coins (sent to CoinGecko)"
          value={query}
          maxLength={60}
          onChange={(e) => setQuery(e.target.value)}
        />
        <Button type="submit" size="sm" disabled={busy || query.trim().length < 2}>
          {busy ? '…' : 'Search'}
        </Button>
      </form>
      {error && <p className="text-danger">{error}</p>}
      {hits && hits.length === 0 && <p className="text-faint">No matches.</p>}
      {hits && hits.length > 0 && (
        <ul className="flex flex-col divide-y divide-edge">
          {hits.map((h) => (
            <li key={h.id} className="flex items-center justify-between gap-2 py-1">
              <span className="min-w-0 truncate">
                <span className="text-ink">{h.symbol}</span>{' '}
                <span className="text-muted">{h.name}</span>{' '}
                <span className="text-faint">
                  {h.rank ? `#${h.rank}` : 'unranked'} · {h.id}
                </span>
              </span>
              <Button
                size="sm"
                variant="ghost"
                disabled={watched.has(h.id)}
                onClick={() => watchlist.add({ id: h.id, symbol: h.symbol, name: h.name })}
              >
                {watched.has(h.id) ? 'watching' : '+ watch'}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
