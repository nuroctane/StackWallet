import { COINGECKO_API, parseHistory, validIds, type MarketClient } from '@stackwallet/market';

import type { Fiat } from './jurisdictions.js';
import type { PricePoint } from './model.js';

/**
 * Daily prices in the report currency from CoinGecko's keyless market-chart
 * endpoint. The request names a coin (or a token contract) and a currency,
 * never an address or an amount. The public tier only serves the last 365
 * days; anything older is reported as missing for the user to fill in.
 */

export const PRICE_SERIES_TTL_MS = 6 * 3_600_000;
export const PRICE_HISTORY_DAYS = 365;

/** CoinGecko asset platforms for token contracts on mainnets. */
export const TOKEN_PLATFORMS: Readonly<Record<string, string>> = {
  'eip155:1': 'ethereum',
  'eip155:10': 'optimistic-ethereum',
  'eip155:56': 'binance-smart-chain',
  'eip155:100': 'xdai',
  'eip155:137': 'polygon-pos',
  'eip155:324': 'zksync',
  'eip155:8453': 'base',
  'eip155:42161': 'arbitrum-one',
  'eip155:43114': 'avalanche',
  'eip155:59144': 'linea',
  'eip155:534352': 'scroll',
  'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp': 'solana',
};

const CONTRACT = /^(0x[0-9a-f]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/;

export function tokenPriceKey(chainId: string, contract: string): string | null {
  const platform = TOKEN_PLATFORMS[chainId];
  if (!platform || !CONTRACT.test(contract)) return null;
  return `${platform}/${contract}`;
}

export function priceSeriesUrl(key: string, fiat: Fiat): string {
  const slash = key.indexOf('/');
  const q = `market_chart?vs_currency=${fiat}&days=${PRICE_HISTORY_DAYS}&interval=daily`;
  if (slash < 0) {
    if (validIds([key]).length !== 1) throw new Error('not a coin id');
    return `${COINGECKO_API}/coins/${key}/${q}`;
  }
  const platform = key.slice(0, slash);
  const contract = key.slice(slash + 1);
  if (!Object.values(TOKEN_PLATFORMS).includes(platform) || !CONTRACT.test(contract))
    throw new Error('not a token price key');
  return `${COINGECKO_API}/coins/${platform}/contract/${contract}/${q}`;
}

export async function fetchPriceSeries(
  client: MarketClient,
  key: string,
  fiat: Fiat,
): Promise<PricePoint[]> {
  const raw = await client.getJson('coingecko', priceSeriesUrl(key, fiat), PRICE_SERIES_TTL_MS);
  return parseHistory(raw).points.map((p) => ({ t: p.t, v: p.usd }));
}
