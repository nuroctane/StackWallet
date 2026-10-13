import { fetchJson, type ChainInfo, type FetchOptions } from '@stackwallet/chains';
import { z } from 'zod';

/**
 * USD prices for native assets, fetched by the client from CoinGecko's
 * public, keyless endpoint (D3, D8: no server of ours, no key, no tracking;
 * the request names coins, never addresses). Testnet assets have no price by
 * definition, and an asset without a known id simply has none: nothing here
 * guesses.
 */

export const COINGECKO_API = 'https://api.coingecko.com/api/v3';

/** Native symbol → CoinGecko id, for the mainnets in the bundled catalog. */
export const NATIVE_IDS: Readonly<Record<string, string>> = {
  ETH: 'ethereum',
  BTC: 'bitcoin',
  SOL: 'solana',
  ATOM: 'cosmos',
  OSMO: 'osmosis',
  BNB: 'binancecoin',
  POL: 'polygon-ecosystem-token',
  AVAX: 'avalanche-2',
  LTC: 'litecoin',
  DOGE: 'dogecoin',
  xDAI: 'xdai',
  CELO: 'celo',
  CRO: 'crypto-com-chain',
  MNT: 'mantle',
  METIS: 'metis-token',
  GLMR: 'moonbeam',
  S: 'sonic-3',
  BERA: 'berachain-bera',
  TIA: 'celestia',
  INJ: 'injective-protocol',
  RUNE: 'thorchain',
  JUNO: 'juno-network',
  KAVA: 'kava',
  SCRT: 'secret',
  STRD: 'stride',
  NTRN: 'neutron-3',
  DYDX: 'dydx-chain',
  AXL: 'axelar',
  OM: 'mantra-dao',
  SEI: 'sei-network',
  BABY: 'babylon',
  USDC: 'usd-coin',
  frxETH: 'frax-ether',
  tBTC: 'tbtc',
};

export function coinIdFor(chain: Pick<ChainInfo, 'testnet' | 'nativeAsset'>): string | null {
  if (chain.testnet) return null;
  return NATIVE_IDS[chain.nativeAsset.symbol] ?? null;
}

export interface UsdPrice {
  id: string;
  usd: number;
  fetchedAtMs: number;
}

const Response = z.record(
  z.string().max(80),
  z.object({ usd: z.number().finite().nonnegative().max(1e12).optional() }),
);

export function parsePrices(raw: unknown, now: number): UsdPrice[] {
  const parsed = Response.parse(raw);
  const out: UsdPrice[] = [];
  for (const [id, v] of Object.entries(parsed))
    if (v.usd !== undefined) out.push({ id, usd: v.usd, fetchedAtMs: now });
  return out;
}

export async function fetchUsdPrices(
  ids: readonly string[],
  opts: { fetchOptions?: FetchOptions; now?: () => number } = {},
): Promise<UsdPrice[]> {
  const unique = [...new Set(ids)].filter((id) => /^[a-z0-9-]{1,80}$/.test(id)).sort();
  if (unique.length === 0) return [];
  const url = `${COINGECKO_API}/simple/price?ids=${unique.join(',')}&vs_currencies=usd`;
  return parsePrices(await fetchJson(url, opts.fetchOptions), (opts.now ?? Date.now)());
}

/**
 * USD value of `amount` base units at `usd` per whole coin, in micro-dollars,
 * computed with integers so 18-decimal amounts keep their precision.
 */
export function usdMicros(amount: string, decimals: number, usd: number): bigint {
  if (!/^\d+$/.test(amount) || !Number.isFinite(usd) || usd < 0) return 0n;
  // Price to 1e-6 dollars, then scale by the amount and drop the decimals.
  const microsPerCoin = BigInt(Math.round(usd * 1e6));
  return (BigInt(amount) * microsPerCoin) / 10n ** BigInt(decimals);
}

export function formatUsd(micros: bigint): string {
  const cents = (micros + 5_000n) / 10_000n;
  const whole = cents / 100n;
  const frac = (cents % 100n).toString().padStart(2, '0');
  return `$${whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')}.${frac}`;
}
