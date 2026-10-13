import { fetchJson, type FetchOptions } from '@stackwallet/chains';
import { z } from 'zod';

/**
 * ERC-20 tokens an address holds, as an indexer reports them. These are
 * suggestions only: names and symbols are attacker-chosen, so nothing here
 * is tracked until the user picks it, and tracking re-reads the metadata
 * from the contract itself.
 */
export interface DiscoveredToken {
  chainId: string;
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  /** Base units, as the indexer reports them. */
  balance: string;
  /** The indexer flagged the token (spam, scam); kept but marked. */
  flagged: boolean;
}

const Row = z.object({
  token: z.object({
    address_hash: z.string().max(64).optional(),
    address: z.string().max(64).optional(),
    symbol: z.string().max(400).nullish(),
    name: z.string().max(400).nullish(),
    decimals: z.union([z.string().max(4), z.number()]).nullish(),
    type: z.string().max(32).nullish(),
    reputation: z.string().max(32).nullish(),
  }),
  value: z.string().max(100).nullish(),
});

const ADDR = /^0x[0-9a-fA-F]{40}$/;
const clean = (s: string | null | undefined, max: number) =>
  (s ?? '')
    .replace(/[^\x20-\x7e]/g, '')
    .trim()
    .slice(0, max);

export function parseTokenBalances(chainId: string, raw: unknown): DiscoveredToken[] {
  const rows = z.array(Row).max(1000).parse(raw);
  const out: DiscoveredToken[] = [];
  for (const r of rows) {
    if (r.token.type !== 'ERC-20') continue;
    const address = r.token.address_hash ?? r.token.address ?? '';
    const decimals = Number(r.token.decimals ?? NaN);
    const balance = r.value ?? '0';
    if (!ADDR.test(address) || !Number.isInteger(decimals) || decimals < 0 || decimals > 36)
      continue;
    if (!/^\d{1,80}$/.test(balance) || BigInt(balance) === 0n) continue;
    const symbol = clean(r.token.symbol, 12);
    if (symbol === '') continue;
    out.push({
      chainId,
      address: address.toLowerCase(),
      symbol,
      name: clean(r.token.name, 60) || symbol,
      decimals,
      balance,
      flagged: r.token.reputation != null && r.token.reputation !== 'ok',
    });
  }
  return out;
}

export async function discoverTokens(opts: {
  chainId: string;
  owner: string;
  indexer: string;
  fetchOptions?: FetchOptions;
}): Promise<DiscoveredToken[]> {
  if (!ADDR.test(opts.owner)) throw new TypeError(`invalid evm address ${opts.owner}`);
  const url = `${opts.indexer.replace(/\/+$/, '')}/api/v2/addresses/${opts.owner}/token-balances`;
  return parseTokenBalances(opts.chainId, await fetchJson(url, opts.fetchOptions));
}
