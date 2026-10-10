import type { Account } from '@stackwallet/core-client';
import type { ChainInfo } from '@stackwallet/chains';

import { BALANCE_STALE_MS, type BalanceEntry } from './balances.js';

export interface NativeTotal {
  assetRef: string;
  symbol: string;
  decimals: number;
  /** Base units as a decimal string; summed with bigint so 18-decimal chains keep every digit. */
  amount: string;
  /** Accounts that reference this asset, whether or not their balance has loaded. */
  accounts: number;
  /** True when any contributing account is missing, errored, stale or disputed, so the sum is a floor. */
  incomplete: boolean;
  /** True when two endpoints reported different balances for a contributing account. */
  disputed: boolean;
}

export interface AggregateOptions {
  now?: number;
  staleMs?: number;
}

/**
 * Per-native-asset sum across accounts. Only the chain's native asset is
 * summed because there is no token registry yet to name anything else.
 * Accounts on chains the registry does not know cannot be attributed to an
 * asset and are left out rather than invented.
 */
export function aggregateNative(
  accounts: readonly Account[],
  balancesByAccount: ReadonlyMap<string, BalanceEntry | undefined>,
  chainInfoLookup: (chainId: string) => ChainInfo | undefined,
  options: AggregateOptions = {},
): NativeTotal[] {
  const now = options.now ?? Date.now();
  // The cache refetches right at BALANCE_STALE_MS, so judging staleness at the
  // same boundary would flag every total as partial for the duration of each
  // periodic refresh. Two intervals means "a refresh has actually been missed".
  const staleMs = options.staleMs ?? BALANCE_STALE_MS * 2;

  const byAsset = new Map<string, { total: NativeTotal; sum: bigint }>();
  for (const account of accounts) {
    const info = chainInfoLookup(account.chainId);
    if (!info) continue;
    const ref = info.nativeAsset.ref;
    let slot = byAsset.get(ref);
    if (!slot) {
      slot = {
        sum: 0n,
        total: {
          assetRef: ref,
          symbol: info.nativeAsset.symbol,
          decimals: info.nativeAsset.decimals,
          amount: '0',
          accounts: 0,
          incomplete: false,
          disputed: false,
        },
      };
      byAsset.set(ref, slot);
    }
    slot.total.accounts += 1;

    const entry = balancesByAccount.get(account.id);
    const usable = entry && !entry.error && entry.fetchedAtMs > 0;
    if (!usable) {
      slot.total.incomplete = true;
      continue;
    }
    if (now - entry.fetchedAtMs >= staleMs) slot.total.incomplete = true;
    const native = entry.holdings.find((h) => h.assetRef === ref);
    if (native?.provenance?.kind === 'disagreed') {
      // A disputed balance still counts toward the floor, but the total cannot
      // be called complete when one of its inputs is contested.
      slot.total.incomplete = true;
      slot.total.disputed = true;
    }
    if (native && /^\d+$/.test(native.amount)) slot.sum += BigInt(native.amount);
  }

  return [...byAsset.values()]
    .map(({ total, sum }) => ({ ...total, amount: sum.toString() }))
    .sort((a, b) => b.accounts - a.accounts || a.symbol.localeCompare(b.symbol));
}
