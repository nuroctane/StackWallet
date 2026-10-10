import { describe, expect, it } from 'vitest';
import type { Account } from '@stackwallet/core-client';
import type { ChainInfo } from '@stackwallet/chains';

import type { BalanceEntry } from './balances.js';
import { aggregateNative } from './totals.js';

const chains: Record<string, ChainInfo> = {
  'eip155:1': {
    chainId: 'eip155:1',
    family: 'evm',
    name: 'Ethereum',
    nativeAsset: { ref: 'eip155:1/slip44:60', symbol: 'ETH', decimals: 18 },
    testnet: false,
    defaultRpcs: [],
  },
  'bip122:000000000019d6689c085ae165831e93': {
    chainId: 'bip122:000000000019d6689c085ae165831e93',
    family: 'bitcoin',
    name: 'Bitcoin',
    nativeAsset: {
      ref: 'bip122:000000000019d6689c085ae165831e93/slip44:0',
      symbol: 'BTC',
      decimals: 8,
    },
    testnet: false,
    defaultRpcs: [],
  },
};
const lookup = (id: string) => chains[id];

function account(id: string, chainId: string): Account {
  return {
    id,
    walletId: `w-${id}`,
    family: chainId.startsWith('eip155') ? 'evm' : 'bitcoin',
    chainId,
    address: `addr-${id}`,
    publicKeyHex: '',
    hidden: false,
  };
}

function entry(assetRef: string, amount: string, fetchedAtMs = 1_000): BalanceEntry {
  return {
    holdings: [{ assetRef, amount, updatedAtMs: fetchedAtMs }],
    fetchedAtMs,
    loading: false,
  };
}

const ETH = 'eip155:1/slip44:60';
const BTC = 'bip122:000000000019d6689c085ae165831e93/slip44:0';
const btcChain = 'bip122:000000000019d6689c085ae165831e93';

describe('aggregateNative', () => {
  it('sums per native asset with bigint and sorts by account count', () => {
    const accounts = [account('a', 'eip155:1'), account('b', 'eip155:1'), account('c', btcChain)];
    const balances = new Map<string, BalanceEntry>([
      ['a', entry(ETH, '1000000000000000000')],
      ['b', entry(ETH, '4768000000000000000')],
      ['c', entry(BTC, '31000000')],
    ]);
    const out = aggregateNative(accounts, balances, lookup, { now: 1_000 });
    expect(out).toEqual([
      {
        assetRef: ETH,
        symbol: 'ETH',
        decimals: 18,
        amount: '5768000000000000000',
        accounts: 2,
        incomplete: false,
        disputed: false,
      },
      {
        assetRef: BTC,
        symbol: 'BTC',
        decimals: 8,
        amount: '31000000',
        accounts: 1,
        incomplete: false,
        disputed: false,
      },
    ]);
  });

  it('marks incomplete for missing, errored and stale entries but keeps the partial sum', () => {
    const accounts = [account('a', 'eip155:1'), account('b', 'eip155:1'), account('c', 'eip155:1')];
    const balances = new Map<string, BalanceEntry | undefined>([
      ['a', entry(ETH, '5')],
      ['b', undefined],
    ]);
    const missing = aggregateNative(accounts, balances, lookup, { now: 1_000 });
    expect(missing[0]).toMatchObject({ amount: '5', accounts: 3, incomplete: true });

    const errored = new Map<string, BalanceEntry>([
      ['a', entry(ETH, '5')],
      ['b', { holdings: [], fetchedAtMs: 1_000, loading: false, error: 'rpc down' }],
      ['c', entry(ETH, '7')],
    ]);
    expect(aggregateNative(accounts, errored, lookup, { now: 1_000 })[0]).toMatchObject({
      amount: '12',
      incomplete: true,
    });

    const stale = new Map<string, BalanceEntry>([
      ['a', entry(ETH, '5', 500)],
      ['b', entry(ETH, '5', 1_000)],
      ['c', entry(ETH, '5', 1_000)],
    ]);
    expect(aggregateNative(accounts, stale, lookup, { now: 1_000, staleMs: 10 })[0]).toMatchObject({
      amount: '15',
      incomplete: true,
      disputed: false,
    });
    const fresh = new Map<string, BalanceEntry>([
      ['a', entry(ETH, '5', 995)],
      ['b', entry(ETH, '5', 1_000)],
      ['c', entry(ETH, '5', 1_000)],
    ]);
    expect(
      aggregateNative(accounts, fresh, lookup, { now: 1_000, staleMs: 10 })[0]?.incomplete,
    ).toBe(false);
  });

  it('marks a total disputed and incomplete when two endpoints disagreed on an account', () => {
    const accounts = [account('a', 'eip155:1'), account('b', 'eip155:1')];
    const disputed: BalanceEntry = {
      holdings: [
        {
          assetRef: ETH,
          amount: '5',
          updatedAtMs: 1_000,
          provenance: {
            kind: 'disagreed',
            endpoints: ['https://a.example', 'https://b.example'],
            other: '6',
          },
        },
      ],
      fetchedAtMs: 1_000,
      loading: false,
    };
    const balances = new Map<string, BalanceEntry>([
      ['a', disputed],
      ['b', entry(ETH, '7')],
    ]);
    expect(aggregateNative(accounts, balances, lookup, { now: 1_000 })[0]).toMatchObject({
      amount: '12',
      accounts: 2,
      incomplete: true,
      disputed: true,
    });
  });

  it('treats a fetched account with no native holding as zero and skips unknown chains', () => {
    const accounts = [account('a', 'eip155:1'), account('x', 'eip155:999999')];
    const balances = new Map<string, BalanceEntry>([
      ['a', { holdings: [], fetchedAtMs: 1_000, loading: false }],
      ['x', entry('eip155:999999/slip44:60', '9')],
    ]);
    const out = aggregateNative(accounts, balances, lookup, { now: 1_000 });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ symbol: 'ETH', amount: '0', accounts: 1, incomplete: false });
  });

  it('returns nothing for no accounts', () => {
    expect(aggregateNative([], new Map(), lookup)).toEqual([]);
  });
});
