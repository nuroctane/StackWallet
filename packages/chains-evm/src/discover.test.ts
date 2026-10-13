import { describe, expect, it } from 'vitest';

import { parseTokenBalances } from './discover.js';

const T = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

describe('token discovery', () => {
  it('keeps held ERC-20s with sane metadata and marks flagged ones', () => {
    const rows = [
      {
        token: { address_hash: T, symbol: 'USDC', name: 'USD Coin', decimals: '6', type: 'ERC-20' },
        value: '5',
      },
      {
        token: {
          address_hash: T.replace('a', 'b'),
          symbol: 'FREE‮GIFT',
          decimals: '18',
          type: 'ERC-20',
          reputation: 'scam',
        },
        value: '1',
      },
      {
        token: {
          address_hash: T.replace('a', 'c'),
          symbol: 'NFT',
          decimals: null,
          type: 'ERC-721',
        },
        value: '1',
      },
      {
        token: {
          address_hash: T.replace('a', 'd'),
          symbol: 'ZERO',
          decimals: '18',
          type: 'ERC-20',
        },
        value: '0',
      },
      { token: { address_hash: 'nope', symbol: 'X', decimals: '18', type: 'ERC-20' }, value: '1' },
    ];
    const got = parseTokenBalances('eip155:1', rows);
    expect(got.map((t) => [t.symbol, t.flagged])).toEqual([
      ['USDC', false],
      ['FREEGIFT', true],
    ]);
    expect(got[0]).toMatchObject({ address: T, decimals: 6, balance: '5', name: 'USD Coin' });
  });
});
