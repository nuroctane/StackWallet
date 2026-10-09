import { describe, expect, it } from 'vitest';
import type { ChainInfo } from '@stackwallet/chains';

import { explorerAddressUrl } from './chains.js';

const base: ChainInfo = {
  chainId: 'eip155:1',
  family: 'evm',
  name: 'Ethereum',
  nativeAsset: { ref: 'eip155:1/slip44:60', symbol: 'ETH', decimals: 18 },
  testnet: false,
  defaultRpcs: [],
};

describe('explorerAddressUrl', () => {
  it('derives /address/ from an etherscan-style tx template', () => {
    expect(
      explorerAddressUrl({ ...base, explorerTxUrl: 'https://etherscan.io/tx/{hash}' }, '0xabc'),
    ).toBe('https://etherscan.io/address/0xabc');
  });

  it('uses /account/ for solana and keeps cluster params', () => {
    expect(
      explorerAddressUrl(
        {
          ...base,
          chainId: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
          family: 'solana',
          explorerTxUrl: 'https://explorer.solana.com/tx/{hash}?cluster=devnet',
        },
        'So11111111111111111111111111111111111111112',
      ),
    ).toBe(
      'https://explorer.solana.com/account/So11111111111111111111111111111111111111112?cluster=devnet',
    );
  });

  it('returns nothing when the template has no /tx/ segment or no template', () => {
    expect(explorerAddressUrl(base, '0xabc')).toBeUndefined();
    expect(
      explorerAddressUrl(
        { ...base, explorerTxUrl: 'https://example.org/lookup?h={hash}' },
        '0xabc',
      ),
    ).toBeUndefined();
  });

  it('refuses non-https templates', () => {
    expect(
      explorerAddressUrl({ ...base, explorerTxUrl: 'http://example.org/tx/{hash}' }, '0xabc'),
    ).toBeUndefined();
  });
});
