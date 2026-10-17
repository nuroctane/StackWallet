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

  it('maps Tronscan fragment routes to the address page', () => {
    expect(
      explorerAddressUrl(
        { ...base, explorerTxUrl: 'https://nile.tronscan.org/#/transaction/{hash}' },
        'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
      ),
    ).toBe('https://nile.tronscan.org/#/address/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t');
    expect(
      explorerAddressUrl({ ...base, explorerTxUrl: 'http://x.org/#/transaction/{hash}' }, 'T1'),
    ).toBeUndefined();
  });

  it('maps the Aptos, XRPL and IOTA explorer routes', () => {
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'aptos',
          explorerTxUrl: 'https://explorer.aptoslabs.com/txn/{hash}?network=testnet',
        },
        '0x1',
      ),
    ).toBe('https://explorer.aptoslabs.com/account/0x1?network=testnet');
    expect(
      explorerAddressUrl(
        { ...base, family: 'xrpl', explorerTxUrl: 'https://testnet.xrpl.org/transactions/{hash}' },
        'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe',
      ),
    ).toBe('https://testnet.xrpl.org/accounts/rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'sui',
          explorerTxUrl: 'https://explorer.iota.org/txblock/{hash}?network=mainnet',
        },
        '0x2',
      ),
    ).toBe('https://explorer.iota.org/address/0x2?network=mainnet');
    expect(
      explorerAddressUrl(
        { ...base, family: 'sui', explorerTxUrl: 'https://suiscan.xyz/testnet/tx/{hash}' },
        '0x2',
      ),
    ).toBe('https://suiscan.xyz/testnet/account/0x2');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'algorand',
          explorerTxUrl: 'https://lora.algokit.io/testnet/transaction/{hash}',
        },
        'A1',
      ),
    ).toBe('https://lora.algokit.io/testnet/account/A1');
    expect(
      explorerAddressUrl(
        { ...base, family: 'tezos', explorerTxUrl: 'https://shadownet.tzkt.io/{hash}' },
        'tz1abc',
      ),
    ).toBe('https://shadownet.tzkt.io/tz1abc');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'stacks',
          explorerTxUrl: 'https://explorer.hiro.so/txid/{hash}?chain=testnet',
        },
        'ST1',
      ),
    ).toBe('https://explorer.hiro.so/address/ST1?chain=testnet');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'vechain',
          explorerTxUrl: 'https://insight.vecha.in/#/test/txs/{hash}',
        },
        '0xabc',
      ),
    ).toBe('https://insight.vecha.in/#/test/accounts/0xabc');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'starknet',
          explorerTxUrl: 'https://sepolia.voyager.online/tx/{hash}',
        },
        '0x123',
      ),
    ).toBe('https://sepolia.voyager.online/contract/0x123');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'cardano',
          explorerTxUrl: 'https://preprod.cardanoscan.io/transaction/{hash}',
        },
        'addr_test1q',
      ),
    ).toBe('https://preprod.cardanoscan.io/address/addr_test1q');
    expect(
      explorerAddressUrl(
        { ...base, family: 'near', explorerTxUrl: 'https://nearblocks.io/txns/{hash}' },
        'alice.near',
      ),
    ).toBe('https://nearblocks.io/address/alice.near');
  });

  it('refuses non-https templates', () => {
    expect(
      explorerAddressUrl({ ...base, explorerTxUrl: 'http://example.org/tx/{hash}' }, '0xabc'),
    ).toBeUndefined();
  });
});
