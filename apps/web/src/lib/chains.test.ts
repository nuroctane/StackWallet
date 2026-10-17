import { describe, expect, it } from 'vitest';
import type { ChainInfo } from '@stackwallet/chains';

import { explorerAddressUrl, explorerTxUrl } from './chains.js';

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

  it('maps the Qubic, Starcoin, Alephium, Neo and Aleo explorer routes', () => {
    expect(
      explorerAddressUrl(
        { ...base, family: 'qubic', explorerTxUrl: 'https://explorer.qubic.org/tx/{hash}' },
        'BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK',
      ),
    ).toBe(
      'https://explorer.qubic.org/network/address/BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK',
    );
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'starcoin',
          explorerTxUrl: 'https://stcscan.io/main/transactions/detail/{hash}',
        },
        '0x1',
      ),
    ).toBe('https://stcscan.io/main/address/0x1');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'starcoin',
          explorerTxUrl: 'https://stcscan.io/barnard/transactions/detail/{hash}',
        },
        '0x1',
      ),
    ).toBe('https://stcscan.io/barnard/address/0x1');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'alephium',
          explorerTxUrl: 'https://explorer.alephium.org/transactions/{hash}',
        },
        '1Dq',
      ),
    ).toBe('https://explorer.alephium.org/addresses/1Dq');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'neo',
          explorerTxUrl: 'https://dora.coz.io/transaction/neo3/mainnet/{hash}',
        },
        'NXV7ZhHiyM1aHXwpVsRZC6BwNFP2jghXAq',
      ),
    ).toBe('https://dora.coz.io/address/neo3/mainnet/NXV7ZhHiyM1aHXwpVsRZC6BwNFP2jghXAq');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'neo',
          explorerTxUrl: 'https://dora.coz.io/transaction/neo3/testnet/{hash}',
        },
        'NXV7ZhHiyM1aHXwpVsRZC6BwNFP2jghXAq',
      ),
    ).toBe('https://dora.coz.io/address/neo3/testnet/NXV7ZhHiyM1aHXwpVsRZC6BwNFP2jghXAq');
    expect(
      explorerAddressUrl(
        {
          ...base,
          family: 'aleo',
          explorerTxUrl: 'https://explorer.provable.com/transaction/{hash}',
        },
        'aleo1abc',
      ),
    ).toBe('https://explorer.provable.com/address/aleo1abc');
  });
});

describe('explorerTxUrl', () => {
  it('accepts prefixed, base64 and short hex transaction ids', () => {
    expect(
      explorerTxUrl(
        {
          ...base,
          family: 'radix',
          explorerTxUrl: 'https://stokenet-dashboard.radixdlt.com/transaction/{hash}',
        },
        'txid_tdx_2_1q8dxf6g5s7w9k2m4n3p5r7t9v1x3z5b7d9f2h4j6l8n0q2s4u6w8y0a',
      ),
    ).toBe(
      'https://stokenet-dashboard.radixdlt.com/transaction/txid_tdx_2_1q8dxf6g5s7w9k2m4n3p5r7t9v1x3z5b7d9f2h4j6l8n0q2s4u6w8y0a',
    );
    expect(
      explorerTxUrl(
        { ...base, family: 'aeternity', explorerTxUrl: 'https://aescan.io/transactions/{hash}' },
        'th_2WLMdXTqxsLPU6wQ1aXRahDErchr3uBdk7wMNiAyYXAd2a2JTF',
      ),
    ).toBe('https://aescan.io/transactions/th_2WLMdXTqxsLPU6wQ1aXRahDErchr3uBdk7wMNiAyYXAd2a2JTF');
    expect(
      explorerTxUrl(
        { ...base, family: 'obyte', explorerTxUrl: 'https://explorer.obyte.org/{hash}' },
        'oj8yEksX9Ubq7lLc+p6F2uyHUuynugeVq4+ikT67X6E=',
      ),
    ).toBe('https://explorer.obyte.org/oj8yEksX9Ubq7lLc%2Bp6F2uyHUuynugeVq4%2BikT67X6E%3D');
    expect(
      explorerTxUrl(
        { ...base, family: 'starknet', explorerTxUrl: 'https://sepolia.voyager.online/tx/{hash}' },
        '0x1a2b3c4d5e6f',
      ),
    ).toBe('https://sepolia.voyager.online/tx/0x1a2b3c4d5e6f');
  });

  it('refuses hashes that could inject path segments or queries', () => {
    expect(
      explorerTxUrl({ ...base, explorerTxUrl: 'https://etherscan.io/tx/{hash}' }, 'abc?x=1'),
    ).toBeUndefined();
    expect(
      explorerTxUrl({ ...base, explorerTxUrl: 'https://etherscan.io/tx/{hash}' }, '../admin'),
    ).toBeUndefined();
    expect(
      explorerTxUrl({ ...base, explorerTxUrl: 'https://etherscan.io/tx/{hash}' }, 'short'),
    ).toBeUndefined();
  });
});
