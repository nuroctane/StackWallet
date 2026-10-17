import type { ChainInfo } from './types.js';

/**
 * Aleo reads go through the Provable explorer API (CORS *, both networks
 * verified against their genesis block hashes). Transfers are not offered:
 * every Aleo execution is a client-side snarkVM proof, so the family is
 * read-only plus an address codec. Balances cover public credits only;
 * record-held (private) balances are invisible to any API by design.
 */
export const ALEO: ChainInfo[] = [
  {
    chainId: 'aleo:mainnet',
    family: 'aleo',
    name: 'Aleo',
    nativeAsset: { ref: 'aleo:mainnet:native', symbol: 'ALEO', decimals: 6 },
    testnet: false,
    defaultRpcs: ['https://api.explorer.provable.com'],
    explorerTxUrl: 'https://explorer.provable.com/transaction/{hash}',
    extra: { coinType: 683 },
    layer: 'L1',
    priceId: 'aleo',
  },
  {
    chainId: 'aleo:testnet',
    family: 'aleo',
    name: 'Aleo Testnet',
    nativeAsset: { ref: 'aleo:testnet:native', symbol: 'ALEO', decimals: 6 },
    testnet: true,
    defaultRpcs: ['https://api.explorer.provable.com'],
    explorerTxUrl: 'https://testnet.explorer.provable.com/transaction/{hash}',
    extra: { coinType: 1 },
    layer: 'L1',
  },
];
