import type { ChainInfo } from './types.js';

/**
 * NEO N3 is tracked read-only: its P-256 signatures are not in the core, so
 * no key derivation or sending exists. NEO has 0 decimals; GAS (8 decimals)
 * is the fee token. Endpoints prove their network via getversion magic.
 */
export const NEO: ChainInfo[] = [
  {
    chainId: 'neo3:mainnet',
    family: 'neo',
    name: 'NEO N3',
    nativeAsset: { ref: 'neo3:mainnet:native', symbol: 'NEO', decimals: 0 },
    testnet: false,
    explorerTxUrl: 'https://dora.coz.io/transaction/neo3/mainnet/{hash}',
    defaultRpcs: ['https://rpc10.n3.nspcc.ru:10331', 'https://mainnet1.neo.coz.io:443'],
    extra: { coinType: 888 },
    layer: 'L1',
    priceId: 'neo',
  },
  {
    chainId: 'neo3:testnet3',
    family: 'neo',
    name: 'NEO N3 Testnet',
    nativeAsset: { ref: 'neo3:testnet3:native', symbol: 'NEO', decimals: 0 },
    testnet: true,
    explorerTxUrl: 'https://dora.coz.io/transaction/neo3/testnet/{hash}',
    defaultRpcs: ['https://testnet1.neo.coz.io:443', 'https://testnet2.neo.coz.io:443'],
    extra: { coinType: 888 },
    layer: 'L1',
  },
];
