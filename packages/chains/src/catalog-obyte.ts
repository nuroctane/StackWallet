import type { ChainInfo } from './types.js';

/**
 * Hub REST endpoints serve every read with CORS `*`; the network is proven by
 * fetching the genesis joint. Broadcast is websocket-only (wss hub, one
 * connection per post_joint). coinType 0 is deliberate: the official wallet
 * derives at m/44'/0'/0'/0/{i} and ignores SLIP-44's 592.
 */
export const OBYTE: ChainInfo[] = [
  {
    chainId: 'obyte:mainnet',
    family: 'obyte',
    name: 'Obyte',
    nativeAsset: { ref: 'obyte:mainnet:native', symbol: 'GBYTE', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://explorer.obyte.org/{hash}',
    defaultRpcs: ['https://obyte.org'],
    extra: { coinType: 0 },
    layer: 'L1',
    priceId: 'byteball',
  },
  {
    chainId: 'obyte:testnet',
    family: 'obyte',
    name: 'Obyte Testnet',
    nativeAsset: { ref: 'obyte:testnet:native', symbol: 'GBYTE', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://testnetexplorer.obyte.org/{hash}',
    defaultRpcs: ['https://testnet.obyte.org'],
    extra: { coinType: 0 },
    layer: 'L1',
  },
];
