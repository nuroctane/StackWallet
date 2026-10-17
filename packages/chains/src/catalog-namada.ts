import type { ChainInfo } from './types.js';

/**
 * CAIP-2 references forbid dots, but Namada native chain ids are
 * `<name>.<hash>`; the reference is the hash suffix and the full native id is
 * pinned in the core. Housefire's RPCs were all dead (NXDOMAIN/521) at build
 * time; the entry stays so the network revives without a code change.
 */
export const NAMADA: ChainInfo[] = [
  {
    chainId: 'namada:5f5de2dd1b88cba30586420',
    family: 'namada',
    name: 'Namada',
    nativeAsset: { ref: 'namada:5f5de2dd1b88cba30586420:native', symbol: 'NAM', decimals: 6 },
    testnet: false,
    explorerTxUrl: 'https://namada.world/tx/{hash}',
    defaultRpcs: ['https://rpc.namada.net'],
    extra: { coinType: 877 },
    layer: 'L1',
    priceId: 'namada',
  },
  {
    chainId: 'namada:cc0d3e0c033be',
    family: 'namada',
    name: 'Namada Housefire',
    nativeAsset: { ref: 'namada:cc0d3e0c033be:native', symbol: 'NAM', decimals: 6 },
    testnet: true,
    // The mainnet explorer does not index Housefire; a wrong link is worse than none.
    defaultRpcs: ['https://rpc.testnet.namada.net', 'https://rpc.housefire.namada.tech'],
    extra: { coinType: 877 },
    layer: 'L1',
  },
];
