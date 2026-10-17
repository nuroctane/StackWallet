import type { ChainInfo } from './types.js';

/**
 * CAIP-2 reference is the first 16 bytes of the chain id; the adapter pins the full id and makes
 * every endpoint prove it through get_info. Hyperion history bases live in the adapter.
 */
function antelope(spec: {
  ref: string; // first 32 hex chars of the chain id
  name: string;
  symbol: string;
  decimals: number;
  testnet: boolean;
  explorerTxUrl: string;
  rpcs: string[];
  priceId?: string;
}): ChainInfo {
  const chainId = `antelope:${spec.ref}`;
  return {
    chainId,
    family: 'antelope',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: spec.symbol, decimals: spec.decimals },
    testnet: spec.testnet,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 194 },
    layer: 'L1',
    ...(spec.priceId && !spec.testnet ? { priceId: spec.priceId } : {}),
  };
}

export const ANTELOPE: ChainInfo[] = [
  antelope({
    ref: 'aca376f206b8fc25a6ed44dbdc66547c',
    name: 'Vaulta',
    symbol: 'EOS',
    decimals: 4,
    testnet: false,
    explorerTxUrl: 'https://unicove.com/en/vaulta/transaction/{hash}',
    rpcs: [
      'https://eos.greymass.com',
      'https://eos.api.eosnation.io',
      'https://vaulta.greymass.com',
    ],
    priceId: 'vaulta',
  }),
  antelope({
    ref: '73e4385a2708e6d7048834fbc1079f2f',
    name: 'Jungle4 Testnet',
    symbol: 'EOS',
    decimals: 4,
    testnet: true,
    explorerTxUrl: 'https://jungle4.unicove.com/en/jungle4/transaction/{hash}',
    rpcs: [
      'https://jungle4.greymass.com',
      'https://jungle4.api.eosnation.io',
      'https://jungle4.cryptolions.io',
    ],
  }),
  antelope({
    ref: '384da888112027f0321850a169f737c3',
    name: 'XPR Network',
    symbol: 'XPR',
    decimals: 4,
    testnet: false,
    explorerTxUrl: 'https://explorer.xprnetwork.org/transaction/{hash}',
    rpcs: ['https://proton.greymass.com', 'https://proton.eosusa.io', 'https://api.protonnz.com'],
    priceId: 'proton',
  }),
  antelope({
    ref: '71ee83bcf52142d61019d95f9cc5427b',
    name: 'XPR Network Testnet',
    symbol: 'XPR',
    decimals: 4,
    testnet: true,
    explorerTxUrl: 'https://testnet.explorer.xprnetwork.org/transaction/{hash}',
    rpcs: ['https://testnet.protonchain.com', 'https://tn1.protonnz.com'],
  }),
  antelope({
    ref: '1064487b3cd1a897ce03ae5b6a865651',
    name: 'WAX',
    symbol: 'WAX',
    decimals: 8,
    testnet: false,
    explorerTxUrl: 'https://waxblock.io/transaction/{hash}',
    rpcs: ['https://wax.greymass.com', 'https://wax.eosusa.io', 'https://api.waxsweden.org'],
    priceId: 'wax',
  }),
  antelope({
    ref: 'f16b1833c747c43682f4386fca9cbb32',
    name: 'WAX Testnet',
    symbol: 'WAX',
    decimals: 8,
    testnet: true,
    explorerTxUrl: 'https://testnet.waxblock.io/transaction/{hash}',
    rpcs: ['https://waxtestnet.greymass.com', 'https://testnet.waxsweden.org'],
  }),
  antelope({
    ref: '4667b205c6838ef70ff7988f6e8257e8',
    name: 'Telos',
    symbol: 'TLOS',
    decimals: 4,
    testnet: false,
    explorerTxUrl: 'https://explorer.telos.net/transaction/{hash}',
    rpcs: ['https://telos.greymass.com', 'https://mainnet.telos.net'],
    priceId: 'telos',
  }),
  antelope({
    ref: '1eaa0824707c8c16bd25145493bf062a',
    name: 'Telos Testnet',
    symbol: 'TLOS',
    decimals: 4,
    testnet: true,
    explorerTxUrl: 'https://explorer-test.telos.net/transaction/{hash}',
    rpcs: ['https://testnet.telos.net'],
  }),
  antelope({
    ref: '38b1d7815474d0c60683ecbea321d723',
    name: 'Libre',
    symbol: 'LIBRE',
    decimals: 4,
    testnet: false,
    explorerTxUrl: 'https://www.libreblocks.io/tx/{hash}',
    rpcs: ['https://libre.greymass.com', 'https://lb.libre.org', 'https://libre.eosusa.io'],
    priceId: 'libre',
  }),
  antelope({
    ref: 'b64646740308df2ee06c6b72f34c0f7f',
    name: 'Libre Testnet',
    symbol: 'LIBRE',
    decimals: 4,
    testnet: true,
    explorerTxUrl: 'https://www.libreblocks.io/tx/{hash}',
    rpcs: ['https://testnet.libre.org', 'https://api.testnet.libre.cryptobloks.io'],
  }),
];
