/**
 * Static chain catalog bundled with the app. User-added chains and endpoint
 * overrides layer on top at runtime; nothing here is fetched.
 *
 * `defaultRpcs` semantics differ by family: JSON-RPC urls for evm and solana,
 * mempool.space-compatible REST bases for bitcoin, LCD (REST) bases for cosmos.
 */
import type { ChainFamily } from '@stackwallet/core-client';

import type { ChainInfo } from './types.js';

type EvmSpec = {
  id: number;
  name: string;
  symbol: string;
  explorer: string;
  rpcs: string[];
  testnet?: boolean;
  decimals?: number;
};

function evm(spec: EvmSpec): ChainInfo {
  const chainId = `eip155:${spec.id}`;
  return {
    chainId,
    family: 'evm',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: spec.symbol, decimals: spec.decimals ?? 18 },
    testnet: spec.testnet ?? false,
    explorerTxUrl: `${spec.explorer}/tx/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 60 },
  };
}

const EVM: ChainInfo[] = [
  evm({
    id: 1,
    name: 'Ethereum',
    symbol: 'ETH',
    explorer: 'https://etherscan.io',
    rpcs: [
      'https://ethereum-rpc.publicnode.com',
      'https://eth.llamarpc.com',
      'https://cloudflare-eth.com',
    ],
  }),
  evm({
    id: 11155111,
    name: 'Sepolia',
    symbol: 'ETH',
    explorer: 'https://sepolia.etherscan.io',
    rpcs: [
      'https://ethereum-sepolia-rpc.publicnode.com',
      'https://rpc.sepolia.org',
      'https://sepolia.drpc.org',
    ],
    testnet: true,
  }),
  evm({
    id: 8453,
    name: 'Base',
    symbol: 'ETH',
    explorer: 'https://basescan.org',
    rpcs: [
      'https://mainnet.base.org',
      'https://base-rpc.publicnode.com',
      'https://base.llamarpc.com',
    ],
  }),
  evm({
    id: 84532,
    name: 'Base Sepolia',
    symbol: 'ETH',
    explorer: 'https://sepolia.basescan.org',
    rpcs: ['https://sepolia.base.org', 'https://base-sepolia-rpc.publicnode.com'],
    testnet: true,
  }),
  evm({
    id: 42161,
    name: 'Arbitrum One',
    symbol: 'ETH',
    explorer: 'https://arbiscan.io',
    rpcs: [
      'https://arb1.arbitrum.io/rpc',
      'https://arbitrum-one-rpc.publicnode.com',
      'https://arbitrum.llamarpc.com',
    ],
  }),
  evm({
    id: 42170,
    name: 'Arbitrum Nova',
    symbol: 'ETH',
    explorer: 'https://nova.arbiscan.io',
    rpcs: ['https://nova.arbitrum.io/rpc', 'https://arbitrum-nova-rpc.publicnode.com'],
  }),
  evm({
    id: 10,
    name: 'OP Mainnet',
    symbol: 'ETH',
    explorer: 'https://optimistic.etherscan.io',
    rpcs: [
      'https://mainnet.optimism.io',
      'https://optimism-rpc.publicnode.com',
      'https://optimism.llamarpc.com',
    ],
  }),
  evm({
    id: 137,
    name: 'Polygon',
    symbol: 'POL',
    explorer: 'https://polygonscan.com',
    rpcs: [
      'https://polygon-rpc.com',
      'https://polygon-bor-rpc.publicnode.com',
      'https://polygon.llamarpc.com',
    ],
  }),
  evm({
    id: 56,
    name: 'BNB Smart Chain',
    symbol: 'BNB',
    explorer: 'https://bscscan.com',
    rpcs: [
      'https://bsc-dataseed.bnbchain.org',
      'https://bsc-rpc.publicnode.com',
      'https://binance.llamarpc.com',
    ],
  }),
  evm({
    id: 43114,
    name: 'Avalanche C-Chain',
    symbol: 'AVAX',
    explorer: 'https://snowtrace.io',
    rpcs: ['https://api.avax.network/ext/bc/C/rpc', 'https://avalanche-c-chain-rpc.publicnode.com'],
  }),
  evm({
    id: 100,
    name: 'Gnosis',
    symbol: 'xDAI',
    explorer: 'https://gnosisscan.io',
    rpcs: ['https://rpc.gnosischain.com', 'https://gnosis-rpc.publicnode.com'],
  }),
  evm({
    id: 324,
    name: 'ZKsync Era',
    symbol: 'ETH',
    explorer: 'https://explorer.zksync.io',
    rpcs: ['https://mainnet.era.zksync.io', 'https://zksync.drpc.org'],
  }),
  evm({
    id: 59144,
    name: 'Linea',
    symbol: 'ETH',
    explorer: 'https://lineascan.build',
    rpcs: ['https://rpc.linea.build', 'https://linea-rpc.publicnode.com'],
  }),
  evm({
    id: 534352,
    name: 'Scroll',
    symbol: 'ETH',
    explorer: 'https://scrollscan.com',
    rpcs: ['https://rpc.scroll.io', 'https://scroll-rpc.publicnode.com'],
  }),
  evm({
    id: 81457,
    name: 'Blast',
    symbol: 'ETH',
    explorer: 'https://blastscan.io',
    rpcs: ['https://rpc.blast.io', 'https://blast-rpc.publicnode.com'],
  }),
  evm({
    id: 5000,
    name: 'Mantle',
    symbol: 'MNT',
    explorer: 'https://mantlescan.xyz',
    rpcs: ['https://rpc.mantle.xyz', 'https://mantle-rpc.publicnode.com'],
  }),
  evm({
    id: 42220,
    name: 'Celo',
    symbol: 'CELO',
    explorer: 'https://celoscan.io',
    rpcs: ['https://forno.celo.org', 'https://celo-rpc.publicnode.com'],
  }),
  evm({
    id: 146,
    name: 'Sonic',
    symbol: 'S',
    explorer: 'https://sonicscan.org',
    rpcs: ['https://rpc.soniclabs.com', 'https://sonic-rpc.publicnode.com'],
  }),
  evm({
    id: 80094,
    name: 'Berachain',
    symbol: 'BERA',
    explorer: 'https://berascan.com',
    rpcs: ['https://rpc.berachain.com', 'https://berachain-rpc.publicnode.com'],
  }),
  evm({
    id: 130,
    name: 'Unichain',
    symbol: 'ETH',
    explorer: 'https://uniscan.xyz',
    rpcs: ['https://mainnet.unichain.org', 'https://unichain-rpc.publicnode.com'],
  }),
  evm({
    id: 480,
    name: 'World Chain',
    symbol: 'ETH',
    explorer: 'https://worldscan.org',
    rpcs: [
      'https://worldchain-mainnet.g.alchemy.com/public',
      'https://worldchain-rpc.publicnode.com',
    ],
  }),
  evm({
    id: 57073,
    name: 'Ink',
    symbol: 'ETH',
    explorer: 'https://explorer.inkonchain.com',
    rpcs: ['https://rpc-gel.inkonchain.com', 'https://rpc-qnd.inkonchain.com'],
  }),
  evm({
    id: 7777777,
    name: 'Zora',
    symbol: 'ETH',
    explorer: 'https://explorer.zora.energy',
    rpcs: ['https://rpc.zora.energy', 'https://zora.drpc.org'],
  }),
  evm({
    id: 34443,
    name: 'Mode',
    symbol: 'ETH',
    explorer: 'https://explorer.mode.network',
    rpcs: ['https://mainnet.mode.network', 'https://mode.drpc.org'],
  }),
  evm({
    id: 252,
    name: 'Fraxtal',
    symbol: 'frxETH',
    explorer: 'https://fraxscan.com',
    rpcs: ['https://rpc.frax.com', 'https://fraxtal.drpc.org'],
  }),
  evm({
    id: 1088,
    name: 'Metis Andromeda',
    symbol: 'METIS',
    explorer: 'https://andromeda-explorer.metis.io',
    rpcs: ['https://andromeda.metis.io/?owner=1088', 'https://metis-rpc.publicnode.com'],
  }),
  evm({
    id: 1284,
    name: 'Moonbeam',
    symbol: 'GLMR',
    explorer: 'https://moonscan.io',
    rpcs: ['https://rpc.api.moonbeam.network', 'https://moonbeam-rpc.publicnode.com'],
  }),
  evm({
    id: 25,
    name: 'Cronos',
    symbol: 'CRO',
    explorer: 'https://cronoscan.com',
    rpcs: ['https://evm.cronos.org', 'https://cronos-evm-rpc.publicnode.com'],
  }),
  evm({
    id: 204,
    name: 'opBNB',
    symbol: 'BNB',
    explorer: 'https://opbnbscan.com',
    rpcs: ['https://opbnb-mainnet-rpc.bnbchain.org', 'https://opbnb-rpc.publicnode.com'],
  }),
  evm({
    id: 1329,
    name: 'Sei EVM',
    symbol: 'SEI',
    explorer: 'https://seitrace.com',
    rpcs: ['https://evm-rpc.sei-apis.com', 'https://sei-evm-rpc.publicnode.com'],
  }),
  evm({
    id: 143,
    name: 'Monad',
    symbol: 'MON',
    explorer: 'https://monadscan.com',
    rpcs: ['https://rpc.monad.xyz', 'https://monad-rpc.publicnode.com'],
  }),
];

type BitcoinSpec = {
  /** First 32 hex chars of the genesis block hash (CAIP-2 bip122 reference). */
  genesis32: string;
  name: string;
  symbol: string;
  explorerTxUrl: string;
  rpcs: string[];
  hrp?: string;
  p2pkh: number;
  p2sh: number;
  coinType: number;
  testnet?: boolean;
};

function bitcoin(spec: BitcoinSpec): ChainInfo {
  const chainId = `bip122:${spec.genesis32}`;
  return {
    chainId,
    family: 'bitcoin',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: spec.symbol, decimals: 8 },
    testnet: spec.testnet ?? false,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rpcs,
    extra: {
      ...(spec.hrp !== undefined ? { bech32Prefix: spec.hrp } : {}),
      segwit: spec.hrp !== undefined,
      p2pkhVersion: spec.p2pkh,
      p2shVersion: spec.p2sh,
      coinType: spec.coinType,
    },
  };
}

const BITCOIN: ChainInfo[] = [
  bitcoin({
    genesis32: '000000000019d6689c085ae165831e93',
    name: 'Bitcoin',
    symbol: 'BTC',
    explorerTxUrl: 'https://mempool.space/tx/{hash}',
    rpcs: ['https://mempool.space/api', 'https://blockstream.info/api'],
    hrp: 'bc',
    p2pkh: 0x00,
    p2sh: 0x05,
    coinType: 0,
  }),
  bitcoin({
    genesis32: '00000000da84f2bafbbc53dee25a72ae',
    name: 'Bitcoin Testnet4',
    symbol: 'tBTC',
    explorerTxUrl: 'https://mempool.space/testnet4/tx/{hash}',
    rpcs: ['https://mempool.space/testnet4/api'],
    hrp: 'tb',
    p2pkh: 0x6f,
    p2sh: 0xc4,
    coinType: 1,
    testnet: true,
  }),
  bitcoin({
    genesis32: '00000008819873e925422c1ff0f99f7c',
    name: 'Bitcoin Signet',
    symbol: 'sBTC',
    explorerTxUrl: 'https://mempool.space/signet/tx/{hash}',
    rpcs: ['https://mempool.space/signet/api'],
    hrp: 'tb',
    p2pkh: 0x6f,
    p2sh: 0xc4,
    coinType: 1,
    testnet: true,
  }),
  bitcoin({
    genesis32: '12a765e31ffd4059bada1e25190f6e98',
    name: 'Litecoin',
    symbol: 'LTC',
    explorerTxUrl: 'https://litecoinspace.org/tx/{hash}',
    rpcs: ['https://litecoinspace.org/api'],
    hrp: 'ltc',
    p2pkh: 0x30,
    p2sh: 0x32,
    coinType: 2,
  }),
  // Dogecoin has no segwit and no public mempool.space-compatible API that we
  // trust; balances need a user-supplied endpoint until an indexer adapter lands.
  bitcoin({
    genesis32: '1a91e3dace36e2be3bf030a65679fe82',
    name: 'Dogecoin',
    symbol: 'DOGE',
    explorerTxUrl: 'https://blockchair.com/dogecoin/transaction/{hash}',
    rpcs: [],
    p2pkh: 0x1e,
    p2sh: 0x16,
    coinType: 3,
  }),
];

const SOLANA: ChainInfo[] = [
  {
    chainId: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
    family: 'solana',
    name: 'Solana',
    nativeAsset: {
      ref: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:native',
      symbol: 'SOL',
      decimals: 9,
    },
    testnet: false,
    explorerTxUrl: 'https://solscan.io/tx/{hash}',
    defaultRpcs: ['https://api.mainnet-beta.solana.com', 'https://solana-rpc.publicnode.com'],
    extra: { coinType: 501 },
  },
  {
    chainId: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
    family: 'solana',
    name: 'Solana Devnet',
    nativeAsset: {
      ref: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:native',
      symbol: 'SOL',
      decimals: 9,
    },
    testnet: true,
    explorerTxUrl: 'https://solscan.io/tx/{hash}?cluster=devnet',
    defaultRpcs: ['https://api.devnet.solana.com'],
    extra: { coinType: 501 },
  },
];

type CosmosSpec = {
  id: string;
  name: string;
  symbol: string;
  denom: string;
  decimals: number;
  prefix: string;
  gasPrice: string;
  explorerTxUrl: string;
  rests: string[];
  coinType?: number;
  addressAlgo?: 'secp256k1' | 'ethsecp256k1';
  testnet?: boolean;
};

function cosmos(spec: CosmosSpec): ChainInfo {
  const chainId = `cosmos:${spec.id}`;
  return {
    chainId,
    family: 'cosmos',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: spec.symbol, decimals: spec.decimals },
    testnet: spec.testnet ?? false,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rests,
    extra: {
      bech32Prefix: spec.prefix,
      coinType: spec.coinType ?? 118,
      addressAlgo: spec.addressAlgo ?? 'secp256k1',
      baseDenom: spec.denom,
      gasPrice: spec.gasPrice,
    },
  };
}

const mintscan = (slug: string) => `https://www.mintscan.io/${slug}/tx/{hash}`;

const COSMOS: ChainInfo[] = [
  cosmos({
    id: 'cosmoshub-4',
    name: 'Cosmos Hub',
    symbol: 'ATOM',
    denom: 'uatom',
    decimals: 6,
    prefix: 'cosmos',
    gasPrice: '0.025uatom',
    explorerTxUrl: mintscan('cosmos'),
    rests: ['https://cosmos-rest.publicnode.com', 'https://rest.cosmos.directory/cosmoshub'],
  }),
  cosmos({
    id: 'osmosis-1',
    name: 'Osmosis',
    symbol: 'OSMO',
    denom: 'uosmo',
    decimals: 6,
    prefix: 'osmo',
    gasPrice: '0.025uosmo',
    explorerTxUrl: mintscan('osmosis'),
    rests: [
      'https://lcd.osmosis.zone',
      'https://osmosis-rest.publicnode.com',
      'https://rest.cosmos.directory/osmosis',
    ],
  }),
  cosmos({
    id: 'celestia',
    name: 'Celestia',
    symbol: 'TIA',
    denom: 'utia',
    decimals: 6,
    prefix: 'celestia',
    gasPrice: '0.002utia',
    explorerTxUrl: mintscan('celestia'),
    rests: ['https://celestia-rest.publicnode.com', 'https://rest.cosmos.directory/celestia'],
  }),
  cosmos({
    id: 'dydx-mainnet-1',
    name: 'dYdX Chain',
    symbol: 'DYDX',
    denom: 'adydx',
    decimals: 18,
    prefix: 'dydx',
    gasPrice: '12500000000adydx',
    explorerTxUrl: mintscan('dydx'),
    rests: ['https://dydx-rest.publicnode.com', 'https://rest.cosmos.directory/dydx'],
  }),
  cosmos({
    id: 'injective-1',
    name: 'Injective',
    symbol: 'INJ',
    denom: 'inj',
    decimals: 18,
    prefix: 'inj',
    coinType: 60,
    addressAlgo: 'ethsecp256k1',
    gasPrice: '160000000inj',
    explorerTxUrl: 'https://explorer.injective.network/transaction/{hash}',
    rests: [
      'https://sentry.lcd.injective.network',
      'https://injective-rest.publicnode.com',
      'https://rest.cosmos.directory/injective',
    ],
  }),
  cosmos({
    id: 'noble-1',
    name: 'Noble',
    symbol: 'USDC',
    denom: 'uusdc',
    decimals: 6,
    prefix: 'noble',
    gasPrice: '0.1uusdc',
    explorerTxUrl: mintscan('noble'),
    rests: ['https://noble-api.polkachu.com', 'https://rest.cosmos.directory/noble'],
  }),
  cosmos({
    id: 'neutron-1',
    name: 'Neutron',
    symbol: 'NTRN',
    denom: 'untrn',
    decimals: 6,
    prefix: 'neutron',
    gasPrice: '0.0053untrn',
    explorerTxUrl: mintscan('neutron'),
    rests: ['https://neutron-rest.publicnode.com', 'https://rest.cosmos.directory/neutron'],
  }),
  cosmos({
    id: 'stargaze-1',
    name: 'Stargaze',
    symbol: 'STARS',
    denom: 'ustars',
    decimals: 6,
    prefix: 'stars',
    gasPrice: '1ustars',
    explorerTxUrl: mintscan('stargaze'),
    rests: ['https://rest.stargaze-apis.com', 'https://rest.cosmos.directory/stargaze'],
  }),
  cosmos({
    id: 'akashnet-2',
    name: 'Akash',
    symbol: 'AKT',
    denom: 'uakt',
    decimals: 6,
    prefix: 'akash',
    gasPrice: '0.025uakt',
    explorerTxUrl: mintscan('akash'),
    rests: ['https://akash-rest.publicnode.com', 'https://rest.cosmos.directory/akash'],
  }),
  cosmos({
    id: 'kava_2222-10',
    name: 'Kava',
    symbol: 'KAVA',
    denom: 'ukava',
    decimals: 6,
    prefix: 'kava',
    coinType: 459,
    gasPrice: '0.05ukava',
    explorerTxUrl: mintscan('kava'),
    rests: [
      'https://api.data.kava.io',
      'https://kava-rest.publicnode.com',
      'https://rest.cosmos.directory/kava',
    ],
  }),
  cosmos({
    id: 'stride-1',
    name: 'Stride',
    symbol: 'STRD',
    denom: 'ustrd',
    decimals: 6,
    prefix: 'stride',
    gasPrice: '0.0005ustrd',
    explorerTxUrl: mintscan('stride'),
    rests: ['https://stride-rest.publicnode.com', 'https://rest.cosmos.directory/stride'],
  }),
  cosmos({
    id: 'juno-1',
    name: 'Juno',
    symbol: 'JUNO',
    denom: 'ujuno',
    decimals: 6,
    prefix: 'juno',
    gasPrice: '0.075ujuno',
    explorerTxUrl: mintscan('juno'),
    rests: ['https://juno-api.polkachu.com', 'https://rest.cosmos.directory/juno'],
  }),
  cosmos({
    id: 'axelar-dojo-1',
    name: 'Axelar',
    symbol: 'AXL',
    denom: 'uaxl',
    decimals: 6,
    prefix: 'axelar',
    gasPrice: '0.007uaxl',
    explorerTxUrl: mintscan('axelar'),
    rests: ['https://axelar-rest.publicnode.com', 'https://rest.cosmos.directory/axelar'],
  }),
  cosmos({
    id: 'secret-4',
    name: 'Secret Network',
    symbol: 'SCRT',
    denom: 'uscrt',
    decimals: 6,
    prefix: 'secret',
    coinType: 529,
    gasPrice: '0.05uscrt',
    explorerTxUrl: mintscan('secret'),
    rests: ['https://lcd.mainnet.secretsaturn.net', 'https://rest.cosmos.directory/secretnetwork'],
  }),
  cosmos({
    id: 'pacific-1',
    name: 'Sei',
    symbol: 'SEI',
    denom: 'usei',
    decimals: 6,
    prefix: 'sei',
    gasPrice: '0.02usei',
    explorerTxUrl: 'https://seitrace.com/tx/{hash}',
    rests: [
      'https://rest.sei-apis.com',
      'https://sei-rest.publicnode.com',
      'https://rest.cosmos.directory/sei',
    ],
  }),
  cosmos({
    id: 'archway-1',
    name: 'Archway',
    symbol: 'ARCH',
    denom: 'aarch',
    decimals: 18,
    prefix: 'archway',
    gasPrice: '140000000000aarch',
    explorerTxUrl: mintscan('archway'),
    rests: ['https://api.mainnet.archway.io', 'https://rest.cosmos.directory/archway'],
  }),
  cosmos({
    id: 'mantra-1',
    name: 'MANTRA',
    symbol: 'OM',
    denom: 'uom',
    decimals: 6,
    prefix: 'mantra',
    gasPrice: '0.01uom',
    explorerTxUrl: mintscan('mantra'),
    rests: ['https://api.mantrachain.io', 'https://rest.cosmos.directory/mantrachain'],
  }),
  cosmos({
    id: 'bbn-1',
    name: 'Babylon Genesis',
    symbol: 'BABY',
    denom: 'ubbn',
    decimals: 6,
    prefix: 'bbn',
    gasPrice: '0.002ubbn',
    explorerTxUrl: mintscan('babylon'),
    rests: ['https://babylon-rest.publicnode.com', 'https://rest.cosmos.directory/babylon'],
  }),
  cosmos({
    id: 'osmo-test-5',
    name: 'Osmosis Testnet',
    symbol: 'OSMO',
    denom: 'uosmo',
    decimals: 6,
    prefix: 'osmo',
    gasPrice: '0.025uosmo',
    explorerTxUrl: 'https://www.mintscan.io/osmosis-testnet/tx/{hash}',
    rests: ['https://lcd.testnet.osmosis.zone'],
    testnet: true,
  }),
];

export const CHAIN_CATALOG: readonly ChainInfo[] = Object.freeze([
  ...EVM,
  ...BITCOIN,
  ...SOLANA,
  ...COSMOS,
]);

export function chainsForFamily(family: ChainFamily): ChainInfo[] {
  return CHAIN_CATALOG.filter((c) => c.family === family);
}

export function catalogChain(chainId: string): ChainInfo | undefined {
  return CHAIN_CATALOG.find((c) => c.chainId === chainId);
}
