import type { ChainInfo } from './types.js';

function substrate(spec: {
  ref: string;
  name: string;
  symbol: string;
  decimals: number;
  rpcs: string[];
  explorer?: string;
  priceId?: string;
  testnet?: boolean;
  layer: ChainInfo['layer'];
  parent?: string;
}): ChainInfo {
  const chainId = `polkadot:${spec.ref}`;
  return {
    chainId,
    family: 'substrate',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: spec.symbol, decimals: spec.decimals },
    testnet: spec.testnet ?? false,
    ...(spec.explorer ? { explorerTxUrl: `${spec.explorer}/extrinsic/{hash}` } : {}),
    defaultRpcs: spec.rpcs,
    extra: { coinType: 354 },
    layer: spec.layer,
    ...(spec.parent ? { parent: spec.parent } : {}),
    ...(spec.priceId && !spec.testnet ? { priceId: spec.priceId } : {}),
  };
}

/**
 * Catalog entries for the family, used until the shared catalog carries them.
 * Every url answered `chain_getBlockHash(0)` with the right genesis and
 * `access-control-allow-origin: *` (preflight included) when probed.
 */
export const SUBSTRATE: ChainInfo[] = [
  substrate({
    ref: '91b171bb158e2d3848fa23a9f1c25182',
    name: 'Polkadot',
    symbol: 'DOT',
    decimals: 10,
    rpcs: [
      'https://rpc.polkadot.io',
      'https://polkadot-rpc.publicnode.com',
      'https://polkadot.api.onfinality.io/public',
      'https://rpc-polkadot.luckyfriday.io',
      'https://polkadot-rpc.n.dwellir.com',
    ],
    explorer: 'https://polkadot.subscan.io',
    priceId: 'polkadot',
    layer: 'L1',
  }),
  substrate({
    ref: 'b0a8d493285c2df73290dfb7e61f870f',
    name: 'Kusama',
    symbol: 'KSM',
    decimals: 12,
    rpcs: [
      'https://kusama-rpc.polkadot.io',
      'https://kusama-rpc.publicnode.com',
      'https://kusama.api.onfinality.io/public',
      'https://rpc-kusama.luckyfriday.io',
      'https://kusama-rpc.n.dwellir.com',
    ],
    explorer: 'https://kusama.subscan.io',
    priceId: 'kusama',
    layer: 'L1',
  }),
  substrate({
    ref: '68d56f15f85d3136970ec16946040bc1',
    name: 'Polkadot Asset Hub',
    symbol: 'DOT',
    decimals: 10,
    rpcs: [
      'https://polkadot-asset-hub-rpc.polkadot.io',
      'https://asset-hub-polkadot-rpc.n.dwellir.com',
      'https://statemint.api.onfinality.io/public',
    ],
    explorer: 'https://assethub-polkadot.subscan.io',
    priceId: 'polkadot',
    layer: 'parachain',
    parent: 'Polkadot',
  }),
  substrate({
    ref: '48239ef607d7928874027a43a6768920',
    name: 'Kusama Asset Hub',
    symbol: 'KSM',
    decimals: 12,
    rpcs: [
      'https://kusama-asset-hub-rpc.polkadot.io',
      'https://asset-hub-kusama-rpc.n.dwellir.com',
    ],
    explorer: 'https://assethub-kusama.subscan.io',
    priceId: 'kusama',
    layer: 'parachain',
    parent: 'Kusama',
  }),
  substrate({
    ref: '2f0555cc76fc2840a25a6ea3b9637146',
    name: 'Bittensor',
    symbol: 'TAO',
    decimals: 9,
    rpcs: [
      'https://entrypoint-finney.opentensor.ai',
      'https://lite.chain.opentensor.ai',
      'https://bittensor-finney.api.onfinality.io/public',
    ],
    priceId: 'bittensor',
    layer: 'L1',
  }),
  substrate({
    ref: 'afdc188f45c71dacbaa0b62e16a91f72',
    name: 'Hydration',
    symbol: 'HDX',
    decimals: 12,
    rpcs: ['https://rpc.hydradx.cloud', 'https://hydration-rpc.n.dwellir.com'],
    explorer: 'https://hydration.subscan.io',
    priceId: 'hydradx',
    layer: 'parachain',
    parent: 'Polkadot',
  }),
  substrate({
    ref: '262e1b2ad728475fd6fe88e62d34c200',
    name: 'Bifrost Polkadot',
    symbol: 'BNC',
    decimals: 12,
    rpcs: ['https://eu.bifrost-polkadot-rpc.liebi.com'],
    explorer: 'https://bifrost.subscan.io',
    priceId: 'bifrost-native-coin',
    layer: 'parachain',
    parent: 'Polkadot',
  }),
  substrate({
    ref: 'fc41b9bd8ef8fe53d58c7ea67c794c7e',
    name: 'Acala',
    symbol: 'ACA',
    decimals: 12,
    rpcs: [
      'https://acala-rpc.aca-api.network',
      'https://acala-rpc-0.aca-api.network',
      'https://acala-rpc-1.aca-api.network',
    ],
    priceId: 'acala',
    layer: 'parachain',
    parent: 'Polkadot',
  }),
  substrate({
    ref: 'baf5aabe40646d11f0ee8abbdc64f4a4',
    name: 'Karura',
    symbol: 'KAR',
    decimals: 12,
    rpcs: [
      'https://karura-rpc.aca-api.network',
      'https://karura-rpc-0.aca-api.network',
      'https://karura-rpc-1.aca-api.network',
    ],
    priceId: 'karura',
    layer: 'parachain',
    parent: 'Kusama',
  }),
  substrate({
    ref: 'fe1b4c55fd4d668101126434206571a7',
    name: 'Vara',
    symbol: 'VARA',
    decimals: 12,
    rpcs: ['https://rpc.vara.network'],
    explorer: 'https://vara.subscan.io',
    priceId: 'vara-network',
    layer: 'L1',
  }),
  substrate({
    ref: '7e4e32d0feafd4f9c9414b0be86373f9',
    name: 'SORA',
    symbol: 'XOR',
    decimals: 18,
    rpcs: ['https://mof2.sora.org', 'https://ws.mof.sora.org'],
    priceId: 'sora',
    layer: 'L1',
  }),
  substrate({
    ref: '8b8c140b0af9db70686583e3f6bf2a59',
    name: 'Chainflip',
    symbol: 'FLIP',
    decimals: 18,
    rpcs: [
      'https://mainnet-rpc.chainflip.io',
      'https://rpc.mainnet.chainflip.io',
      'https://archive.mainnet.chainflip.io',
    ],
    priceId: 'chainflip',
    layer: 'appchain',
  }),
  substrate({
    ref: 'e143f23803ac50e8f6f8e62695d1ce9e',
    name: 'Westend',
    symbol: 'WND',
    decimals: 12,
    rpcs: [
      'https://westend-rpc.polkadot.io',
      'https://westend-rpc.n.dwellir.com',
      'https://westend.api.onfinality.io/public',
    ],
    explorer: 'https://westend.subscan.io',
    testnet: true,
    layer: 'L1',
  }),
  substrate({
    ref: '67f9723393ef76214df0118c34bbbd3d',
    name: 'Westend Asset Hub',
    symbol: 'WND',
    decimals: 12,
    rpcs: [
      'https://westend-asset-hub-rpc.polkadot.io',
      'https://asset-hub-westend-rpc.n.dwellir.com',
    ],
    explorer: 'https://assethub-westend.subscan.io',
    testnet: true,
    layer: 'parachain',
    parent: 'Westend',
  }),
  substrate({
    ref: '374057be67b355151f271ff70c3db983',
    name: 'Paseo',
    symbol: 'PAS',
    decimals: 10,
    rpcs: ['https://pas-rpc.stakeworld.io', 'https://paseo-rpc.n.dwellir.com'],
    explorer: 'https://paseo.subscan.io',
    testnet: true,
    layer: 'L1',
  }),
  substrate({
    ref: 'd6eec26135305a8ad257a20d00335728',
    name: 'Paseo Asset Hub',
    symbol: 'PAS',
    decimals: 10,
    rpcs: [
      'https://asset-hub-paseo-rpc.n.dwellir.com',
      'https://sys.turboflakes.io/asset-hub-paseo',
    ],
    explorer: 'https://assethub-paseo.subscan.io',
    testnet: true,
    layer: 'parachain',
    parent: 'Paseo',
  }),
];
