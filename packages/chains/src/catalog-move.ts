import type { ChainInfo } from './types.js';

/**
 * Move chains. Aptos-dialect endpoints are REST bases that prove their network through the
 * ledger `chain_id`; Sui endpoints are GraphQL (public fullnodes retired JSON-RPC), while IOTA
 * Rebased still answers JSON-RPC. The adapters pick the protocol from the namespace.
 */
function aptosLike(spec: {
  chainId: string;
  name: string;
  symbol: string;
  testnet: boolean;
  explorerTxUrl: string;
  rpcs: string[];
  priceId?: string;
}): ChainInfo {
  return {
    chainId: spec.chainId,
    family: 'aptos',
    name: spec.name,
    nativeAsset: { ref: `${spec.chainId}:native`, symbol: spec.symbol, decimals: 8 },
    testnet: spec.testnet,
    explorerTxUrl: spec.explorerTxUrl,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 637 },
    layer: 'L1',
    ...(spec.priceId ? { priceId: spec.priceId } : {}),
  };
}

export const APTOS: ChainInfo[] = [
  aptosLike({
    chainId: 'aptos:1',
    name: 'Aptos',
    symbol: 'APT',
    testnet: false,
    explorerTxUrl: 'https://explorer.aptoslabs.com/txn/{hash}?network=mainnet',
    rpcs: [
      'https://api.mainnet.aptoslabs.com/v1',
      'https://fullnode.mainnet.aptoslabs.com/v1',
      'https://aptos-rest.publicnode.com/v1',
    ],
    priceId: 'aptos',
  }),
  aptosLike({
    chainId: 'aptos:2',
    name: 'Aptos Testnet',
    symbol: 'APT',
    testnet: true,
    explorerTxUrl: 'https://explorer.aptoslabs.com/txn/{hash}?network=testnet',
    rpcs: ['https://api.testnet.aptoslabs.com/v1', 'https://fullnode.testnet.aptoslabs.com/v1'],
  }),
  aptosLike({
    chainId: 'movement:126',
    name: 'Movement',
    symbol: 'MOVE',
    testnet: false,
    explorerTxUrl: 'https://explorer.movementnetwork.xyz/txn/{hash}?network=mainnet',
    rpcs: ['https://mainnet.movementnetwork.xyz/v1'],
    priceId: 'movement',
  }),
  aptosLike({
    chainId: 'supra:8',
    name: 'Supra',
    symbol: 'SUPRA',
    testnet: false,
    explorerTxUrl: 'https://suprascan.io/tx/{hash}',
    rpcs: ['https://rpc-mainnet.supra.com/rpc/v1'],
    priceId: 'supra',
  }),
];

function suiChain(spec: {
  chainId: 'sui:mainnet' | 'sui:testnet' | 'sui:devnet' | 'iota:mainnet' | 'iota:testnet';
  name: string;
  rpcs: string[];
}): ChainInfo {
  const [ns, network] = spec.chainId.split(':') as ['sui' | 'iota', string];
  const testnet = network !== 'mainnet';
  const iota = ns === 'iota';
  return {
    chainId: spec.chainId,
    family: 'sui',
    name: spec.name,
    nativeAsset: { ref: `${spec.chainId}:native`, symbol: iota ? 'IOTA' : 'SUI', decimals: 9 },
    testnet,
    explorerTxUrl: iota
      ? `https://explorer.iota.org/txblock/{hash}?network=${network}`
      : `https://suiscan.xyz/${network}/tx/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: iota ? 4218 : 784 },
    layer: 'L1',
    ...(testnet ? {} : { priceId: iota ? 'iota' : 'sui' }),
  };
}

export const SUI: ChainInfo[] = [
  suiChain({
    chainId: 'sui:mainnet',
    name: 'Sui',
    rpcs: ['https://graphql.mainnet.sui.io/graphql'],
  }),
  suiChain({
    chainId: 'sui:testnet',
    name: 'Sui Testnet',
    rpcs: ['https://graphql.testnet.sui.io/graphql'],
  }),
  suiChain({
    chainId: 'sui:devnet',
    name: 'Sui Devnet',
    rpcs: ['https://graphql.devnet.sui.io/graphql'],
  }),
  suiChain({ chainId: 'iota:mainnet', name: 'IOTA', rpcs: ['https://api.mainnet.iota.cafe'] }),
  suiChain({
    chainId: 'iota:testnet',
    name: 'IOTA Testnet',
    rpcs: ['https://api.testnet.iota.cafe'],
  }),
];
