import type { ChainInfo } from './types.js';

/**
 * rippled's `https://host:51234` JSON-RPC ports send no CORS headers; the adapter rewrites
 * them to WebSocket, so the catalog keeps the https form the RPC validators accept.
 */
function xrpl(spec: {
  ref: '0' | '1' | '2';
  name: string;
  explorer: 'livenet' | 'testnet' | 'devnet';
  rpcs: string[];
}): ChainInfo {
  const chainId = `xrpl:${spec.ref}`;
  const testnet = spec.ref !== '0';
  return {
    chainId,
    family: 'xrpl',
    name: spec.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'XRP', decimals: 6 },
    testnet,
    explorerTxUrl: `https://${spec.explorer}.xrpl.org/transactions/{hash}`,
    defaultRpcs: spec.rpcs,
    extra: { coinType: 144 },
    layer: 'L1',
    ...(testnet ? {} : { priceId: 'ripple' }),
  };
}

export const XRPL: ChainInfo[] = [
  xrpl({
    ref: '0',
    name: 'XRP Ledger',
    explorer: 'livenet',
    rpcs: [
      'https://xrplcluster.com',
      'https://s1.ripple.com:51234',
      'https://s2.ripple.com:51234',
      'https://xrpl.ws',
    ],
  }),
  xrpl({
    ref: '1',
    name: 'XRP Ledger Testnet',
    explorer: 'testnet',
    rpcs: [
      'https://s.altnet.rippletest.net:51234',
      'https://clio.altnet.rippletest.net:51234',
      'https://testnet.xrpl-labs.com',
    ],
  }),
  xrpl({
    ref: '2',
    name: 'XRP Ledger Devnet',
    explorer: 'devnet',
    rpcs: ['https://s.devnet.rippletest.net:51234', 'https://devnet.xrpl-labs.com'],
  }),
];
