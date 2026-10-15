/**
 * Builds the catalog from its curated and generated halves. Kept free of
 * runtime imports so Node scripts can load it straight from source.
 */
import type {
  ChainMeta,
  GeneratedCosmos,
  GeneratedEvm,
  GeneratedSvm,
} from './catalog-generated.js';
import type { ChainInfo } from './types.js';

function fromEvm(c: GeneratedEvm): ChainInfo {
  const chainId = `eip155:${c.id}`;
  return {
    chainId,
    family: 'evm',
    name: c.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: c.symbol, decimals: c.decimals },
    testnet: c.testnet,
    ...(c.explorer ? { explorerTxUrl: c.explorer } : {}),
    defaultRpcs: c.rpcs,
    extra: { coinType: 60 },
  };
}

function fromCosmos(c: GeneratedCosmos): ChainInfo {
  const chainId = `cosmos:${c.id}`;
  return {
    chainId,
    family: 'cosmos',
    name: c.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: c.symbol, decimals: c.decimals },
    testnet: false,
    ...(c.explorer ? { explorerTxUrl: c.explorer } : {}),
    defaultRpcs: c.rests,
    extra: {
      bech32Prefix: c.prefix,
      coinType: c.coinType,
      addressAlgo: c.addressAlgo,
      baseDenom: c.denom,
      gasPrice: c.gasPrice,
    },
  };
}

function fromSvm(c: GeneratedSvm): ChainInfo {
  const chainId = `solana:${c.id}`;
  return {
    chainId,
    family: 'solana',
    name: c.name,
    nativeAsset: { ref: `${chainId}:native`, symbol: c.symbol, decimals: 9 },
    testnet: false,
    ...(c.explorer ? { explorerTxUrl: c.explorer } : {}),
    defaultRpcs: c.rpcs,
    extra: { coinType: 501 },
  };
}

function withMeta(c: ChainInfo, meta: ChainMeta | undefined): ChainInfo {
  if (!meta) return c;
  return {
    ...c,
    ...(c.priceId === undefined && meta.priceId && !c.testnet ? { priceId: meta.priceId } : {}),
    ...(c.layer === undefined ? { layer: meta.layer } : {}),
    ...(c.parent === undefined && meta.parent ? { parent: meta.parent } : {}),
    ...(meta.halted ? { halted: true } : {}),
  };
}

export function mergeCatalog(parts: {
  curated: readonly ChainInfo[];
  evm: readonly GeneratedEvm[];
  cosmos: readonly GeneratedCosmos[];
  svm: readonly GeneratedSvm[];
  meta: Readonly<Record<string, ChainMeta>>;
}): ChainInfo[] {
  const out = new Map<string, ChainInfo>();
  for (const c of parts.curated) out.set(c.chainId, c);
  const generated = [
    ...parts.evm.map(fromEvm),
    ...parts.cosmos.map(fromCosmos),
    ...parts.svm.map(fromSvm),
  ];
  for (const c of generated) if (!out.has(c.chainId)) out.set(c.chainId, c);
  return [...out.values()].map((c) => withMeta(c, parts.meta[c.chainId]));
}
