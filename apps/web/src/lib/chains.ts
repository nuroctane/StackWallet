import type { ChainFamily } from '@stackwallet/core-client';
import type { ChainAdapter, ChainInfo, ChainRegistry } from '@stackwallet/chains';

/** Registry calls are wrapped so a half-loaded adapter set degrades to "no chains" instead of a crash. */
export function listChains(registry: ChainRegistry): ChainInfo[] {
  try {
    return registry.chains();
  } catch {
    return [];
  }
}

export function findChain(registry: ChainRegistry, chainId: string): ChainInfo | undefined {
  try {
    return registry.chainInfo(chainId);
  } catch {
    return undefined;
  }
}

export function adapterOrNull(registry: ChainRegistry, chainId: string): ChainAdapter | null {
  try {
    return registry.adapterFor(chainId);
  } catch {
    return null;
  }
}

export function listFamilies(registry: ChainRegistry): ChainFamily[] {
  try {
    return registry.families();
  } catch {
    return [];
  }
}

export const FAMILY_LABEL: Record<ChainFamily, string> = {
  evm: 'EVM',
  bitcoin: 'BTC',
  solana: 'SOL',
  cosmos: 'COSMOS',
};

export const FAMILY_ORDER: ChainFamily[] = ['evm', 'bitcoin', 'solana', 'cosmos'];

/**
 * Explorers publish a tx URL; the address page almost always lives next to it
 * (`/tx/<hash>` -> `/address/<addr>`, Solana explorers use `/account/`). When the
 * pattern does not fit, return nothing rather than guess a broken link.
 */
export function explorerAddressUrl(info: ChainInfo, address: string): string | undefined {
  const tpl = info.explorerTxUrl;
  if (!tpl) return undefined;
  const idx = tpl.indexOf('/tx/');
  if (idx < 0) return undefined;
  const segment = info.family === 'solana' ? 'account' : 'address';
  const base = tpl.slice(0, idx);
  if (!/^https:\/\/[^/]+/.test(base)) return undefined;
  let url: URL;
  try {
    url = new URL(`${base}/${segment}/${encodeURIComponent(address)}`);
  } catch {
    return undefined;
  }
  // Solana explorers encode the cluster as a query parameter; keep it from the template.
  const q = tpl.indexOf('?');
  if (q >= 0) {
    const params = new URLSearchParams(tpl.slice(q + 1));
    params.forEach((v, k) => {
      if (!/[{}]/.test(v)) url.searchParams.set(k, v);
    });
  }
  return url.toString();
}

/** The chain's explorer page for a transaction hash, https only. */
export function explorerTxUrl(info: ChainInfo, hash: string): string | undefined {
  if (!info.explorerTxUrl || !/^(0x)?[0-9a-fA-F]{64}$|^[1-9A-HJ-NP-Za-km-z]{43,90}$/.test(hash)) {
    return undefined;
  }
  const url = info.explorerTxUrl.replace('{hash}', encodeURIComponent(hash));
  return url.startsWith('https://') ? url : undefined;
}

/**
 * EVM networks the core signs on (mirror of `evm::SIGNING_TESTNETS`). The
 * core refuses every other chain id; the UI only offers these.
 */
export const EVM_SIGNING_CHAINS: ReadonlySet<string> = new Set(
  [11155111, 17000, 560048, 84532, 11155420, 421614, 80002].map((n) => `eip155:${n}`),
);

/** EVM networks offered first wherever one address is watched across chains. */
export const POPULAR_EVM: readonly string[] = [
  'eip155:1',
  'eip155:8453',
  'eip155:42161',
  'eip155:10',
  'eip155:137',
  'eip155:56',
  'eip155:43114',
  'eip155:324',
  'eip155:59144',
  'eip155:534352',
];
