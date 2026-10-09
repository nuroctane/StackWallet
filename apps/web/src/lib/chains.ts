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
