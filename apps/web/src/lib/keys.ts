import type { ChainInfo } from '@stackwallet/chains';
import type { Curve } from '@stackwallet/core-client';

export interface StandardPath {
  curve: Extract<Curve, 'secp256k1' | 'ed25519'>;
  path: string;
}

/**
 * The derivation path other wallets use for the first account on `chain`, so
 * an exported phrase restores the same addresses in MetaMask, Phantom, Keplr
 * or any BIP84 Bitcoin wallet.
 */
export function standardPath(chain: ChainInfo): StandardPath | null {
  const coin = typeof chain.extra?.coinType === 'number' ? chain.extra.coinType : null;
  switch (chain.family) {
    case 'evm':
      return { curve: 'secp256k1', path: "m/44'/60'/0'/0/0" };
    case 'solana':
      return { curve: 'ed25519', path: "m/44'/501'/0'/0'" };
    case 'bitcoin':
      if (coin === null) return null;
      // Native SegWit (BIP84) where the chain has it, legacy BIP44 otherwise.
      return {
        curve: 'secp256k1',
        path: chain.extra?.segwit ? `m/84'/${coin}'/0'/0/0` : `m/44'/${coin}'/0'/0/0`,
      };
    case 'cosmos':
      return coin === null ? null : { curve: 'secp256k1', path: `m/44'/${coin}'/0'/0/0` };
    default:
      return null;
  }
}

/**
 * Path of account `index` on `chain`, following each family's common wallet
 * convention so the same phrase shows the same accounts elsewhere: MetaMask
 * and Keplr step the address index, Phantom the account, BIP84 the account.
 * Index 0 is always `standardPath`.
 */
export function accountPath(chain: ChainInfo, index: number): StandardPath | null {
  const base = standardPath(chain);
  if (!base || !Number.isInteger(index) || index < 0 || index >= 2 ** 31) return null;
  if (index === 0) return base;
  const coin = typeof chain.extra?.coinType === 'number' ? chain.extra.coinType : null;
  switch (chain.family) {
    case 'evm':
      return { curve: 'secp256k1', path: `m/44'/60'/0'/0/${index}` };
    case 'solana':
      return { curve: 'ed25519', path: `m/44'/501'/${index}'/0'` };
    case 'bitcoin':
      return chain.extra?.segwit
        ? { curve: 'secp256k1', path: `m/84'/${coin}'/${index}'/0/0` }
        : { curve: 'secp256k1', path: `m/44'/${coin}'/${index}'/0/0` };
    case 'cosmos':
      return { curve: 'secp256k1', path: `m/44'/${coin}'/0'/0/${index}` };
    default:
      return null;
  }
}

/** The lowest account index on `chainId` that the wallet does not use yet. */
export function nextAccountIndex(
  chain: ChainInfo,
  usedPaths: readonly (string | null | undefined)[],
): number {
  const used = new Set(usedPaths.filter(Boolean));
  for (let i = 0; i < 1000; i++) {
    const p = accountPath(chain, i);
    if (p && !used.has(p.path)) return i;
  }
  return 1000;
}
