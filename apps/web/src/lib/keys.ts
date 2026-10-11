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
