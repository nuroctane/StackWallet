import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { base58, createBase58check } from '@scure/base';
import type { ChainInfo } from '@stackwallet/chains';

const b58check = createBase58check(sha256);

/**
 * A raw private key from the core in the import format each family's other
 * wallets expect: 0x-hex for EVM, the 64-byte keypair in base58 for Solana
 * (Phantom, Solflare), compressed WIF for the Bitcoin family, hex for Cosmos.
 */
export function formatPrivateKey(chain: ChainInfo, secretHex: string, publicHex: string): string {
  switch (chain.family) {
    case 'evm':
      return `0x${secretHex}`;
    case 'solana': {
      const kp = new Uint8Array(64);
      kp.set(hexToBytes(secretHex), 0);
      kp.set(hexToBytes(publicHex), 32);
      return base58.encode(kp);
    }
    case 'bitcoin': {
      const p2pkh = typeof chain.extra?.p2pkhVersion === 'number' ? chain.extra.p2pkhVersion : 0;
      // WIF version is the P2PKH version plus 0x80 on every Bitcoin-family network.
      const body = new Uint8Array(34);
      body[0] = (p2pkh + 0x80) & 0xff;
      body.set(hexToBytes(secretHex), 1);
      body[33] = 0x01;
      return b58check.encode(body);
    }
    default:
      return secretHex;
  }
}
