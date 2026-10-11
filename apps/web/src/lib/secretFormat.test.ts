import { catalogChain } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import { formatPrivateKey } from './secretFormat.js';

describe('private key formats', () => {
  it('encodes the BIP32 test key as compressed WIF', () => {
    // Private key 1 (the generator point) has well-known encodings.
    const one = '0000000000000000000000000000000000000000000000000000000000000001';
    const btc = catalogChain('bip122:000000000019d6689c085ae165831e93')!;
    expect(formatPrivateKey(btc, one, '')).toBe(
      'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
    );
    expect(formatPrivateKey(catalogChain('eip155:1')!, one, '')).toBe(`0x${one}`);
  });

  it('packs a Solana keypair as 64 bytes of base58', () => {
    const sol = catalogChain('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')!;
    const out = formatPrivateKey(sol, '11'.repeat(32), '22'.repeat(32));
    expect(out.length).toBeGreaterThan(80);
  });
});
