import { catalogChain } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import { standardPath } from './keys.js';

describe('standard paths', () => {
  it('matches what other wallets derive', () => {
    const p = (id: string) => standardPath(catalogChain(id)!);
    expect(p('eip155:8453')).toEqual({ curve: 'secp256k1', path: "m/44'/60'/0'/0/0" });
    expect(p('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')).toEqual({
      curve: 'ed25519',
      path: "m/44'/501'/0'/0'",
    });
    expect(p('bip122:000000000019d6689c085ae165831e93')?.path).toBe("m/84'/0'/0'/0/0");
    expect(p('bip122:1a91e3dace36e2be3bf030a65679fe82')?.path).toBe("m/44'/3'/0'/0/0");
    expect(p('cosmos:cosmoshub-4')?.path).toBe("m/44'/118'/0'/0/0");
    expect(p('cosmos:thorchain-1')?.path).toBe("m/44'/931'/0'/0/0");
  });
});
