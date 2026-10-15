import { catalogChain } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import { accountPath, nextAccountIndex, standardPath } from './keys.js';

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

describe('account paths', () => {
  it('step the index the way other wallets do', () => {
    const c = (id: string) => catalogChain(id)!;
    expect(accountPath(c('eip155:8453'), 3)?.path).toBe("m/44'/60'/0'/0/3");
    expect(accountPath(c('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'), 2)?.path).toBe(
      "m/44'/501'/2'/0'",
    );
    expect(accountPath(c('bip122:000000000019d6689c085ae165831e93'), 1)?.path).toBe(
      "m/84'/0'/1'/0/0",
    );
    expect(accountPath(c('cosmos:cosmoshub-4'), 4)?.path).toBe("m/44'/118'/0'/0/4");
    // TronLink steps the address index under coin type 195.
    expect(accountPath(c('tron:0x2b6653dc'), 0)?.path).toBe("m/44'/195'/0'/0/0");
    expect(accountPath(c('tron:0xcd8690dc'), 2)?.path).toBe("m/44'/195'/0'/0/2");
    expect(accountPath(c('eip155:8453'), 0)).toEqual(standardPath(c('eip155:8453')));
    expect(accountPath(c('eip155:8453'), -1)).toBeNull();
    expect(nextAccountIndex(c('eip155:8453'), ["m/44'/60'/0'/0/0", "m/44'/60'/0'/0/1"])).toBe(2);
  });
});
