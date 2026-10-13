import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { encodeNftTransfer } from './nftCalls.js';

const sel = (sig: string) => bytesToHex(keccak_256(new TextEncoder().encode(sig))).slice(0, 8);
const A = '0x1111111111111111111111111111111111111111';
const B = '0x2222222222222222222222222222222222222222';

describe('nft transfer calldata', () => {
  it('uses the canonical selectors and layout', () => {
    const erc721 = encodeNftTransfer('erc721', A, B, '7')!;
    expect(erc721.slice(2, 10)).toBe(sel('safeTransferFrom(address,address,uint256)'));
    expect(erc721).toHaveLength(2 + 8 + 64 * 3);
    const erc1155 = encodeNftTransfer('erc1155', A, B, '7', '3')!;
    expect(erc1155.slice(2, 10)).toBe(
      sel('safeTransferFrom(address,address,uint256,uint256,bytes)'),
    );
    expect(erc1155).toHaveLength(2 + 8 + 64 * 6);
    expect(erc1155.slice(-128, -64)).toBe('a0'.padStart(64, '0'));
  });

  it('refuses what it cannot encode safely', () => {
    expect(encodeNftTransfer('erc404', A, B, '1')).toBeNull();
    expect(encodeNftTransfer('erc721', A, 'nope', '1')).toBeNull();
    expect(encodeNftTransfer('erc1155', A, B, '1', '0')).toBeNull();
  });
});
