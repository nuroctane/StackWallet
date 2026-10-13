/**
 * Calldata for moving one collectible. Only the standard, statically encoded
 * forms: ERC-721 `safeTransferFrom(from, to, id)` and ERC-1155
 * `safeTransferFrom(from, to, id, amount, "")`. Anything else is not sent.
 */

const ADDR = /^0x[0-9a-fA-F]{40}$/;
const word = (n: bigint) => n.toString(16).padStart(64, '0');
const addr = (a: string) => a.slice(2).toLowerCase().padStart(64, '0');

export function encodeNftTransfer(
  standard: string,
  from: string,
  to: string,
  tokenId: string,
  amount = '1',
): string | null {
  if (!ADDR.test(from) || !ADDR.test(to) || !/^\d{1,78}$/.test(tokenId)) return null;
  const id = BigInt(tokenId);
  if (id >= 1n << 256n) return null;
  if (standard === 'erc721') return `0x42842e0e${addr(from)}${addr(to)}${word(id)}`;
  if (standard === 'erc1155') {
    if (!/^\d{1,78}$/.test(amount) || BigInt(amount) === 0n) return null;
    // The empty `data` bytes sit after the five head words: offset 0xa0, length 0.
    return `0xf242432a${addr(from)}${addr(to)}${word(id)}${word(BigInt(amount))}${word(0xa0n)}${word(0n)}`;
  }
  return null;
}
