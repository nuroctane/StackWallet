/**
 * Local calldata decoding for the approval screen and history. Only exact
 * selector matches with well-formed static arguments decode; anything else is
 * reported as undecodable rather than guessed at.
 */

export type ArgType = 'address' | 'uint256' | 'bool';

export interface DecodedArg {
  name: string;
  type: ArgType;
  value: string;
}

export type DecodedCall =
  | { kind: 'none' }
  | { kind: 'call'; selector: string; function: string; args: DecodedArg[] }
  | { kind: 'unknown'; selector: string; bytes: number };

interface Signature {
  name: string;
  args: readonly { name: string; type: ArgType }[];
}

/** The calls a wallet most often signs; selectors are keccak of the canonical signature. */
export const KNOWN_SELECTORS: Readonly<Record<string, Signature>> = {
  '0xa9059cbb': {
    name: 'transfer',
    args: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
  },
  '0x095ea7b3': {
    name: 'approve',
    args: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
  },
  '0x23b872dd': {
    name: 'transferFrom',
    args: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
  },
  '0x42842e0e': {
    name: 'safeTransferFrom',
    args: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'tokenId', type: 'uint256' },
    ],
  },
  '0xa22cb465': {
    name: 'setApprovalForAll',
    args: [
      { name: 'operator', type: 'address' },
      { name: 'approved', type: 'bool' },
    ],
  },
  '0xd0e30db0': { name: 'deposit', args: [] },
  '0x2e1a7d4d': { name: 'withdraw', args: [{ name: 'amount', type: 'uint256' }] },
};

export const MAX_UINT256 = (1n << 256n) - 1n;

function word(hex: string, i: number): string | null {
  const w = hex.slice(i * 64, i * 64 + 64);
  return w.length === 64 ? w : null;
}

export function decodeCalldata(data: string): DecodedCall {
  const hex = (data.startsWith('0x') ? data.slice(2) : data).toLowerCase();
  if (hex.length === 0) return { kind: 'none' };
  if (!/^[0-9a-f]*$/.test(hex) || hex.length % 2 !== 0) {
    return { kind: 'unknown', selector: '0x', bytes: Math.floor(hex.length / 2) };
  }
  const selector = `0x${hex.slice(0, 8)}`;
  const sig = KNOWN_SELECTORS[selector];
  const body = hex.slice(8);
  const unknown = { kind: 'unknown' as const, selector, bytes: hex.length / 2 };
  if (!sig || body.length !== sig.args.length * 64) return unknown;
  const args: DecodedArg[] = [];
  for (const [i, a] of sig.args.entries()) {
    const w = word(body, i);
    if (!w) return unknown;
    const n = BigInt(`0x${w}`);
    if (a.type === 'address') {
      if (!w.startsWith('0'.repeat(24))) return unknown;
      args.push({ ...a, value: `0x${w.slice(24)}` });
    } else if (a.type === 'bool') {
      if (n > 1n) return unknown;
      args.push({ ...a, value: n === 1n ? 'true' : 'false' });
    } else {
      args.push({ ...a, value: n.toString() });
    }
  }
  return { kind: 'call', selector, function: sig.name, args };
}

/** Approvals that hand over everything deserve their own warning line. */
export function isUnlimitedApproval(call: DecodedCall): boolean {
  if (call.kind !== 'call') return false;
  if (call.function === 'setApprovalForAll') return call.args[1]?.value === 'true';
  if (call.function === 'approve') {
    return BigInt(call.args[1]?.value ?? '0') >= MAX_UINT256 / 2n;
  }
  return false;
}
