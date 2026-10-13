import { describe, expect, it } from 'vitest';

import { decodeCalldata, isUnlimitedApproval, MAX_UINT256 } from './decode.js';

const addr = (a: string) => a.slice(2).toLowerCase().padStart(64, '0');
const num = (n: bigint) => n.toString(16).padStart(64, '0');
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

describe('calldata decoding', () => {
  it('decodes transfers and approvals', () => {
    const t = decodeCalldata(`0xa9059cbb${addr(TO)}${num(5_000_000n)}`);
    expect(t).toEqual({
      kind: 'call',
      selector: '0xa9059cbb',
      function: 'transfer',
      args: [
        { name: 'to', type: 'address', value: TO.toLowerCase() },
        { name: 'amount', type: 'uint256', value: '5000000' },
      ],
    });
    expect(isUnlimitedApproval(t)).toBe(false);
    const a = decodeCalldata(`0x095ea7b3${addr(TO)}${num(MAX_UINT256)}`);
    expect(isUnlimitedApproval(a)).toBe(true);
    expect(isUnlimitedApproval(decodeCalldata(`0xa22cb465${addr(TO)}${num(1n)}`))).toBe(true);
  });

  it('refuses to guess', () => {
    expect(decodeCalldata('')).toEqual({ kind: 'none' });
    expect(decodeCalldata('0xdeadbeef')).toMatchObject({ kind: 'unknown', selector: '0xdeadbeef' });
    // Right selector, wrong length.
    expect(decodeCalldata(`0xa9059cbb${addr(TO)}`).kind).toBe('unknown');
    // Dirty high bytes in an address word.
    expect(decodeCalldata(`0xa9059cbb${'f'.repeat(24)}${addr(TO).slice(24)}${num(1n)}`).kind).toBe(
      'unknown',
    );
    expect(decodeCalldata(`0xa22cb465${addr(TO)}${num(2n)}`).kind).toBe('unknown');
  });
});

describe('erc-1155 transfers', () => {
  it('decode only with empty data', async () => {
    const { encodeNftTransfer } = await import('./nftCalls.js');
    const a = '0x1111111111111111111111111111111111111111';
    const b = '0x2222222222222222222222222222222222222222';
    const call = decodeCalldata(encodeNftTransfer('erc1155', a, b, '9', '2')!);
    expect(call.kind === 'call' && call.args.map((x) => x.value)).toEqual([
      a,
      b,
      '9',
      '2',
      '160',
      '0',
    ]);
    expect(
      decodeCalldata(encodeNftTransfer('erc1155', a, b, '9', '2')! + '00'.repeat(32)).kind,
    ).toBe('unknown');
  });
});
