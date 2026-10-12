import { describe, expect, it } from 'vitest';
import { mergeHistory } from './TransactionsElement.js';
import type { TxRecord } from '@stackwallet/chains';
const record = (chainId: string, hash: string, blockNumber = 1): TxRecord => ({
  chainId,
  hash,
  blockNumber,
  from: '',
  feeAssetRef: 'native',
  fee: null,
  assetDeltas: [],
  status: 'confirmed',
});
describe('history pagination', () => {
  it('deduplicates EVM case variants and replaces observations with refreshed status', () => {
    const result = mergeHistory(
      [record('eip155:1', '0xAA')],
      [{ ...record('eip155:1', '0xaa', 2), status: 'failed' }],
    );
    expect(result).toHaveLength(1);
    expect(result[0]?.status).toBe('failed');
  });
  it('keeps identical hashes on different chains and case-sensitive Solana signatures distinct', () => {
    const result = mergeHistory(
      [record('eip155:1', 'abc'), record('solana:cluster', 'Abc')],
      [record('eip155:2', 'abc'), record('solana:cluster', 'abc')],
    );
    expect(result).toHaveLength(4);
  });
});

it('retains separate token-transfer events across pages while deduplicating repeated events', () => {
  const first = { ...record('eip155:1', '0xaa'), entryId: '0xaa:1' };
  const second = { ...first, entryId: '0xaa:2' };
  expect(mergeHistory([first], [first, second])).toHaveLength(2);
});
