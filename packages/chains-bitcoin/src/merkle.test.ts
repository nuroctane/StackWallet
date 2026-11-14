import { Block, Transaction } from 'bitcoinjs-lib';
import { describe, expect, it } from 'vitest';

function coinbaseLike(marker: number): Transaction {
  const tx = new Transaction();
  tx.version = 2;
  tx.addInput(new Uint8Array(32).fill(marker), 0xffffffff);
  tx.addOutput(Uint8Array.from([0x51]), 0n);
  return tx;
}

describe('block merkle root validation', () => {
  it('rejects a transaction list whose duplicate fills the odd-level padding', () => {
    const honest = [coinbaseLike(1), coinbaseLike(2), coinbaseLike(3)];
    // Duplicating the last of an odd number of transactions reproduces the
    // padding hash, so the forged list shares the honest block's merkle root.
    const mutated = [...honest, honest[2]!];
    expect(Block.calculateMerkleRoot(mutated)).toEqual(Block.calculateMerkleRoot(honest));

    const block = new Block();
    block.merkleRoot = Block.calculateMerkleRoot(honest);
    block.transactions = mutated;
    expect(block.checkTxRoots()).toBe(false);
  });
});
