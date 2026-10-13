import { describe, expect, it } from 'vitest';
import { buildHoldingRows } from './HoldingsElement.js';
import type { BalanceEntry } from '../../store/balances.js';
const accounts = [{ id: 'a', walletId: 'w', chainId: 'eip155:1', address: '0xpublic' }];
const chain = {
  name: 'Ethereum',
  nativeAsset: { ref: 'eip155:1:native', symbol: 'ETH', decimals: 18 },
};
describe('holding readability', () => {
  it('keeps failed token reads unknown and retains spendability qualifications', () => {
    const rows = buildHoldingRows(
      accounts,
      () => 'wallet',
      () =>
        ({
          fetchedAtMs: 1,
          loading: false,
          holdings: [
            {
              assetRef: 'eip155:1:erc20:0xtoken',
              amount: '0',
              updatedAtMs: 1,
              error: 'unavailable',
              notice: 'Public amount only',
            },
          ],
        }) as BalanceEntry,
      () => chain,
    );
    expect(rows[1]).toMatchObject({
      hasAmount: false,
      zero: false,
      error: 'unavailable',
      notice: 'Public amount only',
    });
  });
  it('keeps unavailable and unread native balances out of the known-zero category', () => {
    const unread = buildHoldingRows(
      accounts,
      () => 'wallet',
      () => undefined,
      () => chain,
    )[0]!;
    expect(unread.zero).toBe(false);
    expect(unread.hasAmount).toBe(false);
    const failed = buildHoldingRows(
      accounts,
      () => 'wallet',
      () => ({ holdings: [], fetchedAtMs: 1, loading: false, error: 'offline' }) as BalanceEntry,
      () => chain,
    )[0]!;
    expect(failed.zero).toBe(false);
    expect(failed.hasAmount).toBe(false);
    expect(failed.error).toBe('offline');
  });
  it('retains full asset identity and provenance without inventing token decimals', () => {
    const rows = buildHoldingRows(
      accounts,
      () => 'wallet',
      () =>
        ({
          fetchedAtMs: 1,
          loading: false,
          holdings: [
            {
              assetRef: chain.nativeAsset.ref,
              amount: '0',
              updatedAtMs: 1,
              provenance: { kind: 'single', endpoint: 'https://rpc.example' },
            },
            { assetRef: 'eip155:1:erc20:0xcontract', amount: '123456789', updatedAtMs: 1 },
          ],
        }) as BalanceEntry,
      () => chain,
    );
    expect(rows[0]).toMatchObject({ zero: true, hasAmount: true, metadataKnown: true });
    expect(rows[0]?.provenance).toContain('https://rpc.example');
    expect(rows[1]).toMatchObject({
      assetRef: 'eip155:1:erc20:0xcontract',
      hasAmount: true,
      metadataKnown: false,
      amount: '123456789',
    });
  });
});
