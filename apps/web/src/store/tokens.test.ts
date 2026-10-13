import { describe, expect, it } from 'vitest';
import { TokenStore } from './tokens.js';
import { SPL_TOKEN_PROGRAM, createSolanaAdapter, SOLANA_DEVNET } from '@stackwallet/chains-solana';
import { createEvmAdapter } from '@stackwallet/chains-evm';
import { ChainRegistry } from '@stackwallet/chains';
import { vi } from 'vitest';

const token = { chainId: 'eip155:1', address: '0x' + 'ab'.repeat(20), symbol: 'USDC', decimals: 6 };
function storage() {
  const map = new Map<string, string>();
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => {
      map.set(key, value);
    },
    removeItem: (key: string) => {
      map.delete(key);
    },
  };
}
describe('tracked tokens', () => {
  it('applies changes to the appropriate adapter and stops after unsubscribe', () => {
    const evm = createEvmAdapter();
    const sol = createSolanaAdapter();
    const evmSet = vi.spyOn(evm, 'setTrackedTokens');
    const solSet = vi.spyOn(sol, 'setTrackedTokens');
    const store = new TokenStore(storage());
    const stop = store.configure(new ChainRegistry().register(evm).register(sol));
    const spl = {
      chainId: SOLANA_DEVNET,
      address: 'So11111111111111111111111111111111111111112',
      symbol: 'WSOL',
      decimals: 9,
      programId: SPL_TOKEN_PROGRAM as typeof SPL_TOKEN_PROGRAM,
    };
    store.track(token);
    store.track(spl);
    expect(evmSet).toHaveBeenLastCalledWith([token]);
    expect(solSet).toHaveBeenLastCalledWith([spl]);
    stop();
    store.remove(spl);
    expect(solSet).toHaveBeenCalledTimes(3);
  });
  it('preserves Solana mint case and its program across persistence', () => {
    const saved = storage();
    const store = new TokenStore(saved);
    const spl = {
      chainId: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
      address: 'So11111111111111111111111111111111111111112',
      symbol: 'WSOL',
      decimals: 9,
      programId: SPL_TOKEN_PROGRAM as typeof SPL_TOKEN_PROGRAM,
    };
    store.track(spl);
    store.track({ ...spl, symbol: 'LOCAL' });
    const reopened = new TokenStore(saved);
    expect(reopened.getSnapshot()).toEqual([{ ...spl, symbol: 'LOCAL' }]);
    expect(reopened.find(`${spl.chainId}:spl:${spl.address}`)?.symbol).toBe('LOCAL');
    expect(reopened.find(`${spl.chainId}:spl:${spl.address.toLowerCase()}`)).toBeUndefined();
    reopened.remove(spl);
    expect(reopened.getSnapshot()).toEqual([]);
  });
  it('quarantines malformed metadata before the next write', () => {
    const saved = storage();
    saved.setItem('stackwallet.tokens.v1', '[{"decimals":999}]');
    const store = new TokenStore(saved);
    expect(store.quarantinedKey).toBeTruthy();
    expect(saved.getItem(store.quarantinedKey!)).toBe('[{"decimals":999}]');
    store.track(token);
    expect(new TokenStore(saved).getSnapshot()).toHaveLength(1);
    expect(saved.getItem(store.quarantinedKey!)).toBe('[{"decimals":999}]');
  });
  it('persists canonical contracts, replaces metadata and isolates chain identities', () => {
    const saved = storage();
    const store = new TokenStore(saved);
    store.track(token);
    store.track({
      ...token,
      address: token.address.toUpperCase().replace('0X', '0x'),
      symbol: 'NEW',
    });
    store.track({ ...token, chainId: 'eip155:11155111' });
    const reopened = new TokenStore(saved);
    expect(reopened.getSnapshot()).toHaveLength(2);
    expect(reopened.find(`eip155:1:erc20:${token.address}`)?.symbol).toBe('NEW');
    reopened.remove(token);
    expect(reopened.getSnapshot()[0]?.chainId).toBe('eip155:11155111');
  });
  it('rejects hostile metadata and preserves state after a failed write', () => {
    const store = new TokenStore(storage());
    for (const patch of [
      { decimals: 255 },
      { symbol: '\u202eUSDC' },
      { address: '0x1' },
      { chainId: 'solana:x' },
    ])
      expect(() => store.track({ ...token, ...patch })).toThrow();
    const broken = new TokenStore({
      ...storage(),
      setItem: () => {
        throw new Error('quota');
      },
    });
    expect(() => broken.track(token)).toThrow('quota');
    expect(broken.getSnapshot()).toEqual([]);
  });
});
