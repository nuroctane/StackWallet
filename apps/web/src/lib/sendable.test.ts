import { describe, expect, it } from 'vitest';
import { BITCOIN_SIGNET } from '@stackwallet/chains-bitcoin';
import { COSMOS_TESTNET } from '@stackwallet/chains-cosmos';
import { SOLANA_DEVNET } from '@stackwallet/chains-solana';

import { canSendFrom, SENDABLE_TESTNETS } from './sendable.js';

const single = { kind: 'single' as const };
const acct = (chainId: string, family: 'evm' | 'bitcoin' | 'solana' | 'cosmos') => ({
  chainId,
  family,
  derivationPath: "m/44'/60'/0'/0/0",
});

describe('canSendFrom', () => {
  it('allows the signing testnets of a single-key wallet', () => {
    expect(canSendFrom(acct('eip155:11155111', 'evm'), single)).toBe(true);
    expect(canSendFrom(acct(BITCOIN_SIGNET, 'bitcoin'), single)).toBe(true);
    expect(canSendFrom(acct(SOLANA_DEVNET, 'solana'), single)).toBe(true);
    expect(canSendFrom(acct(COSMOS_TESTNET, 'cosmos'), single)).toBe(true);
  });

  it('refuses mainnets, watch wallets and accounts without a path', () => {
    expect(canSendFrom(acct('eip155:1', 'evm'), single)).toBe(false);
    expect(canSendFrom(acct('cosmos:cosmoshub-4', 'cosmos'), single)).toBe(false);
    expect(canSendFrom(acct('eip155:11155111', 'evm'), { kind: 'watch' })).toBe(false);
    expect(
      canSendFrom({ ...acct('eip155:11155111', 'evm'), derivationPath: undefined }, single),
    ).toBe(false);
    expect(canSendFrom(acct('eip155:11155111', 'evm'), undefined)).toBe(false);
  });

  it('lets a shared wallet send only on Solana Devnet', () => {
    expect(canSendFrom(acct(SOLANA_DEVNET, 'solana'), { kind: 'tss' })).toBe(true);
    expect(canSendFrom(acct('eip155:11155111', 'evm'), { kind: 'tss' })).toBe(false);
  });

  it('defaults new wallets to one sendable testnet per family', () => {
    for (const chainId of SENDABLE_TESTNETS) {
      const family = chainId.startsWith('eip155:')
        ? 'evm'
        : chainId.startsWith('bip122:')
          ? 'bitcoin'
          : chainId.startsWith('solana:')
            ? 'solana'
            : 'cosmos';
      expect(canSendFrom(acct(chainId, family), single)).toBe(true);
    }
  });
});
