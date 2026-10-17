import { describe, expect, it } from 'vitest';
import { BITCOIN_SIGNET } from '@stackwallet/chains-bitcoin';
import { COSMOS_TESTNET } from '@stackwallet/chains-cosmos';
import { SOLANA_DEVNET } from '@stackwallet/chains-solana';
import { TRON_NILE } from '@stackwallet/chains-tron';
import { chainFamilyOf, type ChainFamily } from '@stackwallet/core-client';

import { canSendFrom, SENDABLE_TESTNETS } from './sendable.js';

const single = { kind: 'single' as const };
// Testnet paths for the families whose signatures carry no network id; the
// core refuses any other path for them, and every other family takes any path.
const TESTNET_PATH: Partial<Record<ChainFamily, string>> = {
  bitcoin: "m/84'/1'/0'/0/0",
  btcfork: "m/44'/1'/0'/0/0",
  everscale: "m/44'/1'/0'/0'/0'",
};
const acct = (chainId: string, family: ChainFamily) => ({
  chainId,
  family,
  derivationPath: TESTNET_PATH[family] ?? "m/44'/60'/0'/0/0",
});

describe('canSendFrom', () => {
  it('allows the signing testnets of a single-key wallet', () => {
    expect(canSendFrom(acct('eip155:11155111', 'evm'), single)).toBe(true);
    expect(canSendFrom(acct(BITCOIN_SIGNET, 'bitcoin'), single)).toBe(true);
    expect(canSendFrom(acct(SOLANA_DEVNET, 'solana'), single)).toBe(true);
    expect(canSendFrom(acct(COSMOS_TESTNET, 'cosmos'), single)).toBe(true);
    expect(canSendFrom(acct(TRON_NILE, 'tron'), single)).toBe(true);
  });

  it('keeps Send off for network-blind families added under another path', () => {
    const atEvmPath = (chainId: string, family: ChainFamily) => ({
      chainId,
      family,
      derivationPath: "m/44'/60'/0'/0/0",
    });
    expect(canSendFrom(atEvmPath(BITCOIN_SIGNET, 'bitcoin'), single)).toBe(false);
    expect(canSendFrom(atEvmPath('btcfork:dash-testnet', 'btcfork'), single)).toBe(false);
    expect(canSendFrom(atEvmPath('venom:1002', 'everscale'), single)).toBe(false);
    expect(canSendFrom(atEvmPath(COSMOS_TESTNET, 'cosmos'), single)).toBe(true);
  });

  it('refuses mainnets, watch wallets and accounts without a path', () => {
    expect(canSendFrom(acct('eip155:1', 'evm'), single)).toBe(false);
    expect(canSendFrom(acct('cosmos:cosmoshub-4', 'cosmos'), single)).toBe(false);
    expect(canSendFrom(acct('tron:0x2b6653dc', 'tron'), single)).toBe(false);
    expect(canSendFrom(acct('stellar:pubnet', 'stellar'), single)).toBe(false);
    expect(
      canSendFrom(acct('polkadot:91b171bb158e2d3848fa23a9f1c25182', 'substrate'), single),
    ).toBe(false);
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
      const family = chainFamilyOf(chainId);
      expect(family, chainId).toBeDefined();
      expect(canSendFrom(acct(chainId, family!), single), chainId).toBe(true);
    }
  });
});
