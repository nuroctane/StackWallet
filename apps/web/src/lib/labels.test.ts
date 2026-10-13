import type { Account, Ledger } from '@stackwallet/core-client';
import type { NameRecord } from '@stackwallet/names';
import { describe, expect, it } from 'vitest';

import { firstSeen, KNOWN_CONTRACTS, labelFor } from './labels.js';

const MINE = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const NAMED = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

const account = {
  id: 'a',
  walletId: 'w',
  family: 'evm',
  chainId: 'eip155:1',
  address: MINE,
  publicKeyHex: '',
  hidden: false,
} as Account;
const name: NameRecord = {
  service: 'ens',
  name: 'vitalik.eth',
  address: NAMED,
  chainId: 'eip155:1',
  nonAscii: false,
  resolvedAtMs: 1,
};
const ledger = {
  txs: [
    { createdAtMs: 50, intent: { kind: 'transfer', to: NAMED.toLowerCase() } },
    { createdAtMs: 20, intent: { kind: 'transfer', to: NAMED } },
  ],
  audit: [],
  policies: [],
} as unknown as Ledger;

const inputs = {
  wallets: [{ id: 'w', name: 'tag', kind: 'single' as const }],
  accounts: [account],
  names: new Map([[NAMED.toLowerCase(), name]]),
  walletText: () => 'trading',
  ledger,
};

describe('address labels', () => {
  it('prefers own wallets, then verified names, then the registry', () => {
    expect(labelFor(MINE.toLowerCase(), 'eip155:1', inputs)).toMatchObject({
      label: 'trading',
      source: 'wallet',
    });
    expect(labelFor(NAMED, 'eip155:1', inputs)).toMatchObject({
      label: 'vitalik.eth',
      sourceText: 'ENS',
      firstSeenMs: 20,
    });
    expect(
      labelFor('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'eip155:1', inputs),
    ).toMatchObject({ label: 'USDC', source: 'known' });
    // Registry entries are chain-scoped.
    expect(
      labelFor('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'eip155:8453', inputs).source,
    ).toBe('none');
    expect(
      labelFor('0x0000000000000000000000000000000000000001', 'eip155:1', inputs),
    ).toMatchObject({ label: null, sourceText: 'unknown', firstSeenMs: null });
    expect(firstSeen(null, NAMED)).toBeNull();
  });

  it('keeps registry keys lowercase so lookups cannot miss on casing', () => {
    for (const k of Object.keys(KNOWN_CONTRACTS)) expect(k).toMatch(/^0x[0-9a-f]{40}$/);
  });
});

describe('contact labels', () => {
  it("names an address after the user's wallets and before name services", () => {
    const addr = '0x2222222222222222222222222222222222222222';
    const inputs = {
      wallets: [],
      accounts: [],
      names: new Map(),
      walletText: (id: string) => id,
      ledger: null,
      contacts: [{ name: 'Bob', chainId: null, address: addr }],
    };
    const l = labelFor(addr.toUpperCase().replace('0X', '0x'), 'eip155:1', inputs);
    expect(l).toMatchObject({ label: 'Bob', source: 'contact' });
    expect(labelFor(addr, 'solana:x', inputs).source).toBe('none');
  });
});
