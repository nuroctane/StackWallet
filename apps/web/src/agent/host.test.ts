import type { Account } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { labelFor, type LabelInputs } from '../lib/labels.js';
import { agentSource } from './host.js';

const SEPOLIA = 'eip155:11155111';
const MINE = '0x1111111111111111111111111111111111111111';
const WATCHED = '0x2222222222222222222222222222222222222222';
const FRIEND = '0x3333333333333333333333333333333333333333';

function inputs(): LabelInputs {
  const account = (walletId: string, address: string) =>
    ({ id: `a-${walletId}`, walletId, chainId: SEPOLIA, address }) as unknown as Account;
  return {
    wallets: [
      { id: 'hot', name: 'Hot', kind: 'single' },
      { id: 'whale', name: 'A whale I follow', kind: 'watch' },
    ],
    accounts: [account('hot', MINE), account('whale', WATCHED)],
    names: new Map(),
    walletText: (id) => id,
    ledger: null,
    contacts: [{ name: 'Friend', chainId: null, address: FRIEND }],
  };
}

describe('agent destination trust', () => {
  it('trusts only keyed wallets and contacts, never a watched address', () => {
    const source = (address: string) => agentSource(labelFor(address, SEPOLIA, inputs()));
    expect(source(MINE)).toBe('wallet');
    expect(source(MINE.toUpperCase().replace('0X', '0x'))).toBe('wallet');
    expect(source(FRIEND)).toBe('contact');
    // In the directory, but someone else's: the agent must flag it.
    expect(source(WATCHED)).toBe('watched');
    expect(source('0x4444444444444444444444444444444444444444')).toBe('none');
    // Invisible characters never make an address match a known one.
    expect(source(`${FRIEND}​`)).toBe('none');
  });
});
