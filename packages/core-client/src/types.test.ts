import { describe, expect, it } from 'vitest';

import { chainFamilyOf, ChainId, Decision, KeyGroup, Policy, TxIntent } from './types.js';

describe('core types', () => {
  it('accepts CAIP-2 chain ids and maps families', () => {
    expect(ChainId.parse('eip155:1')).toBe('eip155:1');
    expect(chainFamilyOf('cosmos:osmosis-1')).toBe('cosmos');
    expect(chainFamilyOf('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')).toBe('solana');
    expect(() => ChainId.parse('mainnet')).toThrow();
  });

  it('parses the Rust serialization of a transfer intent', () => {
    // Exactly what `serde_json::to_string(&TxIntent)` emits for a transfer.
    const json = {
      id: 'tx1',
      walletId: 'w1',
      accountId: 'a1',
      chainId: 'eip155:1',
      proposer: { kind: 'agent', sessionId: 's', grantId: 'g', rationale: 'rebalance' },
      kind: 'transfer',
      to: '0xabc',
      asset: 'eip155:1:native',
      amount: '1000',
      usdMicros: 2000000,
      untrustedDestinations: [],
      createdAtMs: 0,
    };
    const intent = TxIntent.parse(json);
    expect(intent.kind).toBe('transfer');
  });

  it('parses policy rules and decisions', () => {
    const policy = Policy.parse({
      id: 'p',
      name: 'folder',
      mode: 'enforce',
      rules: [
        { rule: 'spendCap', window: '24h', usdMicros: 100_000_000 },
        { rule: 'requireSimulationPass' },
        { rule: 'requireApprovers', deviceIds: ['phone'], atLeast: 1 },
      ],
    });
    expect(policy.rules).toHaveLength(3);
    const deny = Decision.parse({ decision: 'deny', reasons: ['x'], auditNotes: [] });
    expect(deny.decision).toBe('deny');
  });

  it('key group shape matches the core', () => {
    const g = KeyGroup.parse({
      id: 'g',
      threshold: 2,
      parties: [
        { deviceId: 'laptop', role: 'human' },
        { deviceId: 'agent', role: 'agent' },
      ],
      curves: ['secp256k1', 'ed25519'],
    });
    expect(g.publicKeys).toEqual([]);
  });
});
