import { describe, expect, it } from 'vitest';

import { TauriCoreClient, UnavailableCoreClient, WasmCoreClient } from './client.js';

describe('CoreClient backends', () => {
  it('unavailable client fails closed on every call', async () => {
    const c = new UnavailableCoreClient('no wasm');
    await expect(c.coreVersion()).rejects.toThrow(/core unavailable/);
    await expect(c.canTransition('draft', 'signing')).rejects.toThrow(/core unavailable/);
  });

  it('wasm client validates JSON coming back from the core', async () => {
    const c = new WasmCoreClient({
      core_version: () => '0.0.1',
      evaluate_policy: () =>
        JSON.stringify({ decision: 'allow', requiredApprovers: [], auditNotes: [] }),
      validate_key_group: () => undefined,
      can_transition: () => true,
      schema_sql: () => 'PRAGMA foreign_keys = ON;',
    });
    expect(await c.coreVersion()).toBe('0.0.1');
    const d = await c.evaluatePolicy(
      [],
      {
        id: 't',
        walletId: 'w',
        accountId: 'a',
        chainId: 'eip155:1',
        proposer: { kind: 'human', deviceId: 'laptop' },
        kind: 'claim',
        validator: null,
        untrustedDestinations: [],
        createdAtMs: 0,
      },
      { nowMs: 0, spentUsdMicros: {}, pendingProposals: 0 },
    );
    expect(d.decision).toBe('allow');
    expect(
      await c.validateKeyGroup({ id: 'g', threshold: 1, parties: [], curves: [], publicKeys: [] }),
    ).toBeNull();
  });

  it('tauri client passes commands and args through invoke', async () => {
    const calls: Array<[string, unknown]> = [];
    const c = new TauriCoreClient(async (cmd, args) => {
      calls.push([cmd, args]);
      if (cmd === 'can_transition') return true as never;
      return 'x' as never;
    });
    expect(await c.canTransition('draft', 'simulated')).toBe(true);
    expect(calls[0]).toEqual(['can_transition', { from: 'draft', to: 'simulated' }]);
  });
});
