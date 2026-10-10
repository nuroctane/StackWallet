import { describe, expect, it } from 'vitest';

import {
  CoreUnsupportedError,
  type CoreClient,
  TauriCoreClient,
  UnavailableCoreClient,
  WasmCoreClient,
  type WasmModule,
} from './client.js';

const unused = () => {
  throw new Error('not exercised by this test');
};

/** Only the stateless calls are faked; the real binary is covered by the web bridge test. */
const fakeModule: WasmModule = {
  core_version: () => '0.0.1',
  evaluate_policy: () =>
    JSON.stringify({ decision: 'allow', requiredApprovers: [], auditNotes: [] }),
  validate_key_group: () => undefined,
  can_transition: () => true,
  schema_sql: () => 'PRAGMA foreign_keys = ON;',
  verify_ceremony_message: () => true,
  device_id_from_public_hex: unused,
  pairing_new_code_hex: () => 'ab'.repeat(32),
  pairing_offer_encode: unused,
  pairing_offer_decode: unused,
  WasmVault: class {
    constructor() {
      unused();
    }
    static open = unused;
  } as unknown as WasmModule['WasmVault'],
  WasmSession: {
    pair_as_issuer: unused,
    pair_as_scanner: unused,
    connect_initiator: unused,
    connect_responder: unused,
  },
};

describe('CoreClient backends', () => {
  it('unavailable client fails closed on every call', async () => {
    const c: CoreClient = new UnavailableCoreClient('no wasm');
    await expect(c.coreVersion()).rejects.toThrow(/core unavailable/);
    await expect(c.canTransition('draft', 'signing')).rejects.toThrow(/core unavailable/);
    await expect(c.createVault('pw')).rejects.toThrow(/core unavailable/);
  });

  it('tauri client fails closed on stateful calls it cannot serve yet', async () => {
    const c: CoreClient = new TauriCoreClient(async () => 'x' as never);
    await expect(c.createVault('pw')).rejects.toBeInstanceOf(CoreUnsupportedError);
    await expect(c.newPairingCodeHex()).rejects.toThrow(/tauri backend/);
  });

  it('wasm client validates JSON coming back from the core', async () => {
    const c = new WasmCoreClient(fakeModule);
    expect(await c.newPairingCodeHex()).toBe('ab'.repeat(32));
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
