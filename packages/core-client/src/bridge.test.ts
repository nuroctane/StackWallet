/**
 * Drives the real wasm core through `WasmCoreClient`. The binary is produced by
 * `pnpm --filter @stackwallet/web build:wasm`; when it is absent (a checkout
 * without the Rust toolchain) the suite is skipped rather than failed, and CI
 * always builds it first so the hand-written module shape cannot drift.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

import { WasmCoreClient, type WasmModule } from './client.js';
import type { Device } from './types.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = resolve(here, '../../../apps/web/public/wasm');
const glue = resolve(wasmDir, 'stackwallet_wasm.js');
const binary = resolve(wasmDir, 'stackwallet_wasm_bg.wasm');
const built = existsSync(glue) && existsSync(binary);

async function load(): Promise<WasmCoreClient> {
  const m = (await import(pathToFileURL(glue).href)) as WasmModule;
  await m.default?.({ module_or_path: readFileSync(binary) });
  return new WasmCoreClient(m);
}

// Argon2id at the OWASP floor takes a moment in wasm; one vault per suite.
const PASS = 'correct horse battery staple';

function deviceFrom(
  info: { deviceId: string; publicHex: string; noiseStaticHex: string },
  name: string,
): Device {
  return {
    id: info.deviceId,
    name,
    kind: 'browser',
    identityPubHex: info.publicHex,
    noiseStaticHex: info.noiseStaticHex,
    endpoints: [],
    pairedAtMs: 0,
    lastSeenAtMs: null,
    revokedAtMs: null,
  };
}

describe.skipIf(!built)('wasm bridge against the built core', () => {
  it('seals policy edits with an audit row and preserves them across lock and reopen', async () => {
    const core = await load();
    const vault = await core.createVault(PASS);
    const policies = [
      {
        id: 'simulation',
        name: 'Simulation required',
        mode: 'enforce' as const,
        rules: [{ rule: 'requireSimulationPass' as const }],
      },
    ];
    await vault.setPolicies(policies, 'device', 1);
    const first = await vault.ledger();
    expect(first.policies).toEqual(policies);
    expect(first.audit).toHaveLength(1);
    expect(first.audit[0]?.event).toBe('policyChanged');
    const bytes = await vault.toBytes();
    await vault.lock();
    await expect(vault.setPolicies([], 'device', 2)).rejects.toThrow();
    vault.free();
    const reopened = await core.openVault(bytes);
    await reopened.unlock(PASS);
    expect((await reopened.ledger()).policies).toEqual(policies);
    await reopened.setPolicies([{ ...policies[0]!, mode: 'audit' }], 'device', 3);
    await reopened.setPolicies([], 'device', 4);
    const final = await reopened.ledger();
    expect(final.policies).toEqual([]);
    expect(final.audit).toHaveLength(3);
    reopened.free();
  });
  it('answers the stateless calls', async () => {
    const c = await load();
    expect(await c.coreVersion()).toMatch(/^\d+\.\d+\.\d+/);
    expect(await c.canTransition('draft', 'simulated')).toBe(true);
    expect(await c.schemaSql()).toMatch(/PRAGMA foreign_keys = ON/);
    expect(await c.newPairingCodeHex()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('creates a vault, seals an identity, round-trips through bytes and re-unlocks', async () => {
    const c = await load();
    const vault = await c.createVault(PASS);
    expect(await vault.isUnlocked()).toBe(true);
    expect(await vault.kdfParams()).toEqual({ mCostKib: 19_456, tCost: 2, pCost: 1 });

    const info = await vault.createIdentity('device-identity');
    expect(info.deviceId).toMatch(/^[0-9a-f]{32}$/);
    expect(await vault.identityInfo('device-identity')).toEqual(info);
    expect(await vault.labels()).toEqual([
      { handle: expect.any(String), label: 'device-identity' },
    ]);

    const bytes = await vault.toBytes();
    vault.free();

    const reopened = await c.openVault(bytes);
    expect(await reopened.isUnlocked()).toBe(false);
    expect((await reopened.labels()).map((l) => l.label)).toEqual(['device-identity']);
    await expect(reopened.identityInfo('device-identity')).rejects.toThrow();
    await expect(reopened.unlock('wrong')).rejects.toThrow();
    await reopened.unlock(PASS);
    expect(await reopened.identityInfo('device-identity')).toEqual(info);

    const signed = await reopened.signCeremonyMessage('device-identity', {
      sessionId: 's1',
      payloadHashHex: '',
      fromDeviceId: info.deviceId,
      toDeviceId: null,
      round: 0,
      bodyHex: '00ff',
    });
    expect(await c.verifyCeremonyMessage(signed, info.publicHex)).toBe(true);
    expect(await c.verifyCeremonyMessage(signed, '11'.repeat(32))).toBe(false);
    reopened.free();
  });

  it('seals the device table in the vault and refuses a forged entry', async () => {
    const c = await load();
    const own = await c.createVault(PASS);
    const peerVault = await c.createVault(PASS);
    const peerInfo = await peerVault.createIdentity('device-identity');
    peerVault.free();

    expect(await own.devices()).toEqual([]);
    const peer = deviceFrom(peerInfo, 'Peer laptop');
    await own.setDevices([peer]);
    expect((await own.labels()).map((l) => l.label)).toEqual(['device-table']);

    const bytes = await own.toBytes();
    own.free();
    const reopened = await c.openVault(bytes);
    await expect(reopened.devices()).rejects.toThrow();
    await reopened.unlock(PASS);
    expect(await reopened.devices()).toEqual([peer]);

    // An id that is not the derivation of the identity key must never be sealed.
    const forged = { ...peer, id: 'ab'.repeat(16) };
    await expect(reopened.setDevices([forged])).rejects.toThrow(/identity key/);
    expect(await reopened.devices()).toEqual([peer]);
    await expect(reopened.setDevices([peer, { ...peer, name: 'Twin' }])).rejects.toThrow();
    await reopened.setDevices([]);
    expect(await reopened.devices()).toEqual([]);
    reopened.free();
  });

  it('keeps single-wallet keys inside and marks every reveal', async () => {
    const c = await load();
    const v = await c.createVault(PASS);
    await v.importPhrase('dev', 'test test test test test test test test test test test junk', 1);
    // The first Hardhat account: proves the path math matches every other wallet.
    const pub = await v.singlePublicKey('dev', 'secp256k1', "m/44'/60'/0'/0/0");
    expect(pub).toMatch(/^0[23][0-9a-f]{64}$/);
    expect((await v.provenance()).wallets[0]?.origin.kind).toBe('importedPhrase');

    const session = { kind: 'passphrase' as const, passphrase: PASS };
    const gate = {
      session,
      folderId: 'root',
      folderKey: 'folder key 1',
      walletKey: 'wallet key 1',
    };
    await expect(v.reveal('dev', gate, { kind: 'mnemonic' }, 'screen', 2)).rejects.toThrow(
      /no export key/,
    );
    await v.setExportKey({ scope: 'folder', id: 'root', session, next: gate.folderKey });
    await v.setExportKey({ scope: 'wallet', id: 'dev', session, next: gate.walletKey });
    expect(await v.exportKeys()).toEqual([
      { scope: 'folder', id: 'root' },
      { scope: 'wallet', id: 'dev' },
    ]);
    await expect(
      v.reveal(
        'dev',
        { ...gate, session: { kind: 'passphrase', passphrase: 'wrong passphrase!' } },
        { kind: 'mnemonic' },
        'screen',
        2,
      ),
    ).rejects.toThrow();
    await expect(
      v.reveal('dev', { ...gate, walletKey: 'not the key' }, { kind: 'mnemonic' }, 'screen', 2),
    ).rejects.toThrow(/wrong wallet key/);
    expect((await v.provenance()).wallets[0]?.exposures).toEqual([]);
    const key = await v.reveal(
      'dev',
      gate,
      { kind: 'privateKey', curve: 'secp256k1', path: "m/44'/60'/0'/0/0" },
      'clipboard',
      3,
    );
    expect(key.secret).toBe('ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
    expect(key.publicHex).toBe(pub);
    const exposures = (await v.provenance()).wallets[0]?.exposures ?? [];
    expect(exposures.map((e) => e.channel)).toEqual(['clipboard']);

    const message = await v.signMessage({
      walletId: 'dev',
      path: "m/44'/60'/0'/0/0",
      address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      session,
      kind: 'personal',
      payload: 'hello world',
      deviceId: 'd',
      nowMs: 4,
    });
    expect(message.digestHex).toBe(
      '0xd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68',
    );
    expect((await v.ledger()).audit.at(-1)?.event).toBe('messageSigned');

    await v.put('agent-session:s1', new TextEncoder().encode('{"id":"s1"}'));
    expect(await v.appRecord('agent-session:s1')).toBe('{"id":"s1"}');
    await expect(v.appRecord('mnemonic:dev')).rejects.toThrow(/not an app record/);
    await expect(v.providerKey('../mnemonic')).rejects.toThrow();

    // The page writes and deletes only its own records: never the ledger and
    // its policies, a phrase, a share, the device table or an identity.
    for (const label of ['tx-ledger', 'mnemonic:dev', 'tss:w', 'device-table', 'provider-key:'])
      await expect(v.put(label, new Uint8Array(32))).rejects.toThrow(/not an app record/);
    await v.createIdentity('device-identity');
    await expect(v.createIdentity('device-identity')).rejects.toThrow(/already holds/);
    const labels = await v.labels();
    for (const l of labels.filter((x) => !x.label.startsWith('agent-session:')))
      await expect(v.delete(l.handle)).rejects.toThrow(/not an app record/);
    // Only the device identity signs ceremony envelopes or opens identities.
    await expect(v.identityInfo('mnemonic:dev')).rejects.toThrow(/not a device identity/);
    await expect(v.createIdentity('tss:w')).rejects.toThrow(/not a device identity/);
    expect((await v.identityInfo('device-identity')).deviceId).toBeTruthy();

    await v.createSingle('fresh', 4);
    const sol = await v.singlePublicKey('fresh', 'ed25519', "m/44'/501'/0'/0'");
    expect(sol).toMatch(/^[0-9a-f]{64}$/);
    expect(await v.hasSingleKey('fresh')).toBe(true);
    v.free();
  });

  it('opens the session with a device-bound PIN and a passkey PRF, never exports with a PIN', async () => {
    const c = await load();
    const v = await c.createVault(PASS);
    const device = new Uint8Array(32).fill(5);
    const pin = new TextEncoder().encode('246810');
    const pinId = await v.addSlot({
      passphrase: PASS,
      kind: 'pin',
      label: 'PIN',
      secret: pin,
      device,
      nowMs: 1,
    });
    const prf = new Uint8Array(32).fill(9);
    const keyId = await v.addSlot({
      passphrase: PASS,
      kind: 'passkey',
      label: 'Windows Hello',
      credentialId: 'Y3JlZA',
      secret: prf,
      nowMs: 2,
    });
    expect((await v.slots()).map((s) => [s.kind, s.label])).toEqual([
      ['pin', 'PIN'],
      ['passkey', 'Windows Hello'],
    ]);
    const bytes = await v.toBytes();
    v.free();

    const reopened = await c.openVault(bytes);
    await expect(reopened.unlockWithSlot(pinId, pin, new Uint8Array(32))).rejects.toThrow();
    await reopened.unlockWithSlot(pinId, pin, device);
    expect(await reopened.isUnlocked()).toBe(true);
    const pinSession = { kind: 'slot' as const, slotId: pinId, secret: pin, device };
    await expect(
      reopened.setExportKey({
        scope: 'folder',
        id: 'f',
        session: pinSession,
        next: 'folder key 1',
      }),
    ).rejects.toThrow(/PIN cannot/);
    await reopened.setExportKey({
      scope: 'folder',
      id: 'f',
      session: { kind: 'slot', slotId: keyId, secret: prf },
      next: 'folder key 1',
    });
    await reopened.removeSlot(pinId);
    expect((await reopened.slots()).map((s) => s.kind)).toEqual(['passkey']);
    reopened.free();
  });

  it('runs a transaction through the core ledger and refuses a swapped recipient', async () => {
    const c = await load();
    const v = await c.createVault(PASS);
    await v.importPhrase('w', 'test test test test test test test test test test test junk', 1);
    const to = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const base = {
      walletId: 'w',
      accountId: 'a',
      chainId: 'eip155:11155111',
      proposer: { kind: 'human' as const, deviceId: 'd' },
      usdMicros: null,
      untrustedDestinations: [],
      createdAtMs: 1,
    };
    const intent = {
      ...base,
      id: 'tx1',
      kind: 'transfer' as const,
      to,
      asset: 'eip155:11155111:native',
      amount: '1000',
    };
    const unsigned = {
      chainId: 11155111,
      nonce: 0,
      maxPriorityFeePerGas: '1000000000',
      maxFeePerGas: '20000000000',
      gasLimit: 21000,
      to,
      value: '1000',
      dataHex: '',
    };
    const signer = {
      walletId: 'w',
      path: "m/44'/60'/0'/0/0",
      address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    };
    expect((await v.txPropose(intent, 'd', 2)).state).toBe('draft');
    await expect(
      v.txAttach({
        txId: 'tx1',
        signer,
        unsigned: { ...unsigned, to: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' },
        simulation: {},
        simulationOk: true,
        deviceId: 'd',
        nowMs: 3,
      }),
    ).rejects.toThrow(/destination/);
    const attached = await v.txAttach({
      txId: 'tx1',
      signer,
      unsigned,
      simulation: { ok: true },
      simulationOk: true,
      deviceId: 'd',
      nowMs: 3,
    });
    expect(attached.state).toBe('simulated');
    expect((await v.txEvaluate('tx1', 'd', 4)).state).toBe('awaiting');
    const signed = await v.txApprove('tx1', PASS, 'd', 5);
    expect(signed.state).toBe('signed');
    expect(signed.rawSignedHex).toMatch(/^0x02f8/);
    expect(signed.hash).toMatch(/^0x[0-9a-f]{64}$/);
    await v.txReport('tx1', 'broadcast', null, 'd', 6);
    await v.txReport('tx1', 'pending', null, 'd', 7);
    const ledger = await v.ledger();
    expect(ledger.txs[0]?.state).toBe('pending');
    expect(ledger.audit.map((e) => e.to ?? e.event)).toEqual([
      'txProposed',
      'simulated',
      'evaluated',
      'awaiting',
      'signing',
      'signed',
      'broadcast',
      'pending',
    ]);
    v.free();
  });

  it('pairs two identities through the sans-IO session end to end', async () => {
    const c = await load();
    const vaultA = await c.createVault(PASS);
    const vaultB = await c.createVault(PASS);
    const infoA = await vaultA.createIdentity('device-identity');
    const infoB = await vaultB.createIdentity('device-identity');
    const a = deviceFrom(infoA, 'A');
    const b = deviceFrom(infoB, 'B');
    const idA = await vaultA.identity('device-identity');
    const idB = await vaultB.identity('device-identity');
    const now = Date.now();

    const offer = {
      version: 1 as const,
      deviceId: a.id,
      deviceName: a.name,
      kind: a.kind,
      identityPubHex: a.identityPubHex,
      noiseStaticHex: a.noiseStaticHex,
      endpoints: [],
      oneTimeCodeHex: await c.newPairingCodeHex(),
      expiresAtMs: now + 60_000,
    };

    const issuer = await c.pairAsIssuer(idA, a, offer, now);
    const scanner = await c.pairAsScanner(idB, b, offer, now);
    expect(await issuer.isPairing()).toBe(true);

    // Pump ciphertexts between the two until both channels are open.
    const seen = { issuer: [] as string[], scanner: [] as string[] };
    for (let round = 0; round < 8; round++) {
      for (const bytes of await scanner.takeOutgoing()) {
        for (const ev of await issuer.handleIncoming(bytes)) seen.issuer.push(ev.type);
      }
      for (const bytes of await issuer.takeOutgoing()) {
        for (const ev of await scanner.handleIncoming(bytes)) seen.scanner.push(ev.type);
      }
      if ((await issuer.state()) === 'open' && (await scanner.state()) === 'open') break;
    }
    expect(await issuer.state()).toBe('open');
    expect(await scanner.state()).toBe('open');
    expect(seen.issuer).toContain('paired');
    expect(seen.scanner).toContain('paired');
    expect((await issuer.peer())?.id).toBe(b.id);
    expect((await scanner.peer())?.id).toBe(a.id);

    // Pings are answered inside the session; the pong surfaces to the sender.
    await issuer.sendFrame({ type: 'ping', nonce: 7 });
    for (const bytes of await issuer.takeOutgoing()) {
      expect(await scanner.handleIncoming(bytes)).toEqual([]);
    }
    const pong = await scanner.takeOutgoing();
    expect(pong).toHaveLength(1);
    expect(await issuer.handleIncoming(pong[0]!)).toEqual([
      { type: 'frame', frame: { type: 'pong', nonce: 7 } },
    ]);

    // A ceremony envelope from the peer itself surfaces as a plain frame.
    const signed = await vaultA.signCeremonyMessage('device-identity', {
      sessionId: 's1',
      payloadHashHex: '',
      fromDeviceId: a.id,
      toDeviceId: b.id,
      round: 0,
      bodyHex: 'beef',
    });
    await issuer.sendFrame({ type: 'ceremony', ...signed });
    const events = [];
    for (const bytes of await issuer.takeOutgoing()) {
      events.push(...(await scanner.handleIncoming(bytes)));
    }
    expect(events).toEqual([{ type: 'frame', frame: { type: 'ceremony', ...signed } }]);

    for (const h of [issuer, scanner, idA, idB, vaultA, vaultB]) h.free();
  });
});
