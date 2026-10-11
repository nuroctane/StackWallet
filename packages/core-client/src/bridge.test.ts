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
    const peerInfo = await peerVault.createIdentity('id');
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

  it('pairs two identities through the sans-IO session end to end', async () => {
    const c = await load();
    const vaultA = await c.createVault(PASS);
    const vaultB = await c.createVault(PASS);
    const infoA = await vaultA.createIdentity('id');
    const infoB = await vaultB.createIdentity('id');
    const a = deviceFrom(infoA, 'A');
    const b = deviceFrom(infoB, 'B');
    const idA = await vaultA.identity('id');
    const idB = await vaultB.identity('id');
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
    const signed = await vaultA.signCeremonyMessage('id', {
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
