/**
 * Two browsers pairing through the controller with the real wasm core and an
 * in-memory carrier. Skipped when the wasm bundle has not been built (CI
 * always builds it first).
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  decodePairingOffer,
  encodePairingOffer,
  WasmCoreClient,
  type Device,
  type PairingOffer,
  type WasmModule,
} from '@stackwallet/core-client';

import type { LocalDevice } from '../store/devices.js';
import { LoopbackCarrier, LoopbackFactory } from './carrier.js';
import { deviceOf, PairingController, runPairingSession, type PairingView } from './pairing.js';
import { splitPairingText } from './webrtc.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(here, '..', '..', 'public', 'wasm');
const glue = join(wasmDir, 'stackwallet_wasm.js');
const binary = join(wasmDir, 'stackwallet_wasm_bg.wasm');
const built = existsSync(glue) && existsSync(binary);

let shared: Promise<WasmCoreClient> | null = null;
function core(): Promise<WasmCoreClient> {
  shared ??= (async () => {
    const m = (await import(pathToFileURL(glue).href)) as WasmModule;
    await m.default?.({ module_or_path: readFileSync(binary) });
    return new WasmCoreClient(m);
  })();
  return shared;
}

const IDENTITY = 'device-identity';

async function browser(name: string) {
  const c = await core();
  const vault = await c.createVault('a passphrase long enough');
  const info = await vault.createIdentity(IDENTITY);
  const local: LocalDevice = {
    id: info.deviceId,
    name,
    kind: 'browser',
    identityPubHex: info.publicHex,
    noiseStaticHex: info.noiseStaticHex,
  };
  const pinned: Device[] = [];
  return { c, vault, local, pinned };
}
type Browser = Awaited<ReturnType<typeof browser>>;

async function offerFrom(side: Browser, expiresAtMs = Date.now() + 60_000): Promise<PairingOffer> {
  return {
    version: 1,
    deviceId: side.local.id,
    deviceName: side.local.name,
    kind: 'browser',
    identityPubHex: side.local.identityPubHex,
    noiseStaticHex: side.local.noiseStaticHex,
    endpoints: [],
    oneTimeCodeHex: await side.c.newPairingCodeHex(),
    expiresAtMs,
  };
}

function controllerFor(side: Browser, carriers: LoopbackFactory): PairingController {
  return new PairingController({
    core: () => side.c,
    identity: () => side.vault.identity(IDENTITY),
    local: () => side.local,
    carriers,
    pin: (peer) => {
      side.pinned.push(peer);
      return { ok: true };
    },
    lingerMs: 0,
  });
}

function until(ctrl: PairingController, pred: (v: PairingView) => boolean): Promise<PairingView> {
  return new Promise((ok, fail) => {
    if (pred(ctrl.getSnapshot())) {
      ok(ctrl.getSnapshot());
      return;
    }
    const timer = setTimeout(() => fail(new Error('state never reached')), 5_000);
    const off = ctrl.subscribe(() => {
      if (pred(ctrl.getSnapshot())) {
        clearTimeout(timer);
        off();
        ok(ctrl.getSnapshot());
      }
    });
  });
}

describe.skipIf(!built)('pairing over a carrier', () => {
  it('runPairingSession pairs an issuer and a scanner back to back', async () => {
    const a = await browser('A');
    const b = await browser('B');
    const offer = decodePairingOffer(encodePairingOffer(await offerFrom(a)));
    const [ca, cb] = LoopbackCarrier.pair();
    ca.connect();
    const idA = await a.vault.identity(IDENTITY);
    const idB = await b.vault.identity(IDENTITY);
    try {
      const [peerOfA, peerOfB] = await Promise.all([
        runPairingSession({
          core: a.c,
          identity: idA,
          local: deviceOf(a.local),
          offer,
          role: 'issuer',
          carrier: ca,
        }),
        runPairingSession({
          core: b.c,
          identity: idB,
          local: deviceOf(b.local),
          offer,
          role: 'scanner',
          carrier: cb,
        }),
      ]);
      expect(peerOfA.id).toBe(b.local.id);
      expect(peerOfB.id).toBe(a.local.id);
      expect(peerOfA.identityPubHex).toBe(b.local.identityPubHex);
      expect(peerOfB.noiseStaticHex).toBe(a.local.noiseStaticHex);
    } finally {
      idA.free();
      idB.free();
    }
  });

  it('controllers walk issue → answer → handshake → pinned on both sides', async () => {
    const a = await browser('A');
    const b = await browser('B');
    const carriers = new LoopbackFactory();
    const issuer = controllerFor(a, carriers);
    const scanner = controllerFor(b, carriers);

    await issuer.issue();
    const live = issuer.getSnapshot().issuer;
    expect(live.phase).toBe('live');
    if (live.phase !== 'live') return;
    const parts = splitPairingText(live.text);
    expect(parts.pair).toBeDefined();
    // The loopback factory's connection offer has no stackwallet-rtc prefix,
    // so it is simply the second line.
    const rtcText = live.text.split('\n')[1] ?? '';
    const offer = decodePairingOffer(parts.pair ?? '');
    expect(offer.deviceId).toBe(a.local.id);

    const connecting = scanner.connect(offer, rtcText);
    const waiting = await until(scanner, (v) => v.scanner.phase === 'waiting');
    const answerText = waiting.scanner.phase === 'waiting' ? waiting.scanner.answerText : '';
    expect(answerText).toBe(`${rtcText}:answer`);

    await issuer.acceptAnswer(answerText);
    await connecting;

    expect(issuer.getSnapshot().issuer.phase).toBe('paired');
    expect(scanner.getSnapshot().scanner.phase).toBe('paired');
    expect(a.pinned.map((d) => d.id)).toEqual([b.local.id]);
    expect(b.pinned.map((d) => d.id)).toEqual([a.local.id]);
    expect(a.pinned[0]?.name).toBe('B');
    expect(b.pinned[0]?.name).toBe('A');
  });

  it('cancelling while waiting leaves the scanner idle once the carrier dies', async () => {
    const a = await browser('A');
    const b = await browser('B');
    const carriers = new LoopbackFactory();
    const issuer = controllerFor(a, carriers);
    const scanner = controllerFor(b, carriers);
    await issuer.issue();
    const live = issuer.getSnapshot().issuer;
    if (live.phase !== 'live') throw new Error('not live');
    const offer = decodePairingOffer(splitPairingText(live.text).pair ?? '');
    const connecting = scanner.connect(offer, live.text.split('\n')[1] ?? '');
    await until(scanner, (v) => v.scanner.phase === 'waiting');
    scanner.resetScanner();
    await connecting;
    expect(scanner.getSnapshot().scanner.phase).toBe('idle');
    expect(b.pinned).toEqual([]);
  });

  it('a wrong answer paste keeps the offer live instead of burning it', async () => {
    const a = await browser('A');
    const issuer = controllerFor(a, new LoopbackFactory());
    await issuer.issue();
    const before = issuer.getSnapshot().issuer;
    // The loopback carrier accepts any answer; a factory that rejects stands in
    // for a malformed WebRTC answer.
    const rejecting = new LoopbackFactory();
    rejecting.offer = async () => {
      const [carrier] = LoopbackCarrier.pair();
      carrier.acceptAnswer = async () => {
        throw new Error('not an answer');
      };
      return { carrier, text: 'loop:x' };
    };
    const strict = controllerFor(a, rejecting);
    await strict.issue();
    await expect(strict.acceptAnswer('garbage')).rejects.toThrow(/not an answer/);
    expect(strict.getSnapshot().issuer.phase).toBe('live');
    expect(before.phase).toBe('live');
  });

  it('refuses an expired offer before opening anything', async () => {
    const b = await browser('B');
    const scanner = controllerFor(b, new LoopbackFactory());
    await scanner.connect(await offerFrom(b, Date.now() - 1), 'loop:none');
    const state = scanner.getSnapshot().scanner;
    expect(state.phase).toBe('failed');
    if (state.phase === 'failed') expect(state.error).toMatch(/expired/);
  });
});
