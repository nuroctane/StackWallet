/**
 * Two browsers create a 2-of-2 threshold wallet and sign a Solana Devnet
 * transfer with it, each holding only its own share, over real Noise sessions
 * on an in-memory carrier. Skipped when the wasm bundle has not been built.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  WasmCoreClient,
  type Device,
  type KeyGroup,
  type SessionProof,
  type VaultHandle,
  type WasmModule,
} from '@stackwallet/core-client';

import { LoopbackFactory, type OfferCarrier } from '../core/carrier.js';
import { deviceOf } from '../core/pairing.js';
import type { LocalDevice } from '../store/devices.js';
import {
  joinKeygen,
  joinSign,
  proposeKeygen,
  proposeSign,
  readProposal,
  SESSION_MS,
  type ThresholdOps,
} from './ceremony.js';
import { openLink } from './link.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(here, '..', '..', 'public', 'wasm');
const glue = join(wasmDir, 'stackwallet_wasm.js');
const binary = join(wasmDir, 'stackwallet_wasm_bg.wasm');
const built = existsSync(glue) && existsSync(binary);

const IDENTITY = 'device-identity';
const PASS = 'a passphrase long enough';
const proof: SessionProof = { kind: 'passphrase', passphrase: PASS };
const DEVNET = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';

let shared: Promise<WasmCoreClient> | null = null;
function core(): Promise<WasmCoreClient> {
  shared ??= (async () => {
    const m = (await import(pathToFileURL(glue).href)) as WasmModule;
    await m.default?.({ module_or_path: readFileSync(binary) });
    return new WasmCoreClient(m);
  })();
  return shared;
}

async function browser(name: string) {
  const c = await core();
  const vault = await c.createVault(PASS);
  const info = await vault.createIdentity(IDENTITY);
  const local: LocalDevice = {
    id: info.deviceId,
    name,
    kind: 'browser',
    identityPubHex: info.publicHex,
    noiseStaticHex: info.noiseStaticHex,
  };
  return { c, vault, local, device: deviceOf(local) };
}
type Browser = Awaited<ReturnType<typeof browser>>;

function wrap<T>(p: Promise<T>) {
  return p.then(
    (value) => ({ ok: true as const, value }),
    (err: unknown) => ({
      ok: false as const,
      error: err instanceof Error ? err.message : String(err),
    }),
  );
}

function opsFor(v: VaultHandle, deviceId: string): ThresholdOps {
  const now = () => Date.now();
  return {
    thresholdKeygen: (r) => wrap(v.thresholdKeygen({ ...r, deviceId, nowMs: now() })),
    thresholdFinishKeygen: (d) => wrap(d.finishKeygen(v, now())),
    thresholdSign: (r) => wrap(v.thresholdSign({ ...r, nowMs: now() })),
    thresholdReview: (request, session, proposerDeviceId) =>
      wrap(v.thresholdReview({ request, session, proposerDeviceId, nowMs: now() })),
    thresholdEnd: (d, aborted) => d.auditEnd(v, aborted, now()),
    txBeginThreshold: (txId, session) => wrap(v.txBeginThreshold(txId, session, deviceId, now())),
    txCompleteThreshold: (txId, sig) => wrap(v.txCompleteThreshold(txId, sig, deviceId, now())),
  };
}

/** A fresh authenticated channel between two paired browsers. */
async function links(a: Browser, b: Browser) {
  const carriers = new LoopbackFactory();
  const offer = await carriers.offer();
  const answer = await carriers.answer(offer.text);
  const opening = Promise.all([
    openLink({
      core: a.c,
      identity: await a.vault.identity(IDENTITY),
      local: a.device,
      carrier: offer.carrier,
      sign: (m) => a.vault.signCeremonyMessage(IDENTITY, m),
      role: { kind: 'initiator', peer: b.device },
    }),
    openLink({
      core: b.c,
      identity: await b.vault.identity(IDENTITY),
      local: b.device,
      carrier: answer.carrier,
      sign: (m) => b.vault.signCeremonyMessage(IDENTITY, m),
      role: { kind: 'responder', known: [a.device] as Device[] },
    }),
  ]);
  await (offer.carrier as OfferCarrier).acceptAnswer(answer.text);
  return opening;
}

describe.skipIf(!built)('threshold wallets across two browsers', () => {
  it('generates a 2-of-2 key and signs a Solana transfer only with both shares', async () => {
    const [a, b] = [await browser('laptop'), await browser('phone')];
    const group: KeyGroup = {
      id: 'group-1',
      threshold: 2,
      parties: [
        { deviceId: a.local.id, role: 'human' },
        { deviceId: b.local.id, role: 'human' },
      ],
      curves: ['ed25519'],
      publicKeys: [],
    };
    const now = Date.now();
    const ceremony = await a.c.thresholdKeygenSession(group, 'kg-1', now);
    const [la, lb] = await links(a, b);
    const [accA, accB] = await Promise.all([
      proposeKeygen({
        ops: opsFor(a.vault, a.local.id),
        link: la,
        localId: a.local.id,
        walletId: 'w',
        group,
        ceremony,
        session: proof,
      }),
      (async () => {
        const p = readProposal(await lb.next());
        if (p.kind !== 'keyGen') throw new Error('expected keygen');
        return joinKeygen({
          ops: opsFor(b.vault, b.local.id),
          link: lb,
          proposal: p,
          walletId: 'w',
          session: proof,
        });
      })(),
    ]);
    expect(accA.solanaAddress).toBe(accB.solanaAddress);

    const to = '11111111111111111111111111111112';
    await a.vault.txPropose(
      {
        id: 't1',
        walletId: 'w',
        accountId: 'acc',
        chainId: DEVNET,
        proposer: { kind: 'human', deviceId: a.local.id },
        kind: 'transfer',
        to,
        asset: `${DEVNET}:native`,
        amount: '1000',
        usdMicros: null,
        untrustedDestinations: [],
        createdAtMs: now,
      },
      a.local.id,
      now,
    );
    await a.vault.txAttach({
      txId: 't1',
      signer: { walletId: 'w', path: 'tss', address: accA.solanaAddress },
      unsigned: {
        chainId: DEVNET,
        from: accA.solanaAddress,
        to,
        lamports: '1000',
        recentBlockhash: '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi',
        lastValidBlockHeight: 100,
      },
      simulation: { ok: true },
      simulationOk: true,
      deviceId: a.local.id,
      nowMs: now,
    });
    await a.vault.txEvaluate('t1', a.local.id, now);

    const [sa, sb] = await links(a, b);
    const [signed] = await Promise.all([
      proposeSign({
        ops: opsFor(a.vault, a.local.id),
        link: sa,
        localId: a.local.id,
        txId: 't1',
        session: proof,
        sessionId: 'sg-1',
      }),
      (async () => {
        const p = readProposal(await sb.next());
        if (p.kind !== 'sign') throw new Error('expected sign');
        const review = await b.vault.thresholdReview({
          request: p.request,
          session: p.session,
          proposerDeviceId: sb.peer.id,
          nowMs: Date.now(),
        });
        expect(review).toMatchObject({ to, lamports: '1000', decision: { decision: 'allow' } });
        await joinSign({ ops: opsFor(b.vault, b.local.id), link: sb, proposal: p, session: proof });
      })(),
    ]);
    expect(signed.state).toBe('signed');
    expect(signed.rawSignedHex?.length).toBeGreaterThan(2 + 2 * 64);
  }, 60_000);
});
