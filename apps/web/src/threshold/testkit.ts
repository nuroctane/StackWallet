/**
 * Test harness for ceremonies between browsers: real wasm cores, real Noise
 * sessions, an in-memory carrier. Shared by the ceremony tests and the opt-in
 * funded Signet run.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  WasmCoreClient,
  type CosignSummary,
  type Device,
  type KeyGroup,
  type SessionProof,
  type ThresholdAccount,
  type TxRecord,
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
  type ThresholdOps,
} from './ceremony.js';
import { openLink, type CeremonyLink } from './link.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(here, '..', '..', 'public', 'wasm');
const glue = join(wasmDir, 'stackwallet_wasm.js');
const binary = join(wasmDir, 'stackwallet_wasm_bg.wasm');
export const built = existsSync(glue) && existsSync(binary);

export const IDENTITY = 'device-identity';
export const PASS = 'a passphrase long enough';
export const proof: SessionProof = { kind: 'passphrase', passphrase: PASS };
export const DEVNET = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';

let shared: Promise<WasmCoreClient> | null = null;
export function core(): Promise<WasmCoreClient> {
  shared ??= (async () => {
    const m = (await import(pathToFileURL(glue).href)) as WasmModule;
    await m.default?.({ module_or_path: readFileSync(binary) });
    return new WasmCoreClient(m);
  })();
  return shared;
}

export async function browser(name: string, saved?: Uint8Array) {
  const c = await core();
  let vault: VaultHandle;
  let info: { deviceId: string; publicHex: string; noiseStaticHex: string };
  if (saved) {
    vault = await c.openVault(saved);
    await vault.unlock(PASS);
    info = await vault.identityInfo(IDENTITY);
  } else {
    vault = await c.createVault(PASS);
    info = await vault.createIdentity(IDENTITY);
  }
  const local: LocalDevice = {
    id: info.deviceId,
    name,
    kind: 'browser',
    identityPubHex: info.publicHex,
    noiseStaticHex: info.noiseStaticHex,
  };
  return { c, vault, local, device: deviceOf(local) };
}
export type Browser = Awaited<ReturnType<typeof browser>>;

/** Browsers that have all been paired with one another. */
export async function browsers<N extends string[]>(
  ...names: N
): Promise<{ [K in keyof N]: Browser }> {
  const all = await Promise.all(names.map((n) => browser(n)));
  for (const b of all) await b.vault.setDevices(all.filter((o) => o !== b).map((o) => o.device));
  return all as { [K in keyof N]: Browser };
}

function wrap<T>(p: Promise<T>) {
  return p.then(
    (value) => ({ ok: true as const, value }),
    (err: unknown) => ({
      ok: false as const,
      error: err instanceof Error ? err.message : String(err),
    }),
  );
}

export function opsFor(v: VaultHandle, deviceId: string): ThresholdOps {
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
    thresholdRefresh: (r) => wrap(v.thresholdRefresh({ ...r, nowMs: now() })),
    thresholdFinishRefresh: (d) => wrap(d.finishRefresh(v, now())),
    thresholdShareFingerprint: (w) => wrap(v.thresholdShareFingerprint(w)),
    thresholdReconcile: (s, w, peers) =>
      wrap(v.thresholdReconcileRefresh(s, w, peers, deviceId, now())),
  };
}

/** A fresh authenticated channel from the hub to one other browser. */
export async function link(hub: Browser, peer: Browser): Promise<[CeremonyLink, CeremonyLink]> {
  const carriers = new LoopbackFactory();
  const offer = await carriers.offer();
  const answer = await carriers.answer(offer.text);
  const opening = Promise.all([
    openLink({
      core: hub.c,
      identity: await hub.vault.identity(IDENTITY),
      local: hub.device,
      carrier: offer.carrier,
      sign: (m) => hub.vault.signCeremonyMessage(IDENTITY, m),
      open: (m) => hub.vault.openCeremonyMessage(IDENTITY, m),
      role: { kind: 'initiator', peer: peer.device },
    }),
    openLink({
      core: peer.c,
      identity: await peer.vault.identity(IDENTITY),
      local: peer.device,
      carrier: answer.carrier,
      sign: (m) => peer.vault.signCeremonyMessage(IDENTITY, m),
      open: (m) => peer.vault.openCeremonyMessage(IDENTITY, m),
      admitRelayed: (signed) => peer.vault.admitRelayed(signed),
      role: { kind: 'responder', known: [hub.device] as Device[] },
    }),
  ]);
  await (offer.carrier as OfferCarrier).acceptAnswer(answer.text);
  return opening;
}

export async function links(hub: Browser, peers: Browser[]) {
  const pairs = [];
  for (const p of peers) pairs.push(await link(hub, p));
  return { hub: pairs.map(([h]) => h), peers: pairs.map(([, p]) => p) };
}

/** Every browser runs DKG for wallet `w`; each seals only its own share. */
export async function shareKey(
  hub: Browser,
  peers: Browser[],
  curve: KeyGroup['curves'][number],
  threshold = peers.length + 1,
): Promise<[ThresholdAccount, ThresholdAccount, ...ThresholdAccount[]]> {
  const group: KeyGroup = {
    id: `group-${curve}-${peers.length}`,
    threshold,
    parties: [hub, ...peers].map((b) => ({ deviceId: b.local.id, role: 'human' as const })),
    curves: [curve],
    publicKeys: [],
  };
  const ceremony = await hub.c.thresholdKeygenSession(group, `kg-${curve}`, Date.now());
  const l = await links(hub, peers);
  const out = await Promise.all([
    proposeKeygen({
      ops: opsFor(hub.vault, hub.local.id),
      links: l.hub,
      localId: hub.local.id,
      walletId: 'w',
      group,
      ceremony,
      session: proof,
    }),
    ...peers.map(async (b, i) => {
      const p = readProposal(await l.peers[i]!.next());
      if (p.kind !== 'keyGen') throw new Error('expected keygen');
      return joinKeygen({
        ops: opsFor(b.vault, b.local.id),
        link: l.peers[i]!,
        localId: b.local.id,
        proposal: p,
        walletId: 'w',
        session: proof,
      });
    }),
  ]);
  return out as [ThresholdAccount, ThresholdAccount, ...ThresholdAccount[]];
}

/** The hub proposes `txId`; each co-signer reviews it and joins. */
export async function signTogether(hub: Browser, cosigners: Browser[], txId: string) {
  const l = await links(hub, cosigners);
  const [signed, ...reviews] = await Promise.all([
    proposeSign({
      ops: opsFor(hub.vault, hub.local.id),
      links: l.hub,
      localId: hub.local.id,
      txId,
      session: proof,
      sessionId: `sg-${txId}`,
    }),
    ...cosigners.map(async (b, i) => {
      const sb = l.peers[i]!;
      const p = readProposal(await sb.next());
      if (p.kind !== 'sign') throw new Error('expected sign');
      const review = await b.vault.thresholdReview({
        request: p.request,
        session: p.session,
        proposerDeviceId: sb.peer.id,
        nowMs: Date.now(),
      });
      await joinSign({
        ops: opsFor(b.vault, b.local.id),
        link: sb,
        localId: b.local.id,
        proposal: p,
        session: proof,
      });
      return review;
    }),
  ]);
  return [signed as TxRecord, reviews as CosignSummary[]] as const;
}

/** A non-segwit transaction paying `value` sats to a Signet P2TR output key. */
export function fundingTx(outputKeyHex: string, value: bigint) {
  const le = (n: bigint, bytes: number) =>
    Array.from({ length: bytes }, (_, i) =>
      Number((n >> BigInt(8 * i)) & 0xffn)
        .toString(16)
        .padStart(2, '0'),
    ).join('');
  const hex =
    '02000000' +
    '01' +
    '11'.repeat(32) +
    '00000000' +
    '00' +
    'ffffffff' +
    '01' +
    le(value, 8) +
    '225120' +
    outputKeyHex +
    '00000000';
  const bytes = Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
  const txid = Array.from(sha256(sha256(bytes)).reverse(), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');
  return { txid, vout: 0, previousTxHex: hex };
}
