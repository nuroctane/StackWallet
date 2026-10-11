/**
 * Pairing between this browser and one other device over a `Carrier`. The
 * core's `Session` does the cryptography; this file pumps its bytes, keeps the
 * two UI-facing state machines (issuer: "show my code", scanner: "paste a
 * code") and pins the peer the core vouched for. It lives outside React so a
 * pane closing mid-handshake does not abandon the connection.
 */
import { useSyncExternalStore } from 'react';
import {
  encodePairingOffer,
  type CoreClient,
  type Device,
  type IdentityHandle,
  type PairingOffer,
  type SessionHandle,
} from '@stackwallet/core-client';

import type { LocalDevice } from '../store/devices.js';
import type { Carrier, CarrierFactory, OfferCarrier } from './carrier.js';

export const OFFER_TTL_MS = 10 * 60_000;
export const HANDSHAKE_TIMEOUT_MS = 30_000;
/** Lets the last frames of the handshake leave before the channel is torn down. */
export const LINGER_MS = 400;

export type Role = 'issuer' | 'scanner';

export function deviceOf(local: LocalDevice): Device {
  return {
    id: local.id,
    name: local.name,
    kind: local.kind,
    identityPubHex: local.identityPubHex,
    noiseStaticHex: local.noiseStaticHex,
    endpoints: [],
    pairedAtMs: 0,
    lastSeenAtMs: null,
    revokedAtMs: null,
  };
}

export interface RunPairingOptions {
  core: CoreClient;
  identity: IdentityHandle;
  local: Device;
  offer: PairingOffer;
  role: Role;
  carrier: Carrier;
  nowMs?: number;
  timeoutMs?: number;
}

/**
 * Drive one pairing handshake to completion. Resolves with the peer the core
 * authenticated (`paired` event) after the session's final frames have been
 * handed to the carrier; rejects if the channel closes, the core refuses, or
 * nothing happens for `timeoutMs`. The caller owns the carrier.
 */
export async function runPairingSession(opts: RunPairingOptions): Promise<Device> {
  const { core, identity, local, offer, role, carrier } = opts;
  const nowMs = opts.nowMs ?? Date.now();
  const timeoutMs = opts.timeoutMs ?? HANDSHAKE_TIMEOUT_MS;
  await carrier.ready;
  const session: SessionHandle =
    role === 'issuer'
      ? await core.pairAsIssuer(identity, local, offer, nowMs)
      : await core.pairAsScanner(identity, local, offer, nowMs);

  const drain = async () => {
    for (const bytes of await session.takeOutgoing()) carrier.send(bytes);
  };

  try {
    return await new Promise<Device>((resolve, reject) => {
      let settled = false;
      let chain: Promise<void> = Promise.resolve();
      const timer = setTimeout(
        () => fail(new Error('the other device did not answer in time')),
        timeoutMs,
      );
      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      };
      const succeed = (peer: Device) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(peer);
      };
      carrier.onClose((reason) => fail(new Error(reason)));
      carrier.onMessage((bytes) => {
        // Sequential: a Noise session must see ciphertexts in the order they were sent.
        chain = chain
          .then(async () => {
            if (settled) return;
            const events = await session.handleIncoming(bytes);
            await drain();
            for (const ev of events) {
              if (ev.type === 'paired') succeed(ev.peer);
              else if (ev.type === 'closed') fail(new Error(ev.reason));
            }
          })
          .catch((err: unknown) => fail(err instanceof Error ? err : new Error(String(err))));
      });
      drain().catch((err: unknown) => fail(err instanceof Error ? err : new Error(String(err))));
    });
  } finally {
    session.free();
  }
}

export type IssuerState =
  | { phase: 'idle' }
  | { phase: 'issuing' }
  | { phase: 'live'; offer: PairingOffer; text: string }
  | { phase: 'connecting'; offer: PairingOffer; text: string }
  | { phase: 'handshaking'; offer: PairingOffer }
  | { phase: 'paired'; peer: Device }
  | { phase: 'failed'; error: string };

export type ScannerState =
  | { phase: 'idle' }
  | { phase: 'answering'; offer: PairingOffer }
  | { phase: 'waiting'; offer: PairingOffer; answerText: string }
  | { phase: 'handshaking'; offer: PairingOffer }
  | { phase: 'paired'; peer: Device }
  | { phase: 'failed'; error: string };

export interface PairingView {
  issuer: IssuerState;
  scanner: ScannerState;
}

export interface PairingDeps {
  core: () => CoreClient | null;
  identity: () => Promise<IdentityHandle>;
  local: () => LocalDevice | null;
  carriers: CarrierFactory;
  pin: (peer: Device) => Promise<{ ok: true } | { ok: false; error: string }>;
  now?: () => number;
  lingerMs?: number;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export class PairingController {
  private view: PairingView = { issuer: { phase: 'idle' }, scanner: { phase: 'idle' } };
  private readonly listeners = new Set<() => void>();
  private issuerCarrier: OfferCarrier | null = null;
  private scannerCarrier: Carrier | null = null;
  // A reset while a flow is awaiting the carrier must win over that flow's
  // eventual failure; each flow only writes state while its run is current.
  private issuerRun = 0;
  private scannerRun = 0;
  private readonly now: () => number;
  private readonly lingerMs: number;

  constructor(private readonly deps: PairingDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.lingerMs = deps.lingerMs ?? LINGER_MS;
  }

  readonly subscribe = (l: () => void): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getSnapshot = (): PairingView => this.view;

  private set(next: Partial<PairingView>): void {
    this.view = { ...this.view, ...next };
    for (const l of this.listeners) l();
  }

  private setIssuer(run: number, issuer: IssuerState): boolean {
    if (run !== this.issuerRun) return false;
    this.set({ issuer });
    return true;
  }

  private setScanner(run: number, scanner: ScannerState): boolean {
    if (run !== this.scannerRun) return false;
    this.set({ scanner });
    return true;
  }

  private require(): { core: CoreClient; local: LocalDevice } {
    const core = this.deps.core();
    if (!core) throw new Error('core not loaded');
    const local = this.deps.local();
    if (!local) throw new Error('this browser has no device identity yet');
    return { core, local };
  }

  // -- issuer -------------------------------------------------------------

  /** Mint a fresh one-time code and a connection offer; shows both as one code. */
  async issue(): Promise<void> {
    if (this.view.issuer.phase === 'issuing') return;
    this.resetIssuer();
    const run = this.issuerRun;
    this.setIssuer(run, { phase: 'issuing' });
    try {
      const { core, local } = this.require();
      const offer: PairingOffer = {
        version: 1,
        deviceId: local.id,
        deviceName: local.name,
        kind: local.kind,
        identityPubHex: local.identityPubHex,
        noiseStaticHex: local.noiseStaticHex,
        endpoints: [],
        oneTimeCodeHex: await core.newPairingCodeHex(),
        expiresAtMs: this.now() + OFFER_TTL_MS,
      };
      const { carrier, text } = await this.deps.carriers.offer();
      if (run !== this.issuerRun) {
        carrier.close('superseded');
        return;
      }
      this.issuerCarrier = carrier;
      this.setIssuer(run, {
        phase: 'live',
        offer,
        text: `${encodePairingOffer(offer)}\n${text}`,
      });
    } catch (err) {
      this.setIssuer(run, { phase: 'failed', error: message(err) });
    }
  }

  /** The other device pasted our code and sent back its answer. */
  async acceptAnswer(answerText: string): Promise<void> {
    const state = this.view.issuer;
    if (state.phase !== 'live' || !this.issuerCarrier) return;
    const run = this.issuerRun;
    const carrier = this.issuerCarrier;
    const { offer, text } = state;
    this.setIssuer(run, { phase: 'connecting', offer, text });
    let answerAccepted = false;
    try {
      if (this.now() >= offer.expiresAtMs)
        throw new Error('this code has expired; issue a new one');
      await carrier.acceptAnswer(answerText);
      answerAccepted = true;
      await carrier.ready;
      this.setIssuer(run, { phase: 'handshaking', offer });
      const peer = await this.pairOver(carrier, offer, 'issuer');
      this.setIssuer(run, { phase: 'paired', peer });
    } catch (err) {
      // A rejected paste should not burn the offer; anything after the answer
      // was accepted does, since the one-time code may have been consumed.
      if (!answerAccepted && run === this.issuerRun) {
        this.setIssuer(run, { phase: 'live', offer, text });
        throw err;
      }
      this.setIssuer(run, { phase: 'failed', error: message(err) });
    } finally {
      if (run === this.issuerRun && this.view.issuer.phase !== 'live') this.dropIssuerCarrier();
    }
  }

  resetIssuer(): void {
    this.issuerRun += 1;
    this.dropIssuerCarrier();
    this.set({ issuer: { phase: 'idle' } });
  }

  private dropIssuerCarrier(): void {
    const carrier = this.issuerCarrier;
    this.issuerCarrier = null;
    if (carrier) setTimeout(() => carrier.close('done'), this.lingerMs);
  }

  // -- scanner ------------------------------------------------------------

  /** Pasted code from the other device: build the answer, then wait for the channel. */
  async connect(offer: PairingOffer, rtcOfferText: string): Promise<void> {
    if (this.view.scanner.phase === 'answering' || this.view.scanner.phase === 'handshaking') {
      return;
    }
    this.resetScanner();
    const run = this.scannerRun;
    this.setScanner(run, { phase: 'answering', offer });
    try {
      this.require();
      if (this.now() >= offer.expiresAtMs)
        throw new Error('this code has expired; ask for a fresh one');
      const { carrier, text } = await this.deps.carriers.answer(rtcOfferText);
      if (run !== this.scannerRun) {
        carrier.close('superseded');
        return;
      }
      this.scannerCarrier = carrier;
      this.setScanner(run, { phase: 'waiting', offer, answerText: text });
      await carrier.ready;
      this.setScanner(run, { phase: 'handshaking', offer });
      const peer = await this.pairOver(carrier, offer, 'scanner');
      this.setScanner(run, { phase: 'paired', peer });
    } catch (err) {
      this.setScanner(run, { phase: 'failed', error: message(err) });
    } finally {
      if (run === this.scannerRun) this.dropScannerCarrier();
    }
  }

  resetScanner(): void {
    this.scannerRun += 1;
    this.dropScannerCarrier();
    this.set({ scanner: { phase: 'idle' } });
  }

  private dropScannerCarrier(): void {
    const carrier = this.scannerCarrier;
    this.scannerCarrier = null;
    if (carrier) setTimeout(() => carrier.close('done'), this.lingerMs);
  }

  // -- shared -------------------------------------------------------------

  private async pairOver(carrier: Carrier, offer: PairingOffer, role: Role): Promise<Device> {
    const { core, local } = this.require();
    const identity = await this.deps.identity();
    try {
      const peer = await runPairingSession({
        core,
        identity,
        local: deviceOf(local),
        offer,
        role,
        carrier,
        nowMs: this.now(),
      });
      const pinned = await this.deps.pin(peer);
      if (!pinned.ok) throw new Error(pinned.error);
      return peer;
    } finally {
      identity.free();
    }
  }
}

export function usePairing(controller: PairingController): PairingView {
  return useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
}
