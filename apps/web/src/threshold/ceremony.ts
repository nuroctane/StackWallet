/**
 * Ceremonies between paired devices over `CeremonyLink`s. The proposer is the
 * hub: it holds one link per other party, sends each a proposal (round 0),
 * and forwards protocol envelopes between them unchanged. Every other party
 * reviews the proposal in its own core before its share does anything, then
 * talks only to the hub. With two devices the hub simply has one link.
 * Every check lives in the core; this file only orders the steps.
 */
import {
  ThresholdProposal,
  type CeremonyMessage,
  type CeremonySession,
  type CosignSummary,
  type KeyGroup,
  type SessionProof,
  type ShareFingerprint,
  type SignRequest,
  type ThresholdAccount,
  type ThresholdDriverHandle,
  type TxRecord,
} from '@stackwallet/core-client';

import type { CeremonyLink, Envelope } from './link.js';

export const PROPOSAL_ROUND = 0;
/** A party that holds its result tells the hub, which stops relaying only then. */
export const DONE_ROUND = 253;
/** After a refresh, each device reports which share generation it now holds. */
export const FINGERPRINT_ROUND = 254;
/** Lets the last round's frames leave before the channel closes. */
export const LINGER_MS = 400;
export const SESSION_MS = 10 * 60_000;

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export type Reconciled = 'inSync' | 'committed' | 'rolledBack';

/** The vault operations a ceremony needs; the page's vault store provides them. */
export interface ThresholdOps {
  thresholdKeygen(req: {
    session: SessionProof;
    walletId: string;
    group: KeyGroup;
    ceremony: CeremonySession;
  }): Promise<Result<ThresholdDriverHandle>>;
  thresholdFinishKeygen(driver: ThresholdDriverHandle): Promise<Result<ThresholdAccount>>;
  thresholdSign(req: {
    session: SessionProof;
    request: SignRequest;
    ceremony: CeremonySession;
    proposerDeviceId: string;
  }): Promise<Result<ThresholdDriverHandle>>;
  thresholdReview(
    request: SignRequest,
    ceremony: CeremonySession,
    proposerDeviceId: string,
  ): Promise<Result<CosignSummary>>;
  thresholdEnd(driver: ThresholdDriverHandle, aborted: string | null): Promise<unknown>;
  txBeginThreshold(
    txId: string,
    session: SessionProof,
  ): Promise<Result<{ record: TxRecord; request: SignRequest | null }>>;
  txCompleteThreshold(txId: string, signatureHex: string): Promise<Result<TxRecord>>;
  thresholdRefresh(req: {
    session: SessionProof;
    ceremony: CeremonySession;
  }): Promise<Result<ThresholdDriverHandle>>;
  thresholdFinishRefresh(driver: ThresholdDriverHandle): Promise<Result<ThresholdAccount>>;
  thresholdShareFingerprint(walletId: string): Promise<Result<ShareFingerprint>>;
  thresholdReconcile(
    session: SessionProof,
    walletId: string,
    peerCurrents: string[],
  ): Promise<Result<Reconciled>>;
}

function unwrap<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(r.error);
  return r.value;
}

function toHex(text: string): string {
  return [...new TextEncoder().encode(text)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): string {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error('proposal body is not hex');
  return new TextDecoder('utf-8', { fatal: true }).decode(
    Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16)),
  );
}

export function proposalMessage(p: ThresholdProposal, from: string, to: string): CeremonyMessage {
  return {
    sessionId: p.session.id,
    payloadHashHex: p.session.payloadHashHex ?? '',
    fromDeviceId: from,
    toDeviceId: to,
    round: PROPOSAL_ROUND,
    bodyHex: toHex(JSON.stringify(p)),
  };
}

/** A proposal whose envelope does not match its own session is refused. */
export function readProposal(msg: CeremonyMessage): ThresholdProposal {
  if (msg.round !== PROPOSAL_ROUND) throw new Error('expected a ceremony proposal first');
  const p = ThresholdProposal.parse(JSON.parse(fromHex(msg.bodyHex)));
  if (
    p.session.id !== msg.sessionId ||
    (p.session.payloadHashHex ?? '') !== msg.payloadHashHex ||
    !p.session.participants.includes(msg.fromDeviceId)
  )
    throw new Error('the proposal envelope does not match its session');
  return p;
}

type Arrival = { env: Envelope; link: CeremonyLink };

/**
 * Reads several links at once and hands out the first arrival a caller asks
 * for, keeping the rest in order: a fast party's refresh fingerprint can
 * arrive while a slower one is still in protocol rounds.
 */
class Mailbox {
  private readonly stash: Arrival[] = [];
  private readonly pending = new Map<
    CeremonyLink,
    Promise<{ ok: true; arrival: Arrival } | { ok: false; link: CeremonyLink; error: unknown }>
  >();
  constructor(private readonly links: readonly CeremonyLink[]) {}

  async take(match: (a: Arrival) => boolean): Promise<Arrival> {
    const kept = this.stash.findIndex(match);
    if (kept >= 0) return this.stash.splice(kept, 1)[0]!;
    for (;;) {
      for (const link of this.links)
        if (!this.pending.has(link))
          this.pending.set(
            link,
            link.nextEnvelope().then(
              (env) => ({ ok: true as const, arrival: { env, link } }),
              (error: unknown) => ({ ok: false as const, link, error }),
            ),
          );
      const got = await Promise.race(this.pending.values());
      if (!got.ok) {
        this.pending.delete(got.link);
        throw got.error;
      }
      this.pending.delete(got.arrival.link);
      if (match(got.arrival)) return got.arrival;
      // A ceremony has a handful of messages in flight; more is a flood.
      if (this.stash.length >= 256) throw new Error('too many unexpected ceremony messages');
      this.stash.push(got.arrival);
    }
  }
}

const isRound = (a: Arrival) =>
  a.env.msg.round !== FINGERPRINT_ROUND && a.env.msg.round !== PROPOSAL_ROUND;

/**
 * The hub's rounds: run the local driver, deliver its output to the addressed
 * link (or every link), forward what one party sends to another unchanged,
 * and keep relaying until every party has said it holds its result.
 */
async function hubRounds(
  driver: ThresholdDriverHandle,
  box: Mailbox,
  links: readonly CeremonyLink[],
  localId: string,
): Promise<void> {
  const byId = new Map(links.map((l) => [l.peer.id, l]));
  const route = async (m: CeremonyMessage) => {
    if (m.toDeviceId === null) for (const l of links) await l.send(m);
    else {
      const to = byId.get(m.toDeviceId);
      if (!to) throw new Error(`no connection to ${m.toDeviceId}`);
      await to.send(m);
    }
  };
  for (const m of await driver.takeInitial()) await route(m);
  const done = new Set<string>();
  while (!(await driver.complete()) || done.size < links.length) {
    const { env, link } = await box.take(isRound);
    const m = env.msg;
    if (m.round === DONE_ROUND) {
      if (m.toDeviceId !== localId || m.fromDeviceId !== link.peer.id)
        throw new Error('a misaddressed completion notice');
      done.add(link.peer.id);
      continue;
    }
    // Peers do not relay; only the hub forwards between them.
    if (m.fromDeviceId !== link.peer.id) throw new Error('a peer passed on another device');
    if (m.toDeviceId !== null && m.toDeviceId !== localId) {
      const to = byId.get(m.toDeviceId);
      if (!to || to === link) throw new Error(`cannot deliver to ${m.toDeviceId}`);
      await to.forward(env.signed);
      continue;
    }
    if (m.toDeviceId === null) for (const l of links) if (l !== link) await l.forward(env.signed);
    for (const out of await driver.handle(m)) await route(out);
  }
}

/** A non-hub party's rounds, all through its one link to the hub. */
async function peerRounds(
  driver: ThresholdDriverHandle,
  box: Mailbox,
  link: CeremonyLink,
  localId: string,
): Promise<void> {
  for (const m of await driver.takeInitial()) await link.send(m);
  while (!(await driver.complete())) {
    const { env } = await box.take(isRound);
    for (const out of await driver.handle(env.msg)) await link.send(out);
  }
  const s = await driver.session();
  await link.send({
    sessionId: s.id,
    payloadHashHex: s.payloadHashHex ?? '',
    fromDeviceId: localId,
    toDeviceId: link.peer.id,
    round: DONE_ROUND,
    bodyHex: '',
  });
}

async function finish(links: readonly CeremonyLink[], reason: string) {
  await new Promise((r) => setTimeout(r, LINGER_MS));
  for (const l of links) l.close(reason);
}

async function guarded<T>(
  ops: ThresholdOps,
  driver: ThresholdDriverHandle,
  links: readonly CeremonyLink[],
  run: () => Promise<T>,
): Promise<T> {
  try {
    const out = await run();
    await ops.thresholdEnd(driver, null);
    await finish(links, 'done');
    return out;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    await ops.thresholdEnd(driver, reason).catch(() => undefined);
    for (const l of links) l.close('aborted');
    throw err;
  } finally {
    driver.free();
  }
}

async function sendProposal(p: ThresholdProposal, links: readonly CeremonyLink[], localId: string) {
  for (const l of links) await l.send(proposalMessage(p, localId, l.peer.id));
}

/** Proposer side of DKG: `links` reach every other party of `group`. */
export async function proposeKeygen(opts: {
  ops: ThresholdOps;
  links: CeremonyLink[];
  localId: string;
  walletId: string;
  group: KeyGroup;
  ceremony: CeremonySession;
  session: SessionProof;
}): Promise<ThresholdAccount> {
  const { ops, links } = opts;
  const driver = unwrap(
    await ops.thresholdKeygen({
      session: opts.session,
      walletId: opts.walletId,
      group: opts.group,
      ceremony: opts.ceremony,
    }),
  );
  return guarded(ops, driver, links, async () => {
    await sendProposal(
      { kind: 'keyGen', group: opts.group, session: opts.ceremony },
      links,
      opts.localId,
    );
    await hubRounds(driver, new Mailbox(links), links, opts.localId);
    return unwrap(await ops.thresholdFinishKeygen(driver));
  });
}

/** Joiner side of DKG, after the user accepted the proposal. */
export async function joinKeygen(opts: {
  ops: ThresholdOps;
  link: CeremonyLink;
  localId: string;
  proposal: Extract<ThresholdProposal, { kind: 'keyGen' }>;
  walletId: string;
  session: SessionProof;
}): Promise<ThresholdAccount> {
  const { ops, link, proposal } = opts;
  const driver = unwrap(
    await ops.thresholdKeygen({
      session: opts.session,
      walletId: opts.walletId,
      group: proposal.group,
      ceremony: proposal.session,
    }),
  );
  return guarded(ops, driver, [link], async () => {
    await peerRounds(driver, new Mailbox([link]), link, opts.localId);
    return unwrap(await ops.thresholdFinishKeygen(driver));
  });
}

/**
 * Approve a threshold wallet's transaction: the ledger runs its signing-time
 * checks and hands out the request, each co-signer reviews it in its own core,
 * and the aggregate signature goes back through the ledger. `links` reach the
 * co-signers chosen for this signature.
 */
export async function proposeSign(opts: {
  ops: ThresholdOps;
  links: CeremonyLink[];
  localId: string;
  txId: string;
  session: SessionProof;
  sessionId: string;
}): Promise<TxRecord> {
  const { ops, links } = opts;
  const begun = unwrap(await ops.txBeginThreshold(opts.txId, opts.session));
  if (!begun.request) {
    for (const l of links) l.close('refused');
    return begun.record;
  }
  const request = begun.request;
  const now = Date.now();
  const ceremony: CeremonySession = {
    id: opts.sessionId,
    kind: 'sign',
    keyGroupId: request.keyGroupId,
    // The core picked the curve from the wallet's group key.
    curve: request.curve,
    payloadHashHex: request.payloadHashHex,
    participants: [opts.localId, ...links.map((l) => l.peer.id)],
    state: 'rounds',
    createdAtMs: now,
    expiresAtMs: now + SESSION_MS,
  };
  const driver = unwrap(
    await ops.thresholdSign({
      session: opts.session,
      request,
      ceremony,
      proposerDeviceId: opts.localId,
    }),
  );
  const signature = await guarded(ops, driver, links, async () => {
    await sendProposal({ kind: 'sign', request, session: ceremony }, links, opts.localId);
    await hubRounds(driver, new Mailbox(links), links, opts.localId);
    const sig = await driver.signatureHex();
    if (!sig) throw new Error('the ceremony finished without a signature');
    return sig;
  });
  return unwrap(await ops.txCompleteThreshold(opts.txId, signature));
}

/** Co-signer side, after the user read the core's review and agreed. */
export async function joinSign(opts: {
  ops: ThresholdOps;
  link: CeremonyLink;
  localId: string;
  proposal: Extract<ThresholdProposal, { kind: 'sign' }>;
  session: SessionProof;
}): Promise<void> {
  const { ops, link, proposal } = opts;
  const driver = unwrap(
    await ops.thresholdSign({
      session: opts.session,
      request: proposal.request,
      ceremony: proposal.session,
      proposerDeviceId: link.peer.id,
    }),
  );
  await guarded(ops, driver, [link], () =>
    peerRounds(driver, new Mailbox([link]), link, opts.localId),
  );
}

/**
 * Swap share fingerprints with every other party and settle any pending
 * refresh: the core commits only if all of them hold the new share and rolls
 * back only if one still holds the old one, so a message lost here cannot
 * split the devices. Fingerprints are public and broadcast; the hub forwards
 * each to the other parties.
 */
async function reconcile(opts: {
  ops: ThresholdOps;
  box: Mailbox;
  links: readonly CeremonyLink[];
  hub: boolean;
  ceremony: CeremonySession;
  localId: string;
  walletId: string;
  session: SessionProof;
}): Promise<Reconciled> {
  const { ops, links, ceremony } = opts;
  const mine = unwrap(await ops.thresholdShareFingerprint(opts.walletId));
  for (const l of links)
    await l.send({
      sessionId: ceremony.id,
      payloadHashHex: ceremony.payloadHashHex ?? '',
      fromDeviceId: opts.localId,
      toDeviceId: null,
      round: FINGERPRINT_ROUND,
      bodyHex: mine.current,
    });
  const others = ceremony.participants.filter((p) => p !== opts.localId);
  const heard = new Map<string, string>();
  while (heard.size < others.length) {
    const { env, link } = await opts.box.take((a) => a.env.msg.round === FINGERPRINT_ROUND);
    const m = env.msg;
    if (
      m.sessionId !== ceremony.id ||
      m.toDeviceId !== null ||
      !others.includes(m.fromDeviceId) ||
      heard.has(m.fromDeviceId) ||
      !/^[0-9a-f]{64}$/.test(m.bodyHex)
    )
      throw new Error('a device did not report its share generation properly');
    heard.set(m.fromDeviceId, m.bodyHex);
    if (opts.hub) for (const l of links) if (l !== link) await l.forward(env.signed);
  }
  return unwrap(await ops.thresholdReconcile(opts.session, opts.walletId, [...heard.values()]));
}

/**
 * Proposer side of a share refresh: new share material on every device, the
 * same addresses. Each device keeps its previous share sealed until every
 * other one has reported the new generation.
 */
export async function proposeRefresh(opts: {
  ops: ThresholdOps;
  links: CeremonyLink[];
  localId: string;
  walletId: string;
  ceremony: CeremonySession;
  session: SessionProof;
}): Promise<Reconciled> {
  const { ops, links } = opts;
  const driver = unwrap(
    await ops.thresholdRefresh({ session: opts.session, ceremony: opts.ceremony }),
  );
  return guarded(ops, driver, links, async () => {
    const box = new Mailbox(links);
    await sendProposal({ kind: 'refresh', session: opts.ceremony }, links, opts.localId);
    await hubRounds(driver, box, links, opts.localId);
    unwrap(await ops.thresholdFinishRefresh(driver));
    return reconcile({ ...opts, box, hub: true });
  });
}

/** Joiner side of a refresh, after the user agreed. */
export async function joinRefresh(opts: {
  ops: ThresholdOps;
  link: CeremonyLink;
  localId: string;
  walletId: string;
  proposal: Extract<ThresholdProposal, { kind: 'refresh' }>;
  session: SessionProof;
}): Promise<Reconciled> {
  const { ops, link, proposal } = opts;
  const driver = unwrap(
    await ops.thresholdRefresh({ session: opts.session, ceremony: proposal.session }),
  );
  return guarded(ops, driver, [link], async () => {
    const box = new Mailbox([link]);
    await peerRounds(driver, box, link, opts.localId);
    unwrap(await ops.thresholdFinishRefresh(driver));
    return reconcile({
      ...opts,
      box,
      links: [link],
      hub: false,
      ceremony: proposal.session,
    });
  });
}

/** Settle a refresh left pending (a dropped connection) with every other device. */
export async function proposeReconcile(opts: {
  ops: ThresholdOps;
  links: CeremonyLink[];
  localId: string;
  walletId: string;
  ceremony: CeremonySession;
  session: SessionProof;
}): Promise<Reconciled> {
  try {
    await sendProposal({ kind: 'reconcile', session: opts.ceremony }, opts.links, opts.localId);
    const out = await reconcile({ ...opts, box: new Mailbox(opts.links), hub: true });
    await finish(opts.links, 'done');
    return out;
  } catch (err) {
    for (const l of opts.links) l.close('aborted');
    throw err;
  }
}

export async function joinReconcile(opts: {
  ops: ThresholdOps;
  link: CeremonyLink;
  localId: string;
  walletId: string;
  proposal: Extract<ThresholdProposal, { kind: 'reconcile' }>;
  session: SessionProof;
}): Promise<Reconciled> {
  try {
    const out = await reconcile({
      ...opts,
      box: new Mailbox([opts.link]),
      links: [opts.link],
      hub: false,
      ceremony: opts.proposal.session,
    });
    await finish([opts.link], 'done');
    return out;
  } catch (err) {
    opts.link.close('aborted');
    throw err;
  }
}
