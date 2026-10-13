/**
 * The two-device ceremonies over a `CeremonyLink`. The proposer sends one
 * proposal (round 0); the other device reviews it in its own core before its
 * share does anything, then both drivers exchange rounds until done. Every
 * check lives in the core; this file only orders the steps.
 */
import {
  ThresholdProposal,
  type CeremonyMessage,
  type CeremonySession,
  type CosignSummary,
  type KeyGroup,
  type SessionProof,
  type SignRequest,
  type ThresholdAccount,
  type ThresholdDriverHandle,
  type TxRecord,
} from '@stackwallet/core-client';

import type { CeremonyLink } from './link.js';

export const PROPOSAL_ROUND = 0;
/** Lets the last round's frames leave before the channel closes. */
export const LINGER_MS = 400;
export const SESSION_MS = 10 * 60_000;

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

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

/** Run rounds until this driver holds its result. */
export async function exchange(
  driver: ThresholdDriverHandle,
  link: CeremonyLink,
  onRound?: (n: number) => void,
): Promise<void> {
  for (const m of await driver.takeInitial()) await link.send(m);
  let n = 0;
  while (!(await driver.complete())) {
    const msg = await link.next();
    onRound?.(++n);
    for (const out of await driver.handle(msg)) await link.send(out);
  }
}

async function finish(link: CeremonyLink, reason: string) {
  await new Promise((r) => setTimeout(r, LINGER_MS));
  link.close(reason);
}

async function guarded<T>(
  ops: ThresholdOps,
  driver: ThresholdDriverHandle,
  link: CeremonyLink,
  run: () => Promise<T>,
): Promise<T> {
  try {
    const out = await run();
    await ops.thresholdEnd(driver, null);
    await finish(link, 'done');
    return out;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    await ops.thresholdEnd(driver, reason).catch(() => undefined);
    link.close('aborted');
    throw err;
  } finally {
    driver.free();
  }
}

/** Proposer side of DKG for a new 2-party wallet. */
export async function proposeKeygen(opts: {
  ops: ThresholdOps;
  link: CeremonyLink;
  localId: string;
  walletId: string;
  group: KeyGroup;
  ceremony: CeremonySession;
  session: SessionProof;
}): Promise<ThresholdAccount> {
  const { ops, link } = opts;
  const driver = unwrap(
    await ops.thresholdKeygen({
      session: opts.session,
      walletId: opts.walletId,
      group: opts.group,
      ceremony: opts.ceremony,
    }),
  );
  return guarded(ops, driver, link, async () => {
    await link.send(
      proposalMessage(
        { kind: 'keyGen', group: opts.group, session: opts.ceremony },
        opts.localId,
        link.peer.id,
      ),
    );
    await exchange(driver, link);
    return unwrap(await ops.thresholdFinishKeygen(driver));
  });
}

/** Joiner side of DKG, after the user accepted the proposal. */
export async function joinKeygen(opts: {
  ops: ThresholdOps;
  link: CeremonyLink;
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
  return guarded(ops, driver, link, async () => {
    await exchange(driver, link);
    return unwrap(await ops.thresholdFinishKeygen(driver));
  });
}

/**
 * Approve a threshold wallet's transaction: the ledger runs its signing-time
 * checks and hands out the request, the co-signer reviews it in its own core,
 * and the aggregate signature goes back through the ledger.
 */
export async function proposeSign(opts: {
  ops: ThresholdOps;
  link: CeremonyLink;
  localId: string;
  txId: string;
  session: SessionProof;
  sessionId: string;
}): Promise<TxRecord> {
  const { ops, link } = opts;
  const begun = unwrap(await ops.txBeginThreshold(opts.txId, opts.session));
  if (!begun.request) {
    link.close('refused');
    return begun.record;
  }
  const request = begun.request;
  const now = Date.now();
  const ceremony: CeremonySession = {
    id: opts.sessionId,
    kind: 'sign',
    keyGroupId: request.keyGroupId,
    curve: 'ed25519',
    payloadHashHex: request.payloadHashHex,
    participants: [opts.localId, link.peer.id],
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
  const signature = await guarded(ops, driver, link, async () => {
    await link.send(
      proposalMessage({ kind: 'sign', request, session: ceremony }, opts.localId, link.peer.id),
    );
    await exchange(driver, link);
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
  await guarded(ops, driver, link, () => exchange(driver, link));
}
