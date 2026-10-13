/**
 * An authenticated channel to one paired device that carries ceremony
 * messages. The core's Noise session authenticates the peer against its
 * pinned record and verifies every envelope's identity signature; this file
 * only pumps bytes and queues what arrives.
 */
import type {
  CeremonyMessage,
  CoreClient,
  Device,
  IdentityHandle,
  SessionHandle,
  SignedCeremonyMessage,
} from '@stackwallet/core-client';

import type { Carrier } from '../core/carrier.js';

export const LINK_TIMEOUT_MS = 60_000;

export interface CeremonyLink {
  readonly peer: Device;
  send(msg: CeremonyMessage): Promise<void>;
  /** The next message from the peer; rejects on close or after `timeoutMs`. */
  next(timeoutMs?: number): Promise<CeremonyMessage>;
  close(reason: string): void;
}

export interface OpenLinkOptions {
  core: CoreClient;
  identity: IdentityHandle;
  local: Device;
  carrier: Carrier;
  /** Signs an envelope with this device's identity. */
  sign: (msg: CeremonyMessage) => Promise<SignedCeremonyMessage>;
  /** The initiator names the peer; the responder accepts any pinned device. */
  role: { kind: 'initiator'; peer: Device } | { kind: 'responder'; known: Device[] };
  timeoutMs?: number;
}

export async function openLink(opts: OpenLinkOptions): Promise<CeremonyLink> {
  const { core, identity, local, carrier, sign, role } = opts;
  const timeoutMs = opts.timeoutMs ?? LINK_TIMEOUT_MS;
  await carrier.ready;
  const session: SessionHandle =
    role.kind === 'initiator'
      ? await core.connectInitiator(identity, local, role.peer, Date.now())
      : await core.connectResponder(identity, local, role.known, Date.now());

  const inbox: CeremonyMessage[] = [];
  let waiter: { resolve: (m: CeremonyMessage) => void; reject: (e: Error) => void } | null = null;
  let closed: Error | null = null;
  let peer: Device | null = null;
  let opened!: () => void;
  let failOpen!: (e: Error) => void;
  const open = new Promise<void>((resolve, reject) => {
    opened = resolve;
    failOpen = reject;
  });

  const shut = (err: Error) => {
    if (closed) return;
    closed = err;
    failOpen(err);
    waiter?.reject(err);
    waiter = null;
  };
  const deliver = (msg: CeremonyMessage) => {
    if (waiter) {
      const w = waiter;
      waiter = null;
      w.resolve(msg);
    } else inbox.push(msg);
  };
  const drain = async () => {
    for (const bytes of await session.takeOutgoing()) carrier.send(bytes);
  };

  let chain: Promise<void> = Promise.resolve();
  carrier.onClose((reason) => shut(new Error(reason || 'the connection closed')));
  carrier.onMessage((bytes) => {
    // A Noise session must see ciphertexts in the order they were sent.
    chain = chain
      .then(async () => {
        if (closed) return;
        const events = await session.handleIncoming(bytes);
        await drain();
        for (const ev of events) {
          if (ev.type === 'opened') {
            if (role.kind === 'initiator' && ev.peer.id !== role.peer.id) {
              shut(new Error('connected to a different device than chosen'));
              return;
            }
            peer = ev.peer;
            opened();
          } else if (ev.type === 'frame' && ev.frame.type === 'ceremony') {
            // The session verified the envelope against the peer's pinned identity.
            if (ev.frame.msg.fromDeviceId !== peer?.id) {
              shut(new Error('a message did not come from the connected device'));
              return;
            }
            deliver(ev.frame.msg);
          } else if (ev.type === 'relayed') {
            shut(
              new Error(
                'the peer relayed a message from another device; ceremonies here are direct',
              ),
            );
          } else if (ev.type === 'closed') {
            shut(new Error(ev.reason));
          }
        }
      })
      .catch((err: unknown) => shut(err instanceof Error ? err : new Error(String(err))));
  });
  await drain();

  const timer = setTimeout(
    () => shut(new Error('the other device did not connect in time')),
    timeoutMs,
  );
  try {
    await open;
  } catch (err) {
    session.free();
    carrier.close('failed');
    throw err;
  } finally {
    clearTimeout(timer);
  }

  return {
    peer: peer!,
    async send(msg) {
      if (closed) throw closed;
      const signed = await sign(msg);
      await session.sendFrame({ type: 'ceremony', ...signed });
      await drain();
    },
    next(ms = timeoutMs) {
      if (inbox.length > 0) return Promise.resolve(inbox.shift()!);
      if (closed) return Promise.reject(closed);
      return new Promise<CeremonyMessage>((resolve, reject) => {
        const t = setTimeout(() => {
          waiter = null;
          reject(new Error('the other device stopped answering'));
        }, ms);
        waiter = {
          resolve: (m) => {
            clearTimeout(t);
            resolve(m);
          },
          reject: (e) => {
            clearTimeout(t);
            reject(e);
          },
        };
      });
    },
    close(reason) {
      shut(new Error(reason));
      void session
        .close(reason)
        .then(drain)
        .catch(() => undefined)
        .finally(() => {
          session.free();
          carrier.close(reason);
        });
    },
  };
}
