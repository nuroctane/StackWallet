/**
 * WebRTC data channel as a `Carrier`. Signalling is by hand: the offer and
 * answer travel as `stackwallet-rtc:` text that people paste or scan, so no
 * server is involved (D3). Without ICE servers only host candidates are
 * gathered, which reaches devices on the same network and nothing beyond it;
 * a relay would be a server and is deliberately absent.
 */
import type { Carrier, CarrierFactory, OfferCarrier } from './carrier.js';

export const RTC_PREFIX = 'stackwallet-rtc:';
export const CHANNEL_LABEL = 'stackwallet';
/** Host candidates arrive within a few hundred ms; this only guards a wedged stack. */
export const GATHER_TIMEOUT_MS = 4_000;
export const OPEN_TIMEOUT_MS = 30_000;

export interface Signal {
  type: 'offer' | 'answer';
  sdp: string;
}

function base64UrlEncode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(body: string): string | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(body)) return undefined;
  const padded = body
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(body.length / 4) * 4, '=');
  try {
    const bin = atob(padded);
    return new TextDecoder('utf-8', { fatal: true }).decode(
      Uint8Array.from(bin, (ch) => ch.charCodeAt(0)),
    );
  } catch {
    return undefined;
  }
}

export function encodeSignal(signal: Signal): string {
  return `${RTC_PREFIX}${base64UrlEncode(JSON.stringify(signal))}`;
}

export function decodeSignal(text: string): Signal {
  const trimmed = text.trim();
  if (!trimmed.startsWith(RTC_PREFIX)) throw new Error(`missing ${RTC_PREFIX} prefix`);
  const json = base64UrlDecode(trimmed.slice(RTC_PREFIX.length));
  if (json === undefined) throw new Error('not base64url');
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('malformed');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !('type' in parsed) ||
    !('sdp' in parsed) ||
    (parsed.type !== 'offer' && parsed.type !== 'answer') ||
    typeof parsed.sdp !== 'string' ||
    parsed.sdp.length === 0 ||
    parsed.sdp.length > 16_384
  ) {
    throw new Error('malformed');
  }
  return { type: parsed.type, sdp: parsed.sdp };
}

/**
 * Pull the pairing offer and the connection offer out of one pasted blob.
 * They are shown as two lines, but a paste may mangle whitespace, so each is
 * found by prefix wherever it sits.
 */
export function splitPairingText(text: string): { pair?: string; rtc?: string } {
  const out: { pair?: string; rtc?: string } = {};
  for (const token of text.split(/\s+/)) {
    if (token.startsWith('stackwallet-pair:')) out.pair = token;
    else if (token.startsWith(RTC_PREFIX)) out.rtc = token;
  }
  return out;
}

function waitForGathering(pc: RTCPeerConnection): Promise<void> {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      pc.removeEventListener('icegatheringstatechange', check);
      resolve();
    };
    const check = () => {
      if (pc.iceGatheringState === 'complete') done();
    };
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(done, GATHER_TIMEOUT_MS);
  });
}

class RtcCarrier implements OfferCarrier {
  private message: ((bytes: Uint8Array) => void) | null = null;
  private closed: ((reason: string) => void) | null = null;
  private queue: Uint8Array[] = [];
  private channel: RTCDataChannel | null = null;
  private opened = false;
  private done = false;
  private resolveReady!: () => void;
  private rejectReady!: (err: Error) => void;
  readonly ready = new Promise<void>((resolve, reject) => {
    this.resolveReady = resolve;
    this.rejectReady = reject;
  });

  constructor(readonly pc: RTCPeerConnection) {
    // Nobody may be awaiting `ready` when the channel dies (an offer that was
    // never answered); the rejection must not surface as unhandled.
    this.ready.catch(() => undefined);
    pc.addEventListener('connectionstatechange', () => {
      if (pc.connectionState === 'failed') this.fail('connection failed');
      else if (pc.connectionState === 'disconnected' || pc.connectionState === 'closed') {
        this.fail('connection closed');
      }
    });
  }

  /** Both descriptions are set; ICE is now running and must finish in bounded time. */
  armOpenTimeout(): void {
    setTimeout(() => {
      if (!this.opened) this.fail('timed out waiting for the other device');
    }, OPEN_TIMEOUT_MS);
  }

  attach(channel: RTCDataChannel): void {
    this.channel = channel;
    channel.binaryType = 'arraybuffer';
    channel.addEventListener('open', () => {
      this.opened = true;
      this.resolveReady();
    });
    channel.addEventListener('close', () => this.fail('channel closed'));
    channel.addEventListener('error', () => this.fail('channel error'));
    channel.addEventListener('message', (ev: MessageEvent<unknown>) => {
      const data = ev.data;
      const bytes =
        data instanceof ArrayBuffer
          ? new Uint8Array(data)
          : ArrayBuffer.isView(data)
            ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
            : null;
      // Text frames are not part of the protocol; dropping them keeps a
      // misbehaving peer from feeding the session something it never framed.
      if (!bytes) return;
      if (this.message) this.message(bytes);
      else this.queue.push(bytes);
    });
  }

  private fail(reason: string): void {
    if (this.done) return;
    this.done = true;
    this.rejectReady(new Error(reason));
    this.closed?.(reason);
    try {
      this.channel?.close();
      this.pc.close();
    } catch {
      // Already torn down.
    }
  }

  send(bytes: Uint8Array): void {
    if (!this.channel || this.channel.readyState !== 'open') throw new Error('channel not open');
    // Copy out of wasm linear memory: the view may alias a buffer that grows.
    this.channel.send(new Uint8Array(bytes).buffer as ArrayBuffer);
  }

  onMessage(cb: (bytes: Uint8Array) => void): void {
    this.message = cb;
    for (const bytes of this.queue.splice(0)) cb(bytes);
  }

  onClose(cb: (reason: string) => void): void {
    this.closed = cb;
  }

  close(reason = 'closed'): void {
    this.fail(reason);
  }

  async acceptAnswer(text: string): Promise<void> {
    const signal = decodeSignal(text);
    if (signal.type !== 'answer') throw new Error('expected an answer, got an offer');
    if (this.pc.signalingState !== 'have-local-offer') {
      throw new Error('this connection already has an answer');
    }
    await this.pc.setRemoteDescription({ type: 'answer', sdp: signal.sdp });
    this.armOpenTimeout();
  }
}

function newPeerConnection(): RTCPeerConnection {
  if (typeof RTCPeerConnection === 'undefined') {
    throw new Error('WebRTC is not available in this browser');
  }
  return new RTCPeerConnection({ iceServers: [] });
}

export const webRtcCarriers: CarrierFactory = {
  async offer() {
    const pc = newPeerConnection();
    const carrier = new RtcCarrier(pc);
    carrier.attach(pc.createDataChannel(CHANNEL_LABEL, { ordered: true }));
    await pc.setLocalDescription(await pc.createOffer());
    await waitForGathering(pc);
    const sdp = pc.localDescription?.sdp;
    if (!sdp) throw new Error('no local description');
    return { carrier, text: encodeSignal({ type: 'offer', sdp }) };
  },

  async answer(offerText: string) {
    const signal = decodeSignal(offerText);
    if (signal.type !== 'offer') throw new Error('expected an offer, got an answer');
    const pc = newPeerConnection();
    const carrier = new RtcCarrier(pc);
    pc.addEventListener('datachannel', (ev) => {
      if (ev.channel.label === CHANNEL_LABEL) carrier.attach(ev.channel);
    });
    await pc.setRemoteDescription({ type: 'offer', sdp: signal.sdp });
    await pc.setLocalDescription(await pc.createAnswer());
    await waitForGathering(pc);
    const sdp = pc.localDescription?.sdp;
    if (!sdp) throw new Error('no local description');
    carrier.armOpenTimeout();
    return { carrier: carrier as Carrier, text: encodeSignal({ type: 'answer', sdp }) };
  },
};
