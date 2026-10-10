import { describe, expect, it } from 'vitest';

import {
  decodePairingOffer,
  Device,
  deviceIdFromPublicHex,
  encodePairingOffer,
  formatEndpoint,
  Frame,
  isPairingOfferExpired,
  PAIRING_OFFER_PREFIX,
  PairingOffer,
  PairingOfferError,
  pairingOfferIdMatches,
  parseEndpoint,
  SessionEvent,
} from './types.js';

const ZERO_KEY = '00'.repeat(32);
// SHA-256 of 32 zero bytes starts 66687aadf862bd776c8fc18b8e9f8e20...; the
// core takes the first 16 bytes of that as the device id.
const ZERO_KEY_ID = '66687aadf862bd776c8fc18b8e9f8e20';

const offer: PairingOffer = {
  version: 1,
  deviceId: ZERO_KEY_ID,
  deviceName: 'Study desktop',
  kind: 'desktop',
  identityPubHex: ZERO_KEY,
  noiseStaticHex: '11'.repeat(32),
  endpoints: ['tcp://192.168.1.20:4000'],
  oneTimeCodeHex: '22'.repeat(32),
  expiresAtMs: 1_700_000_000_000,
};

function base64Url(text: string): string {
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    if (err instanceof PairingOfferError) return err.code;
    throw err;
  }
  throw new Error('expected a PairingOfferError');
}

describe('pairing offer text form', () => {
  it('round-trips through encode and decode', () => {
    const text = encodePairingOffer(offer);
    expect(text.startsWith(PAIRING_OFFER_PREFIX)).toBe(true);
    expect(text).not.toMatch(/[+/=]/);
    expect(decodePairingOffer(text)).toEqual(offer);
    expect(decodePairingOffer(`  ${text}\n`)).toEqual(offer);
  });

  it('decodes exactly what the core emits, padded or not', () => {
    const json = JSON.stringify(offer);
    expect(decodePairingOffer(`${PAIRING_OFFER_PREFIX}${base64Url(json)}`)).toEqual(offer);
    const padded = btoa(json).replace(/\+/g, '-').replace(/\//g, '_');
    expect(decodePairingOffer(`${PAIRING_OFFER_PREFIX}${padded}`)).toEqual(offer);
  });

  it('rejects a missing prefix', () => {
    expect(codeOf(() => decodePairingOffer(base64Url(JSON.stringify(offer))))).toBe('prefix');
    expect(codeOf(() => decodePairingOffer('bitcoin:bc1q...'))).toBe('prefix');
  });

  it('rejects bytes that are not base64url', () => {
    expect(codeOf(() => decodePairingOffer(`${PAIRING_OFFER_PREFIX}not base64!`))).toBe('base64');
    expect(codeOf(() => decodePairingOffer(`${PAIRING_OFFER_PREFIX}a+b/c`))).toBe('base64');
  });

  it('rejects payloads that are not JSON', () => {
    expect(codeOf(() => decodePairingOffer(`${PAIRING_OFFER_PREFIX}${base64Url('{nope')}`))).toBe(
      'json',
    );
    // 0xff 0xfe can never start a UTF-8 sequence; base64url of those two bytes.
    const invalidUtf8 = `${PAIRING_OFFER_PREFIX}__4`;
    expect(codeOf(() => decodePairingOffer(invalidUtf8))).toBe('json');
  });

  it('rejects another wire version before looking at the shape', () => {
    const v2 = { ...offer, version: 2, deviceId: 'garbage' };
    expect(
      codeOf(() => decodePairingOffer(`${PAIRING_OFFER_PREFIX}${base64Url(JSON.stringify(v2))}`)),
    ).toBe('version');
  });

  it('rejects short or non-hex keys and codes', () => {
    for (const field of ['identityPubHex', 'noiseStaticHex', 'oneTimeCodeHex'] as const) {
      for (const bad of ['ab'.repeat(31), 'zz'.repeat(32), 'AB'.repeat(32)]) {
        const broken = { ...offer, [field]: bad };
        const text = `${PAIRING_OFFER_PREFIX}${base64Url(JSON.stringify(broken))}`;
        expect(
          codeOf(() => decodePairingOffer(text)),
          `${field}=${bad}`,
        ).toBe('shape');
      }
    }
    const shortId = { ...offer, deviceId: 'abcd' };
    expect(
      codeOf(() =>
        decodePairingOffer(`${PAIRING_OFFER_PREFIX}${base64Url(JSON.stringify(shortId))}`),
      ),
    ).toBe('shape');
  });

  it('enforces the device name byte limit the core uses', () => {
    expect(PairingOffer.safeParse({ ...offer, deviceName: '   ' }).success).toBe(false);
    expect(PairingOffer.safeParse({ ...offer, deviceName: 'a'.repeat(64) }).success).toBe(true);
    // 22 three-byte glyphs are 22 code units but 66 bytes.
    expect(PairingOffer.safeParse({ ...offer, deviceName: '€'.repeat(22) }).success).toBe(false);
  });

  it('knows when an offer has expired', () => {
    expect(isPairingOfferExpired(offer, offer.expiresAtMs - 1)).toBe(false);
    expect(isPairingOfferExpired(offer, offer.expiresAtMs)).toBe(true);
    expect(isPairingOfferExpired(offer, offer.expiresAtMs + 60_000)).toBe(true);
  });

  it('derives device ids the way the core does', async () => {
    expect(await deviceIdFromPublicHex(ZERO_KEY)).toBe(ZERO_KEY_ID);
    expect(await pairingOfferIdMatches(offer)).toBe(true);
    expect(await pairingOfferIdMatches({ ...offer, deviceId: '00'.repeat(16) })).toBe(false);
    await expect(deviceIdFromPublicHex('abcd')).rejects.toThrow();
  });
});

describe('endpoints', () => {
  it('parses and formats the two carrier forms', () => {
    expect(parseEndpoint('tcp://192.168.1.2:4000')).toEqual({
      kind: 'tcp',
      addr: '192.168.1.2:4000',
    });
    expect(parseEndpoint(`webrtc-via://${ZERO_KEY_ID}`)).toEqual({
      kind: 'webRtc',
      viaDeviceId: ZERO_KEY_ID,
    });
    for (const text of ['tcp://192.168.1.2:4000', `webrtc-via://${ZERO_KEY_ID}`]) {
      expect(formatEndpoint(parseEndpoint(text)!)).toBe(text);
    }
    expect(parseEndpoint('http://x')).toBeUndefined();
    expect(parseEndpoint('tcp://')).toBeUndefined();
    expect(parseEndpoint('webrtc-via://not-an-id')).toBeUndefined();
  });
});

describe('device and frame shapes', () => {
  it('parses the Rust serialization of a device, defaulting the noise static', () => {
    const d = Device.parse({
      id: ZERO_KEY_ID,
      name: 'Phone',
      kind: 'mobile',
      identityPubHex: ZERO_KEY,
      pairedAtMs: 1,
      lastSeenAtMs: null,
      revokedAtMs: null,
    });
    expect(d.noiseStaticHex).toBe('');
    expect(d.endpoints).toEqual([]);
  });

  it('parses every tagged frame variant', () => {
    const hello = Frame.parse({
      type: 'hello',
      deviceId: ZERO_KEY_ID,
      deviceName: 'Phone',
      kind: 'mobile',
      identityPubHex: ZERO_KEY,
      handshakeSigHex: 'ab'.repeat(64),
    });
    expect(hello.type).toBe('hello');
    const ceremony = Frame.parse({
      type: 'ceremony',
      msg: {
        sessionId: 's',
        payloadHashHex: 'cd'.repeat(32),
        fromDeviceId: ZERO_KEY_ID,
        toDeviceId: null,
        round: 1,
        bodyHex: '',
      },
      signatureHex: 'ef'.repeat(64),
    });
    expect(ceremony.type).toBe('ceremony');
    expect(Frame.parse({ type: 'ping', nonce: 7 })).toEqual({ type: 'ping', nonce: 7 });
    expect(Frame.parse({ type: 'pong', nonce: 7 }).type).toBe('pong');
    expect(Frame.parse({ type: 'bye', reason: 'done' }).type).toBe('bye');
    expect(
      Frame.parse({
        type: 'signal',
        toDeviceId: 'a',
        fromDeviceId: 'b',
        sdpOrIceJson: '{}',
      }).type,
    ).toBe('signal');
    expect(Frame.safeParse({ type: 'hello' }).success).toBe(false);
    expect(Frame.safeParse({ type: 'nope' }).success).toBe(false);
  });

  it('parses session events from the wasm bridge', () => {
    const peer = Device.parse({
      id: ZERO_KEY_ID,
      name: 'Phone',
      kind: 'mobile',
      identityPubHex: ZERO_KEY,
      noiseStaticHex: '11'.repeat(32),
      endpoints: [],
      pairedAtMs: 1,
      lastSeenAtMs: 2,
      revokedAtMs: null,
    });
    expect(SessionEvent.parse({ type: 'paired', peer }).type).toBe('paired');
    expect(SessionEvent.parse({ type: 'closed', reason: 'bye' }).type).toBe('closed');
    expect(
      SessionEvent.parse({
        type: 'relayed',
        signed: {
          msg: {
            sessionId: 's',
            payloadHashHex: 'cd'.repeat(32),
            fromDeviceId: ZERO_KEY_ID,
            toDeviceId: null,
            round: 2,
            bodyHex: 'ff',
          },
          signatureHex: 'ef'.repeat(64),
        },
      }).type,
    ).toBe('relayed');
    expect(SessionEvent.parse({ type: 'frame', frame: { type: 'ping', nonce: 1 } }).type).toBe(
      'frame',
    );
  });
});
