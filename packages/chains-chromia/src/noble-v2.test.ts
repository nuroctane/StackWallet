/**
 * Guards the @noble/curves v2 point API. Version 2 split the decoders: byte
 * input goes through `Point.fromBytes`, while `Point.fromHex` is string-only.
 * The FT4 helpers already hold SEC1 bytes, so they must decode those bytes
 * directly rather than round-tripping through hex.
 */
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';

vi.mock('@noble/curves/secp256k1.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@noble/curves/secp256k1.js')>();
  const RealPoint = actual.secp256k1.Point;
  class StringOnlyPoint extends RealPoint {
    static override fromHex(): never {
      throw new Error('Point.fromHex is string-only; SEC1 bytes go to Point.fromBytes');
    }
  }
  return { ...actual, secp256k1: { ...actual.secp256k1, Point: StringOnlyPoint } };
});

import { chromiaAccountIdFromPublicKey, chromiaAuthDescriptor } from './chromia.js';

/** Compressed key of the synthetic private key 0x07..07 and its FT4 account id. */
const PUBKEY = '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const ACCOUNT = '40e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122';

describe('chromia point decoding', () => {
  it('derives the FT4 account id from raw public-key bytes', () => {
    expect(chromiaAccountIdFromPublicKey(hexToBytes(PUBKEY))).toBe(ACCOUNT);
  });

  it('embeds the compressed key in the auth descriptor', () => {
    expect(chromiaAuthDescriptor(hexToBytes(PUBKEY))).toEqual([
      0,
      [['A', 'T'], hexToBytes(PUBKEY)],
      null,
    ]);
  });
});
