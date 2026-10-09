/**
 * Public-key encoding helpers shared by the adapters. Only point
 * compression/decompression lives here; it needs field arithmetic but no
 * scalar multiplication, so a full curve library is not justified yet.
 */
import type { PublicKey } from '@stackwallet/core-client';

import { UnsupportedKeyError } from './errors.js';

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new TypeError('invalid hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

// secp256k1 field prime and curve constant (y^2 = x^3 + 7).
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const B = 7n;

function mod(a: bigint, m = P): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m = P): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + (bytesToHex(bytes) || '0'));
}

function bigIntTo32(n: bigint): Uint8Array {
  return hexToBytes(n.toString(16).padStart(64, '0'));
}

function isOnCurve(x: bigint, y: bigint): boolean {
  return mod(y * y) === mod(x * x * x + B);
}

/**
 * Compressed (33-byte) or uncompressed (65-byte, `04` prefix) or raw 64-byte
 * secp256k1 key to uncompressed 65 bytes. Rejects points off the curve so a
 * corrupted key cannot silently produce a valid-looking address.
 */
export function secp256k1Uncompressed(key: Uint8Array): Uint8Array {
  if (key.length === 64) return secp256k1Uncompressed(concat(new Uint8Array([4]), key));
  if (key.length === 65) {
    if (key[0] !== 4) throw new UnsupportedKeyError('65-byte secp256k1 key must start with 04');
    const x = bytesToBigInt(key.subarray(1, 33));
    const y = bytesToBigInt(key.subarray(33, 65));
    if (x >= P || y >= P || !isOnCurve(x, y))
      throw new UnsupportedKeyError('point is not on secp256k1');
    return new Uint8Array(key);
  }
  if (key.length === 33) {
    const prefix = key[0];
    if (prefix !== 2 && prefix !== 3)
      throw new UnsupportedKeyError('compressed key must start with 02 or 03');
    const x = bytesToBigInt(key.subarray(1));
    if (x >= P) throw new UnsupportedKeyError('x coordinate out of field');
    // p ≡ 3 (mod 4), so the square root is a single exponentiation.
    const y2 = mod(x * x * x + B);
    let y = modPow(y2, (P + 1n) / 4n);
    if (mod(y * y) !== y2) throw new UnsupportedKeyError('point is not on secp256k1');
    if ((y & 1n) !== BigInt(prefix & 1)) y = P - y;
    return concat(new Uint8Array([4]), bigIntTo32(x), bigIntTo32(y));
  }
  throw new UnsupportedKeyError(`secp256k1 key must be 33, 64 or 65 bytes, got ${key.length}`);
}

/** Any accepted secp256k1 encoding to the 33-byte compressed form. */
export function secp256k1Compressed(key: Uint8Array): Uint8Array {
  const full = secp256k1Uncompressed(key);
  const yOdd = (full[64]! & 1) === 1;
  return concat(new Uint8Array([yOdd ? 3 : 2]), full.subarray(1, 33));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function publicKeyBytes(pub: PublicKey): Uint8Array {
  try {
    return hexToBytes(pub.hex);
  } catch {
    throw new UnsupportedKeyError('public key hex is malformed');
  }
}

export function requireCurve(pub: PublicKey, ...allowed: PublicKey['curve'][]): void {
  if (!allowed.includes(pub.curve)) {
    throw new UnsupportedKeyError(
      `curve ${pub.curve} cannot derive this address; expected ${allowed.join(' or ')}`,
    );
  }
}
