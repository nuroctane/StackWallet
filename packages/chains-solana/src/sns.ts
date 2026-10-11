/**
 * Solana Name Service, read directly from chain accounts so no third-party
 * proxy sits between the user and their names. Only the favourite (primary)
 * domain is shown, and only after its name account is confirmed to be owned
 * by the address it is displayed for.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { base58 } from '@scure/base';

export const NAME_PROGRAM_ID = 'namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX';
export const SOL_TLD = '58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx';
export const REVERSE_LOOKUP_CLASS = '33m47vH6Eav6jr5Ry86XjhRft2jRBLDnDgPSHoquXi2Z';
export const NAME_OFFERS_ID = '85iDfUvr3HJyLM2zcq5BXSiDvUWfw6cSE1FfNBo8Ap29';
const HASH_PREFIX = 'SPL Name Service';
const PDA_MARKER = new TextEncoder().encode('ProgramDerivedAddress');
/** parent (32) + owner (32) + class (32) */
export const NAME_HEADER_LEN = 96;

const P = 2n ** 255n - 19n;
const D = (-121665n * modInv(121666n)) % P;

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function modPow(b: bigint, e: bigint): bigint {
  let r = 1n;
  let x = mod(b);
  let k = e;
  while (k > 0n) {
    if (k & 1n) r = (r * x) % P;
    x = (x * x) % P;
    k >>= 1n;
  }
  return r;
}

function modInv(a: bigint): bigint {
  return modPow(a, P - 2n);
}

/**
 * True when the 32 bytes decode to a point on edwards25519. Program derived
 * addresses must be off the curve, so this is the only curve check PDA
 * derivation needs; a full curve library would be dead weight here.
 */
export function isOnEd25519(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? bytes[i]! & 0x7f : bytes[i]!);
  if (y >= P) return false;
  const y2 = mod(y * y);
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const x2 = mod(u * modInv(v));
  if (x2 === 0n) return (bytes[31]! & 0x80) === 0;
  // Euler's criterion: x² has a square root iff it is a quadratic residue.
  return modPow(x2, (P - 1n) / 2n) === 1n;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function findProgramAddress(seeds: readonly Uint8Array[], programId: string): string {
  const program = base58.decode(programId);
  for (let bump = 255; bump >= 0; bump--) {
    const hash = sha256(concat([...seeds, Uint8Array.of(bump), program, PDA_MARKER]));
    if (!isOnEd25519(hash)) return base58.encode(hash);
  }
  throw new Error('no viable program address');
}

const ZERO32 = new Uint8Array(32);

export function hashedName(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(HASH_PREFIX + name));
}

export function nameAccountKey(hashed: Uint8Array, nameClass?: string, parent?: string): string {
  return findProgramAddress(
    [
      hashed,
      nameClass ? base58.decode(nameClass) : ZERO32,
      parent ? base58.decode(parent) : ZERO32,
    ],
    NAME_PROGRAM_ID,
  );
}

/** Name account of `label.sol`. */
export function domainKey(label: string): string {
  return nameAccountKey(hashedName(label), undefined, SOL_TLD);
}

export function reverseKey(nameAccount: string): string {
  return nameAccountKey(hashedName(nameAccount), REVERSE_LOOKUP_CLASS);
}

export function favouriteKey(owner: string): string {
  return findProgramAddress(
    [new TextEncoder().encode('favourite_domain'), base58.decode(owner)],
    NAME_OFFERS_ID,
  );
}

/** Name account recorded in a favourite-domain account: tag byte, then the key. */
export function parseFavourite(data: Uint8Array): string | null {
  if (data.length < 33) return null;
  return base58.encode(data.subarray(1, 33));
}

export function nameOwner(data: Uint8Array): string | null {
  if (data.length < NAME_HEADER_LEN) return null;
  return base58.encode(data.subarray(32, 64));
}

/** Reverse records carry a u32 length and the UTF-8 label after the header. */
export function parseReverse(data: Uint8Array): string | null {
  if (data.length < NAME_HEADER_LEN + 4) return null;
  const view = new DataView(data.buffer, data.byteOffset + NAME_HEADER_LEN, 4);
  const len = view.getUint32(0, true);
  const start = NAME_HEADER_LEN + 4;
  if (len === 0 || len > 256 || start + len > data.length) return null;
  const label = new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(start, start + len));
  // Subdomain reverse records begin with a NUL and need their parent; primary names are top level.
  if (label.startsWith('\0')) return null;
  return label;
}

export type AccountFetcher = (keys: readonly string[]) => Promise<(Uint8Array | null)[]>;

/**
 * Primary `.sol` name of `owner`, or null. The favourite record points at a
 * name account; that account's owner must be `owner` and its reverse record
 * must hash back to the same account, otherwise nothing is shown.
 */
export async function primarySolName(owner: string, fetch: AccountFetcher): Promise<string | null> {
  const [fav] = await fetch([favouriteKey(owner)]);
  const nameAccount = fav ? parseFavourite(fav) : null;
  if (!nameAccount) return null;
  const [nameData, revData] = await fetch([nameAccount, reverseKey(nameAccount)]);
  if (!nameData || !revData || nameOwner(nameData) !== owner) return null;
  const label = parseReverse(revData);
  if (!label || domainKey(label) !== nameAccount) return null;
  return `${label}.sol`;
}
