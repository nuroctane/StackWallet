/**
 * Radix Babylon transfer construction. The encoder mirrors the core's
 * `radix.rs` byte for byte: manifest SBOR, the `b'T'`-prefixed hash chain,
 * Ed25519 intent and notary signatures, and the compiled
 * `NotarizedTransactionV1` the gateway's `/transaction/submit` accepts.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { HttpError, RpcFailoverError, type Simulation, type TxStatus } from '@stackwallet/chains';
import { z } from 'zod';

import {
  ENTITY,
  NETWORKS,
  RADIX_STOKENET,
  radixAddressBytes,
  radixAddressFromPublicKey,
  radixHashString,
  type RadixAdapter,
} from './radix.js';
import type { TxIntent } from '@stackwallet/core-client';

/** XRD base unit: 1 XRD = 10^18 attos; the wire amount field name. */
const AccountAddress = z.string().regex(/^account_tdx_2_1[02-9ac-hj-np-z]{20,60}$/);
const Attos = z.string().regex(/^[1-9][0-9]{0,28}$/);
const Epoch = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
export const RadixTx = z.strictObject({
  chainId: z.literal(RADIX_STOKENET),
  from: AccountAddress,
  to: AccountAddress,
  attos: Attos,
  startEpochInclusive: Epoch,
  endEpochExclusive: Epoch,
  nonce: z.number().int().nonnegative().max(0xffffffff),
  tipPercentage: z.number().int().nonnegative().max(100),
});
export type RadixTx = z.infer<typeof RadixTx>;

/** Fee locked by the manifest's first instruction; the unspent part is refunded. */
export const LOCK_FEE_ATTOS = 5_000_000_000_000_000_000n;
/** Validity window: about 45–50 minutes of stokenet epochs, like the official wallet default. */
const VALID_EPOCHS = 10;
const MAX_EPOCH_RANGE = 100;
const MAX_ATTOS = 30_000_000_000_000_000_000_000_000_000n;
/** Stokenet XRD resource node id (`resource_tdx_2_1tkn…tfd2jc`). */
const XRD_NODE_ID = hexToBytes('5da66318c6318c61f5a61b4c6318c6318cf794aa8d295f14e6318c6318c6');
const HASHABLE_PREFIX = 0x54; // 'T'

const KIND = {
  bool: 0x01,
  u8: 0x07,
  u16: 0x08,
  u32: 0x09,
  u64: 0x0a,
  string: 0x0c,
  array: 0x20,
  tuple: 0x21,
  enum: 0x22,
  address: 0x80,
  bucket: 0x81,
  decimal: 0x85,
} as const;

function hash(bytes: Uint8Array): Uint8Array {
  return blake2b(bytes, { dkLen: 32 });
}

function pushSize(out: number[], size: number): void {
  let s = size;
  for (;;) {
    const seven = s & 0x7f;
    s >>= 7;
    if (s === 0) {
      out.push(seven);
      return;
    }
    out.push(seven | 0x80);
  }
}

const u8 = (v: number) => [KIND.u8, v];
const u16 = (v: number) => [KIND.u16, v & 0xff, (v >> 8) & 0xff];
const u32 = (v: number) => [
  KIND.u32,
  v & 0xff,
  (v >>> 8) & 0xff,
  (v >>> 16) & 0xff,
  (v >>> 24) & 0xff,
];
function u64(v: number): number[] {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
  return [KIND.u64, ...b];
}
function str(s: string): number[] {
  const bytes = new TextEncoder().encode(s);
  const out = [KIND.string];
  pushSize(out, bytes.length);
  return [...out, ...bytes];
}
function tuple(fields: number[][]): number[] {
  const out = [KIND.tuple];
  pushSize(out, fields.length);
  return [...out, ...fields.flat()];
}
/** Enum body without the value-kind byte, for array elements. */
function enumBody(disc: number, fields: number[][]): number[] {
  const out = [disc];
  pushSize(out, fields.length);
  return [...out, ...fields.flat()];
}
function enumValue(disc: number, fields: number[][]): number[] {
  return [KIND.enum, ...enumBody(disc, fields)];
}
function staticAddress(node: Uint8Array): number[] {
  return [KIND.address, 0x00, ...node];
}
function decimal(attos: bigint): number[] {
  const b = new Uint8Array(24);
  let v = attos;
  for (let i = 0; i < 16; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return [KIND.decimal, ...b];
}
function byteArray(bytes: Uint8Array): number[] {
  const out = [KIND.array, KIND.u8];
  pushSize(out, bytes.length);
  return [...out, ...bytes];
}
/** `PublicKey::Ed25519`: enum 1 wrapping the 32-byte key array. */
function ed25519PublicKey(publicKey: Uint8Array): number[] {
  return enumValue(1, [byteArray(publicKey)]);
}
/** `Ed25519Signature`: a one-field tuple wrapping the 64-byte array. */
function ed25519Signature(signature: Uint8Array): number[] {
  return tuple([byteArray(signature)]);
}

function checkedFields(tx: RadixTx): { from: Uint8Array; to: Uint8Array; amount: bigint } {
  if (tx.chainId !== RADIX_STOKENET) throw new Error('Only Radix Stokenet transfers are enabled');
  const from = radixAddressBytes(tx.from, NETWORKS[RADIX_STOKENET]!.accountHrp);
  const to = radixAddressBytes(tx.to, NETWORKS[RADIX_STOKENET]!.accountHrp);
  if (!from || !to || bytesToHex(from) === bytesToHex(to))
    throw new Error('Invalid XRD sender or recipient');
  if (from[0] !== ENTITY.virtualEd25519Account)
    throw new Error('Sender must be a virtual Ed25519 account');
  const amount = BigInt(tx.attos);
  if (amount <= 0n || amount > MAX_ATTOS || amount.toString() !== tx.attos)
    throw new Error('XRD amount must be a positive canonical integer of attos in range');
  if (
    tx.endEpochExclusive <= tx.startEpochInclusive ||
    tx.endEpochExclusive - tx.startEpochInclusive > MAX_EPOCH_RANGE
  )
    throw new Error('Invalid epoch range');
  if (tx.tipPercentage > 100) throw new Error('Tip above 100 percent');
  return { from, to, amount };
}

function headerBytes(tx: RadixTx, publicKey: Uint8Array): number[] {
  return tuple([
    u8(2), // Stokenet network id
    u64(tx.startEpochInclusive),
    u64(tx.endEpochExclusive),
    u32(tx.nonce),
    ed25519PublicKey(publicKey),
    [KIND.bool, 1], // notary_is_signatory
    u16(tx.tipPercentage),
  ]);
}

function instructionBytes(tx: RadixTx): number[] {
  const { from, to, amount } = checkedFields(tx);
  const xrd = staticAddress(XRD_NODE_ID);
  const value = decimal(amount);
  const instructions = [
    // CALL_METHOD <from> "lock_fee" Decimal(5 XRD); unspent fee is refunded.
    enumBody(0x41, [staticAddress(from), str('lock_fee'), tuple([decimal(LOCK_FEE_ATTOS)])]),
    // CALL_METHOD <from> "withdraw" (Address(XRD), Decimal(amount))
    enumBody(0x41, [staticAddress(from), str('withdraw'), tuple([xrd, value])]),
    // TAKE_FROM_WORKTOP Address(XRD) Decimal(amount)
    enumBody(0x00, [xrd, value]),
    // CALL_METHOD <to> "try_deposit_or_abort" (Bucket(0), None)
    enumBody(0x41, [
      staticAddress(to),
      str('try_deposit_or_abort'),
      tuple([[KIND.bucket, 0, 0, 0, 0], enumValue(0, [])]),
    ]),
  ];
  const out = [KIND.array, KIND.enum];
  pushSize(out, instructions.length);
  return [...out, ...instructions.flat()];
}

const EMPTY_BLOBS = [KIND.array, KIND.array, 0x00];
const NO_MESSAGE = [KIND.enum, 0x00, 0x00];

/** blake2b-256 of `b'T' || 0x01 || field hashes`; what the intent signature signs. */
export function intentHash(tx: RadixTx, publicKey: Uint8Array): Uint8Array {
  return hash(
    Uint8Array.from([
      HASHABLE_PREFIX,
      0x01,
      ...hash(Uint8Array.from(headerBytes(tx, publicKey))),
      ...hash(Uint8Array.from(instructionBytes(tx))),
      // Empty blob list hashes as blake2b-256 of zero bytes (no SBOR wrapper).
      ...hash(new Uint8Array(0)),
      ...hash(Uint8Array.from(NO_MESSAGE)),
    ]),
  );
}

/** The `20 22 01 …` intent-signatures array holding one Ed25519 signature. */
function intentSignatures(publicKey: Uint8Array, signature: Uint8Array): number[] {
  const element = enumBody(1, [byteArray(publicKey), ed25519Signature(signature)]);
  const out = [KIND.array, KIND.enum];
  pushSize(out, 1);
  return [...out, ...element];
}

export function signedIntentHash(
  tx: RadixTx,
  publicKey: Uint8Array,
  intentSignature: Uint8Array,
): Uint8Array {
  return hash(
    Uint8Array.from([
      HASHABLE_PREFIX,
      0x02,
      ...intentHash(tx, publicKey),
      ...hash(Uint8Array.from(intentSignatures(publicKey, intentSignature))),
    ]),
  );
}

/**
 * Compiles the `NotarizedTransactionV1` and reports the byte offsets of the
 * three signature-bearing regions so a broadcast can re-derive and compare.
 */
export function compileNotarized(
  tx: RadixTx,
  publicKey: Uint8Array,
  intentSignature: Uint8Array,
  notarySignature: Uint8Array,
): {
  bytes: Uint8Array;
  /** Both offsets: the notary key appears in the header and in the signature entry. */
  publicKeyAts: [number, number];
  intentSignatureAt: number;
  notarySignatureAt: number;
} {
  const intent = tuple([headerBytes(tx, publicKey), instructionBytes(tx), EMPTY_BLOBS, NO_MESSAGE]);
  const sigs = intentSignatures(publicKey, intentSignature);
  const signedIntent = tuple([intent, sigs]);
  const notary = enumValue(1, [ed25519Signature(notarySignature)]);
  const wire = [0x4d, KIND.enum, 0x03, 0x02, ...signedIntent, ...notary];
  const bytes = Uint8Array.from(wire);
  const needle = (part: Uint8Array, fromIndex: number) => {
    outer: for (let i = fromIndex; i + part.length <= bytes.length; i++) {
      for (let j = 0; j < part.length; j++) if (bytes[i + j] !== part[j]) continue outer;
      return i;
    }
    return -1;
  };
  const pkAt = needle(publicKey, 8);
  const pkAt2 = needle(publicKey, pkAt + 32);
  const intentAt = needle(intentSignature, pkAt2 + 32);
  const notaryAt = needle(notarySignature, bytes.length - 80);
  if (pkAt < 0 || pkAt2 < 0 || intentAt < 0 || notaryAt < 0)
    throw new Error('Compiled layout is off');
  return {
    bytes,
    publicKeyAts: [pkAt, pkAt2],
    intentSignatureAt: intentAt,
    notarySignatureAt: notaryAt,
  };
}

/** The `txid_tdx_2_…` explorers show; also the `intent_hash` the gateway tracks. */
export function txidOf(tx: RadixTx, publicKey: Uint8Array): string {
  return radixHashString(NETWORKS[RADIX_STOKENET]!.txidHrp, intentHash(tx, publicKey));
}

/** The full sign step, identical to `RadixTx::sign` in the core. */
export function signTransfer(
  input: RadixTx,
  secretKey: Uint8Array,
): { wireHex: string; txid: string } {
  const tx = RadixTx.parse(input);
  checkedFields(tx);
  if (secretKey.length !== 32) throw new TypeError('Ed25519 secret key must be 32 bytes');
  const publicKey = ed25519.getPublicKey(secretKey);
  if (radixAddressFromPublicKey(publicKey, RADIX_STOKENET) !== tx.from)
    throw new Error('Sender differs from signing key');
  const intent = intentHash(tx, publicKey);
  const intentSignature = ed25519.sign(intent, secretKey);
  const notarySignature = ed25519.sign(signedIntentHash(tx, publicKey, intentSignature), secretKey);
  const { bytes } = compileNotarized(tx, publicKey, intentSignature, notarySignature);
  return { wireHex: bytesToHex(bytes), txid: txidOf(tx, publicKey) };
}

export async function prepareRadix(
  adapter: RadixAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: RadixTx; simulation: Simulation }> {
  if (
    intent.chainId !== RADIX_STOKENET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${RADIX_STOKENET}:native`
  )
    throw new Error('Only native XRD transfers on Stokenet are enabled');
  if (!/^account_tdx_2_1/.test(from)) throw new Error('Sender must be a Stokenet account');
  return adapter.withGateway(intent.chainId, async (call) => {
    const status = await call('/status/gateway-status', {}, GatewayStatusLite);
    const epoch = status.ledger_state.epoch;
    const nonceBytes = new Uint8Array(4);
    crypto.getRandomValues(nonceBytes);
    const unsigned = RadixTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      attos: intent.amount,
      startEpochInclusive: epoch,
      endEpochExclusive: epoch + VALID_EPOCHS,
      nonce: new DataView(nonceBytes.buffer).getUint32(0),
      tipPercentage: 0,
    });
    checkedFields(unsigned);
    const [holding] = await adapter.getBalances(from, intent.chainId);
    const balance = BigInt(holding?.amount ?? '0');
    const needed = BigInt(intent.amount) + LOCK_FEE_ATTOS;
    const simulation: Simulation = {
      ok: balance >= needed,
      assetDeltas: [
        { assetRef: intent.asset, amount: `-${intent.amount}` },
        { assetRef: intent.asset, amount: `-${LOCK_FEE_ATTOS.toString()}` },
      ],
      fee: { assetRef: intent.asset, amount: LOCK_FEE_ATTOS.toString() },
      warnings: [
        {
          kind: 'other',
          message:
            'Radix locks up to 5 XRD as a fee deposit and refunds everything execution does not burn; the final fee of a plain transfer is a small fraction of the lock.',
        },
      ],
      ...(balance < needed
        ? { error: 'Balance does not cover the transfer and the fee lock' }
        : {}),
    };
    return { unsigned, simulation };
  });
}

const GatewayStatusLite = z.object({
  ledger_state: z.object({ epoch: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER) }),
});

/** Approval is refused once the epoch window is over or nearly over. */
export async function radixApprovalValid(adapter: RadixAdapter, tx: RadixTx): Promise<boolean> {
  const status = await adapter.networkStatus(tx.chainId);
  return status.ledger_state.epoch < tx.endEpochExclusive - 1;
}

const SubmitResult = z.object({ duplicate: z.boolean() });
const SubmitError = z.object({
  message: z.string().max(1024).optional(),
  details: z
    .object({ type: z.string().max(128).optional() })
    .loose()
    .optional(),
});

/**
 * Broadcast only bytes that re-derive exactly from the checked transfer fields:
 * the captured public key must belong to `from`, both signatures must verify,
 * and every other byte must match the template the core would sign.
 */
export async function broadcastRadix(
  adapter: RadixAdapter,
  tx: RadixTx,
  wireHex: string,
): Promise<string> {
  if (tx.chainId !== RADIX_STOKENET) throw new Error('Only Stokenet broadcasts are enabled');
  const wire = hexToBytes(wireHex.replace(/^0x/, '').toLowerCase());
  // Distinct markers so the template's placeholder regions cannot collide with
  // fixed zero runs elsewhere in the encoding.
  const template = compileNotarized(
    tx,
    new Uint8Array(32).fill(1),
    new Uint8Array(64).fill(2),
    new Uint8Array(64).fill(3),
  );
  const ranges: [number, number][] = [
    [template.publicKeyAts[0], 32],
    [template.publicKeyAts[1], 32],
    [template.intentSignatureAt, 64],
    [template.notarySignatureAt, 64],
  ];
  if (wire.length !== template.bytes.length)
    throw new Error('Signed bytes are not this XRD transfer');
  const covered = (i: number) => ranges.some(([at, len]) => i >= at && i < at + len);
  for (let i = 0; i < wire.length; i++)
    if (!covered(i) && wire[i] !== template.bytes[i])
      throw new Error('Signed bytes are not this XRD transfer');
  const publicKey = wire.slice(template.publicKeyAts[0], template.publicKeyAts[0] + 32);
  if (
    bytesToHex(wire.slice(template.publicKeyAts[1], template.publicKeyAts[1] + 32)) !==
    bytesToHex(publicKey)
  )
    throw new Error('Signed bytes are not this XRD transfer');
  const intentSignature = wire.slice(template.intentSignatureAt, template.intentSignatureAt + 64);
  const notarySignature = wire.slice(template.notarySignatureAt, template.notarySignatureAt + 64);
  if (radixAddressFromPublicKey(publicKey, RADIX_STOKENET) !== tx.from)
    throw new Error('Notary key does not belong to the sender');
  if (!ed25519.verify(intentSignature, intentHash(tx, publicKey), publicKey))
    throw new Error('Intent signature does not verify');
  if (!ed25519.verify(notarySignature, signedIntentHash(tx, publicKey, intentSignature), publicKey))
    throw new Error('Notary signature does not verify');
  const txid = txidOf(tx, publicKey);
  try {
    await adapter.withGateway(tx.chainId, (call) =>
      call(
        '/transaction/submit',
        { notarized_transaction_hex: wireHex.replace(/^0x/, '') },
        SubmitResult,
      ),
    );
    return txid;
  } catch (err) {
    const cause =
      err instanceof RpcFailoverError && err.causes.length > 0 ? err.causes[0]!.error : err;
    if (cause instanceof HttpError) {
      let body: unknown = {};
      try {
        body = JSON.parse(cause.body);
      } catch {
        body = { message: cause.body.slice(0, 512) };
      }
      const parsed = SubmitError.safeParse(body);
      const detail = parsed.success
        ? `${parsed.data.details?.type ?? ''} ${parsed.data.message ?? ''}`.trim()
        : '';
      throw new Error(`Broadcast rejected: HTTP ${cause.status} ${detail}`.trim());
    }
    throw err;
  }
}

/**
 * Once the end epoch has passed a pending intent can never land; the gateway
 * keeps reporting it as unknown forever, so map that to `expired`.
 */
export async function radixTransferStatus(
  adapter: RadixAdapter,
  tx: RadixTx,
  txid: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(txid, tx.chainId);
  if (status.state !== 'unknown') return status;
  const head = await adapter.networkStatus(tx.chainId);
  if (head.ledger_state.epoch < tx.endEpochExclusive) return status;
  const again = await adapter.status(txid, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
