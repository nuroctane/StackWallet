/**
 * ICP send path. The adapter builds checked fields; the core encodes and signs
 * the legacy ledger `transfer` call. Broadcast POSTs the core's CBOR envelope
 * to the v3 call endpoint after re-deriving every byte from the unsigned tx.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { sha224, sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  ICP_LEDGER,
  ICP_MAINNET,
  type CType,
  type CborValue,
  type IcpAdapter,
  candidDecode,
  candidEncode,
  cborBytes,
  cborDecodeRoot,
  cborEncodeEnvelope,
  cborMapGet,
  cborNat,
  cborText,
  field,
  icpAccountIdentifier,
  idlHash,
  isValidIcpAddress,
  leb128,
} from './icp.js';

const AccountId = z
  .string()
  .regex(/^[0-9a-f]{64}$/)
  .refine(isValidIcpAddress, 'bad checksum');
const Nanos = z.string().regex(/^(0|[1-9]\d{0,18})$/);

/** Mirrors `IcpTx` in the Rust core; the lead re-declares this in core-client. */
export const IcpTx = z.strictObject({
  chainId: z.literal(ICP_MAINNET),
  from: AccountId,
  to: AccountId,
  e8s: z.string().regex(/^[1-9]\d{0,17}$/),
  memo: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  createdAtNanos: Nanos,
  ingressExpiryNanos: Nanos,
});
export type IcpTx = z.infer<typeof IcpTx>;

export const ICP_FEE_E8S = 10_000n;
/** Leaves four minutes between submission and the replica's ingress deadline. */
const INGRESS_LIFETIME_MS = 4 * 60 * 1000;
const LEDGER_BYTES = Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 2, 1, 1]);

/** Candid `TransferArgs`, byte-identical to the core encoder (both pinned). */
export function candidTransferArgs(input: IcpTx): Uint8Array {
  const tx = IcpTx.parse(input);
  if (tx.from === tx.to) throw new Error('Invalid ICP sender or recipient');
  const amount = BigInt(tx.e8s);
  if (amount <= 0n || amount.toString() !== tx.e8s) throw new Error('Invalid e8s amount');
  const vecNat8: CType = { kind: 'vec', of: { kind: 'nat8' } };
  const tokens: CType = { kind: 'record', fields: [[idlHash('e8s'), { kind: 'nat64' }]] };
  const optBlob: CType = { kind: 'opt', of: { kind: 'ref', index: 0 } };
  const timestamp: CType = {
    kind: 'record',
    fields: [[idlHash('timestamp_nanos'), { kind: 'nat64' }]],
  };
  const optTimestamp: CType = { kind: 'opt', of: { kind: 'ref', index: 3 } };
  const transferArgs: CType = {
    kind: 'record',
    fields: [
      [idlHash('to'), { kind: 'ref', index: 0 }],
      [idlHash('fee'), { kind: 'ref', index: 1 }],
      [idlHash('memo'), { kind: 'nat64' }],
      [idlHash('from_subaccount'), { kind: 'ref', index: 2 }],
      [idlHash('created_at_time'), { kind: 'ref', index: 4 }],
      [idlHash('amount'), { kind: 'ref', index: 1 }],
    ],
  };
  return candidEncode(
    [vecNat8, tokens, optBlob, timestamp, optTimestamp, transferArgs],
    { kind: 'ref', index: 5 },
    new Map<number, unknown>([
      [idlHash('to'), hexToBytes(tx.to)],
      [idlHash('fee'), new Map([[idlHash('e8s'), ICP_FEE_E8S]])],
      [idlHash('memo'), BigInt(tx.memo)],
      [idlHash('from_subaccount'), null],
      [
        idlHash('created_at_time'),
        new Map([[idlHash('timestamp_nanos'), BigInt(tx.createdAtNanos)]]),
      ],
      [idlHash('amount'), new Map([[idlHash('e8s'), amount]])],
    ]),
  );
}

/** The call content the envelope must carry, as a CBOR value map. */
function contentEntries(tx: IcpTx, senderPrincipal: Uint8Array): [string, CborValue][] {
  return [
    ['request_type', { text: 'call' }],
    ['canister_id', { bytes: LEDGER_BYTES }],
    ['method_name', { text: 'transfer' }],
    ['arg', { bytes: candidTransferArgs(tx) }],
    ['sender', { bytes: senderPrincipal }],
    ['ingress_expiry', { tag: 2n, value: { bytes: beBytes(BigInt(tx.ingressExpiryNanos)) } }],
  ];
}

function beBytes(value: bigint): Uint8Array {
  const out: number[] = [];
  let v = value;
  do {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v > 0n);
  return Uint8Array.from(out);
}

export async function prepareIcp(
  adapter: IcpAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: IcpTx; simulation: Simulation }> {
  if (
    intent.chainId !== ICP_MAINNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${ICP_MAINNET}:native`
  )
    throw new Error('Only native ICP transfers on mainnet are enabled');
  if (!isValidIcpAddress(intent.to)) throw new Error('Invalid ICP destination account identifier');
  const unsigned = IcpTx.parse({
    chainId: intent.chainId,
    from,
    to: intent.to,
    e8s: intent.amount,
    memo: 0,
    createdAtNanos: (BigInt(now) * 1_000_000n).toString(),
    ingressExpiryNanos: (BigInt(now + INGRESS_LIFETIME_MS) * 1_000_000n).toString(),
  });
  candidTransferArgs(unsigned);
  const balance = BigInt(await adapter.getBalances(from, intent.chainId).then((h) => h[0]!.amount));
  const total = BigInt(intent.amount) + ICP_FEE_E8S;
  const error =
    balance < total ? 'Balance does not cover the transfer and the fixed fee' : undefined;
  return {
    unsigned,
    simulation: {
      ok: error === undefined,
      assetDeltas: [
        { assetRef: intent.asset, amount: `-${intent.amount}` },
        { assetRef: intent.asset, amount: `-${ICP_FEE_E8S}` },
      ],
      fee: { assetRef: intent.asset, amount: ICP_FEE_E8S.toString() },
      warnings: [
        {
          kind: 'other',
          message:
            'ICP has no public testnet: this is a mainnet transfer. The fee is the fixed 10_000 e8s ledger charge.',
        },
      ],
      ...(error ? { error } : {}),
    },
  };
}

/** Approval is refused once the replica could drop the request before it lands. */
export function icpApprovalValid(_adapter: IcpAdapter, tx: IcpTx, now = Date.now()): boolean {
  return BigInt(now) * 1_000_000n < BigInt(tx.ingressExpiryNanos) - 60_000_000_000n;
}

function decodeVariant(value: ReturnType<typeof candidDecode>): { name: string; value: unknown } {
  if (typeof value !== 'object' || value === null || !('id' in value))
    throw new Error('expected a Candid variant');
  return { name: String(value.id), value: value.value };
}

function variantName(id: number, names: string[]): string {
  for (const name of names) if (idlHash(name) === id) return name;
  return `variant#${id}`;
}

type CborArray = Extract<CborValue, { array: CborValue[] }>;

function labelEquals(node: CborValue, label: Uint8Array): node is CborArray {
  if (!('array' in node) || node.array.length !== 3) return false;
  if (cborNat(node.array[0]!) !== 2n) return false;
  const bytes = cborBytes(node.array[1]!);
  return bytes !== undefined && bytesToHex(bytes) === bytesToHex(label);
}

function leafBytes(node: CborValue | undefined): Uint8Array | undefined {
  if (!node || !('array' in node) || node.array.length !== 2) return undefined;
  if (cborNat(node.array[0]!) !== 3n) return undefined;
  return cborBytes(node.array[1]!);
}

/** The leaf bytes of `label` directly under a labeled hash-tree node. */
function lookupSub(node: CborArray, label: string): Uint8Array | undefined {
  const wanted = new TextEncoder().encode(label);
  for (const child of node.array) {
    if (labelEquals(child, wanted)) return leafBytes((child as CborArray).array[2]!);
  }
  return undefined;
}

/** Walks a certificate hash tree: [1,l,r] fork, [2,label,node] labeled, [3,bytes] leaf, [4,hash] pruned. */
function lookupPath(node: CborValue, path: Uint8Array[]): CborValue | undefined {
  if (!('array' in node) || node.array.length === 0) return undefined;
  const tag = cborNat(node.array[0]!);
  if (tag === 1n) {
    for (const child of node.array.slice(1)) {
      const hit = lookupPath(child, path);
      if (hit !== undefined) return hit;
    }
    return undefined;
  }
  if (tag === 2n && path.length > 0 && labelEquals(node, path[0]!)) {
    const sub = (node as CborArray).array[2]!;
    return path.length === 1 ? sub : lookupPath(sub, path.slice(1));
  }
  return undefined;
}

function lebToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  let shift = 0n;
  for (const b of bytes) {
    out |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) return out;
    shift += 7n;
  }
  return out;
}

/**
 * Reads the transfer reply out of a call certificate's hash tree. Returns an
 * empty array while the request is still received/processing; throws on a
 * replica reject.
 */
export function certificateReply(certificate: Uint8Array, requestId: Uint8Array): Uint8Array {
  const cert = cborDecodeRoot(certificate);
  const tree = cborMapGet(cert, 'tree');
  if (!tree || !('array' in tree)) throw new Error('ICP certificate has no tree');
  const node = lookupPath(tree, [new TextEncoder().encode('request_status'), requestId]);
  if (!node || !('array' in node)) return new Uint8Array();
  const statusBytes = lookupSub(node, 'status');
  const statusText = statusBytes ? new TextDecoder().decode(statusBytes) : undefined;
  if (statusText === 'replied') {
    const reply = lookupSub(node, 'reply');
    if (!reply) throw new Error('ICP certificate is missing the reply');
    return reply;
  }
  if (statusText === 'rejected') {
    const code = lookupSub(node, 'reject_code');
    const message = lookupSub(node, 'reject_message');
    const text = message ? new TextDecoder().decode(message) : 'rejected';
    throw new Error(
      `ICP call rejected (code ${code ? Number(lebToBigInt(code)) : 'unknown'}): ${text.slice(0, 256)}`,
    );
  }
  return new Uint8Array();
}

/**
 * Broadcasts the core's envelope. Every byte is re-derived from the unsigned
 * tx first; the wire must equal the recomputed envelope except for the
 * 64-byte signature. Returns the ledger block height as the hash.
 */
export async function broadcastIcp(
  adapter: IcpAdapter,
  tx: IcpTx,
  rawHex: string,
  requestIdHex?: string,
): Promise<string> {
  if (tx.chainId !== ICP_MAINNET) throw new Error('Only ICP mainnet broadcasts are enabled');
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) throw new Error('Signed payload is not hex');
  const wire = hexToBytes(hex);
  const envelope = cborDecodeRoot(wire);
  const content = cborMapGet(envelope, 'content');
  const pub = cborBytes(cborMapGet(envelope, 'sender_pubkey'));
  const sig = cborBytes(cborMapGet(envelope, 'sender_sig'));
  if (!content || !pub || !sig) throw new Error('Signed payload is not an ICP call envelope');
  if (pub.length !== 88 || sig.length !== 64)
    throw new Error('Signed payload has bad key or signature');
  // The embedded public key must derive the sender account.
  const derPrincipal = sha224Principal(pub);
  if (icpAccountIdentifier(derPrincipal) !== tx.from)
    throw new Error('Signed payload signs as a different account');
  // Recompute the full envelope from checked fields; only the signature may differ.
  const expected = cborEncodeEnvelope([
    [
      'content',
      {
        map: contentEntries(tx, derPrincipal).map(
          ([k, v]) => [{ text: k }, v] as [CborValue, CborValue],
        ),
      },
    ],
    ['sender_pubkey', { bytes: pub }],
    ['sender_sig', { bytes: sig }],
  ]);
  if (bytesToHex(expected) !== hex) throw new Error('Signed bytes are not this ICP transfer');
  // The signature itself must verify over sha256("\x0Aic-request" || request_id).
  const computedId = deriveRequestId(tx, derPrincipal);
  const sighash = sha256(concat(new TextEncoder().encode('\x0Aic-request'), computedId));
  if (!secp256k1.verify(sig, sighash, pub.subarray(23), { prehash: false }))
    throw new Error('Signed payload carries an invalid signature');
  if (requestIdHex && requestIdHex !== bytesToHex(computedId))
    throw new Error('Request id does not match the signed content');

  const res = await adapter.callCanister(tx.chainId, ICP_LEDGER, wire);
  if (res.length === 0) return `request:${bytesToHex(computedId)}`;
  const decoded = cborDecodeRoot(res);
  const status = cborText(cborMapGet(decoded, 'status'));
  const certificate = cborBytes(cborMapGet(decoded, 'certificate'));
  if (!certificate) throw new Error('ICP broadcast returned no certificate');
  const reply = certificateReply(certificate, computedId);
  if (reply.length === 0) return `request:${bytesToHex(computedId)}`;
  const result = candidDecode(reply);
  const variant = decodeVariant(result);
  const name = variantName(Number(variant.name), ['Ok', 'Err']);
  if (name === 'Ok') {
    if (typeof variant.value !== 'bigint') throw new Error('ICP transfer reply is malformed');
    return variant.value.toString();
  }
  const err = decodeVariant(variant.value as ReturnType<typeof candidDecode>);
  const errName = variantName(Number(err.name), [
    'BadFee',
    'InsufficientFunds',
    'TxTooOld',
    'TxCreatedInFuture',
    'TxDuplicate',
  ]);
  if (errName === 'TxDuplicate') {
    const dup = err.value instanceof Map ? field(err.value, 'duplicate_of') : undefined;
    if (typeof dup === 'bigint') return dup.toString();
  }
  const balance = err.value instanceof Map ? field(err.value, 'balance') : undefined;
  const e8s = balance instanceof Map ? field(balance, 'e8s') : undefined;
  const detail = typeof e8s === 'bigint' ? ` (balance ${e8s} e8s)` : '';
  throw new Error(`ICP transfer failed: ${errName}${detail}`);
}

function sha224Principal(der: Uint8Array): Uint8Array {
  // Self-authenticating principal: sha224(der) || 0x02.
  const digest = sha224(der);
  const out = new Uint8Array(29);
  out.set(digest, 0);
  out[28] = 2;
  return out;
}

/** Request id of the unsigned tx for a sender principal (spec hash-of-map). */
export function deriveRequestId(tx: IcpTx, senderPrincipal: Uint8Array): Uint8Array {
  const pairs: [string, Uint8Array][] = [
    ['arg', candidTransferArgs(tx)],
    ['canister_id', LEDGER_BYTES],
    ['ingress_expiry', leb128(BigInt(tx.ingressExpiryNanos))],
    ['method_name', new TextEncoder().encode('transfer')],
    ['request_type', new TextEncoder().encode('call')],
    ['sender', senderPrincipal],
  ];
  const hashed = pairs
    .map(([k, v]) => concat(sha256(new TextEncoder().encode(k)), sha256(v)))
    .sort((a, b) => compare(a, b));
  return sha256(concat(...hashed));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

/** Confirms a broadcast transfer by reading its block back and matching fields. */
export async function icpTransferStatus(
  adapter: IcpAdapter,
  tx: IcpTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  if (!/^\d{1,19}$/.test(hash)) {
    // Not a block height (e.g. an asynchronous request id): expiry check only.
    return icpApprovalValid(adapter, tx) ? { state: 'unknown' } : { state: 'expired' };
  }
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'confirmed') return status;
  return status;
}
