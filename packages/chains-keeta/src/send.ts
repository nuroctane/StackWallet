/**
 * Prepare/approve/broadcast helpers for native KTA transfers. The unsigned
 * fields mirror the core's `KeetaTx` exactly; the core re-encodes the whole
 * block from them, so the adapter only assembles checked facts (the sender's
 * head block hash and the current time).
 */
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  AccountState,
  BASE_TOKEN,
  KEETA_TEST,
  keetaAddressBytes,
  keetaTokenBytes,
  type KeetaAdapter,
} from './keeta.js';

/**
 * Mirrors the Rust `KeetaTx` field for field. The lead wires this schema
 * into `packages/core-client`; until then the package ships its own copy.
 */
export const KeetaTx = z.strictObject({
  chainId: z.literal(KEETA_TEST),
  from: z.string().regex(/^keeta_[a-z2-7]{63}$/),
  to: z.string().regex(/^keeta_[a-z2-7]{63}$/),
  /** Decimal 10^-18 KTA base units. */
  attoKta: z.string().regex(/^[1-9][0-9]{0,38}$/),
  /** Sender account head block hash, 32 lowercase hex bytes. */
  previous: z.string().regex(/^[0-9a-f]{64}$/),
  /** Unix seconds; becomes the block's GeneralizedTime date. */
  timestamp: z.number().int().positive().max(0xffffffff),
});
export type KeetaTx = z.infer<typeof KeetaTx>;

const NETWORK_ID_TEST = 0x54455354n;

// --- DER writer for the v1 block subset (mirrors crates/stackwallet-core/src/keeta.rs) ---

function derLen(len: number): number[] {
  if (len < 0x80) return [len];
  if (len < 0x100) return [0x81, len];
  return [0x82, (len >> 8) & 0xff, len & 0xff];
}
function derTlv(tag: number, content: Uint8Array | number[]): number[] {
  return [tag, ...derLen(content.length), ...content];
}
function derInt(value: bigint): number[] {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const bytes = [...(hex.match(/../g) ?? ['00'])].map((b) => parseInt(b, 16));
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return derTlv(0x02, bytes);
}
const derOctet = (bytes: Uint8Array | number[]) => derTlv(0x04, bytes);
const derNull = [0x05, 0x00];
function derGentime(secs: number): number[] {
  const iso = new Date(secs * 1000).toISOString(); // YYYY-MM-DDTHH:MM:SS.sssZ
  const compact = `${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(
    11,
    13,
  )}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`;
  return derTlv(0x18, [...new TextEncoder().encode(compact)]);
}

/** The same unsigned v1 block DER the core encodes independently from checked fields. */
export function unsignedBlock(input: KeetaTx): Uint8Array {
  const tx = KeetaTx.parse(input);
  const from = keetaAddressBytes(tx.from);
  const to = keetaAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid KTA sender or recipient');
  const token = keetaTokenBytes(BASE_TOKEN[KEETA_TEST]!);
  if (!token) throw new Error('Invalid Keeta base token');
  const amount = BigInt(tx.attoKta);
  if (amount <= 0n || amount.toString() !== tx.attoKta)
    throw new Error('KTA amount must be a positive canonical integer');
  if (/^0+$/.test(tx.previous)) throw new Error('Zero previous block hash');
  const previous = [...(tx.previous.match(/../g) ?? [])].map((b) => parseInt(b, 16));
  const send = derTlv(0xa0, derTlv(0x30, [...derOctet(to), ...derInt(amount), ...derOctet(token)]));
  const block = [
    ...derInt(0n),
    ...derInt(NETWORK_ID_TEST),
    ...derNull,
    ...derGentime(tx.timestamp),
    ...derOctet(from),
    ...derNull,
    ...derOctet(previous),
    ...derTlv(0x30, send),
  ];
  return Uint8Array.from(derTlv(0x30, block));
}

/** The block hash in the uppercase hex form the explorer shows. */
export function blockHash(tx: KeetaTx): string {
  return bytesToHex(sha3_256(unsignedBlock(tx))).toUpperCase();
}

export async function prepareKeeta(
  adapter: KeetaAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: KeetaTx; simulation: Simulation }> {
  if (
    intent.chainId !== KEETA_TEST ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${KEETA_TEST}:native`
  )
    throw new Error('Only native KTA transfers on the Keeta test network are enabled');
  return adapter.withNode(intent.chainId, async (call) => {
    const state = await call(`/node/ledger/account/${from}`, AccountState);
    const unsigned = KeetaTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      attoKta: intent.amount,
      previous: (state.currentHeadBlock ?? '0'.repeat(64)).toLowerCase(),
      timestamp: Math.floor(now / 1000),
    });
    const token = BASE_TOKEN[intent.chainId]!;
    const entry = state.balances.find((b) => b.token === token);
    const balance = entry ? BigInt(entry.balance) : 0n;
    let error: string | undefined;
    if (state.currentHeadBlock === null)
      error = 'Sender account has no head block on the Keeta test network (fund it first)';
    else if (balance < BigInt(intent.amount)) error = 'Balance does not cover the transfer';
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [{ assetRef: intent.asset, amount: `-${intent.amount}` }],
        fee: { assetRef: intent.asset, amount: '0' },
        warnings: [
          {
            kind: 'other',
            message:
              'Keeta blocks carry no explicit fee; representatives currently accept zero-fee vote options.',
          },
        ],
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Approval is refused once the sender's head block moved past the prepared one. */
export async function keetaApprovalValid(adapter: KeetaAdapter, tx: KeetaTx): Promise<boolean> {
  const state = await adapter.withNode(tx.chainId, (call) =>
    call(`/node/ledger/account/${tx.from}`, AccountState),
  );
  return state.currentHeadBlock?.toLowerCase() === tx.previous;
}

/** Broadcast only bytes that are exactly the ledger's block plus one 64-byte signature. */
export async function broadcastKeeta(
  adapter: KeetaAdapter,
  tx: KeetaTx,
  signedBase64: string,
): Promise<string> {
  if (tx.chainId !== KEETA_TEST) throw new Error('Only test-network broadcasts are enabled');
  const unsigned = unsignedBlock(tx);
  let signed: Uint8Array;
  try {
    signed = Uint8Array.from(atob(signedBase64), (c) => c.charCodeAt(0));
  } catch {
    throw new Error('Signed payload is not base64');
  }
  if (signed.length !== unsigned.length + 66)
    throw new Error('Signed bytes are not this KTA block');
  for (let i = 3; i < unsigned.length; i++)
    if (signed[i] !== unsigned[i]) throw new Error('Signed bytes are not this KTA block');
  const sigStart = signed.length - 64;
  if (signed[sigStart - 2] !== 0x04 || signed[sigStart - 1] !== 0x40)
    throw new Error('Signed bytes are not this KTA block');
  if (!(await adapter.publishBlock(tx.chainId, signedBase64)))
    throw new Error('Broadcast rejected: publish-aid declined the block');
  return blockHash(tx);
}

/**
 * Blocks do not expire; a prepared block becomes unbroadcastable when the
 * sender's head moves ('dropped' if it was never published by then).
 */
export async function keetaTransferStatus(
  adapter: KeetaAdapter,
  tx: KeetaTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const valid = await keetaApprovalValid(adapter, tx).catch(() => true);
  return valid ? status : { state: 'dropped' };
}
