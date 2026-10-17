import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  AccountInfo,
  FeeInfo,
  LSF_DEPOSIT_AUTH,
  LSF_DISALLOW_XRP,
  LSF_REQUIRE_DEST_TAG,
  XRPL_TESTNET,
  accountInfo,
  xrplAddressBytes,
  xrplAddressFromPublicKey,
  type XrplAdapter,
} from './xrpl.js';

/** 100 billion XRP: the total supply. */
export const MAX_DROPS = 100_000_000_000_000_000n;
export const MIN_FEE = 10;
export const MAX_FEE = 1_000_000;
export const MAX_LEDGER_WINDOW = 2_000;
/** The adapter bids at most 0.1 XRP; above that the payment waits in the queue. */
const MAX_BID = 100_000;
/** About 15 to 20 minutes of ledgers: long enough to review and approve. */
const LEDGER_WINDOW = 300;
/** Approval is refused once fewer ledgers than this remain before `lastLedgerSequence`. */
const APPROVAL_MARGIN = 20;

/** Mirrors `xrpl::XrplTx` in the core; the core re-checks every field. */
export const XrplTx = z.strictObject({
  chainId: z.literal(XRPL_TESTNET),
  from: z.string().regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/),
  to: z.string().regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/),
  drops: z.string().regex(/^[0-9]+$/),
  fee: z.number().int().min(MIN_FEE).max(MAX_FEE),
  sequence: z.number().int().min(1).max(0xffff_ffff),
  lastLedgerSequence: z.number().int().min(2).max(0xffff_ffff),
  builtAtLedger: z.number().int().min(1).max(0xffff_ffff),
  destinationTag: z.number().int().min(0).max(0xffff_ffff).optional(),
  publicKeyHex: z.string().regex(/^(02|03)[0-9a-f]{64}$/),
});
export type XrplTx = z.infer<typeof XrplTx>;

const HASH_PREFIX_SIGN = Uint8Array.of(0x53, 0x54, 0x58, 0x00);
const HASH_PREFIX_TX_ID = Uint8Array.of(0x54, 0x58, 0x4e, 0x00);

class Writer {
  private readonly bytes: number[] = [];
  raw(...b: (number | Uint8Array)[]): this {
    for (const x of b) {
      if (typeof x === 'number') this.bytes.push(x);
      else this.bytes.push(...x);
    }
    return this;
  }
  u32(header: number[], v: number): this {
    return this.raw(...header, (v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
  xrp(header: number, drops: bigint): this {
    const v = 0x4000_0000_0000_0000n | drops;
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, v);
    return this.raw(header, out);
  }
  vl(header: number, b: Uint8Array): this {
    if (b.length > 192) throw new Error('Blob too long for a one-byte length');
    return this.raw(header, b.length, b);
  }
  done(): Uint8Array {
    return Uint8Array.from(this.bytes);
  }
}

function checked(input: XrplTx) {
  const tx = XrplTx.parse(input);
  const from = xrplAddressBytes(tx.from);
  const to = xrplAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid XRP sender or recipient');
  const drops = BigInt(tx.drops);
  if (drops <= 0n || drops > MAX_DROPS || drops.toString() !== tx.drops)
    throw new Error('XRP amount must be canonical drops within the supply');
  if (
    tx.lastLedgerSequence <= tx.builtAtLedger ||
    tx.lastLedgerSequence - tx.builtAtLedger > MAX_LEDGER_WINDOW
  )
    throw new Error('lastLedgerSequence must fall shortly after the build ledger');
  const publicKey = hexToBytes(tx.publicKeyHex);
  if (xrplAddressFromPublicKey(publicKey) !== tx.from)
    throw new Error('Public key does not belong to the sender');
  return { tx, from, to, drops, publicKey };
}

/** Canonical binary fields in field-id order, as the core encodes them independently. */
export function xrplFields(input: XrplTx, signature?: Uint8Array): Uint8Array {
  const { tx, from, to, drops, publicKey } = checked(input);
  const w = new Writer().raw(0x12, 0x00, 0x00); // TransactionType Payment
  w.u32([0x22], 0); // Flags
  w.u32([0x24], tx.sequence);
  if (tx.destinationTag !== undefined) w.u32([0x2e], tx.destinationTag);
  w.u32([0x20, 0x1b], tx.lastLedgerSequence);
  w.xrp(0x61, drops).xrp(0x68, BigInt(tx.fee));
  w.vl(0x73, publicKey);
  if (signature) w.vl(0x74, signature);
  return w.vl(0x81, from).vl(0x83, to).done();
}

const sha512Half = (b: Uint8Array): Uint8Array => sha512(b).subarray(0, 32);
const concat = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

export function xrplSigningPayload(tx: XrplTx): Uint8Array {
  return concat(HASH_PREFIX_SIGN, xrplFields(tx));
}

/** SHA-512Half of the signing payload: the digest the ECDSA signature covers. */
export function xrplSigningHash(tx: XrplTx): Uint8Array {
  return sha512Half(xrplSigningPayload(tx));
}

/** The transaction hash explorers show (uppercase hex) for a signed blob. */
export function xrplBlobHash(blob: Uint8Array): string {
  return bytesToHex(sha512Half(concat(HASH_PREFIX_TX_ID, blob))).toUpperCase();
}

function feeBid(fee: FeeInfo): number {
  const open = Number(fee.drops.open_ledger_fee);
  const base = Number(fee.drops.base_fee);
  return Math.min(MAX_BID, Math.max(MIN_FEE, base, open));
}

function spendable(info: AccountInfo, reserveBase: number, reserveInc: number): bigint {
  const locked = BigInt(reserveBase) + BigInt(info.account_data.OwnerCount) * BigInt(reserveInc);
  return BigInt(info.account_data.Balance) - locked;
}

const Reserves = z.object({
  state: z
    .object({
      validated_ledger: z.object({
        seq: z.number().int().nonnegative(),
        reserve_base: z.number().int().nonnegative(),
        reserve_inc: z.number().int().nonnegative(),
      }),
    })
    .loose(),
});

export interface PrepareXrplOptions {
  destinationTag?: number | undefined;
}

export async function prepareXrpl(
  adapter: XrplAdapter,
  intent: TxIntent,
  from: string,
  publicKeyHex: string,
  opts: PrepareXrplOptions = {},
): Promise<{ unsigned: XrplTx; simulation: Simulation }> {
  if (
    intent.chainId !== XRPL_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${XRPL_TESTNET}:native`
  )
    throw new Error('Only native XRP payments on testnet are enabled');
  const tag = opts.destinationTag;
  if (tag !== undefined && (!Number.isInteger(tag) || tag < 0 || tag > 0xffff_ffff))
    throw new Error('Destination tag must be an integer from 0 to 4294967295');
  return adapter.withNode(intent.chainId, async (call) => {
    const [sender, recipient, fee, state] = await Promise.all([
      accountInfo(call, from, 'current'),
      accountInfo(call, intent.to, 'validated'),
      call('fee', {}, FeeInfo),
      call('server_state', {}, Reserves),
    ]);
    if (!sender) throw new Error('Sender account is not funded on XRPL testnet');
    if (!fee || !state) throw new Error('rippled did not report fees or reserves');
    const { reserve_base: reserveBase, reserve_inc: reserveInc } = state.state.validated_ledger;
    const amount = BigInt(intent.amount);
    if (!recipient && amount < BigInt(reserveBase))
      throw new Error(
        `The recipient account is not activated yet; send at least ${reserveBase} drops (the base reserve) to create it`,
      );
    const builtAtLedger = fee.ledger_current_index;
    const unsigned = XrplTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      drops: intent.amount,
      fee: feeBid(fee),
      sequence: sender.account_data.Sequence,
      lastLedgerSequence: builtAtLedger + LEDGER_WINDOW,
      builtAtLedger,
      ...(tag !== undefined ? { destinationTag: tag } : {}),
      publicKeyHex,
    });
    xrplFields(unsigned);
    const feeDrops = BigInt(unsigned.fee);
    let error: string | undefined;
    const warnings: Simulation['warnings'] = [];
    if (spendable(sender, reserveBase, reserveInc) < amount + feeDrops)
      error = 'Balance above the reserve does not cover the payment and fee';
    const flags = recipient?.account_data.Flags ?? 0;
    if (flags & LSF_REQUIRE_DEST_TAG && tag === undefined)
      error = 'The recipient requires a destination tag';
    if (flags & LSF_DEPOSIT_AUTH)
      error = 'The recipient only accepts payments from preauthorized senders';
    if (flags & LSF_DISALLOW_XRP)
      warnings.push({ kind: 'other', message: 'The recipient asks not to be sent XRP.' });
    if (!recipient)
      warnings.push({
        kind: 'other',
        message:
          'The recipient account is not activated yet; this payment creates it, and the base reserve stays locked in it.',
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${feeDrops}` },
        ],
        fee: { assetRef: intent.asset, amount: feeDrops.toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/**
 * Approval is refused once the payment could expire before it lands, once the
 * sender's sequence moved, or once an unfunded recipient would bounce it.
 */
export async function xrplApprovalValid(adapter: XrplAdapter, tx: XrplTx): Promise<boolean> {
  xrplFields(tx);
  return adapter.withNode(tx.chainId, async (call) => {
    const [sender, recipient, fee, state] = await Promise.all([
      accountInfo(call, tx.from, 'current'),
      accountInfo(call, tx.to, 'validated'),
      call('fee', {}, FeeInfo),
      call('server_state', {}, Reserves),
    ]);
    if (!sender || !fee || !state) return false;
    return (
      fee.ledger_current_index + APPROVAL_MARGIN < tx.lastLedgerSequence &&
      sender.account_data.Sequence === tx.sequence &&
      (recipient !== null || BigInt(tx.drops) >= BigInt(state.state.validated_ledger.reserve_base))
    );
  });
}

/** Parses `TxnSignature` out of a signed blob whose other bytes must be exactly this payment. */
function signatureOf(tx: XrplTx, blob: Uint8Array): Uint8Array {
  const unsigned = xrplFields(tx);
  // Account and Destination (2 x 22 bytes) follow the signature.
  const split = unsigned.length - 44;
  const sigLen = blob[split + 1] ?? 0;
  if (blob.length !== unsigned.length + 2 + sigLen || blob[split] !== 0x74 || sigLen > 72)
    throw new Error('Signed bytes are not this XRP payment');
  const sig = blob.slice(split + 2, split + 2 + sigLen);
  const rebuilt = xrplFields(tx, sig);
  if (bytesToHex(rebuilt) !== bytesToHex(blob))
    throw new Error('Signed bytes are not this XRP payment');
  return sig;
}

/** Engine results meaning the network has (or had) this exact payment. */
const KNOWN = new Set(['tefPAST_SEQ', 'tefALREADY']);

/**
 * Broadcast only bytes that are exactly the ledger's blob: this payment plus a
 * low-S DER signature that verifies against the sender's key.
 */
export async function broadcastXrpl(
  adapter: XrplAdapter,
  tx: XrplTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== XRPL_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0 || hex.length > 1024)
    throw new Error('Signed bytes are not this XRP payment');
  const blob = hexToBytes(hex);
  const der = signatureOf(tx, blob);
  if (
    !secp256k1.verify(der, xrplSigningHash(tx), hexToBytes(tx.publicKeyHex), {
      prehash: false,
      format: 'der',
      lowS: true,
    })
  )
    throw new Error('Signature does not verify against the sender');
  const hash = xrplBlobHash(blob);
  const res = await adapter.submit(tx.chainId, hex.toUpperCase());
  const reported = res.tx_json?.hash?.toUpperCase();
  if (reported && reported !== hash)
    throw new Error('rippled reported a different transaction hash');
  const code = res.engine_result;
  // tec results are applied: the payment lands in a ledger as failed and the fee is spent.
  if (code === 'tesSUCCESS' || code === 'terQUEUED' || code.startsWith('tec')) return hash;
  if (KNOWN.has(code)) {
    // A retry of an accepted payment collides with its own sequence.
    const status = await adapter.status(hash, tx.chainId);
    if (status.state !== 'unknown') return hash;
  }
  throw new Error(
    `Broadcast rejected: ${code}${res.engine_result_message ? ` ${res.engine_result_message}` : ''}`.slice(
      0,
      512,
    ),
  );
}

/**
 * Expiry is reported once the validated ledger is past `lastLedgerSequence`,
 * or the sender's validated sequence moved past `sequence`, and the hash is
 * still absent.
 */
export async function xrplTransferStatus(
  adapter: XrplAdapter,
  tx: XrplTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown' && status.state !== 'pending') return status;
  const dead = await adapter.withNode(tx.chainId, async (call) => {
    const [sender, state] = await Promise.all([
      accountInfo(call, tx.from, 'validated'),
      call('server_state', {}, Reserves),
    ]);
    const pastLedger = state !== null && state.state.validated_ledger.seq > tx.lastLedgerSequence;
    const seqUsed = sender !== null && sender.account_data.Sequence > tx.sequence;
    return pastLedger || seqUsed;
  });
  if (!dead) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' || again.state === 'pending' ? { state: 'expired' } : again;
}
