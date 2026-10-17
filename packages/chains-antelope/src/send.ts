import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  ANTELOPE_TESTNET,
  AntelopeAdapter,
  NETWORKS,
  antelopeKeyBytes,
  antelopeTimeMs,
  decodeAntelopeSignature,
  isCanonicalSignature,
  isValidAntelopeAccount,
  isValidAntelopePublicKey,
  nameValue,
  normalizeAntelopeKey,
  type AccountResponse,
  type AntelopeNode,
  type ChainInfoResponse,
} from './antelope.js';

const TOKEN = NETWORKS[ANTELOPE_TESTNET]!.token;
const AccountName = z
  .string()
  .regex(/^[.1-5a-z]{1,12}$/)
  .refine(isValidAntelopeAccount, 'invalid account name');

/** Mirrors `antelope::AntelopeTx` in the core; the core re-checks every field. */
export const AntelopeTx = z.strictObject({
  chainId: z.literal(ANTELOPE_TESTNET),
  from: AccountName,
  permission: AccountName,
  to: AccountName,
  antelopeUnits: z.string().regex(/^[1-9][0-9]{0,18}$/),
  symbol: z.literal('WAX'),
  precision: z.literal(8),
  tokenContract: z.literal('eosio.token'),
  memo: z.string().max(256),
  expiration: z.number().int().min(1).max(0xffff_ffff),
  refBlockNum: z.number().int().min(0).max(0xffff),
  refBlockPrefix: z.number().int().min(0).max(0xffff_ffff),
  builtAtSecs: z.number().int().min(1).max(0xffff_ffff),
  publicKey: z.string().regex(/^PUB_K1_[1-9A-HJ-NP-Za-km-z]{48,52}$/),
});
export type AntelopeTx = z.infer<typeof AntelopeTx>;

/** `asset.amount` is an int64 the token contract bounds to `2^62 - 1`. */
export const MAX_UNITS = (1n << 62n) - 1n;
export const MAX_MEMO_BYTES = 256;
export const MAX_LIFETIME_SECS = 3_600;
/** Signed transactions stay valid this long; well inside the chain's one-hour limit. */
export const LIFETIME_SECS = 1_800;
/**
 * A one-action transfer bills about 150 bytes of NET and 100-300 µs of CPU;
 * below these the node refuses it before it reaches a block.
 */
export const MIN_CPU_US = 400n;
export const MIN_NET_BYTES = 300n;

const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** Empty, or at most 256 UTF-8 bytes with no control or bidirectional-override characters. */
export function memoError(memo: string): string | undefined {
  if (enc.encode(memo).length > MAX_MEMO_BYTES) return 'Memo is longer than 256 bytes';
  if (CONTROL.test(memo) || BIDI.test(memo)) return 'Memo may not contain control characters';
  return undefined;
}

const enc = new TextEncoder();

function varuint(out: number[], value: number): void {
  let v = value;
  for (;;) {
    const byte = v & 0x7f;
    v >>>= 7;
    if (v === 0) {
      out.push(byte);
      return;
    }
    out.push(byte | 0x80);
  }
}

function u64le(out: number[], value: bigint): void {
  for (let i = 0n; i < 8n; i++) out.push(Number((value >> (8n * i)) & 0xffn));
}

function uintLe(out: number[], value: number, bytes: number): void {
  for (let i = 0; i < bytes; i++) out.push(Math.floor(value / 2 ** (8 * i)) & 0xff);
}

function name(n: string): bigint {
  const v = nameValue(n);
  if (v === undefined) throw new Error(`Invalid Antelope name ${n}`);
  return v;
}

function units(tx: AntelopeTx): bigint {
  const n = BigInt(tx.antelopeUnits);
  if (n <= 0n || n > MAX_UNITS || n.toString() !== tx.antelopeUnits)
    throw new Error('Amount must be canonical positive base units');
  return n;
}

/** `eosio.token::transfer` data: from, to, quantity, memo. */
export function antelopeActionData(input: AntelopeTx): Uint8Array {
  const tx = AntelopeTx.parse(input);
  const from = name(tx.from);
  const to = name(tx.to);
  if (from === to) throw new Error('Sender and recipient must differ');
  const err = memoError(tx.memo);
  if (err) throw new Error(err);
  const out: number[] = [];
  u64le(out, from);
  u64le(out, to);
  u64le(out, units(tx));
  const symbol = new Uint8Array(8);
  symbol[0] = tx.precision;
  symbol.set(enc.encode(tx.symbol), 1);
  out.push(...symbol);
  const memo = enc.encode(tx.memo);
  varuint(out, memo.length);
  out.push(...memo);
  return Uint8Array.from(out);
}

/** The packed transaction, byte for byte what the core encodes from the same fields. */
export function antelopePacked(input: AntelopeTx): Uint8Array {
  const tx = AntelopeTx.parse(input);
  const data = antelopeActionData(tx);
  if (!isValidAntelopePublicKey(tx.publicKey)) throw new Error('Invalid PUB_K1 key');
  if (tx.expiration <= tx.builtAtSecs || tx.expiration - tx.builtAtSecs > MAX_LIFETIME_SECS)
    throw new Error('Expiration must fall within an hour of the build time');
  const out: number[] = [];
  uintLe(out, tx.expiration, 4);
  uintLe(out, tx.refBlockNum, 2);
  uintLe(out, tx.refBlockPrefix, 4);
  varuint(out, 0); // max_net_usage_words
  out.push(0); // max_cpu_usage_ms
  varuint(out, 0); // delay_sec
  varuint(out, 0); // context_free_actions
  varuint(out, 1);
  u64le(out, name(tx.tokenContract));
  u64le(out, name('transfer'));
  varuint(out, 1);
  u64le(out, name(tx.from));
  u64le(out, name(tx.permission));
  varuint(out, data.length);
  out.push(...data);
  varuint(out, 0); // transaction_extensions
  return Uint8Array.from(out);
}

/** `sha256(chain_id || packed_trx || 0^32)`: the digest the K1 signature covers. */
export function antelopeSigningDigest(tx: AntelopeTx): Uint8Array {
  const packed = antelopePacked(tx);
  const chain = hexToBytes(NETWORKS[tx.chainId]!.chainId);
  const input = new Uint8Array(32 + packed.length + 32);
  input.set(chain);
  input.set(packed, 32);
  return sha256(input);
}

/** `sha256(packed_trx)`, the id explorers show. */
export function antelopeTxId(tx: AntelopeTx): string {
  return bytesToHex(sha256(antelopePacked(tx)));
}

/** TaPoS reference for a block: low 16 bits of its number and bytes 8..12 of its id (LE). */
export function tapos(
  blockNum: number,
  blockId: string,
): { refBlockNum: number; refBlockPrefix: number } {
  if (!/^[0-9a-f]{64}$/.test(blockId)) throw new Error('Invalid block id');
  const b = hexToBytes(blockId.slice(16, 24));
  return {
    refBlockNum: blockNum & 0xffff,
    refBlockPrefix: (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0,
  };
}

/**
 * The permission of `account` this key satisfies on its own: `active` first,
 * then custom permissions, `owner` last.
 */
export function permissionFor(account: AccountResponse, key: string): string | undefined {
  const k1 = normalizeAntelopeKey(key);
  if (!k1) return undefined;
  const usable = account.permissions
    .filter((p) =>
      p.required_auth.keys.some(
        (k) => normalizeAntelopeKey(k.key) === k1 && k.weight >= p.required_auth.threshold,
      ),
    )
    .map((p) => p.perm_name)
    .filter(isValidAntelopeAccount);
  const rank = (p: string) => (p === 'active' ? 0 : p === 'owner' ? 2 : 1);
  return usable.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))[0];
}

const big = (v: number | string) => BigInt(v);

/** CPU (µs) and NET (bytes) the account can spend now; negative "unlimited" reads as plenty. */
export function resources(account: AccountResponse): { cpu: bigint; net: bigint } {
  const read = (l: { available: number | string; max: number | string }) =>
    big(l.max) < 0n ? MAX_UNITS : big(l.available);
  return { cpu: read(account.cpu_limit), net: read(account.net_limit) };
}

const headSecs = (info: ChainInfoResponse) =>
  Math.floor(antelopeTimeMs(info.head_block_time) / 1000);

export interface PrepareAntelopeOptions {
  /** User-entered memo; the core encodes it but `TxIntent` cannot bind it. */
  memo?: string;
}

export async function prepareAntelope(
  adapter: AntelopeAdapter,
  intent: TxIntent,
  from: string,
  publicKey: string,
  options: PrepareAntelopeOptions = {},
): Promise<{ unsigned: AntelopeTx; simulation: Simulation }> {
  if (
    intent.chainId !== ANTELOPE_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${ANTELOPE_TESTNET}:native`
  )
    throw new Error('Only native WAX transfers on WAX testnet are enabled');
  if (!isValidAntelopeAccount(from) || !isValidAntelopeAccount(intent.to) || from === intent.to)
    throw new Error('Sender and recipient must be different Antelope account names');
  if (!isValidAntelopePublicKey(publicKey)) throw new Error('Invalid PUB_K1 key');
  const memo = options.memo ?? '';
  const memoErr = memoError(memo);
  if (memoErr) throw new Error(memoErr);
  return adapter.withNode(intent.chainId, async (node: AntelopeNode) => {
    const [info, sender, recipient, balance] = await Promise.all([
      node.info(),
      node.account(from),
      node.account(intent.to),
      node.balance(from, TOKEN),
    ]);
    if (!sender) throw new Error(`The account ${from} does not exist on this chain`);
    if (!recipient)
      throw new Error(
        `The account ${intent.to} does not exist on this chain; Antelope transfers need an existing recipient account`,
      );
    const permission = permissionFor(sender, publicKey);
    if (!permission) throw new Error(`This key does not control the account ${from}`);
    const builtAtSecs = headSecs(info);
    const unsigned = AntelopeTx.parse({
      chainId: intent.chainId,
      from,
      permission,
      to: intent.to,
      antelopeUnits: intent.amount,
      symbol: TOKEN.symbol,
      precision: TOKEN.precision,
      tokenContract: TOKEN.contract,
      memo,
      expiration: builtAtSecs + LIFETIME_SECS,
      ...tapos(info.last_irreversible_block_num, info.last_irreversible_block_id),
      builtAtSecs,
      publicKey,
    });
    antelopePacked(unsigned);
    const amount = BigInt(intent.amount);
    const { cpu, net } = resources(sender);
    let error: string | undefined;
    if (balance < amount) error = 'Balance does not cover the transfer';
    else if (cpu < MIN_CPU_US || net < MIN_NET_BYTES)
      error =
        `The sender has ${cpu} µs of CPU and ${net} bytes of NET available; a transfer needs about ` +
        `${MIN_CPU_US} µs and ${MIN_NET_BYTES} bytes. Antelope bills resources instead of fees: ` +
        'rent CPU and NET (PowerUp) or stake WAX for them, then try again.';
    const warnings: Simulation['warnings'] = [
      {
        kind: 'other',
        message:
          'No token fee: the transfer uses the sender’s CPU and NET resources. It counts as final once the block is irreversible, which can take a few minutes.',
      },
    ];
    if (memo)
      warnings.push({
        kind: 'other',
        message: `Memo "${memo}" is signed with the transfer; check it, because the approval policy does not compare memos.`,
      });
    if (permission !== 'active')
      warnings.push({
        kind: 'other',
        message: `Signing with the ${permission} permission of ${from}.`,
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [{ assetRef: intent.asset, amount: `-${intent.amount}` }],
        fee: { assetRef: intent.asset, amount: '0' },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/**
 * Approval is refused once the chain head is within a minute of the
 * expiration, or once the key no longer satisfies `from@permission`.
 */
export async function antelopeApprovalValid(
  adapter: AntelopeAdapter,
  tx: AntelopeTx,
): Promise<boolean> {
  return adapter.withNode(tx.chainId, async (node) => {
    const [info, sender] = await Promise.all([node.info(), node.account(tx.from)]);
    if (headSecs(info) >= tx.expiration - 60) return false;
    if (!sender) return false;
    const perm = sender.permissions.find((p) => p.perm_name === tx.permission);
    const k1 = normalizeAntelopeKey(tx.publicKey);
    return (
      perm !== undefined &&
      perm.required_auth.keys.some(
        (k) => normalizeAntelopeKey(k.key) === k1 && k.weight >= perm.required_auth.threshold,
      )
    );
  });
}

const SignedBody = z.strictObject({
  signatures: z.array(z.string().max(128)).length(1),
  compression: z.literal(0),
  packed_context_free_data: z.literal(''),
  packed_trx: z
    .string()
    .regex(/^[0-9a-f]+$/)
    .max(4096),
});

/**
 * Broadcast only a body that carries exactly this transfer and one canonical,
 * low-S K1 signature that recovers the transaction's `publicKey`.
 */
export async function broadcastAntelope(
  adapter: AntelopeAdapter,
  tx: AntelopeTx,
  wire: string,
): Promise<string> {
  if (tx.chainId !== ANTELOPE_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  let body: z.infer<typeof SignedBody>;
  try {
    body = SignedBody.parse(JSON.parse(wire));
  } catch {
    throw new Error('Signed bytes are not this Antelope transfer');
  }
  const packed = antelopePacked(tx);
  if (body.packed_trx !== bytesToHex(packed))
    throw new Error('Signed bytes are not this Antelope transfer');
  const raw = decodeAntelopeSignature(body.signatures[0]!);
  if (!raw) throw new Error('Signature is not a valid SIG_K1');
  const rs = raw.subarray(1);
  if (!isCanonicalSignature(rs)) throw new Error('Signature is not canonical');
  const sig = secp256k1.Signature.fromBytes(rs, 'compact');
  if (sig.hasHighS()) throw new Error('Signature is not low-S');
  const key = antelopeKeyBytes(tx.publicKey);
  let recovered: Uint8Array;
  try {
    recovered = sig
      .addRecoveryBit(raw[0]! - 31)
      .recoverPublicKey(antelopeSigningDigest(tx))
      .toBytes(true);
  } catch {
    throw new Error('Signature does not verify against the sender key');
  }
  if (!key || bytesToHex(recovered) !== bytesToHex(key))
    throw new Error('Signature does not verify against the sender key');
  const id = bytesToHex(sha256(packed));
  const res = await adapter.pushTransaction(tx.chainId, body);
  if ('id' in res) {
    if (res.id !== id) throw new Error('The node reported a different transaction id');
    return id;
  }
  if (res.error.errorName === 'tx_duplicate') {
    // A retry of an accepted transfer meets its own earlier submission.
    const status = await adapter.status(id, tx.chainId);
    if (status.state === 'confirmed' || status.state === 'pending') return id;
  }
  throw new Error(`Broadcast rejected: ${res.error.message}`.slice(0, 512));
}

/**
 * Expiry is reported once the chain head is past the expiration and the
 * transaction is still unknown to the node and to Hyperion.
 */
export async function antelopeTransferStatus(
  adapter: AntelopeAdapter,
  tx: AntelopeTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const info = await adapter.info(tx.chainId);
  if (headSecs(info) <= tx.expiration) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
