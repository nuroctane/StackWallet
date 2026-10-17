import { ed25519 } from '@noble/curves/ed25519.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  APTOS_TESTNET,
  AptosAdapter,
  GasEstimate,
  NETWORKS,
  aptosAddressBytes,
  aptosAddressFromPublicKey,
} from './aptos.js';

/** Mirrors `aptos::AptosTx` in the core; the core re-checks every field. */
export const AptosTx = z.strictObject({
  chainId: z.literal(APTOS_TESTNET),
  from: z.string().regex(/^0x[0-9a-f]{64}$/),
  to: z.string().regex(/^0x[0-9a-f]{64}$/),
  octas: z.string().regex(/^[0-9]+$/),
  sequenceNumber: z.string().regex(/^[0-9]+$/),
  maxGasAmount: z.number().int().min(1).max(20_000),
  gasUnitPrice: z.number().int().min(1).max(10_000),
  expirationTimestampSecs: z.number().int().positive().max(4_102_444_800),
});
export type AptosTx = z.infer<typeof AptosTx>;

const U64_MAX = 0xffffffffffffffffn;
export const MAX_GAS_AMOUNT = 20_000;
/** The core refuses a transaction that could cost more than one APT in fees. */
export const MAX_FEE_OCTAS = 100_000_000n;
/** The network minimum; the adapter never bids above `MAX_BID`. */
export const MIN_GAS_UNIT_PRICE = 100;
const MAX_BID = 1_000;
/**
 * Storage for a new state slot (the sender's account resource on its first
 * transaction, the recipient's APT store on its first deposit) is charged in
 * gas units, and the prologue refuses a `maxGasAmount` that cannot cover the
 * sender's slot. 500,000 octas is the larger of the two on-chain slot fees.
 */
const SLOT_OCTAS = 500_000;
/** Execution and I/O of a transfer; it uses a few hundred units at most. */
const EXECUTION_UNITS = 2_000;
const LIFETIME_S = 30 * 60;
const CHAIN_ID_BYTE = NETWORKS[APTOS_TESTNET]!.ledgerChainId;
const ENTRY_FUNCTION_PAYLOAD = 2;
const ED25519_AUTHENTICATOR = 0;
const USER_TRANSACTION = 0;

function uleb128(out: number[], value: number): void {
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

function bcsBytes(out: number[], bytes: Uint8Array): void {
  uleb128(out, bytes.length);
  out.push(...bytes);
}

function positiveU64(value: string, what: string): bigint {
  const n = BigInt(value);
  if (n <= 0n || n > U64_MAX || n.toString() !== value)
    throw new Error(`${what} must be a positive canonical u64`);
  return n;
}

const domain = (tag: string) => sha3_256(new TextEncoder().encode(tag));

/** BCS `RawTransaction`, byte for byte what the core encodes from the same fields. */
export function aptosRawTransaction(input: AptosTx): Uint8Array {
  const tx = AptosTx.parse(input);
  const from = aptosAddressBytes(tx.from);
  const to = aptosAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid APT sender or recipient');
  const octas = positiveU64(tx.octas, 'APT amount');
  const sequence = tx.sequenceNumber === '0' ? 0n : positiveU64(tx.sequenceNumber, 'Sequence');
  if (BigInt(tx.maxGasAmount) * BigInt(tx.gasUnitPrice) > MAX_FEE_OCTAS)
    throw new Error('Maximum fee exceeds one APT');
  const out: number[] = [...from];
  u64le(out, sequence);
  out.push(ENTRY_FUNCTION_PAYLOAD);
  const framework = new Uint8Array(32);
  framework[31] = 1;
  out.push(...framework);
  const text = new TextEncoder();
  bcsBytes(out, text.encode('aptos_account'));
  bcsBytes(out, text.encode('transfer'));
  uleb128(out, 0);
  uleb128(out, 2);
  bcsBytes(out, to);
  const amount: number[] = [];
  u64le(amount, octas);
  bcsBytes(out, Uint8Array.from(amount));
  u64le(out, BigInt(tx.maxGasAmount));
  u64le(out, BigInt(tx.gasUnitPrice));
  u64le(out, BigInt(tx.expirationTimestampSecs));
  out.push(CHAIN_ID_BYTE);
  return Uint8Array.from(out);
}

/** `sha3-256("APTOS::RawTransaction") || bcs(raw)`: the bytes Ed25519 signs. */
export function aptosSigningMessage(tx: AptosTx): Uint8Array {
  const raw = aptosRawTransaction(tx);
  const out = new Uint8Array(32 + raw.length);
  out.set(domain('APTOS::RawTransaction'));
  out.set(raw, 32);
  return out;
}

/** `sha3-256(sha3-256("APTOS::Transaction") || 0x00 || bcs(SignedTransaction))`, as explorers show it. */
export function aptosSignedTxHash(signed: Uint8Array): string {
  const input = new Uint8Array(33 + signed.length);
  input.set(domain('APTOS::Transaction'));
  input[32] = USER_TRANSACTION;
  input.set(signed, 33);
  return `0x${bytesToHex(sha3_256(input))}`;
}

/** Gas units that cover execution plus every state slot this transfer may create. */
export function maxGasFor(gasUnitPrice: number, newSlots: number): number {
  return Math.min(
    MAX_GAS_AMOUNT,
    Math.ceil((newSlots * SLOT_OCTAS) / gasUnitPrice) + EXECUTION_UNITS,
  );
}

export function gasBid(estimate: z.infer<typeof GasEstimate>): number {
  return Math.min(MAX_BID, Math.max(MIN_GAS_UNIT_PRICE, estimate.gas_estimate));
}

export async function prepareAptos(
  adapter: AptosAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: AptosTx; simulation: Simulation }> {
  if (
    intent.chainId !== APTOS_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${APTOS_TESTNET}:native`
  )
    throw new Error('Only native APT transfers on testnet are enabled');
  if (!aptosAddressBytes(from) || !aptosAddressBytes(intent.to) || from === intent.to)
    throw new Error('Invalid APT sender or recipient');
  const coin = NETWORKS[APTOS_TESTNET]!.coinType;
  return adapter.withNode(intent.chainId, async (node) => {
    const [sequenceNumber, gas, balance, recipientBalance, ledger] = await Promise.all([
      AptosAdapter.sequenceNumber(node, from),
      node.get('/estimate_gas_price', GasEstimate),
      AptosAdapter.nativeBalance(node, coin, from),
      AptosAdapter.nativeBalance(node, coin, intent.to),
      node.ledger(),
    ]);
    if (!gas) throw new Error('The node did not report a gas price');
    const gasUnitPrice = gasBid(gas);
    const recipientNew = recipientBalance === '0';
    const newSlots = (sequenceNumber === '0' ? 1 : 0) + (recipientNew ? 1 : 0);
    const expirationTimestampSecs = Math.floor(now / 1000) + LIFETIME_S;
    const ledgerSecs = Number(BigInt(ledger.ledger_timestamp) / 1_000_000n);
    if (ledgerSecs >= expirationTimestampSecs - 60)
      throw new Error('This device clock is behind the Aptos ledger; fix the clock and retry');
    const unsigned = AptosTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      octas: intent.amount,
      sequenceNumber,
      maxGasAmount: maxGasFor(gasUnitPrice, newSlots),
      gasUnitPrice,
      expirationTimestampSecs,
    });
    aptosRawTransaction(unsigned);
    const maxFee = BigInt(unsigned.maxGasAmount) * BigInt(unsigned.gasUnitPrice);
    let error: string | undefined;
    // The prologue reserves the whole fee bound before the transfer executes.
    if (BigInt(balance) < BigInt(intent.amount) + maxFee)
      error = 'Balance does not cover the transfer plus the maximum network fee';
    const warnings: Simulation['warnings'] = [
      {
        kind: 'other',
        message:
          'The fee shown is the most this transaction may be charged; unused gas is not charged.',
      },
    ];
    if (recipientNew)
      warnings.push({
        kind: 'other',
        message:
          'The recipient holds no APT yet; the first deposit pays for creating its balance store.',
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${maxFee}` },
        ],
        fee: { assetRef: intent.asset, amount: maxFee.toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/**
 * Approval is refused once the ledger could pass the expiration before the
 * transaction lands, or once the sender's sequence number moved.
 */
export async function aptosApprovalValid(
  adapter: AptosAdapter,
  tx: AptosTx,
  now = Date.now(),
): Promise<boolean> {
  if (now / 1000 > tx.expirationTimestampSecs - 60) return false;
  return adapter.withNode(tx.chainId, async (node) => {
    const [sequenceNumber, ledger] = await Promise.all([
      AptosAdapter.sequenceNumber(node, tx.from),
      node.ledger(),
    ]);
    const ledgerSecs = Number(BigInt(ledger.ledger_timestamp) / 1_000_000n);
    return ledgerSecs < tx.expirationTimestampSecs - 60 && sequenceNumber === tx.sequenceNumber;
  });
}

const SubmitOk = z.object({ hash: z.string().regex(/^0x[0-9a-f]{64}$/) }).loose();
const SubmitError = z
  .object({
    message: z.string().max(4096).optional(),
    error_code: z.string().max(128).optional(),
    vm_error_code: z.number().int().nullable().optional(),
  })
  .loose();

/**
 * Broadcast only bytes that are exactly the ledger's `SignedTransaction`: this
 * transaction plus one Ed25519 authenticator whose key is the sender's and
 * whose signature verifies over the signing message.
 */
export async function broadcastAptos(
  adapter: AptosAdapter,
  tx: AptosTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== APTOS_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const raw = aptosRawTransaction(tx);
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  const expected = bytesToHex(raw) + bytesToHex(Uint8Array.of(ED25519_AUTHENTICATOR, 32));
  const length = raw.length + 2 + 32 + 1 + 64;
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== length * 2 || !hex.startsWith(expected))
    throw new Error('Signed bytes are not this APT transfer');
  const bytes = hexToBytes(hex);
  const pub = bytes.subarray(raw.length + 2, raw.length + 34);
  if (bytes[raw.length + 34] !== 64) throw new Error('Signed bytes are not this APT transfer');
  const sig = bytes.subarray(raw.length + 35);
  if (aptosAddressFromPublicKey(pub) !== tx.from)
    throw new Error('Signing key is not the sender account');
  if (!ed25519.verify(sig, aptosSigningMessage(tx), pub, { zip215: false }))
    throw new Error('Signature does not verify against the sender');
  const hash = aptosSignedTxHash(bytes);
  const res = await adapter.submit(tx.chainId, bytes);
  if (res.status === 200 || res.status === 202) {
    const ok = SubmitOk.parse(res.body);
    if (ok.hash !== hash) throw new Error('The node reported a different transaction hash');
    return hash;
  }
  const err = SubmitError.safeParse(res.body);
  const message = err.success ? (err.data.message ?? '') : '';
  if (/SEQUENCE_NUMBER_TOO_OLD|already in mempool/i.test(message)) {
    // A retry of an accepted transfer meets its own sequence number or mempool entry.
    const status = await adapter.status(hash, tx.chainId);
    if (status.state === 'confirmed' || status.state === 'pending') return hash;
  }
  throw new Error(`Broadcast rejected: ${message || `HTTP ${res.status}`}`.slice(0, 512));
}

/**
 * Expiry is reported once the ledger is past the expiration, or the sender's
 * sequence number moved past this transaction's, and the hash is still absent.
 */
export async function aptosTransferStatus(
  adapter: AptosAdapter,
  tx: AptosTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const dead = await adapter.withNode(tx.chainId, async (node) => {
    const [sequenceNumber, ledger] = await Promise.all([
      AptosAdapter.sequenceNumber(node, tx.from),
      node.ledger(),
    ]);
    const pastTime =
      BigInt(ledger.ledger_timestamp) / 1_000_000n > BigInt(tx.expirationTimestampSecs);
    const seqUsed = BigInt(sequenceNumber) > BigInt(tx.sequenceNumber);
    return pastTime || seqUsed;
  });
  if (!dead) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
