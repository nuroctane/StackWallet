import { sha512_256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  Nonces,
  STACKS_TESTNET,
  StxBalance,
  VERSION,
  isValidStacksAddress,
  stacksAddressBytes,
  type StacksAdapter,
} from './stacks.js';

const U64_MAX = 0xffffffffffffffffn;
/** Mirrors the core: a plain transfer never needs anywhere near 1 STX of fee. */
export const MAX_FEE = 1_000_000;
const MAX_NONCE = Number.MAX_SAFE_INTEGER;
const SIG_OFFSET = 44;
const SIG_LEN = 65;
const PAYLOAD_LEN = 1 + 22 + 8 + 34;

/** Mirror of the core's `StacksTx`; every signed byte is derived from these fields. */
export const StacksTx = z.strictObject({
  chainId: z.literal(STACKS_TESTNET),
  from: z.string().max(64),
  to: z.string().max(64),
  microstx: z.string().regex(/^[1-9][0-9]{0,19}$/),
  fee: z.number().int().min(1).max(MAX_FEE),
  nonce: z.number().int().nonnegative().max(MAX_NONCE),
});
export type StacksTx = z.infer<typeof StacksTx>;

const u64 = (value: bigint) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value);
  return [...out];
};

function encode(input: StacksTx, fee: number, nonce: number, signature: Uint8Array): Uint8Array {
  const tx = StacksTx.parse(input);
  const from = stacksAddressBytes(tx.from);
  const to = stacksAddressBytes(tx.to);
  if (!from || from.version !== VERSION.testnetP2pkh)
    throw new Error('STX sender must be a single-sig testnet address');
  if (!to || !isValidStacksAddress(tx.to, STACKS_TESTNET))
    throw new Error('STX recipient must be a testnet address');
  if (bytesToHex(from.hash) === bytesToHex(to.hash))
    throw new Error('STX sender and recipient must differ');
  const amount = BigInt(tx.microstx);
  if (amount <= 0n || amount > U64_MAX) throw new Error('STX amount must be a positive u64');
  return Uint8Array.from([
    0x80,
    ...[0x80, 0, 0, 0],
    0x04,
    0x00,
    ...from.hash,
    ...u64(BigInt(nonce)),
    ...u64(BigInt(fee)),
    0x00,
    ...signature,
    0x03,
    0x02,
    ...[0, 0, 0, 0],
    0x00,
    0x05,
    to.version,
    ...to.hash,
    ...u64(amount),
    ...new Uint8Array(34),
  ]);
}

/** The transaction with a zero signature; the core encodes the same bytes independently. */
export function stacksUnsignedBytes(tx: StacksTx): Uint8Array {
  return encode(tx, tx.fee, tx.nonce, new Uint8Array(SIG_LEN));
}

/** SIP-005 presign sighash over the cleared-auth txid, auth type, fee and nonce. */
export function stacksSighash(tx: StacksTx): string {
  const initial = sha512_256(encode(tx, 0, 0, new Uint8Array(SIG_LEN)));
  return bytesToHex(
    sha512_256(
      Uint8Array.from([...initial, 0x04, ...u64(BigInt(tx.fee)), ...u64(BigInt(tx.nonce))]),
    ),
  );
}

/** Explorer-style `0x` txid of serialized signed bytes. */
export function stacksTxId(signed: Uint8Array): string {
  return `0x${bytesToHex(sha512_256(signed))}`;
}

const FeeEstimate = z.object({
  estimations: z
    .array(z.object({ fee: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) }))
    .min(1)
    .max(8),
});
const FeeRate = z.number().int().nonnegative().max(MAX_FEE);

export async function prepareStacks(
  adapter: StacksAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: StacksTx; simulation: Simulation }> {
  if (
    intent.chainId !== STACKS_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${STACKS_TESTNET}:native`
  )
    throw new Error('Only native STX transfers on Stacks testnet are enabled');
  if (!isValidStacksAddress(from, STACKS_TESTNET)) throw new Error('Invalid STX sender');
  return adapter.withNode(intent.chainId, async (get, post) => {
    const [nonces, balance] = await Promise.all([
      get(`/extended/v1/address/${from}/nonces`, Nonces),
      get(`/extended/v1/address/${from}/stx`, StxBalance),
    ]);
    if (!nonces) throw new Error('Node did not report the sender nonce');
    const draft = StacksTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      microstx: intent.amount,
      fee: 1,
      nonce: nonces.possible_next_nonce,
    });
    const bytes = stacksUnsignedBytes(draft);
    // The network's floor is 1 microSTX per byte.
    const floor = bytes.length;
    let estimate: number | undefined;
    const res = await post('/v2/fees/transaction', {
      transaction_payload: bytesToHex(bytes.subarray(bytes.length - PAYLOAD_LEN)),
      estimated_len: bytes.length,
    });
    const parsed = res.status === 200 ? FeeEstimate.safeParse(res.body) : undefined;
    if (parsed?.success) {
      const list = parsed.data.estimations;
      estimate = list[Math.min(1, list.length - 1)]!.fee;
    } else {
      const rate = await get('/v2/fees/transfer', FeeRate);
      estimate = (rate ?? 1) * bytes.length;
    }
    const fee = Math.max(floor, estimate);
    let error: string | undefined;
    if (fee > MAX_FEE) error = 'The network fee estimate is above the 1 STX safety bound';
    const unsigned = StacksTx.parse({ ...draft, fee: Math.min(fee, MAX_FEE) });
    const spendable = BigInt(balance?.balance ?? '0') - BigInt(balance?.locked ?? '0');
    if (!error && spendable < BigInt(intent.amount) + BigInt(unsigned.fee))
      error = 'Spendable balance does not cover the transfer and fee';
    const warnings: Simulation['warnings'] = [];
    if (nonces.detected_missing_nonces.length > 0)
      warnings.push({
        kind: 'other',
        message:
          'This account has a gap in its pending nonces; the transfer waits until the missing nonces are filled.',
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${unsigned.fee}` },
        ],
        fee: { assetRef: intent.asset, amount: String(unsigned.fee) },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Approval is refused once another transaction has taken, or is pending with, this nonce. */
export async function stacksApprovalValid(adapter: StacksAdapter, tx: StacksTx): Promise<boolean> {
  const nonces = await adapter.withNode(tx.chainId, (get) =>
    get(`/extended/v1/address/${tx.from}/nonces`, Nonces),
  );
  if (!nonces) return false;
  return (
    nonces.possible_next_nonce === tx.nonce &&
    (nonces.last_executed_tx_nonce === null || nonces.last_executed_tx_nonce < tx.nonce)
  );
}

const Rejection = z
  .object({
    error: z.string().max(256).optional(),
    reason: z.string().max(128).optional(),
    txid: z
      .string()
      .regex(/^(0x)?[0-9a-f]{64}$/)
      .optional(),
  })
  .loose();

/** Broadcast only bytes that are exactly the ledger's transfer plus one 65-byte signature. */
export async function broadcastStacks(
  adapter: StacksAdapter,
  tx: StacksTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== STACKS_TESTNET) throw new Error('Only Stacks testnet broadcasts are enabled');
  const expected = stacksUnsignedBytes(tx);
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expected.length * 2)
    throw new Error('Signed bytes are not this STX transfer');
  const signed = hexToBytes(hex);
  const end = SIG_OFFSET + SIG_LEN;
  if (
    bytesToHex(signed.subarray(0, SIG_OFFSET)) !== bytesToHex(expected.subarray(0, SIG_OFFSET)) ||
    bytesToHex(signed.subarray(end)) !== bytesToHex(expected.subarray(end)) ||
    signed[SIG_OFFSET]! > 3
  )
    throw new Error('Signed bytes are not this STX transfer');
  const txid = stacksTxId(signed);
  const res = await adapter.withNode(tx.chainId, (_get, post) =>
    post('/v2/transactions', { tx: hex }),
  );
  if (res.status === 200) {
    if (typeof res.body !== 'string' || `0x${res.body.replace(/^0x/, '')}` !== txid)
      throw new Error('Node reported a different transaction id');
    return txid;
  }
  const rejection = Rejection.safeParse(res.body);
  // A retry of an accepted transfer is not a failure.
  const known = await adapter.status(txid, tx.chainId).catch(() => ({ state: 'unknown' as const }));
  if (known.state !== 'unknown') return txid;
  const reason = rejection.success ? (rejection.data.reason ?? rejection.data.error) : undefined;
  throw new Error(
    `Broadcast rejected: ${(reason ?? `HTTP ${res.status}`).replace(/[^\x20-\x7e]/g, '')}`,
  );
}

/** Expiry is reported only once the account executed this nonce with another transaction. */
export async function stacksTransferStatus(
  adapter: StacksAdapter,
  tx: StacksTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const nonces = await adapter.withNode(tx.chainId, (get) =>
    get(`/extended/v1/address/${tx.from}/nonces`, Nonces),
  );
  const executed = nonces?.last_executed_tx_nonce;
  if (executed === null || executed === undefined || executed < tx.nonce) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
