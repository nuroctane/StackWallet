/**
 * Build/broadcast path for native WAVES transfers. The adapter only assembles
 * checked fields and ships what the core signed; the body-byte encoder here is
 * pinned to the same vector the Rust core produces (`waves.rs` tests).
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { base58, base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { WAVES_TESTNET, parseWavesAddress, wavesSecureHash, type WavesAdapter } from './waves.js';

/** Nodes reject a transfer once its timestamp is about two hours stale. */
export const WAVES_TX_STALE_MS = 2 * 60 * 60 * 1000;
export const WAVES_FEE_WAVELETS = 100_000;
const VERSION = 3;
const TESTNET_BYTE = 84;

const WavesAddress = z.string().regex(/^3[1-9A-HJ-NP-Za-km-z]{25,35}$/);
/**
 * Mirrors the Rust `WavesTx` (core-client gains the same shape when the family
 * is wired in; keep the two in lockstep).
 */
export const WavesTx = z.strictObject({
  chainId: z.literal(WAVES_TESTNET),
  from: WavesAddress,
  to: WavesAddress,
  wavelets: z.string().regex(/^[1-9][0-9]{0,18}$/),
  publicKeyHex: z.string().regex(/^[0-9a-f]{64}$/),
  timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  builtAtMs: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type WavesTx = z.infer<typeof WavesTx>;

function varint(value: bigint): number[] {
  const out: number[] = [];
  let v = value;
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return out;
}
const intField = (field: number, value: bigint) => [
  ...varint(BigInt(field) << 3n),
  ...varint(value),
];
const bytesField = (field: number, bytes: Uint8Array | number[]) => [
  ...varint((BigInt(field) << 3n) | 2n),
  ...varint(BigInt(bytes.length)),
  ...bytes,
];

function senderPublicKey(tx: WavesTx): Uint8Array {
  const pub = Uint8Array.from(tx.publicKeyHex.match(/../g)!, (h) => parseInt(h, 16));
  const from = parseWavesAddress(tx.from);
  if (!from) throw new Error('Invalid sender address');
  const want = wavesSecureHash(pub).subarray(0, 20);
  if (from.chainByte !== TESTNET_BYTE || want.some((b, i) => b !== from.hash[i]))
    throw new Error('Public key does not match the sender address');
  return pub;
}

/** The same protobuf `waves.Transaction` body the core encodes from checked fields. */
export function transferBodyBytes(input: WavesTx): Uint8Array {
  const tx = WavesTx.parse(input);
  const pub = senderPublicKey(tx);
  const to = parseWavesAddress(tx.to);
  if (!to || to.chainByte !== TESTNET_BYTE) throw new Error('Invalid recipient address');
  const from = parseWavesAddress(tx.from)!;
  if (to.hash.every((b, i) => b === from.hash[i]))
    throw new Error('Sender and recipient must differ');
  const amount = BigInt(tx.wavelets);
  if (amount > 0x7fffffffffffffffn || amount.toString() !== tx.wavelets)
    throw new Error('WAVES amount must be a positive int64 of wavelets');
  const fee = bytesField(3, intField(2, BigInt(WAVES_FEE_WAVELETS)));
  const sum = bytesField(2, intField(2, amount));
  const recipient = bytesField(1, bytesField(1, to.hash));
  const transfer = bytesField(104, [...recipient, ...sum]);
  return Uint8Array.from([
    ...intField(1, BigInt(TESTNET_BYTE)),
    ...bytesField(2, pub),
    ...fee,
    ...intField(4, BigInt(tx.timestamp)),
    ...intField(5, BigInt(VERSION)),
    ...transfer,
  ]);
}

/** The transaction id as explorers show it: base58 of blake2b256(body). */
export function transferTxId(tx: WavesTx): string {
  return base58.encode(blake2b(transferBodyBytes(tx), { dkLen: 32 }));
}

const Balance = z.object({
  balance: z.union([
    z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    z.string().regex(/^\d{1,19}$/),
  ]),
});

export async function prepareWaves(
  adapter: WavesAdapter,
  intent: TxIntent,
  from: string,
  publicKeyHex: string,
  now = Date.now(),
): Promise<{ unsigned: WavesTx; simulation: Simulation }> {
  if (
    intent.chainId !== WAVES_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${WAVES_TESTNET}:native`
  )
    throw new Error('Only native WAVES transfers on testnet are enabled');
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex))
    throw new Error('Sender Waves public key (hex) is required');
  const unsigned = WavesTx.parse({
    chainId: intent.chainId,
    from,
    to: intent.to,
    wavelets: intent.amount,
    publicKeyHex: publicKeyHex.toLowerCase(),
    timestamp: now,
    builtAtMs: now,
  });
  transferBodyBytes(unsigned);
  const sender = await adapter.withNode(intent.chainId, (call) =>
    call(`/addresses/balance/${from}`, Balance),
  );
  const balance = BigInt(sender.balance);
  const total = BigInt(intent.amount) + BigInt(WAVES_FEE_WAVELETS);
  const error =
    balance < total ? 'Balance does not cover the transfer and the 0.001 WAVES fee' : undefined;
  return {
    unsigned,
    simulation: {
      ok: error === undefined,
      assetDeltas: [
        { assetRef: intent.asset, amount: `-${intent.amount}` },
        { assetRef: intent.asset, amount: `-${WAVES_FEE_WAVELETS}` },
      ],
      fee: { assetRef: intent.asset, amount: String(WAVES_FEE_WAVELETS) },
      warnings: [],
      ...(error ? { error } : {}),
    },
  };
}

/** Approval is refused once the network could drop the transaction as stale. */
export function wavesApprovalValid(tx: WavesTx, now = Date.now()): boolean {
  return now <= tx.timestamp + WAVES_TX_STALE_MS - 60_000;
}

const BroadcastOk = z.object({ id: z.string().max(64) });
const BroadcastErr = z
  .object({ error: z.number().optional(), message: z.string().max(2048).optional() })
  .loose();

/**
 * Broadcast only a wire that is exactly this transfer's body plus one 64-byte
 * proof. The node endpoint takes JSON; the protobuf framing is verified
 * byte-for-byte before the proof is extracted into it.
 */
export async function broadcastWaves(
  adapter: WavesAdapter,
  input: WavesTx,
  signedWireB64: string,
): Promise<string> {
  const tx = WavesTx.parse(input);
  const body = transferBodyBytes(tx);
  const txid = transferTxId(tx);
  let wire: Uint8Array;
  try {
    wire = base64.decode(signedWireB64);
  } catch {
    throw new Error('Signed payload is not base64');
  }
  // Exact framing: bytesField(1, body) || bytesField(2, proof); nothing else.
  const head = [...bytesField(1, body)];
  if (
    wire.length !== head.length + 2 + 64 ||
    !head.every((b, i) => wire[i] === b) ||
    wire[head.length] !== 0x12 ||
    wire[head.length + 1] !== 64
  )
    throw new Error('Signed bytes are not this WAVES transfer');
  const proof = wire.subarray(head.length + 2);
  const amount = BigInt(tx.wavelets);
  if (amount > BigInt(Number.MAX_SAFE_INTEGER))
    throw new Error('Amount exceeds what the JSON broadcast can carry exactly');
  const pub = senderPublicKey(tx);
  const json = {
    type: 4,
    version: VERSION,
    senderPublicKey: base58.encode(pub),
    recipient: tx.to,
    amount: Number(amount),
    fee: WAVES_FEE_WAVELETS,
    feeAssetId: null,
    timestamp: tx.timestamp,
    attachment: '',
    proofs: [base58.encode(proof)],
  };
  const res = await adapter.postBroadcast(tx.chainId, json);
  if (res.status === 200) {
    const ok = BroadcastOk.safeParse(JSON.parse(res.text));
    if (ok.success && ok.data.id !== txid)
      throw new Error('Node reported a different transaction id');
    return txid;
  }
  let detail = res.text.slice(0, 300);
  try {
    const parsed = BroadcastErr.parse(JSON.parse(res.text));
    if (parsed.message) detail = `error ${parsed.error ?? '?'}: ${parsed.message}`;
  } catch {
    // keep raw text
  }
  throw new Error(`Broadcast rejected: ${detail}`);
}

/** 'expired' only once the head block is past the staleness horizon. */
export async function wavesTransferStatus(
  adapter: WavesAdapter,
  tx: WavesTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const head = await adapter.withNode(tx.chainId, (call) =>
    call('/blocks/headers/last', z.object({ timestamp: z.number().int().nonnegative() })),
  );
  if (head.timestamp <= tx.timestamp + WAVES_TX_STALE_MS) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
