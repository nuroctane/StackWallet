import { secp256k1 } from '@noble/curves/secp256k1.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { HttpError, type Simulation, type TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  ALEPHIUM_TESTNET,
  SubmitResult,
  Utxos,
  alphAddressFromPublicKey,
  alphAddressBytes,
  isValidAlphAddress,
  type AlephiumAdapter,
} from './alephium.js';

/** Mirrors the core's `AlephiumTx`; the lead copies this into `@stackwallet/core-client`. */
export const AlephiumTx = z.strictObject({
  chainId: z.literal(ALEPHIUM_TESTNET),
  from: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{30,50}$/),
  publicKey: z.string().regex(/^0[23][0-9a-f]{64}$/),
  to: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{30,50}$/),
  attoalph: z.string().regex(/^[1-9][0-9]{0,38}$/),
  change: z.string().regex(/^[1-9][0-9]{0,38}$/),
  inputs: z
    .array(
      z.strictObject({
        hint: z.number().int().min(-0x80000000).max(0x7fffffff),
        key: z.string().regex(/^[0-9a-f]{64}$/),
      }),
    )
    .min(1)
    .max(64),
  gasAmount: z.number().int().min(20_000).max(5_000_000),
  gasPrice: z.string().regex(/^[1-9][0-9]{10,17}$/),
});
export type AlephiumTx = z.infer<typeof AlephiumTx>;

/** Smallest spendable output (0.001 ALPH). */
export const ALPH_DUST = 10n ** 15n;
export const ALPH_GAS_AMOUNT = 20_000;
export const ALPH_GAS_PRICE = 10n ** 11n;
const MIN_GAS_PRICE = 10n ** 11n;
const MAX_GAS_PRICE = 10n ** 18n;
const MAX_AMOUNT = (1n << 128n) - 1n;
const NETWORK_ID_TESTNET = 1;

/** Alephium's signed compact int (i32 codec), non-negative values only. */
function i32Compact(value: number): number[] {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error('i32 codec takes non-negative ints');
  if (value < 0x20) return [value];
  if (value < 0x2000) return [0x40 | (value >> 8), value & 0xff];
  if (value < 0x2000_0000)
    return [0x80 | (value >> 24), (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
  if (value < 0x1_0000_0000)
    return [0xc0, (value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
  throw new Error('i32 codec takes values under 2^32');
}

/** Alephium's unsigned compact int (u256 codec). */
function u256Compact(value: bigint): number[] {
  if (value < 0n || value > MAX_AMOUNT) throw new Error('u256 value out of range');
  if (value < 0x40n) return [Number(value)];
  if (value < 0x4000n) return [0x40 | Number(value >> 8n), Number(value & 0xffn)];
  if (value < 0x4000_0000n)
    return [
      0x80 | Number(value >> 24n),
      Number((value >> 16n) & 0xffn),
      Number((value >> 8n) & 0xffn),
      Number(value & 0xffn),
    ];
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = hexToBytes(hex);
  return [0xc0 + (body.length - 4), ...body];
}

function checked(input: AlephiumTx) {
  const tx = AlephiumTx.parse(input);
  const from = alphAddressBytes(tx.from);
  const to = alphAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid ALPH sender or recipient');
  const value = BigInt(tx.attoalph);
  const change = BigInt(tx.change);
  const gasPrice = BigInt(tx.gasPrice);
  if (value < ALPH_DUST || change < ALPH_DUST)
    throw new Error('ALPH amounts must cover the 0.001 ALPH dust minimum');
  if (gasPrice < MIN_GAS_PRICE || gasPrice > MAX_GAS_PRICE)
    throw new Error('ALPH gas price outside the allowed band');
  if (BigInt(tx.gasAmount) * gasPrice + value + change > MAX_AMOUNT)
    throw new Error('ALPH total is out of range');
  const publicKey = hexToBytes(tx.publicKey);
  if (alphAddressFromPublicKey(publicKey) !== tx.from)
    throw new Error('Public key is not the sender');
  return { tx, from, to, value, change, gasPrice, publicKey };
}

/** The same `UnsignedTx` bytes the core encodes independently from checked fields. */
export function encodeAlphUnsignedTx(input: AlephiumTx): Uint8Array {
  const { tx, from, to, value, change, gasPrice, publicKey } = checked(input);
  const out: number[] = [0x00, NETWORK_ID_TESTNET, 0x00]; // version, network, no script
  out.push(...i32Compact(tx.gasAmount), ...u256Compact(gasPrice));
  out.push(...i32Compact(tx.inputs.length));
  for (const input of tx.inputs)
    out.push(
      (input.hint >>> 24) & 0xff,
      (input.hint >>> 16) & 0xff,
      (input.hint >>> 8) & 0xff,
      input.hint & 0xff,
      ...hexToBytes(input.key),
      0x00, // unlock script: P2PKH
      ...publicKey,
    );
  out.push(...i32Compact(2));
  for (const [hash, amount] of [
    [to, value],
    [from, change],
  ] as const) {
    out.push(...u256Compact(amount), 0x00, ...hash.subarray(1)); // lockup: P2PKH
    out.push(0, 0, 0, 0, 0, 0, 0, 0); // lockTime 0
    out.push(0x00, 0x00); // no tokens, empty additional data
  }
  return Uint8Array.from(out);
}

/** blake2b-256 of the unsigned bytes: the transaction id and the sighash. */
export function alphTxId(tx: AlephiumTx): string {
  return bytesToHex(blake2b(encodeAlphUnsignedTx(tx), { dkLen: 32 }));
}

export interface PrepareAlphOptions {
  now?: number;
}

export async function prepareAlph(
  adapter: AlephiumAdapter,
  intent: TxIntent,
  from: string,
  publicKey: string,
  opts: PrepareAlphOptions = {},
): Promise<{ unsigned: AlephiumTx; simulation: Simulation }> {
  if (
    intent.chainId !== ALEPHIUM_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${ALEPHIUM_TESTNET}:native`
  )
    throw new Error('Only native ALPH transfers on Alephium testnet are enabled');
  if (!isValidAlphAddress(from) || !isValidAlphAddress(intent.to))
    throw new Error('Invalid Alephium address');
  const value = BigInt(intent.amount);
  const fee = BigInt(ALPH_GAS_AMOUNT) * ALPH_GAS_PRICE;
  const now = opts.now ?? Date.now();
  return adapter.withNode(intent.chainId, async (node) => {
    const { utxos } = await node.get(`/addresses/${from}/utxos`, Utxos);
    const warnings: Simulation['warnings'] = [];
    const spendable = utxos.filter((u) => {
      if ((u.tokens?.length ?? 0) > 0) return false; // spending these would move tokens
      if ((u.lockTime ?? 0) > now) return false;
      return true;
    });
    const skipped = utxos.length - spendable.length;
    if (skipped > 0)
      warnings.push({
        kind: 'other',
        message: `${skipped} timelocked or token-carrying UTXO(s) were left unspent.`,
      });
    // Ascending order keeps the change close to the dust bound.
    const sorted = [...spendable].sort((a, b) =>
      BigInt(a.amount) < BigInt(b.amount) ? -1 : BigInt(a.amount) > BigInt(b.amount) ? 1 : 0,
    );
    const inputs: { hint: number; key: string }[] = [];
    let total = 0n;
    for (const utxo of sorted) {
      if (total >= value + fee + ALPH_DUST) break;
      inputs.push({ hint: utxo.ref.hint, key: utxo.ref.key });
      total += BigInt(utxo.amount);
    }
    const change = total - value - fee;
    const fields = {
      chainId: intent.chainId,
      from,
      publicKey: publicKey.toLowerCase(),
      to: intent.to,
      attoalph: intent.amount,
      change: change.toString(),
      inputs,
      gasAmount: ALPH_GAS_AMOUNT,
      gasPrice: ALPH_GAS_PRICE.toString(),
    };
    let error: string | undefined;
    if (inputs.length === 0 && spendable.length === 0)
      error = 'No spendable ALPH UTXOs (all empty, timelocked or token-carrying)';
    else if (change < ALPH_DUST)
      error =
        'Balance does not cover the transfer, the fee and a dust-sized change; sending the exact balance is not supported yet';
    // A failed selection leaves no signable transaction; do not pretend one parses.
    const unsigned = (error === undefined ? AlephiumTx.parse(fields) : fields) as AlephiumTx;
    if (error === undefined) encodeAlphUnsignedTx(unsigned);
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee}` },
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Approval is refused once any input UTXO is gone or became timelocked again. */
export async function alphApprovalValid(
  adapter: AlephiumAdapter,
  tx: AlephiumTx,
): Promise<boolean> {
  const wanted = new Set(AlephiumTx.parse(tx).inputs.map((i) => i.key));
  const now = Date.now();
  try {
    const { utxos } = await adapter.withNode(tx.chainId, (node) =>
      node.get(`/addresses/${tx.from}/utxos`, Utxos),
    );
    const live = new Map(utxos.map((u) => [u.ref.key, u] as const));
    for (const key of wanted) {
      const utxo = live.get(key);
      if (!utxo || (utxo.lockTime ?? 0) > now || (utxo.tokens?.length ?? 0) > 0) return false;
    }
    return true;
  } catch {
    return false;
  }
}

export class BroadcastRejected extends Error {
  override readonly name = 'BroadcastRejected';
  constructor(reason: string) {
    super(`Broadcast rejected: ${reason}`.trim());
  }
}

/**
 * Broadcast only bytes that are exactly the ledger's transfer plus one 64-byte
 * low-S ECDSA signature by its sender; the node wants `{unsignedTx, signature}`.
 */
export async function broadcastAlph(
  adapter: AlephiumAdapter,
  tx: AlephiumTx,
  wireHex: string,
): Promise<string> {
  if (tx.chainId !== ALEPHIUM_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const { publicKey } = checked(tx);
  const unsigned = bytesToHex(encodeAlphUnsignedTx(tx));
  // Signed `Transaction` tail: scriptExecutionOk, no contract inputs, no
  // generated outputs, one 64-byte input signature, no script signatures.
  const prefix = `${unsigned}010000014040`;
  const hex = wireHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== prefix.length + 128 + 2 || !hex.startsWith(prefix))
    throw new Error('Signed bytes are not this ALPH transfer');
  if (!hex.endsWith('00')) throw new Error('Signed bytes are not this ALPH transfer');
  const sigHex = hex.slice(prefix.length, prefix.length + 128);
  const id = alphTxId(tx);
  const sig = secp256k1.Signature.fromBytes(hexToBytes(sigHex), 'compact');
  if (sig.hasHighS()) throw new Error('Signature is not low-S');
  // The sighash is the tx id itself; nothing is hashed again.
  if (!secp256k1.verify(sig.toBytes('compact'), hexToBytes(id), publicKey, { prehash: false }))
    throw new Error('Transfer is not signed by its sender');
  const outcome = await adapter.withNode(tx.chainId, async (node) => {
    try {
      return {
        result: await node.post(
          '/transactions/submit',
          { unsignedTx: unsigned, signature: sigHex },
          SubmitResult,
        ),
      };
    } catch (err) {
      // A 4xx is the network's verdict on the transaction, not a broken endpoint.
      if (err instanceof HttpError && err.status >= 400 && err.status < 500)
        return { rejected: err.body.replace(/[^\x20-\x7e]/g, '').slice(0, 300) };
      throw err;
    }
  });
  if ('rejected' in outcome) {
    // A retry of an accepted transfer is not a failure.
    if (/already|duplicate|mempool/i.test(outcome.rejected)) return id;
    throw new BroadcastRejected(outcome.rejected);
  }
  if (outcome.result.txId !== id) throw new Error('Node reported a different transaction id');
  return id;
}

/** UTXO transactions never expire; an unknown id means the tx was dropped or never landed. */
export async function alphTransferStatus(
  adapter: AlephiumAdapter,
  tx: AlephiumTx,
  hash: string,
): Promise<TxStatus> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  // If a prepared input was spent by another transaction this transfer can never land.
  try {
    const { utxos } = await adapter.withNode(tx.chainId, (node) =>
      node.get(`/addresses/${tx.from}/utxos`, Utxos),
    );
    const live = new Set(utxos.map((u) => u.ref.key));
    if (tx.inputs.some((i) => !live.has(i.key)))
      return { state: 'failed', reason: 'An input UTXO was spent by another transaction' };
  } catch {
    // Keep the node's answer when the UTXO lookup fails.
  }
  return status;
}
