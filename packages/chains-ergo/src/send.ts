/**
 * Prepare / approve / broadcast for native ERG transfers. The unsigned fields
 * are exactly what `ergo.rs` checks; the serialized bytes here are pinned to
 * the same vector as the core so `broadcastErgo` can prove a signed wire
 * carries this transfer and nothing else.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { HttpError, type Simulation, type TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  BoxInfo,
  BoxesPage,
  ERGO_TESTNET,
  FEE_CONTRACT,
  blake2b256,
  ergoAddressBytes,
  ergoP2pkTree,
  type ErgoAdapter,
} from './ergo.js';

/** The minimum spendable box value; also the network minimum fee. */
export const ERGO_MIN_BOX_NANOERG = 1_000_000n;
export const ERGO_FEE_NANOERG = 1_000_000n;
const MAX_FEE_NANOERG = 10_000_000n;
const MAX_INPUTS = 16;
const MAX_HEIGHT = 100_000_000;
const I64_MAX = 0x7fffffffffffffffn;
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

/**
 * Mirrors the Rust `ErgoTx` struct (`crates/stackwallet-core/src/ergo.rs`).
 * The core-client copy is wired by the lead; keep the two identical.
 */
export const ErgoTx = z.strictObject({
  chainId: z.literal(ERGO_TESTNET),
  from: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{51,52}$/),
  to: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{51,52}$/),
  nanoerg: z.string().regex(/^[1-9]\d{0,18}$/),
  inputs: z
    .array(z.string().regex(/^[0-9a-f]{64}$/))
    .min(1)
    .max(MAX_INPUTS),
  change: z.string().regex(/^[1-9]\d{0,18}$/),
  fee: z.string().regex(/^[1-9]\d{0,7}$/),
  height: z.number().int().min(1).max(MAX_HEIGHT),
});
export type ErgoTx = z.infer<typeof ErgoTx>;

function putVlq(out: number[], value: bigint): void {
  let v = value;
  for (;;) {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
    if (v === 0n) return;
  }
}

function putBox(out: number[], value: bigint, ergoTree: string, height: number): void {
  putVlq(out, value);
  for (const b of hexToBytes(ergoTree)) out.push(b);
  putVlq(out, BigInt(height));
  out.push(0); // no tokens
  out.push(0); // no registers
}

/** The same unsigned transaction bytes the core encodes from checked fields. */
export function serializeUnsignedErgoTx(input: ErgoTx): Uint8Array {
  const tx = ErgoTx.parse(input);
  if (tx.chainId !== ERGO_TESTNET) throw new Error('Only Ergo testnet transfers are enabled');
  const from = ergoAddressBytes(tx.from);
  const to = ergoAddressBytes(tx.to);
  if (!from || !to || from[0] !== 0x11 || to[0] !== 0x11)
    throw new Error('Invalid testnet P2PK sender or recipient');
  const amount = BigInt(tx.nanoerg);
  const change = BigInt(tx.change);
  const fee = BigInt(tx.fee);
  if (
    amount < ERGO_MIN_BOX_NANOERG ||
    change < ERGO_MIN_BOX_NANOERG ||
    amount + change + fee > I64_MAX
  )
    throw new Error('Invalid ERG amount or change');
  if (fee < ERGO_FEE_NANOERG || fee > MAX_FEE_NANOERG) throw new Error('Invalid ERG fee');
  if (new Set(tx.inputs).size !== tx.inputs.length) throw new Error('Duplicate input box');
  const out: number[] = [];
  putVlq(out, BigInt(tx.inputs.length));
  for (const id of tx.inputs) {
    for (const b of hexToBytes(id)) out.push(b);
    out.push(0, 0); // empty proof, empty extension
  }
  putVlq(out, 0n); // no data inputs
  putVlq(out, 0n); // no distinct token ids
  putVlq(out, 3n); // recipient, change, fee
  putBox(out, amount, ergoP2pkTree(to.subarray(1)), tx.height);
  putBox(out, change, ergoP2pkTree(from.subarray(1)), tx.height);
  putBox(out, fee, FEE_CONTRACT, tx.height);
  return Uint8Array.from(out);
}

/** The transaction id: blake2b256 of the unsigned bytes (proofs never count). */
export function ergoTxId(tx: ErgoTx): string {
  return bytesToHex(blake2b256(serializeUnsignedErgoTx(tx)));
}

/**
 * Pick plain-ERG P2PK boxes of the sender until `amount + fee + min change`
 * is covered. Token-carrying or scripted boxes are never touched.
 */
export async function prepareErgo(
  adapter: ErgoAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: ErgoTx; simulation: Simulation }> {
  if (
    intent.chainId !== ERGO_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${ERGO_TESTNET}:native`
  )
    throw new Error('Only native ERG transfers on testnet are enabled');
  const fromBytes = ergoAddressBytes(from);
  if (!fromBytes || fromBytes[0] !== 0x11) throw new Error('Invalid testnet sender address');
  const senderTree = ergoP2pkTree(fromBytes.subarray(1));
  const amount = BigInt(intent.amount);
  if (amount < ERGO_MIN_BOX_NANOERG || amount.toString() !== intent.amount)
    throw new Error('ERG amount must be a canonical integer of at least 0.001 ERG');

  return adapter.withExplorer(intent.chainId, async (call) => {
    const boxes: z.infer<typeof BoxesPage>['items'] = [];
    let offset = 0;
    // Page through the sender's unspent boxes; keep only clean P2PK ERG boxes.
    for (;;) {
      const page = await call(
        `/api/v1/boxes/unspent/byAddress/${from}?limit=100&offset=${offset}`,
        BoxesPage,
      );
      boxes.push(...page.items);
      offset += page.items.length;
      if (offset >= page.total || page.items.length === 0) break;
    }
    const usable = boxes
      .filter(
        (b) =>
          b.ergoTree === senderTree &&
          b.assets.length === 0 &&
          Object.keys(b.additionalRegisters).length === 0,
      )
      .sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
    const picked: typeof usable = [];
    let sum = 0n;
    const needed = () => amount + ERGO_FEE_NANOERG + ERGO_MIN_BOX_NANOERG;
    for (const box of usable) {
      if (picked.length >= MAX_INPUTS) break;
      if (sum >= needed()) break;
      picked.push(box);
      sum += BigInt(box.value);
    }
    const { height } = await adapter.height(intent.chainId);
    const change = sum - amount - ERGO_FEE_NANOERG;
    let error: string | undefined;
    if (picked.length === 0 && usable.length === 0)
      error = 'Sender has no plain-ERG P2PK boxes on testnet';
    else if (change < ERGO_MIN_BOX_NANOERG)
      error = `Balance does not cover the amount, the 0.001 ERG fee and the minimum change (0.001 ERG)`;
    const unsigned = ErgoTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      nanoerg: intent.amount,
      inputs: picked.map((b) => b.boxId),
      change: error === undefined ? change.toString() : ERGO_MIN_BOX_NANOERG.toString(),
      fee: ERGO_FEE_NANOERG.toString(),
      height,
    });
    const warnings: Simulation['warnings'] = [];
    const skipped = boxes.length - usable.length;
    if (skipped > 0)
      warnings.push({
        kind: 'other',
        message: `${skipped} box(es) holding tokens or scripts are left untouched.`,
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${ERGO_FEE_NANOERG}` },
        ],
        fee: { assetRef: intent.asset, amount: ERGO_FEE_NANOERG.toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Approval stays valid while every input box is still in the UTXO set. */
export async function ergoApprovalValid(adapter: ErgoAdapter, tx: ErgoTx): Promise<boolean> {
  ErgoTx.parse(tx);
  try {
    return await adapter.withNode(tx.chainId, async (call) => {
      for (const id of tx.inputs) {
        try {
          await call(`/utxo/byId/${id}`, z.unknown());
        } catch {
          return false;
        }
      }
      return true;
    });
  } catch {
    // No node endpoint: fall back to the explorer's spent marker.
    return adapter.withExplorer(tx.chainId, async (call) => {
      for (const id of tx.inputs) {
        const box = await call(`/api/v1/boxes/${id}`, BoxInfo);
        if (box.spentTransactionId) return false;
      }
      return true;
    });
  }
}

const SignedWire = z.object({
  id: z.string().regex(/^[0-9a-f]{64}$/),
  inputs: z
    .array(
      z.object({
        boxId: z.string().regex(/^[0-9a-f]{64}$/),
        spendingProof: z.object({
          proofBytes: z.string().regex(/^[0-9a-f]{112}$/),
          extension: z.record(z.string(), z.string()),
        }),
      }),
    )
    .min(1)
    .max(MAX_INPUTS),
  dataInputs: z.array(z.unknown()).max(0),
  outputs: z
    .array(
      z.object({
        value: SafeInt,
        ergoTree: z
          .string()
          .regex(/^[0-9a-f]+$/)
          .max(4096),
        creationHeight: SafeInt,
        assets: z.array(z.unknown()).max(0),
        additionalRegisters: z.record(z.string(), z.string()),
      }),
    )
    .length(3),
});
export type ErgoSignedWire = z.infer<typeof SignedWire>;

/** Broadcast only a wire that is exactly this transfer plus one proof per input. */
export async function broadcastErgo(
  adapter: ErgoAdapter,
  tx: ErgoTx,
  signedWire: string,
): Promise<string> {
  const parsed = ErgoTx.parse(tx);
  const id = ergoTxId(parsed);
  let wire: ErgoSignedWire;
  try {
    wire = SignedWire.parse(JSON.parse(signedWire));
  } catch {
    throw new Error('Signed payload is not an Ergo EIP-12 transaction');
  }
  if (wire.id !== id) throw new Error('Signed bytes are not this ERG transfer');
  if (wire.inputs.map((i) => i.boxId).join(',') !== parsed.inputs.join(','))
    throw new Error('Signed bytes spend different boxes');
  const from = ergoAddressBytes(parsed.from)!;
  const to = ergoAddressBytes(parsed.to)!;
  const expectedOutputs = [
    { value: Number(BigInt(parsed.nanoerg)), ergoTree: ergoP2pkTree(to.subarray(1)) },
    { value: Number(BigInt(parsed.change)), ergoTree: ergoP2pkTree(from.subarray(1)) },
    { value: Number(BigInt(parsed.fee)), ergoTree: FEE_CONTRACT },
  ];
  for (const [i, expected] of expectedOutputs.entries()) {
    const out = wire.outputs[i]!;
    if (
      out.value !== expected.value ||
      out.ergoTree !== expected.ergoTree ||
      out.creationHeight !== parsed.height ||
      out.assets.length > 0 ||
      Object.keys(out.additionalRegisters).length > 0
    )
      throw new Error('Signed bytes pay different outputs');
  }
  for (const input of wire.inputs)
    if (Object.keys(input.spendingProof.extension).length > 0)
      throw new Error('Signed bytes carry context extensions');

  const ErrorBody = z.object({
    error: SafeInt.optional(),
    reason: z.string().max(256).optional(),
    detail: z.string().max(4096).nullable().optional(),
  });
  // Public full nodes are HTTP-only, so browser bundles cannot reach them;
  // the explorer's mempool submit endpoint is HTTPS and relays to the network.
  // It does not validate, which is safe here: the wire is byte-verified above
  // and a mismatched or dropped id is caught below and by status polling.
  let text: string;
  try {
    try {
      text = await adapter.postExplorer(
        parsed.chainId,
        '/api/v1/mempool/transactions/submit',
        wire,
      );
    } catch (err) {
      if (err instanceof HttpError) throw err;
      text = await adapter.postNode(parsed.chainId, '/transactions', wire);
    }
  } catch (err) {
    if (err instanceof HttpError) {
      let detail = err.body;
      try {
        const body = ErrorBody.parse(JSON.parse(err.body));
        detail = `${body.reason ?? 'error'} ${body.detail ?? ''}`.trim();
      } catch {
        // keep the raw body
      }
      throw new Error(`Broadcast rejected: ${detail}`.slice(0, 512));
    }
    throw err;
  }
  const res = z
    .union([
      z.string().regex(/^[0-9a-f]{64}$/),
      z.object({ id: z.string().regex(/^[0-9a-f]{64}$/) }),
      ErrorBody,
    ])
    .parse(JSON.parse(text));
  if (typeof res !== 'string' && !('id' in res))
    throw new Error(
      `Broadcast rejected: ${res.reason ?? 'error'} ${res.detail ?? ''}`.trim().slice(0, 512),
    );
  const reported = typeof res === 'string' ? res : res.id;
  if (reported !== id) throw new Error('Node reported a different transaction id');
  return id;
}

/** Ergo transactions do not expire; they fail only when inputs are spent. */
export async function ergoTransferStatus(
  adapter: ErgoAdapter,
  tx: ErgoTx,
  hash: string,
): Promise<TxStatus> {
  if (hash !== ergoTxId(ErgoTx.parse(tx))) throw new Error('Hash is not this transfer');
  return adapter.status(hash, tx.chainId);
}
