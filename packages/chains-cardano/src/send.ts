import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  CARDANO_PREPROD,
  cardanoAddressBytes,
  keyHash,
  type CardanoAdapter,
  type ProtocolParams,
  type Utxo,
} from './cardano.js';

/** Total ADA supply: no output can hold more. */
export const MAX_LOVELACE = 45_000_000_000_000_000n;
export const MAX_FEE = 1_000_000;
export const MAX_INPUTS = 40;
export const MAX_TTL_SLOTS = 86_400;
/** Slots are one second on preprod and mainnet: two hours to review and approve. */
const LIFETIME_SLOTS = 7_200;
/** Approval is refused this close to the TTL. */
const APPROVAL_MARGIN_SLOTS = 120;
const UTXO_ENTRY_OVERHEAD = 160n;
/** Witness set with one vkey witness, plus the 4-array header, `true` and `null`. */
const WITNESS_SET_LEN = 107;
const ENVELOPE_OVERHEAD = 1 + WITNESS_SET_LEN + 2;

const Lovelace = z.string().regex(/^[1-9][0-9]{0,16}$/);
const TestnetAddress = z.string().regex(/^addr_test1[02-9ac-hj-np-z]{50,110}$/);
export const CardanoInput = z.strictObject({
  txHash: z.string().regex(/^[0-9a-f]{64}$/),
  index: z.number().int().min(0).max(0xffffffff),
  lovelace: Lovelace,
});
export type CardanoInput = z.infer<typeof CardanoInput>;
export const CardanoTx = z.strictObject({
  chainId: z.literal(CARDANO_PREPROD),
  from: TestnetAddress,
  to: TestnetAddress,
  lovelace: Lovelace,
  inputs: z.array(CardanoInput).min(1).max(MAX_INPUTS),
  fee: z.number().int().min(1).max(MAX_FEE),
  ttl: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  builtSlot: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  minFeeA: z.number().int().min(1).max(1_000),
  minFeeB: z.number().int().min(1).max(1_000_000),
  coinsPerUtxoByte: z.number().int().min(1).max(100_000),
});
export type CardanoTx = z.infer<typeof CardanoTx>;

class Cbor {
  private readonly bytes: number[] = [];
  head(major: number, n: bigint | number): this {
    const v = BigInt(n);
    const m = major << 5;
    if (v < 24n) this.bytes.push(m | Number(v));
    else if (v <= 0xffn) this.bytes.push(m | 24, Number(v));
    else if (v <= 0xffffn) this.bytes.push(m | 25, Number(v >> 8n), Number(v & 0xffn));
    else if (v <= 0xffffffffn) {
      this.bytes.push(m | 26);
      for (let s = 24n; s >= 0n; s -= 8n) this.bytes.push(Number((v >> s) & 0xffn));
    } else {
      this.bytes.push(m | 27);
      for (let s = 56n; s >= 0n; s -= 8n) this.bytes.push(Number((v >> s) & 0xffn));
    }
    return this;
  }
  uint(n: bigint | number): this {
    return this.head(0, n);
  }
  bytesOf(b: Uint8Array): this {
    this.head(2, b.length);
    this.bytes.push(...b);
    return this;
  }
  array(len: number): this {
    return this.head(4, len);
  }
  map(len: number): this {
    return this.head(5, len);
  }
  /** Conway's tag 258 marks an array as a set. */
  set(len: number): this {
    return this.head(6, 258).array(len);
  }
  raw(b: Uint8Array): this {
    this.bytes.push(...b);
    return this;
  }
  done(): Uint8Array {
    return Uint8Array.from(this.bytes);
  }
}

const outputBytes = (address: Uint8Array, lovelace: bigint) =>
  new Cbor().array(2).bytesOf(address).uint(lovelace).done();

const minUtxo = (output: Uint8Array, coinsPerUtxoByte: number) =>
  (UTXO_ENTRY_OVERHEAD + BigInt(output.length)) * BigInt(coinsPerUtxoByte);

interface RawBody {
  inputs: { txHash: string; index: number }[];
  outputs: Uint8Array[];
  fee: bigint;
  ttl: number;
}

function encodeBody(b: RawBody): Uint8Array {
  const w = new Cbor().map(4).uint(0).set(b.inputs.length);
  for (const i of b.inputs) w.array(2).bytesOf(hexToBytes(i.txHash)).uint(i.index);
  w.uint(1).array(b.outputs.length);
  for (const o of b.outputs) w.raw(o);
  return w.uint(2).uint(b.fee).uint(3).uint(b.ttl).done();
}

const minFeeFor = (body: Uint8Array, p: { minFeeA: number; minFeeB: number }) =>
  BigInt(p.minFeeA) * BigInt(body.length + ENVELOPE_OVERHEAD) + BigInt(p.minFeeB);

function compareInputs(a: { txHash: string; index: number }, b: { txHash: string; index: number }) {
  return a.txHash < b.txHash ? -1 : a.txHash > b.txHash ? 1 : a.index - b.index;
}

function lovelace(value: string, what: string): bigint {
  const n = BigInt(value);
  if (n <= 0n || n > MAX_LOVELACE || n.toString() !== value)
    throw new Error(`${what} must be a positive canonical lovelace amount`);
  return n;
}

export function cardanoChange(input: CardanoTx): bigint {
  const tx = CardanoTx.parse(input);
  const total = tx.inputs.reduce((s, i) => s + lovelace(i.lovelace, 'Input amount'), 0n);
  return total - lovelace(tx.lovelace, 'ADA amount') - BigInt(tx.fee);
}

/** The same body CBOR the core encodes independently from checked fields. */
export function cardanoTxBody(input: CardanoTx): Uint8Array {
  const tx = CardanoTx.parse(input);
  const from = cardanoAddressBytes(tx.from);
  const to = cardanoAddressBytes(tx.to);
  if (!from || !to || from.kind === 2) throw new Error('Invalid ADA sender or recipient');
  if (bytesToHex(from.raw) === bytesToHex(to.raw))
    throw new Error('Sender and recipient must differ');
  const amount = lovelace(tx.lovelace, 'ADA amount');
  for (let i = 1; i < tx.inputs.length; i++)
    if (compareInputs(tx.inputs[i - 1]!, tx.inputs[i]!) >= 0)
      throw new Error('Inputs must be unique and sorted');
  if (tx.ttl <= tx.builtSlot || tx.ttl - tx.builtSlot > MAX_TTL_SLOTS)
    throw new Error('ttl must fall within a day of the build slot');
  const change = cardanoChange(tx);
  if (change < 0n) throw new Error('Inputs do not cover amount plus fee');
  const payment = outputBytes(to.raw, amount);
  if (amount < minUtxo(payment, tx.coinsPerUtxoByte))
    throw new Error('Amount is below the minimum UTxO value');
  const outputs = [payment];
  if (change > 0n) {
    const back = outputBytes(from.raw, change);
    if (change < minUtxo(back, tx.coinsPerUtxoByte))
      throw new Error('Change is below the minimum UTxO value');
    outputs.push(back);
  }
  const body = encodeBody({ inputs: tx.inputs, outputs, fee: BigInt(tx.fee), ttl: tx.ttl });
  if (BigInt(tx.fee) < minFeeFor(body, tx)) throw new Error('Fee is below the protocol minimum');
  return body;
}

export function cardanoTxIdBytes(tx: CardanoTx): Uint8Array {
  return blake2b(cardanoTxBody(tx), { dkLen: 32 });
}

export function cardanoTxId(tx: CardanoTx): string {
  return bytesToHex(cardanoTxIdBytes(tx));
}

/** UTxOs this adapter may spend: ADA only, no reference script, held by exactly `from`. */
export function spendableUtxos(utxos: Utxo[], from: string): Utxo[] {
  return utxos
    .filter(
      (u) =>
        u.receiver === from && u.assets.length === 0 && u.script_ref == null && u.amount !== '0',
    )
    .sort((a, b) => {
      const d = BigInt(b.amount) - BigInt(a.amount);
      return d > 0n
        ? 1
        : d < 0n
          ? -1
          : compareInputs(
              { txHash: a.tx_hash, index: a.tx_index },
              { txHash: b.tx_hash, index: b.tx_index },
            );
    });
}

export interface Selection {
  inputs: CardanoInput[];
  fee: number;
  change: bigint;
  /** Lovelace above the minimum fee that was too small for a change output. */
  absorbed: bigint;
}

/**
 * Largest-first selection. A change output is added when it can meet the
 * min-UTxO rule; otherwise a remainder smaller than a change output is paid
 * as fee (bounded by `MAX_FEE`), or another input is taken.
 */
export function selectInputs(
  utxos: Utxo[],
  from: string,
  to: string,
  amount: bigint,
  params: ProtocolParams,
  ttl: number,
): Selection {
  const fromRaw = cardanoAddressBytes(from)?.raw;
  const toRaw = cardanoAddressBytes(to)?.raw;
  if (!fromRaw || !toRaw) throw new Error('Invalid ADA sender or recipient');
  const pool = spendableUtxos(utxos, from);
  const payment = outputBytes(toRaw, amount);
  if (amount < minUtxo(payment, params.coinsPerUtxoByte))
    throw new Error(
      `Cardano outputs must hold at least ${minUtxo(payment, params.coinsPerUtxoByte)} lovelace`,
    );
  for (let k = 1; k <= Math.min(pool.length, MAX_INPUTS); k++) {
    const inputs = pool
      .slice(0, k)
      .map((u) => ({ txHash: u.tx_hash, index: u.tx_index, lovelace: u.amount }))
      .sort(compareInputs);
    const total = inputs.reduce((s, i) => s + BigInt(i.lovelace), 0n);
    if (total < amount) continue;
    // With a change output: settle the fee, whose own width can change the size.
    let fee = 0n;
    for (let n = 0; n < 4; n++) {
      const change = total - amount - fee;
      const outputs = [payment, outputBytes(fromRaw, change > 0n ? change : 1n)];
      const next = minFeeFor(encodeBody({ inputs, outputs, fee, ttl }), params);
      if (next === fee) break;
      fee = next;
    }
    const change = total - amount - fee;
    if (change >= minUtxo(outputBytes(fromRaw, change > 0n ? change : 1n), params.coinsPerUtxoByte))
      return { inputs, fee: Number(fee), change, absorbed: 0n };
    // Without one: everything above the amount is fee.
    const allFee = total - amount;
    if (allFee <= BigInt(MAX_FEE)) {
      const min = minFeeFor(encodeBody({ inputs, outputs: [payment], fee: allFee, ttl }), params);
      if (allFee >= min) return { inputs, fee: Number(allFee), change: 0n, absorbed: allFee - min };
    }
  }
  throw new Error('Spendable ADA does not cover the amount, fee and minimum change');
}

/** The most this address can send in one transfer with no change output. */
export function cardanoMaxSendable(
  utxos: Utxo[],
  from: string,
  to: string,
  params: ProtocolParams,
  ttl: number,
): bigint {
  const toRaw = cardanoAddressBytes(to)?.raw;
  if (!toRaw) throw new Error('Invalid ADA recipient');
  const inputs = spendableUtxos(utxos, from)
    .slice(0, MAX_INPUTS)
    .map((u) => ({ txHash: u.tx_hash, index: u.tx_index, lovelace: u.amount }))
    .sort(compareInputs);
  const total = inputs.reduce((s, i) => s + BigInt(i.lovelace), 0n);
  let fee = 0n;
  for (let n = 0; n < 4; n++) {
    const body = encodeBody({ inputs, outputs: [outputBytes(toRaw, total - fee)], fee, ttl });
    const next = minFeeFor(body, params);
    if (next === fee) break;
    fee = next;
  }
  const max = total - fee;
  return max > 0n && max >= minUtxo(outputBytes(toRaw, max), params.coinsPerUtxoByte) ? max : 0n;
}

export async function prepareCardano(
  adapter: CardanoAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: CardanoTx; simulation: Simulation }> {
  if (
    intent.chainId !== CARDANO_PREPROD ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${CARDANO_PREPROD}:native`
  )
    throw new Error('Only native ADA transfers on preprod are enabled');
  if (!cardanoAddressBytes(from) || !cardanoAddressBytes(intent.to))
    throw new Error('Invalid ADA sender or recipient');
  const amount = lovelace(intent.amount, 'ADA amount');
  const [tip, utxos, params] = await Promise.all([
    adapter.tip(intent.chainId),
    adapter.utxos(from, intent.chainId),
    adapter.protocolParams(intent.chainId),
  ]);
  const ttl = tip.globalSlot + LIFETIME_SLOTS;
  const sel = selectInputs(utxos, from, intent.to, amount, params, ttl);
  const unsigned = CardanoTx.parse({
    chainId: intent.chainId,
    from,
    to: intent.to,
    lovelace: intent.amount,
    inputs: sel.inputs,
    fee: sel.fee,
    ttl,
    builtSlot: tip.globalSlot,
    minFeeA: params.minFeeA,
    minFeeB: params.minFeeB,
    coinsPerUtxoByte: params.coinsPerUtxoByte,
  });
  if (cardanoTxBody(unsigned).length + ENVELOPE_OVERHEAD > params.maxTxSize)
    throw new Error('Transaction would exceed the maximum size');
  const warnings: Simulation['warnings'] = [];
  if (sel.absorbed > 0n)
    warnings.push({
      kind: 'other',
      message: `${sel.absorbed} lovelace left over was too small for a change output and is paid as fee.`,
    });
  const skipped = utxos.length - spendableUtxos(utxos, from).length;
  if (skipped > 0)
    warnings.push({
      kind: 'other',
      message: `${skipped} UTxO(s) holding native tokens or scripts were left untouched.`,
    });
  return {
    unsigned,
    simulation: {
      ok: true,
      assetDeltas: [
        { assetRef: intent.asset, amount: `-${intent.amount}` },
        { assetRef: intent.asset, amount: `-${unsigned.fee}` },
      ],
      fee: { assetRef: intent.asset, amount: String(unsigned.fee) },
      warnings,
    },
  };
}

/** Usable while the TTL is comfortably ahead and every input is still unspent at the sender. */
export async function cardanoApprovalValid(
  adapter: CardanoAdapter,
  tx: CardanoTx,
): Promise<boolean> {
  cardanoTxBody(tx);
  const [tip, utxos] = await Promise.all([
    adapter.tip(tx.chainId),
    adapter.utxos(tx.from, tx.chainId),
  ]);
  if (tip.globalSlot >= tx.ttl - APPROVAL_MARGIN_SLOTS) return false;
  const live = new Map(
    spendableUtxos(utxos, tx.from).map((u) => [`${u.tx_hash}#${u.tx_index}`, u]),
  );
  return tx.inputs.every((i) => live.get(`${i.txHash}#${i.index}`)?.amount === i.lovelace);
}

/** Ogmios `unknownOutputReferences`: an input is already spent (perhaps by this very transaction). */
const UNKNOWN_INPUTS = 3117;

/**
 * Broadcast only bytes that are exactly the ledger's transaction: this body,
 * one vkey witness whose key hashes to the sender's payment credential and
 * whose signature verifies over the tx id, `true` and no auxiliary data.
 */
export async function broadcastCardano(
  adapter: CardanoAdapter,
  tx: CardanoTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== CARDANO_PREPROD) throw new Error('Only preprod broadcasts are enabled');
  const body = cardanoTxBody(tx);
  const prefix = new Cbor().array(4).raw(body).map(1).uint(0).set(1).array(2).head(2, 32).done();
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  const expected = bytesToHex(prefix);
  // vkey(32) || 0x5840 || signature(64) || true || null
  if (
    !/^[0-9a-f]+$/.test(hex) ||
    hex.length !== expected.length + 2 * (32 + 2 + 64 + 2) ||
    !hex.startsWith(expected) ||
    !hex.endsWith('f5f6')
  )
    throw new Error('Signed bytes are not this ADA transfer');
  const bytes = hexToBytes(hex);
  const vkey = bytes.subarray(prefix.length, prefix.length + 32);
  const sigHead = bytes.subarray(prefix.length + 32, prefix.length + 34);
  const sig = bytes.subarray(prefix.length + 34, prefix.length + 98);
  const payment = cardanoAddressBytes(tx.from)!.payment;
  if (
    sigHead[0] !== 0x58 ||
    sigHead[1] !== 0x40 ||
    bytesToHex(keyHash(vkey)) !== bytesToHex(payment)
  )
    throw new Error('Witness key is not the sender');
  const id = cardanoTxIdBytes(tx);
  if (!ed25519.verify(sig, id, vkey, { zip215: false }))
    throw new Error('Signature does not verify against the sender');
  const hash = bytesToHex(id);
  const res = await adapter.submit(tx.chainId, hex);
  if (res.id !== undefined) {
    if (res.id !== hash) throw new Error('Node reported a different transaction id');
    return hash;
  }
  if (res.error?.code === UNKNOWN_INPUTS) {
    // A retry of an accepted transfer finds its own inputs spent.
    const status = await adapter.status(hash, tx.chainId);
    if (status.state === 'confirmed' || status.state === 'pending') return hash;
  }
  throw new Error(
    `Broadcast rejected: ${res.error?.code ?? ''} ${res.error?.message ?? ''}`.slice(0, 512),
  );
}

/**
 * Expiry is reported once the tip passed the TTL, or an input was spent by
 * something else, and the hash is still absent from the indexer.
 */
export async function cardanoTransferStatus(
  adapter: CardanoAdapter,
  tx: CardanoTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const [tip, utxos] = await Promise.all([
    adapter.tip(tx.chainId),
    adapter.utxos(tx.from, tx.chainId),
  ]);
  const live = new Set(utxos.map((u) => `${u.tx_hash}#${u.tx_index}`));
  const dead =
    tip.globalSlot > tx.ttl || tx.inputs.some((i) => !live.has(`${i.txHash}#${i.index}`));
  if (!dead) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
