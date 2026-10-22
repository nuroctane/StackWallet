import { schnorr } from '@noble/curves/secp256k1.js';
import { Transaction } from 'bitcoinjs-lib';
import { BitcoinTx, type TxIntent } from '@stackwallet/core-client';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import { z } from 'zod';
import { decodeSegwit, type BitcoinAdapter } from './bitcoin.js';

export const BITCOIN_SIGNET = 'bip122:00000008819873e925422c1ff0f99f7c';
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const Sats = z.number().int().nonnegative().max(2_100_000_000_000_000);
const Height = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Status = z.object({ confirmed: z.boolean(), block_height: Height.optional() });
const Utxos = z
  .array(
    z.object({
      txid: Hash,
      vout: z.number().int().nonnegative().max(0xffffffff),
      value: Sats,
      status: Status,
    }),
  )
  .max(10000);
const Outspend = z.object({ spent: z.boolean(), txid: Hash.optional() });
const Hex = z
  .string()
  .regex(/^(?:[0-9a-f]{2})+$/)
  .max(400000);

export const BitcoinPrepareOptions = z
  .object({
    inputs: z
      .array(z.object({ txid: Hash, vout: z.number().int().min(0).max(0xffffffff) }).strict())
      .min(1)
      .max(8)
      .optional(),
    feeRate: z.number().int().min(1).max(100).optional(),
  })
  .strict();
export type BitcoinPrepareOptions = z.infer<typeof BitcoinPrepareOptions>;
export type BitcoinCoin = z.infer<typeof Utxos>[number];

function uniqueCoins(coins: BitcoinCoin[]): BitcoinCoin[] {
  const seen = new Set<string>();
  for (const coin of coins) {
    const key = `${coin.txid}:${coin.vout}`;
    if (seen.has(key)) throw new Error('Duplicate UTXO response');
    seen.add(key);
  }
  return coins.sort((a, b) => b.value - a.value || a.txid.localeCompare(b.txid) || a.vout - b.vout);
}

/** Public endpoint observations are refreshed and fully validated again during preparation. */
export async function readBitcoinCoins(
  adapter: BitcoinAdapter,
  from: string,
): Promise<BitcoinCoin[]> {
  if (!signetSender(from)) throw new Error('Only Signet P2WPKH and P2TR senders are enabled');
  return adapter.withSignet(BITCOIN_SIGNET, async (query) => {
    const coins = await query(`/address/${from}/utxo`, Utxos);
    if (!coins) throw new Error('UTXO endpoint unavailable');
    return uniqueCoins(coins);
  });
}

export function isSignetRecipient(text: string): boolean {
  return signetRecipient(text) !== null;
}
export function signetRecipient(text: string): {
  kind: 'P2WPKH' | 'P2WSH' | 'P2TR';
  dustSats: number;
  outputBytes: number;
} | null {
  const d = decodeSegwit(text);
  if (text !== text.toLowerCase() || d?.hrp !== 'tb') return null;
  if (d.version === 0 && d.program.length === 20)
    return { kind: 'P2WPKH', dustSats: 294, outputBytes: 31 };
  if (d.program.length === 32 && (d.version === 0 || d.version === 1))
    return { kind: d.version === 0 ? 'P2WSH' : 'P2TR', dustSats: 330, outputBytes: 43 };
  return null;
}
/**
 * Single keys spend P2WPKH; threshold (FROST) wallets spend a P2TR key path.
 * The figures mirror the core's fee and change bounds for each.
 */
export function signetSender(text: string): {
  kind: 'P2WPKH' | 'P2TR';
  inputVbytes: number;
  changeBytes: number;
  changeDustSats: number;
} | null {
  const d = decodeSegwit(text);
  if (text !== text.toLowerCase() || d?.hrp !== 'tb') return null;
  if (d.version === 0 && d.program.length === 20)
    return { kind: 'P2WPKH', inputVbytes: 69, changeBytes: 31, changeDustSats: 294 };
  // 41 non-witness bytes plus a 64-byte signature witness.
  if (d.version === 1 && d.program.length === 32)
    return { kind: 'P2TR', inputVbytes: 58, changeBytes: 43, changeDustSats: 330 };
  return null;
}
/**
 * The sender's scriptPubKey. bitcoinjs needs an ECC library to decode P2TR
 * addresses, so the witness program is laid out directly.
 */
function senderScript(from: string): Uint8Array {
  const d = decodeSegwit(from);
  if (!signetSender(from) || !d) throw new Error('Unsupported sender');
  return Uint8Array.from([d.version === 0 ? 0 : 0x50 + d.version, d.program.length, ...d.program]);
}
function funding(input: BitcoinTx['inputs'][number], from: string) {
  const previous = Transaction.fromHex(input.previousTxHex);
  if (previous.getId() !== input.txid || previous.isCoinbase())
    throw new Error('Invalid funding transaction');
  const output = previous.outs[input.vout];
  if (!output || !BufferlessEqual(output.script, senderScript(from)))
    throw new Error('Funding output differs from sender');
  return output.value;
}
function BufferlessEqual(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export async function prepareBitcoin(
  adapter: BitcoinAdapter,
  intent: TxIntent,
  from: string,
  options: BitcoinPrepareOptions = {},
): Promise<{ unsigned: BitcoinTx; simulation: Simulation }> {
  const requested = BitcoinPrepareOptions.parse(options);
  const requestedKeys = requested.inputs?.map((u) => `${u.txid}:${u.vout}`);
  if (requestedKeys && new Set(requestedKeys).size !== requestedKeys.length)
    throw new Error('Duplicate selected input');
  const sender = signetSender(from);
  if (
    intent.chainId !== BITCOIN_SIGNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${BITCOIN_SIGNET}:native` ||
    !sender ||
    !isSignetRecipient(intent.to) ||
    intent.to === from
  )
    throw new Error(
      'Only Signet P2WPKH/P2TR senders and native SegWit/Taproot recipients are enabled',
    );
  const recipient = signetRecipient(intent.to)!;
  if (
    !/^[1-9][0-9]*$/.test(intent.amount) ||
    BigInt(intent.amount) < BigInt(recipient.dustSats) ||
    BigInt(intent.amount) > 2_100_000_000_000_000n
  )
    throw new Error('Invalid or dust satoshi amount');
  return adapter.withSignet(intent.chainId, async (query) => {
    const utxos = await query(`/address/${from}/utxo`, Utxos);
    const fees =
      requested.feeRate === undefined
        ? await query(
            '/v1/fees/recommended',
            z.object({ halfHourFee: z.number().int().min(1).max(100) }),
          )
        : { halfHourFee: requested.feeRate };
    if (!utxos || !fees) throw new Error('UTXO or fee endpoint unavailable');
    const available = uniqueCoins(utxos).filter((u) => u.status.confirmed);
    const candidates = requestedKeys
      ? requestedKeys.map((key) => {
          const coin = available.find((u) => `${u.txid}:${u.vout}` === key);
          if (!coin)
            throw new Error('Selected input is missing or unconfirmed; refresh coin control');
          return coin;
        })
      : available;
    const selected: BitcoinTx['inputs'] = [];
    const seen = new Set<string>();
    let total = 0n;
    let fee = 0n;
    for (const u of candidates) {
      const key = `${u.txid}:${u.vout}`;
      if (seen.has(key)) throw new Error('Duplicate UTXO response');
      seen.add(key);
      if (selected.length >= 8) break;
      const previousTxHex = await query(`/tx/${u.txid}/hex`, Hex, true);
      const spent = await query(`/tx/${u.txid}/outspend/${u.vout}`, Outspend);
      if (!previousTxHex || !spent) throw new Error('Cannot validate funding output');
      if (spent.spent) {
        if (requestedKeys) throw new Error('Selected input has been spent; refresh coin control');
        continue;
      }
      const input = { txid: u.txid, vout: u.vout, previousTxHex };
      const value = funding(input, from);
      if (value !== BigInt(u.value))
        throw new Error('UTXO amount differs from funding transaction');
      selected.push(input);
      total += value;
      fee =
        BigInt(
          11 + sender.inputVbytes * selected.length + sender.changeBytes + recipient.outputBytes,
        ) * BigInt(fees.halfHourFee);
      const change = total - BigInt(intent.amount) - fee;
      if (!requestedKeys && (change === 0n || change >= BigInt(sender.changeDustSats))) break;
    }
    const change = total - BigInt(intent.amount) - fee;
    if (
      !selected.length ||
      change < 0n ||
      (change > 0n && change < BigInt(sender.changeDustSats)) ||
      fee > 100000n
    )
      throw new Error(
        'Confirmed inputs cannot cover amount, fee and non-dust change within limits',
      );
    const unsigned = BitcoinTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      amount: intent.amount,
      fee: fee.toString(),
      inputs: selected,
    });
    return {
      unsigned,
      simulation: {
        ok: false,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee}` },
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings: [
          {
            kind: 'other',
            message: `Local funding validation only; no network simulation. ${selected.length} ${requestedKeys ? 'manually selected' : 'automatically selected'} input(s), ${fees.halfHourFee} sats/vB estimated fee rate, ${change} sats change to the sender. RBF signaled; replacement is not implemented.`,
          },
        ],
        error: 'Bitcoin network simulation is unavailable',
      },
    };
  });
}
/**
 * Build the BIP125 replacement of a broadcast transfer: the same inputs again,
 * either paying the same recipient with a higher fee (`speedUp`) or sweeping
 * everything back to the sender (`cancel`). The fee is the larger of the
 * current rate and the floor BIP125 relay demands (old fee plus 1 sat/vB of
 * the new size, at a strictly higher rate); the core rechecks all of it.
 */
export async function planBitcoinReplacement(
  adapter: BitcoinAdapter,
  original: { id: string; hash: string; unsigned: BitcoinTx },
  mode: 'speedUp' | 'cancel',
  feeRate?: number,
): Promise<{ unsigned: BitcoinTx; simulation: Simulation }> {
  const old = BitcoinTx.parse(original.unsigned);
  Hash.parse(original.hash);
  const sender = signetSender(old.from);
  if (!sender) throw new Error('Only Signet P2WPKH/P2TR transfers can be replaced');
  const to = mode === 'cancel' ? old.from : old.to;
  const recipient = signetRecipient(to);
  if (!recipient) throw new Error('Unsupported recipient');
  const size = (n: number, outputBytes: number) =>
    BigInt(11 + sender.inputVbytes * n + sender.changeBytes + outputBytes);
  const oldSize = size(old.inputs.length, signetRecipient(old.to)!.outputBytes);
  const newSize = size(old.inputs.length, recipient.outputBytes);
  return adapter.withSignet(old.chainId, async (query) => {
    const status = await query(`/tx/${original.hash}/status`, Status);
    if (!status) throw new Error('Cannot see the original transaction');
    if (status.confirmed) throw new Error('The original transaction already confirmed');
    for (const input of old.inputs) {
      const out = await query(`/tx/${input.txid}/outspend/${input.vout}`, Outspend);
      if (!out) throw new Error('Cannot verify input spend status');
      if (out.spent && out.txid !== original.hash)
        throw new Error('An input was spent by another transaction; refresh its status');
    }
    const rate =
      feeRate ??
      (
        await query(
          '/v1/fees/recommended',
          z.object({ fastestFee: z.number().int().min(1).max(100) }),
        )
      )?.fastestFee;
    if (rate === undefined) throw new Error('Fee endpoint unavailable');
    const oldFee = BigInt(old.fee);
    const floor = [oldFee + newSize, (oldFee * newSize) / oldSize + 1n].reduce((a, b) =>
      a > b ? a : b,
    );
    const fee = newSize * BigInt(rate) > floor ? newSize * BigInt(rate) : floor;
    if (fee > 100000n || fee > newSize * 100n)
      throw new Error('The replacement fee would exceed the 100 sat/vB or 100,000 sat limits');
    const total = old.inputs.reduce((sum, input) => sum + funding(input, old.from), 0n);
    const amount = mode === 'cancel' ? total - fee : BigInt(old.amount);
    const change = total - amount - fee;
    if (amount < BigInt(recipient.dustSats) || change < 0n)
      throw new Error('The inputs cannot cover a higher fee');
    if (change > 0n && change < BigInt(sender.changeDustSats))
      throw new Error('Raising the fee would leave dust change; cancel instead');
    const unsigned = BitcoinTx.parse({
      chainId: old.chainId,
      from: old.from,
      to,
      amount: amount.toString(),
      fee: fee.toString(),
      replaces: original.id,
      inputs: old.inputs,
    });
    return {
      unsigned,
      simulation: {
        ok: false,
        assetDeltas: [
          {
            assetRef: `${old.chainId}:native`,
            amount: `-${mode === 'cancel' ? fee : amount + fee}`,
          },
        ],
        fee: { assetRef: `${old.chainId}:native`, amount: fee.toString() },
        warnings: [
          {
            kind: 'other',
            message:
              mode === 'cancel'
                ? `Replaces ${original.hash}: every input returns to the sender minus a ${fee} sat fee. Whichever confirms first settles both.`
                : `Replaces ${original.hash} with the same payment at a ${fee} sat fee (was ${oldFee}). Whichever confirms first settles both.`,
          },
        ],
        error: 'Bitcoin network simulation is unavailable',
      },
    };
  });
}

/**
 * Whether every input is still spendable by `tx`. A replacement's inputs are
 * already spent by the transaction it replaces (`replacedHash`), which is the
 * point; a spend by anything else means it can never confirm.
 */
export async function bitcoinInputsUnspent(
  adapter: BitcoinAdapter,
  tx: BitcoinTx,
  replacedHash?: string,
): Promise<boolean> {
  return adapter.withSignet(tx.chainId, async (query) => {
    for (const input of tx.inputs) {
      const out = await query(`/tx/${input.txid}/outspend/${input.vout}`, Outspend);
      if (!out) throw new Error('Cannot verify input spend status');
      if (out.spent && !(replacedHash !== undefined && out.txid === replacedHash)) return false;
    }
    return true;
  });
}
/**
 * Check a threshold wallet's signed spend with bitcoinjs and noble rather than
 * the core that produced it: it spends exactly the proposed inputs, in order,
 * and every input carries one BIP340 signature that verifies against the
 * sender's output key over its own BIP341 sighash.
 */
export function verifyTaprootSpend(tx: BitcoinTx, raw: string): void {
  if (signetSender(tx.from)?.kind !== 'P2TR') throw new Error('Not a Taproot sender');
  const sender = senderScript(tx.from);
  const signed = Transaction.fromHex(raw.replace(/^0x/, ''));
  if (signed.ins.length !== tx.inputs.length) throw new Error('Signed inputs differ');
  const scripts: Uint8Array[] = [];
  const values: bigint[] = [];
  tx.inputs.forEach((input, i) => {
    const txin = signed.ins[i]!;
    const txid = Uint8Array.from(txin.hash).reverse();
    if (
      Array.from(txid, (b) => b.toString(16).padStart(2, '0')).join('') !== input.txid ||
      txin.index !== input.vout
    )
      throw new Error('Signed inputs differ');
    scripts.push(sender);
    values.push(funding(input, tx.from));
  });
  const outputKey = sender.slice(2);
  signed.ins.forEach((txin, i) => {
    const [sig, ...rest] = txin.witness;
    if (!sig || sig.length !== 64 || rest.length)
      throw new Error(`Input ${i} lacks a key-path signature`);
    const digest = signed.hashForWitnessV1(i, scripts, values, Transaction.SIGHASH_DEFAULT);
    if (!schnorr.verify(sig, digest, outputKey))
      throw new Error(`Input ${i} signature does not verify`);
  });
}

export async function broadcastBitcoin(
  adapter: BitcoinAdapter,
  tx: BitcoinTx,
  raw: string,
): Promise<string> {
  if (!/^0x(?:[0-9a-f]{2})+$/.test(raw) || raw.length > 20000)
    throw new Error('Invalid core transaction bytes');
  if (signetSender(tx.from)?.kind === 'P2TR') verifyTaprootSpend(tx, raw);
  return adapter.withSignet(tx.chainId, async (query) => {
    const hash = await query('/tx', Hash, true, raw.slice(2));
    if (!hash) throw new Error('Broadcast returned no hash');
    return hash;
  });
}
export async function bitcoinTransferStatus(
  adapter: BitcoinAdapter,
  tx: BitcoinTx,
  hash: string,
): Promise<TxStatus> {
  Hash.parse(hash);
  return adapter.withSignet(tx.chainId, async (query) => {
    const status = await query(`/tx/${hash}/status`, Status);
    if (!status) return { state: 'unknown' };
    if (!status.confirmed || status.block_height === undefined) return { state: 'pending' };
    const tip = await query(
      '/blocks/tip/height',
      z
        .string()
        .regex(/^(0|[1-9][0-9]*)$/)
        .max(16),
      true,
    );
    if (!tip || BigInt(tip) > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error('Cannot verify confirmation depth');
    if (BigInt(tip) - BigInt(status.block_height) + 1n < 6n) return { state: 'pending' };
    return { state: 'confirmed', blockNumber: status.block_height };
  });
}
