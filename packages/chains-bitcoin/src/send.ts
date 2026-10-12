import { Transaction, address, networks } from 'bitcoinjs-lib';
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
const Outspend = z.object({ spent: z.boolean() });
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
  if (!isSignetSender(from)) throw new Error('Only Signet P2WPKH senders are enabled');
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
function isSignetSender(text: string): boolean {
  const d = decodeSegwit(text);
  return (
    text === text.toLowerCase() && d?.hrp === 'tb' && d.version === 0 && d.program.length === 20
  );
}
function funding(input: BitcoinTx['inputs'][number], from: string) {
  const previous = Transaction.fromHex(input.previousTxHex);
  if (previous.getId() !== input.txid || previous.isCoinbase())
    throw new Error('Invalid funding transaction');
  const output = previous.outs[input.vout];
  if (!output || !BufferlessEqual(output.script, address.toOutputScript(from, networks.testnet)))
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
  if (
    intent.chainId !== BITCOIN_SIGNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${BITCOIN_SIGNET}:native` ||
    !isSignetSender(from) ||
    !isSignetRecipient(intent.to) ||
    intent.to === from
  )
    throw new Error('Only Signet P2WPKH senders and native SegWit/Taproot recipients are enabled');
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
        BigInt(11 + 69 * selected.length + 31 + recipient.outputBytes) * BigInt(fees.halfHourFee);
      const change = total - BigInt(intent.amount) - fee;
      if (!requestedKeys && (change === 0n || change >= 294n)) break;
    }
    const change = total - BigInt(intent.amount) - fee;
    if (!selected.length || change < 0n || (change > 0n && change < 294n) || fee > 100000n)
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
export async function bitcoinInputsUnspent(
  adapter: BitcoinAdapter,
  tx: BitcoinTx,
): Promise<boolean> {
  return adapter.withSignet(tx.chainId, async (query) => {
    for (const input of tx.inputs) {
      const out = await query(`/tx/${input.txid}/outspend/${input.vout}`, Outspend);
      if (!out) throw new Error('Cannot verify input spend status');
      if (out.spent) return false;
    }
    return true;
  });
}
export async function broadcastBitcoin(
  adapter: BitcoinAdapter,
  tx: BitcoinTx,
  raw: string,
): Promise<string> {
  if (!/^0x(?:[0-9a-f]{2})+$/.test(raw) || raw.length > 20000)
    throw new Error('Invalid core transaction bytes');
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
