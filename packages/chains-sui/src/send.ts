import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base58, base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  SUI_TESTNET,
  isSuiDigest,
  netGas,
  suiAddressBytes,
  suiAddressFromPublicKey,
  type SuiAdapter,
  type SuiCoin,
} from './sui.js';

const CanonicalAddress = z.string().regex(/^0x[0-9a-f]{64}$/);

/** Mirrors `sui::SuiTx` in the core; the core re-checks every field. */
export const SuiTx = z.strictObject({
  chainId: z.literal(SUI_TESTNET),
  from: CanonicalAddress,
  to: CanonicalAddress,
  mist: z.string().regex(/^[1-9][0-9]{0,19}$/),
  gasPayment: z
    .array(
      z.strictObject({
        objectId: CanonicalAddress,
        version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        digest: z.string().refine(isSuiDigest, 'not a 32-byte base58 digest'),
      }),
    )
    .min(1)
    .max(16),
  gasPrice: z.number().int().min(1).max(100_000),
  gasBudget: z.number().int().positive().max(1_000_000_000),
});
export type SuiTx = z.infer<typeof SuiTx>;

const U64_MAX = 0xffffffffffffffffn;
export const MAX_GAS_COINS = 16;
export const MAX_GAS_PRICE = 100_000;
/** 1 SUI: the core refuses larger budgets. */
export const MAX_GAS_BUDGET = 1_000_000_000n;
/** The budget the dry run is given before the real cost is known: 0.05 SUI. */
const PROVISIONAL_BUDGET = 50_000_000n;
/** The SDK's safety margin: 1000 computation units on top of the dry-run cost. */
const GAS_SAFE_OVERHEAD = 1000n;
const MIN_GAS_UNITS = 1000n;
export const SIGNATURE_LEN = 97;
const TX_INTENT = Uint8Array.of(0, 0, 0);

function u64le(v: bigint): number[] {
  const out: number[] = [];
  for (let i = 0n; i < 8n; i++) out.push(Number((v >> (8n * i)) & 0xffn));
  return out;
}

/** The same `TransactionData::V1` BCS the core encodes independently from checked fields. */
export function suiTxBcs(input: SuiTx): Uint8Array {
  const tx = SuiTx.parse(input);
  if (tx.from === tx.to) throw new Error('Sender and recipient must differ');
  const amount = BigInt(tx.mist);
  if (amount > U64_MAX || amount.toString() !== tx.mist) throw new Error('Invalid SUI amount');
  if (BigInt(tx.gasBudget) < BigInt(tx.gasPrice) * MIN_GAS_UNITS)
    throw new Error('Gas budget is below the minimum for this gas price');
  const ids = new Set(tx.gasPayment.map((c) => c.objectId));
  if (ids.size !== tx.gasPayment.length) throw new Error('Gas payment repeats a coin object');
  const from = suiAddressBytes(tx.from);
  const out: number[] = [0, 0, 2, 0, 8, ...u64le(amount), 0, 32, ...suiAddressBytes(tx.to)];
  out.push(2, 2, 0, 1, 1, 0, 0, 1, 1, 2, 0, 0, 1, 1, 0);
  out.push(...from, tx.gasPayment.length);
  for (const c of tx.gasPayment) {
    const digest = base58.decode(c.digest);
    out.push(...suiAddressBytes(c.objectId), ...u64le(BigInt(c.version)), 32, ...digest);
  }
  out.push(...from, ...u64le(BigInt(tx.gasPrice)), ...u64le(BigInt(tx.gasBudget)), 0);
  return Uint8Array.from(out);
}

/** blake2b-256(intent || bcs): the message the Ed25519 key signs. */
export function suiSigningDigest(tx: SuiTx): Uint8Array {
  const bcs = suiTxBcs(tx);
  const msg = new Uint8Array(TX_INTENT.length + bcs.length);
  msg.set(TX_INTENT);
  msg.set(bcs, TX_INTENT.length);
  return blake2b(msg, { dkLen: 32 });
}

/** base58(blake2b-256("TransactionData::" || bcs)): the digest explorers show. */
export function suiTxDigest(tx: SuiTx): string {
  const tag = new TextEncoder().encode('TransactionData::');
  const bcs = suiTxBcs(tx);
  const msg = new Uint8Array(tag.length + bcs.length);
  msg.set(tag);
  msg.set(bcs, tag.length);
  return base58.encode(blake2b(msg, { dkLen: 32 }));
}

/** Largest coins first, until they cover `need`, at most 16. */
export function selectGasCoins(coins: SuiCoin[], need: bigint): SuiCoin[] | undefined {
  const picked: SuiCoin[] = [];
  let sum = 0n;
  for (const c of [...coins].sort((a, b) =>
    a.balance === b.balance ? 0 : a.balance > b.balance ? -1 : 1,
  )) {
    if (picked.length === MAX_GAS_COINS) break;
    picked.push(c);
    sum += c.balance;
    if (sum >= need) return picked;
  }
  return undefined;
}

/** The SDK's rule: dry-run computation plus a safety margin plus net storage, never below the computation part. */
export function gasBudgetFor(
  summary: { computationCost: number; storageCost: number; storageRebate: number },
  gasPrice: bigint,
): bigint {
  const base = BigInt(summary.computationCost) + GAS_SAFE_OVERHEAD * gasPrice;
  const withStorage = base + BigInt(summary.storageCost) - BigInt(summary.storageRebate);
  const floor = gasPrice * MIN_GAS_UNITS;
  const budget = withStorage > base ? withStorage : base;
  return budget > floor ? budget : floor;
}

export async function prepareSui(
  adapter: SuiAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: SuiTx; simulation: Simulation }> {
  if (
    intent.chainId !== SUI_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${SUI_TESTNET}:native`
  )
    throw new Error('Only native SUI transfers on testnet are enabled');
  const amount = BigInt(intent.amount);
  if (amount <= 0n || amount > U64_MAX) throw new Error('Invalid SUI amount');
  const sender = from.toLowerCase();
  const { coins, totalBalance, referenceGasPrice } = await adapter.coins(sender, intent.chainId);
  if (referenceGasPrice < 1n || referenceGasPrice > BigInt(MAX_GAS_PRICE))
    throw new Error('Reference gas price is outside the accepted range');
  if (coins.length === 0)
    throw new Error(
      totalBalance > 0n
        ? 'This SUI is held as an address balance, not coin objects; transfers need coin objects to pay gas'
        : 'Sender has no SUI on testnet',
    );
  const floor = referenceGasPrice * MIN_GAS_UNITS * 2n;
  const top = coins.slice(0, MAX_GAS_COINS).reduce((s, c) => s + c.balance, 0n);
  let provisional = PROVISIONAL_BUDGET;
  if (top - amount < provisional) provisional = top - amount;
  if (provisional < floor)
    throw new Error('The largest 16 SUI coins do not cover the amount plus gas');
  const picked = selectGasCoins(coins, amount + provisional)!;
  const base = {
    chainId: SUI_TESTNET,
    from: sender,
    to: intent.to.toLowerCase(),
    mist: intent.amount,
    gasPayment: picked.map((c) => ({ objectId: c.objectId, version: c.version, digest: c.digest })),
    gasPrice: Number(referenceGasPrice),
  } as const;
  const draft = SuiTx.parse({ ...base, gasBudget: Number(provisional) });
  const effects = await adapter.dryRun(base64.encode(suiTxBcs(draft)), intent.chainId);
  const summary = effects.gasEffects?.gasSummary;
  let unsigned = draft;
  let error: string | undefined;
  if (effects.status !== 'SUCCESS' || !summary) {
    error = `Dry run failed: ${effects.executionError?.message ?? 'no gas summary'}`.slice(0, 512);
  } else {
    let budget = gasBudgetFor(summary, referenceGasPrice);
    if (budget > provisional) budget = provisional;
    unsigned = SuiTx.parse({ ...base, gasBudget: Number(budget) });
  }
  suiTxBcs(unsigned);
  const fee = BigInt(unsigned.gasBudget);
  const warnings: Simulation['warnings'] = [];
  if (totalBalance > coins.reduce((s, c) => s + c.balance, 0n))
    warnings.push({
      kind: 'other',
      message:
        'Part of this SUI is an address balance or beyond the 50 largest coins and cannot pay for this transfer.',
    });
  const estimate = summary ? netGas(summary) : undefined;
  if (estimate !== undefined)
    warnings.push({
      kind: 'other',
      message: `Gas is budgeted at up to ${fee} MIST; the dry run charged ${estimate} MIST net of storage rebates.`,
    });
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
}

/**
 * A prepared transfer stays usable while every gas coin is still owned by the
 * sender at the version and digest it names, and the epoch's reference gas
 * price has not risen above the price it bids.
 */
export async function suiApprovalValid(adapter: SuiAdapter, tx: SuiTx): Promise<boolean> {
  const { objects, referenceGasPrice } = await adapter.objects(
    tx.gasPayment.map((c) => c.objectId),
    tx.chainId,
  );
  if (referenceGasPrice > BigInt(tx.gasPrice)) return false;
  return tx.gasPayment.every((c, i) => {
    const o = objects[i];
    return (
      o !== null &&
      o !== undefined &&
      o.objectId === c.objectId &&
      o.version === c.version &&
      o.digest === c.digest &&
      o.owner === tx.from
    );
  });
}

/**
 * Broadcast only bytes that are exactly the ledger's transaction followed by
 * one Ed25519 signature from the sender over its intent digest.
 */
export async function broadcastSui(
  adapter: SuiAdapter,
  tx: SuiTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== SUI_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const bcs = suiTxBcs(tx);
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  const expected = bytesToHex(bcs);
  if (
    !/^[0-9a-f]+$/.test(hex) ||
    hex.length !== (bcs.length + SIGNATURE_LEN) * 2 ||
    !hex.startsWith(expected)
  )
    throw new Error('Signed bytes are not this SUI transfer');
  const signature = hexToBytes(hex.slice(expected.length));
  const publicKey = signature.subarray(65);
  if (signature[0] !== 0 || suiAddressFromPublicKey(publicKey) !== tx.from)
    throw new Error('Signature is not from the sender key');
  if (!ed25519.verify(signature.subarray(1, 65), suiSigningDigest(tx), publicKey))
    throw new Error('Signature does not verify against the sender');
  const digest = suiTxDigest(tx);
  const res = await adapter.execute(tx.chainId, base64.encode(bcs), base64.encode(signature));
  if ('rejected' in res) {
    // A retry of a transaction that already executed can be refused for its spent gas coins.
    const status = await adapter.status(digest, tx.chainId);
    if (status.state === 'confirmed' || status.state === 'failed') return digest;
    throw new Error(`Broadcast rejected: ${res.rejected}`.slice(0, 512));
  }
  if (res.effects?.digest !== undefined && res.effects.digest !== digest)
    throw new Error('The node reported a different transaction digest');
  return digest;
}

/**
 * A Sui transaction has no expiration here, but it can never land once any of
 * its gas coins moved to another version; that is reported as expired.
 */
export async function suiTransferStatus(
  adapter: SuiAdapter,
  tx: SuiTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const { objects } = await adapter.objects(
    tx.gasPayment.map((c) => c.objectId),
    tx.chainId,
  );
  const spent = tx.gasPayment.some((c, i) => {
    const o = objects[i];
    return !o || o.version !== c.version || o.digest !== c.digest;
  });
  if (!spent) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
