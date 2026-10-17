/**
 * Fuel native-ETH transfer assembly: UTXO selection, exact fee math (the same
 * getMinGas/getMaxGas model the fuels SDK uses), witness verification of the
 * signed wire before submit, and expiry-aware status. Every byte the signer
 * sees is encoded here exactly as `crates/stackwallet-core/src/fuel.rs` does.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { concat } from '@stackwallet/chains';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  FUEL_BASE_ASSET_ID,
  FUEL_SEPOLIA,
  FuelAddress,
  isValidFuelAddress,
  type FuelAdapter,
} from './fuel.js';

/** Until this schema lands in `@stackwallet/core-client`, the package exports its own. */
const Amount = z.string().regex(/^(0|[1-9][0-9]{0,19})$/);
export const FuelCoinInput = z.strictObject({
  txId: FuelAddress,
  outputIndex: z.number().int().nonnegative().max(0xffff),
  amount: z.string().regex(/^[1-9][0-9]{0,19}$/),
});
export const FuelTx = z.strictObject({
  chainId: z.literal(FUEL_SEPOLIA),
  from: FuelAddress,
  to: FuelAddress,
  /** Decimal base units (1 ETH = 1e9 base). */
  base: z.string().regex(/^[1-9][0-9]{0,19}$/),
  inputs: z.array(FuelCoinInput).min(1).max(8),
  gasLimit: z.number().int().nonnegative().max(30_000_000),
  maxFee: z.string().regex(/^[1-9][0-9]{0,12}$/),
  expiration: z.number().int().positive().max(0xffffffff),
});
export type FuelTx = z.infer<typeof FuelTx>;

const BASE_ASSET = hexToBytes(FUEL_BASE_ASSET_ID.slice(2));
/** `RET REG_ZERO; NOOP` — the script the fuels SDK uses for plain transfers. */
const TRANSFER_SCRIPT = Uint8Array.from([0x24, 0x00, 0x00, 0x00]);
const MAX_INPUTS = 8;
const MAX_FEE_LIMIT = 1_000_000_000_000n;
/** Headroom the tx stays includable after preparation (Fuel blocks ~1s). */
const EXPIRATION_BLOCKS = 600;
/** Fallback script gas when dry-run is unavailable; RET costs ~1. */
const FALLBACK_SCRIPT_GAS = 1_000n;
const MAX_SCRIPT_GAS = 1_000_000n;

const word = (v: bigint | number): Uint8Array => {
  const out = new Uint8Array(8);
  let n = BigInt(v);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};

interface CheckedFuelTx {
  tx: FuelTx;
  from: Uint8Array;
  to: Uint8Array;
  amount: bigint;
  maxFee: bigint;
  inputs: { txId: Uint8Array; outputIndex: number; amount: bigint }[];
}

/** The same field validation the Rust core applies (`fuel.rs` `FuelTx::check`). */
function checkFuelTx(input: FuelTx): CheckedFuelTx {
  const tx = FuelTx.parse(input);
  if (!isValidFuelAddress(tx.from) || !isValidFuelAddress(tx.to) || tx.from === tx.to)
    throw new Error('Invalid Fuel sender or recipient');
  const amount = BigInt(tx.base);
  const maxFee = BigInt(tx.maxFee);
  if (maxFee > MAX_FEE_LIMIT) throw new Error('Fuel max fee out of range');
  if (tx.gasLimit > 30_000_000) throw new Error('Fuel gas limit exceeds the network maximum');
  let total = 0n;
  const inputs = tx.inputs.map((coin) => {
    total += BigInt(coin.amount);
    return {
      txId: hexToBytes(coin.txId.slice(2)),
      outputIndex: coin.outputIndex,
      amount: BigInt(coin.amount),
    };
  });
  if (total < amount + maxFee) throw new Error('Fuel coins do not cover the transfer and max fee');
  return {
    tx,
    from: hexToBytes(tx.from.slice(2)),
    to: hexToBytes(tx.to.slice(2)),
    amount,
    maxFee,
    inputs,
  };
}

/**
 * The Fuel `TransactionScript` encoding (word-aligned big-endian). Witnesses
 * are the only variable part: the id form passes `[]`, the wire form one
 * 64-byte signature per input.
 */
export function encodeFuelTransaction(input: FuelTx, witnesses: Uint8Array[] = []): Uint8Array {
  const c = checkFuelTx(input);
  const parts: Uint8Array[] = [
    word(0), // TransactionType::Script
    word(c.tx.gasLimit),
    new Uint8Array(32), // receipts root (zeroed until executed)
    word(TRANSFER_SCRIPT.length),
    word(0), // script data length
    word(8 | 16), // policies: MaxFee | Expiration
    word(c.inputs.length),
    word(2), // change + coin outputs
    word(witnesses.length),
    TRANSFER_SCRIPT,
    new Uint8Array(4), // script padded to a word
    word(c.maxFee),
    word(c.tx.expiration),
  ];
  c.inputs.forEach((input, i) => {
    parts.push(
      word(0), // InputType::Coin
      input.txId,
      word(input.outputIndex),
      c.from,
      word(input.amount),
      BASE_ASSET,
      word(0), // tx pointer block height
      word(0), // tx pointer index
      word(i), // witness index
      word(0), // predicate gas used
      word(0), // predicate length
      word(0), // predicate data length
    );
  });
  parts.push(
    word(2), // OutputType::Change
    c.from,
    word(0), // computed by the VM
    BASE_ASSET,
    word(0), // OutputType::Coin
    c.to,
    word(c.amount),
    BASE_ASSET,
  );
  for (const witness of witnesses) parts.push(word(witness.length), witness);
  return concat(...parts);
}

/** sha256(chain id u64 BE || witness-stripped encoding) — the id fuel-core shows. */
export function fuelTxId(tx: FuelTx): string {
  return `0x${bytesToHex(sha256(concat(word(0), encodeFuelTransaction(tx))))}`;
}

const GqlUnsigned = z.object({
  chain: z.object({
    consensusParameters: z.object({
      chainId: z.string().regex(/^\d{1,10}$/),
      txParams: z.object({
        maxInputs: z.string().regex(/^\d+$/),
        maxGasPerTx: z.string().regex(/^\d+$/),
      }),
      feeParams: z.object({
        gasPriceFactor: z.string().regex(/^\d+$/),
        gasPerByte: z.string().regex(/^\d+$/),
      }),
      gasCosts: z.object({
        vmInitialization: z.object({
          base: z.string().regex(/^\d+$/),
          unitsPerGas: z.string().regex(/^\d+$/).optional(),
          gasPerUnit: z.string().regex(/^\d+$/).optional(),
        }),
        s256: z.object({
          base: z.string().regex(/^\d+$/),
          unitsPerGas: z.string().regex(/^\d+$/).optional(),
          gasPerUnit: z.string().regex(/^\d+$/).optional(),
        }),
        ecr1: z.string().regex(/^\d+$/),
      }),
    }),
    latestBlock: z.object({ header: z.object({ height: z.string().regex(/^\d+$/) }) }),
  }),
});
const GasPrice = z.object({
  latestGasPrice: z.object({ gasPrice: z.string().regex(/^\d{1,20}$/) }),
});
const Coins = z.object({
  coins: z.object({
    nodes: z
      .array(
        z.object({
          utxoId: z.string().regex(/^0x[0-9a-f]{68}$/),
          amount: z.string().regex(/^\d{1,30}$/),
        }),
      )
      .max(200),
    pageInfo: z.object({ hasNextPage: z.boolean(), endCursor: z.string().max(128).nullable() }),
  }),
});
const DryRun = z.object({
  dryRun: z.array(
    z.object({
      receipts: z
        .array(
          z.object({
            receiptType: z.string().max(32),
            gasUsed: z.string().regex(/^\d+$/).nullable().optional(),
            result: z.string().max(16).nullable().optional(),
          }),
        )
        .max(64),
    }),
  ),
});
const Submit = z.object({ submit: z.object({ id: FuelAddress }) });

/** Gas of a size-dependent cost entry (`unitsPerGas` divides, `gasPerUnit` multiplies). */
function dependentGas(
  entry: { base: string; unitsPerGas?: string | undefined; gasPerUnit?: string | undefined },
  size: bigint,
): bigint {
  const base = BigInt(entry.base);
  if (entry.unitsPerGas !== undefined) return base + size / BigInt(entry.unitsPerGas);
  return base + size * BigInt(entry.gasPerUnit ?? '0');
}

/**
 * The fuels SDK fee model: maxFee = maxGas * gasPrice / gasPriceFactor + 1,
 * where maxGas = minGas + scriptGasLimit (no witness-limit policy) and minGas
 * charges VM init, one ecr1 per signed input, per-byte and tx-id hashing.
 */
export function fuelMaxFee(params: {
  gasPrice: bigint;
  gasPriceFactor: bigint;
  gasPerByte: bigint;
  vmInit: { base: string; unitsPerGas?: string | undefined; gasPerUnit?: string | undefined };
  s256: { base: string; unitsPerGas?: string | undefined; gasPerUnit?: string | undefined };
  ecr1: bigint;
  txBytes: bigint;
  signedInputs: bigint;
  scriptGasLimit: bigint;
}): bigint {
  const minGas =
    dependentGas(params.vmInit, params.txBytes) +
    params.txBytes * params.gasPerByte +
    params.signedInputs * params.ecr1 +
    dependentGas(params.s256, params.txBytes);
  const maxGas = minGas + params.scriptGasLimit;
  return (maxGas * params.gasPrice) / params.gasPriceFactor + 1n;
}

export async function prepareFuel(
  adapter: FuelAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: FuelTx; simulation: Simulation }> {
  if (
    intent.chainId !== FUEL_SEPOLIA ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${FUEL_SEPOLIA}:native`
  )
    throw new Error('Only native ETH transfers on the Fuel Sepolia testnet are enabled');
  if (!isValidFuelAddress(from) || !isValidFuelAddress(intent.to))
    throw new Error('Invalid Fuel sender or recipient');
  const amount = BigInt(intent.amount);
  if (amount <= 0n) throw new Error('Fuel amount must be positive');
  return adapter.withNode(intent.chainId, async (call) => {
    const [{ chain }, { latestGasPrice }] = await Promise.all([
      call(CHAIN_PARAMS_QUERY, {}, GqlUnsigned),
      call(`{ latestGasPrice { gasPrice } }`, {}, GasPrice),
    ]);
    if (Number(chain.consensusParameters.chainId) !== 0)
      throw new Error('Endpoint is not the Fuel Sepolia testnet');
    const head = Number(chain.latestBlock.header.height);
    const gasPrice = BigInt(latestGasPrice.gasPrice);
    const { feeParams, gasCosts, txParams } = chain.consensusParameters;
    const ecr1 = BigInt(gasCosts.ecr1);
    const feeFor = (inputs: number, scriptGas: bigint) =>
      fuelMaxFee({
        gasPrice,
        gasPriceFactor: BigInt(feeParams.gasPriceFactor),
        gasPerByte: BigInt(feeParams.gasPerByte),
        vmInit: gasCosts.vmInitialization,
        s256: gasCosts.s256,
        ecr1,
        txBytes: BigInt(wireBytes(inputs)),
        signedInputs: BigInt(inputs),
        scriptGasLimit: scriptGas,
      });
    // Select coins oldest-first until the amount plus the exact fee is covered.
    const picked: FuelTx['inputs'] = [];
    let total = 0n;
    let cursor: string | null = null;
    const maxInputs = Math.min(Number(txParams.maxInputs), MAX_INPUTS);
    for (let page = 0; page < 5 && picked.length < maxInputs; page++) {
      const { coins }: z.infer<typeof Coins> = await call(
        COINS_QUERY,
        { owner: from, assetId: FUEL_BASE_ASSET_ID, after: cursor },
        Coins,
      );
      for (const coin of coins.nodes) {
        const txId = `0x${coin.utxoId.slice(2, 66)}`;
        const outputIndex = parseInt(coin.utxoId.slice(66), 16);
        if (picked.some((p) => p.txId === txId && p.outputIndex === outputIndex)) continue;
        picked.push({ txId, outputIndex, amount: coin.amount });
        total += BigInt(coin.amount);
        if (total >= amount + feeFor(picked.length, FALLBACK_SCRIPT_GAS)) break;
      }
      if (total >= amount + feeFor(picked.length, FALLBACK_SCRIPT_GAS)) break;
      if (!coins.pageInfo.hasNextPage || !coins.pageInfo.endCursor) break;
      cursor = coins.pageInfo.endCursor;
    }
    const draft = (gasLimit: number, maxFee: bigint): FuelTx =>
      FuelTx.parse({
        chainId: FUEL_SEPOLIA,
        from,
        to: intent.to,
        base: intent.amount,
        inputs: picked,
        gasLimit,
        maxFee: maxFee.toString(),
        expiration: head + EXPIRATION_BLOCKS,
      });
    let error: string | undefined;
    if (total < amount) error = 'Balance does not cover the transfer';
    // Measure the script's gas with a dry run (dummy witness; utxoValidation off
    // so the placeholder signature is not checked). RET costs ~1 gas.
    let scriptGas = FALLBACK_SCRIPT_GAS;
    if (error === undefined && total >= amount + feeFor(picked.length, FALLBACK_SCRIPT_GAS)) {
      try {
        const draftTx = draft(
          Number(FALLBACK_SCRIPT_GAS),
          feeFor(picked.length, FALLBACK_SCRIPT_GAS),
        );
        const witness = new Uint8Array(64);
        const wire = `0x${bytesToHex(
          encodeFuelTransaction(
            draftTx,
            picked.map(() => witness),
          ),
        )}`;
        const { dryRun } = await call(
          `mutation($txs: [HexString!]!, $uv: Boolean){ dryRun(txs: $txs, utxoValidation: $uv){ receipts { receiptType gasUsed result } } }`,
          { txs: [wire], uv: false },
          DryRun,
        );
        const result = dryRun[0]?.receipts.find((r) => r.receiptType === 'SCRIPT_RESULT');
        if (result?.result === '0' && result.gasUsed != null) {
          const measured = BigInt(result.gasUsed);
          scriptGas =
            measured > 0n && measured <= MAX_SCRIPT_GAS ? measured * 2n : FALLBACK_SCRIPT_GAS;
        }
      } catch {
        // A node that refuses dry-run still gets a working (slightly padded) tx.
      }
    }
    const maxFee = feeFor(picked.length, scriptGas);
    if (error === undefined && total < amount + maxFee)
      error = 'Balance does not cover the transfer and fee';
    const unsigned = draft(Number(scriptGas), maxFee);
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${maxFee.toString()}` },
        ],
        fee: { assetRef: intent.asset, amount: maxFee.toString() },
        warnings: [
          {
            kind: 'other' as const,
            message:
              'The fee is the MaxFee policy upper bound; the settled fee is lower and the difference returns as change.',
          },
        ],
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Wire size for a transfer with n inputs (64-byte signature witnesses). */
function wireBytes(inputs: number): number {
  // header (8 words) + script word + policies (2 words) + change/coin outputs
  const fixed = 8 * 8 + 8 + 16 + 2 * (8 + 32 + 8 + 32);
  return fixed + inputs * (8 + 32 + 8 + 32 + 8 + 32 + 8 + 8 + 8 + 8 + 8) + inputs * (8 + 64);
}

const CHAIN_PARAMS_QUERY = `{ chain { consensusParameters { chainId
  txParams { maxInputs maxGasPerTx } feeParams { gasPriceFactor gasPerByte }
  gasCosts { vmInitialization { ... on LightOperation { base unitsPerGas } ... on HeavyOperation { base gasPerUnit } }
             s256 { ... on LightOperation { base unitsPerGas } ... on HeavyOperation { base gasPerUnit } } ecr1 } }
  latestBlock { header { height } } } }`;
const COINS_QUERY = `query($owner: Address!, $assetId: AssetId!, $after: String){
  coins(first: 50, after: $after, filter: { owner: $owner, assetId: $assetId }) {
    nodes { utxoId amount } pageInfo { hasNextPage endCursor } } }`;

/** Approval is refused once the chain head is close to the expiration policy. */
export async function fuelApprovalValid(adapter: FuelAdapter, tx: FuelTx): Promise<boolean> {
  FuelTx.parse(tx);
  const head = await adapter.headHeight(tx.chainId);
  return head < tx.expiration - 30;
}

/**
 * Broadcast only bytes that are exactly this transfer with one valid
 * sender-recoverable 64-byte signature per input witness.
 */
export async function broadcastFuel(
  adapter: FuelAdapter,
  tx: FuelTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== FUEL_SEPOLIA) throw new Error('Only Fuel testnet broadcasts are enabled');
  const checked = checkFuelTx(tx);
  const hex = rawHex.toLowerCase();
  if (!/^0x(?:[0-9a-f]{2})+$/.test(hex)) throw new Error('Signed Fuel wire is not hex');
  const expectedHead = bytesToHex(
    encodeFuelTransaction(
      tx,
      checked.inputs.map(() => new Uint8Array(64)),
    ),
  );
  const expected = `0x${expectedHead}`;
  if (hex.length !== expected.length) throw new Error('Signed bytes are not this Fuel transfer');
  // Everything except the 64-byte witness bodies must match exactly.
  const witnessSpans: [number, number][] = [];
  let offset = expected.length - checked.inputs.length * 144; // (8 + 64) * 2 hex per witness
  for (let i = 0; i < checked.inputs.length; i++) {
    witnessSpans.push([offset + 16, offset + 144]);
    offset += 144;
  }
  const mask = (s: string) =>
    witnessSpans.reduce((acc, [a, b]) => `${acc.slice(0, a)}${'..'.repeat(64)}${acc.slice(b)}`, s);
  if (mask(hex) !== mask(expected)) throw new Error('Signed bytes are not this Fuel transfer');
  // Every witness must recover to the sender over the tx id.
  const { secp256k1 } = await import('@noble/curves/secp256k1.js');
  const txid = fuelTxId(tx);
  for (const [a, b] of witnessSpans) {
    const sig = hexToBytes(hex.slice(a, b));
    const recovery = sig[32]! >> 7;
    const s = Uint8Array.from(sig.subarray(32));
    s[0]! &= 0x7f;
    let recovered: string;
    try {
      const signature = new secp256k1.Signature(
        BigInt(`0x${bytesToHex(sig.subarray(0, 32))}`),
        BigInt(`0x${bytesToHex(s)}`),
      ).addRecoveryBit(recovery);
      const point = signature.recoverPublicKey(hexToBytes(txid.slice(2)));
      recovered = `0x${bytesToHex(sha256(point.toBytes(false).subarray(1)))}`;
    } catch {
      throw new Error('Fuel witness does not recover to the sender');
    }
    if (recovered !== tx.from) throw new Error('Fuel witness does not recover to the sender');
  }
  const { submit } = await adapter.withNode(tx.chainId, (call) =>
    call(`mutation($tx: HexString!){ submit(tx: $tx){ id } }`, { tx: hex }, Submit),
  );
  if (submit.id !== txid) throw new Error('Node reported a different transaction id');
  return txid;
}

/** Squeezed out or dropped past the expiration height reads as expired. */
export async function fuelTransferStatus(
  adapter: FuelAdapter,
  tx: FuelTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const head = await adapter.headHeight(tx.chainId);
  if (head < tx.expiration) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
