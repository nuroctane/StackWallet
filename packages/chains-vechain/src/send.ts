import { secp256k1 } from '@noble/curves/secp256k1.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { HttpError, type Simulation, type TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  Account,
  Block,
  VECHAIN_TESTNET,
  vechainAddressFromPublicKey,
  normalizeVechainAddress,
  vthoAssetRef,
  type VechainAdapter,
} from './vechain.js';

/** Mirrors the core's `VechainTx`; the lead copies this into `@stackwallet/core-client`. */
export const VechainTx = z.strictObject({
  chainId: z.literal(VECHAIN_TESTNET),
  from: z.string().regex(/^0x[0-9a-f]{40}$/),
  to: z.string().regex(/^0x[0-9a-f]{40}$/),
  vetWei: z.string().regex(/^[1-9][0-9]{0,38}$/),
  blockRef: z.string().regex(/^[0-9a-f]{16}$/),
  expiration: z.number().int().min(1).max(720),
  gasPriceCoef: z.number().int().min(0).max(255),
  gas: z.number().int().min(21_000).max(100_000),
  nonce: z.string().regex(/^[0-9a-f]{16}$/),
});
export type VechainTx = z.infer<typeof VechainTx>;

const CHAIN_TAG: Record<string, number> = { [VECHAIN_TESTNET]: 0x27 };
const INTRINSIC_GAS = 21_000;
const MAX_GAS = 100_000;
/** About 30 minutes at 10 s per block: long enough to review and approve. */
const LIFETIME_BLOCKS = 180;
/** Refuse approval this many blocks (about a minute) before the network would drop it. */
const APPROVAL_MARGIN_BLOCKS = 6;
const MAX_AMOUNT = (1n << 128n) - 1n;
const PARAMS_ADDRESS = '0x0000000000000000000000000000506172616d73';
/** `Params.get(bytes32)` for the legacy base gas price key, right-aligned like thor's `BytesToBytes32`. */
const BASE_GAS_PRICE_CALL =
  '0x8eaa6ac0' + bytesToHex(new TextEncoder().encode('base-gas-price')).padStart(64, '0');

const stripZeros = (b: Uint8Array) => {
  let i = 0;
  while (i < b.length && b[i] === 0) i++;
  return b.subarray(i);
};
const uintBytes = (n: bigint) => {
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return n === 0n ? new Uint8Array() : hexToBytes(hex);
};
function lengthPrefix(len: number, short: number): number[] {
  if (len <= 55) return [short + len];
  const lb = Array.from(uintBytes(BigInt(len)));
  return [short + 55 + lb.length, ...lb];
}
const rlpBytes = (b: Uint8Array): Uint8Array =>
  b.length === 1 && b[0]! < 0x80 ? b : Uint8Array.from([...lengthPrefix(b.length, 0x80), ...b]);
const rlpList = (items: Uint8Array[]): Uint8Array => {
  const payload = items.flatMap((i) => Array.from(i));
  return Uint8Array.from([...lengthPrefix(payload.length, 0xc0), ...payload]);
};
const rlpUint = (n: bigint) => rlpBytes(uintBytes(n));

function unsignedFields(input: VechainTx): Uint8Array[] {
  const tx = VechainTx.parse(input);
  const tag = CHAIN_TAG[tx.chainId];
  if (tag === undefined) throw new Error('Only VeChain testnet transfers are enabled');
  if (tx.from === tx.to || !normalizeVechainAddress(tx.from) || !normalizeVechainAddress(tx.to))
    throw new Error('Invalid VET sender or recipient');
  const amount = BigInt(tx.vetWei);
  if (amount <= 0n || amount > MAX_AMOUNT) throw new Error('VET amount is out of range');
  const clause = rlpList([
    rlpBytes(hexToBytes(tx.to.slice(2))),
    rlpUint(amount),
    rlpBytes(new Uint8Array()),
  ]);
  return [
    rlpUint(BigInt(tag)),
    rlpBytes(stripZeros(hexToBytes(tx.blockRef))),
    rlpUint(BigInt(tx.expiration)),
    rlpList([clause]),
    rlpUint(BigInt(tx.gasPriceCoef)),
    rlpUint(BigInt(tx.gas)),
    rlpBytes(new Uint8Array()),
    rlpBytes(stripZeros(hexToBytes(tx.nonce))),
    rlpList([]),
  ];
}

/** The same unsigned RLP body the core encodes independently from checked fields. */
export function encodeVechainTx(tx: VechainTx): Uint8Array {
  return rlpList(unsignedFields(tx));
}

export function vechainSigningHash(tx: VechainTx): Uint8Array {
  return blake2b(encodeVechainTx(tx), { dkLen: 32 });
}

/** blake2b-256(signing hash || origin), as thor and explorers report it. */
export function vechainTxId(tx: VechainTx): string {
  const origin = hexToBytes(VechainTx.parse(tx).from.slice(2));
  return `0x${bytesToHex(blake2b(Uint8Array.from([...vechainSigningHash(tx), ...origin]), { dkLen: 32 }))}`;
}

/** Smallest legacy coefficient whose price covers `target`; undefined if none can. */
export function gasPriceCoefFor(baseGasPrice: bigint, target: bigint): number | undefined {
  if (baseGasPrice <= 0n) return undefined;
  for (let coef = 0; coef <= 255; coef++) {
    if (legacyGasPrice(baseGasPrice, coef) >= target) return coef;
  }
  return undefined;
}

export function legacyGasPrice(baseGasPrice: bigint, coef: number): bigint {
  return baseGasPrice + (baseGasPrice * BigInt(coef)) / 255n;
}

const CallResult = z.tuple([
  z.object({
    data: z
      .string()
      .regex(/^0x([0-9a-f]{2})*$/)
      .max(2 + 2 * 4096),
    gasUsed: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    reverted: z.boolean(),
    vmError: z.string().max(512),
  }),
]);
const Priority = z.object({ maxPriorityFeePerGas: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/) });

function randomNonce(): string {
  const bytes = new Uint8Array(8);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

export interface PrepareVechainOptions {
  nonce?: string;
}

export async function prepareVechain(
  adapter: VechainAdapter,
  intent: TxIntent,
  sender: string,
  opts: PrepareVechainOptions = {},
): Promise<{ unsigned: VechainTx; simulation: Simulation }> {
  if (
    intent.chainId !== VECHAIN_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${VECHAIN_TESTNET}:native`
  )
    throw new Error('Only native VET transfers on VeChain testnet are enabled');
  const from = normalizeVechainAddress(sender);
  const to = normalizeVechainAddress(intent.to);
  if (!from || !to) throw new Error('Invalid VeChain address');
  const value = BigInt(intent.amount);
  return adapter.withNode(intent.chainId, async ({ get, post }) => {
    const best = await get('/blocks/best', Block);
    const [senderAccount, recipient, params, call, priority] = await Promise.all([
      get(`/accounts/${from}`, Account),
      get(`/accounts/${to}`, Account),
      post(
        '/accounts/*',
        { clauses: [{ to: PARAMS_ADDRESS, value: '0x0', data: BASE_GAS_PRICE_CALL }] },
        CallResult,
      ),
      post(
        '/accounts/*',
        {
          clauses: [{ to, value: `0x${value.toString(16)}`, data: '0x' }],
          caller: from,
          gas: MAX_GAS,
        },
        CallResult,
      ),
      get('/fees/priority', Priority).catch(() => undefined),
    ]);
    const baseGasPrice = BigInt(params[0].data === '0x' ? 0 : params[0].data);
    // Since Galactica a legacy price must cover the block base fee; the
    // suggested tip keeps the transfer from waiting behind tipped ones.
    const baseFee = best.baseFeePerGas ? BigInt(best.baseFeePerGas) : baseGasPrice;
    const tip = priority ? BigInt(priority.maxPriorityFeePerGas) : 0n;
    const coef =
      gasPriceCoefFor(baseGasPrice, baseFee + tip) ?? gasPriceCoefFor(baseGasPrice, baseFee);
    const gas = INTRINSIC_GAS + call[0].gasUsed;
    const unsigned = VechainTx.parse({
      chainId: intent.chainId,
      from,
      to,
      vetWei: intent.amount,
      blockRef: best.id.slice(2, 18),
      expiration: LIFETIME_BLOCKS,
      gasPriceCoef: coef ?? 255,
      gas: Math.min(gas, MAX_GAS),
      nonce: opts.nonce ?? randomNonce(),
    });
    encodeVechainTx(unsigned);
    const fee = BigInt(unsigned.gas) * legacyGasPrice(baseGasPrice, unsigned.gasPriceCoef);
    let error: string | undefined;
    if (coef === undefined)
      error = 'The base fee is above what a legacy VeChain transaction can pay';
    else if (gas > MAX_GAS) error = 'The recipient contract needs more gas than a transfer allows';
    else if (BigInt(senderAccount.balance) < value)
      error = 'VET balance does not cover the transfer';
    else if (BigInt(senderAccount.energy) < fee) error = 'VTHO balance does not cover the fee';
    else if (call[0].reverted)
      error = `Transfer would revert: ${call[0].vmError.replace(/[^\x20-\x7e]/g, '').slice(0, 200)}`;
    const warnings: Simulation['warnings'] = [];
    if (recipient.hasCode) warnings.push({ kind: 'destinationIsContract', address: to });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: vthoAssetRef(intent.chainId), amount: `-${fee}` },
        ],
        fee: { assetRef: vthoAssetRef(intent.chainId), amount: fee.toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

const blockRefNumber = (tx: VechainTx) => parseInt(tx.blockRef.slice(0, 8), 16);
/** The last block that may include the transaction. */
export const vechainLastBlock = (tx: VechainTx) => blockRefNumber(tx) + tx.expiration;

/** Approval is refused once the network could drop the transaction before it lands. */
export async function vechainApprovalValid(
  adapter: VechainAdapter,
  tx: VechainTx,
): Promise<boolean> {
  const best = await adapter.withNode(tx.chainId, ({ get }) => get('/blocks/best', Block));
  return (
    best.number >= blockRefNumber(tx) && best.number < vechainLastBlock(tx) - APPROVAL_MARGIN_BLOCKS
  );
}

const Broadcast = z.object({ id: z.string().regex(/^0x[0-9a-f]{64}$/) });

/** Broadcast only bytes that are exactly the ledger's transfer plus one signature by its sender. */
export async function broadcastVechain(
  adapter: VechainAdapter,
  tx: VechainTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== VECHAIN_TESTNET)
    throw new Error('Only VeChain testnet broadcasts are enabled');
  const fields = unsignedFields(tx);
  const payload = fields.reduce((n, f) => n + f.length, 0) + 2 + 65;
  const expected = bytesToHex(
    Uint8Array.from([
      ...lengthPrefix(payload, 0xc0),
      ...fields.flatMap((f) => Array.from(f)),
      0xb8,
      65,
    ]),
  );
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expected.length + 130 || !hex.startsWith(expected))
    throw new Error('Signed bytes are not this VET transfer');
  const sig = hexToBytes(hex.slice(expected.length));
  if (sig[64]! > 1) throw new Error('Signed bytes are not this VET transfer');
  let signer: string;
  try {
    const point = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact')
      .addRecoveryBit(sig[64]!)
      .recoverPublicKey(vechainSigningHash(tx));
    signer = vechainAddressFromPublicKey(point.toBytes(true));
  } catch {
    throw new Error('Signature does not recover');
  }
  if (signer !== tx.from) throw new Error('Transfer is not signed by its sender');
  const id = vechainTxId(tx);
  const outcome = await adapter.withNode(tx.chainId, async ({ post }) => {
    try {
      return { id: (await post('/transactions', { raw: `0x${hex}` }, Broadcast)).id };
    } catch (err) {
      // A 4xx is the network's verdict on the transaction, not a broken endpoint.
      if (err instanceof HttpError && err.status >= 400 && err.status < 500)
        return { rejected: err.body.replace(/[^\x20-\x7e]/g, '').slice(0, 300) };
      throw err;
    }
  });
  if ('rejected' in outcome) {
    // A retry of an accepted transfer is not a failure.
    if (/known tx/i.test(outcome.rejected)) return id;
    throw new BroadcastRejected(outcome.rejected);
  }
  if (outcome.id !== id) throw new Error('Node reported a different transaction id');
  return id;
}

export class BroadcastRejected extends Error {
  override readonly name = 'BroadcastRejected';
  constructor(reason: string) {
    super(`Broadcast rejected: ${reason}`.trim());
  }
}

/** Expiry is reported only once the head is past the last includable block and the id is absent. */
export async function vechainTransferStatus(
  adapter: VechainAdapter,
  tx: VechainTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown' && status.state !== 'pending') return status;
  const best = await adapter.withNode(tx.chainId, ({ get }) => get('/blocks/best', Block));
  if (best.number <= vechainLastBlock(tx)) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' || again.state === 'pending' ? { state: 'expired' } : again;
}
