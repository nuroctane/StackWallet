import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base58, base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  Block,
  NEAR_TESTNET,
  STORAGE_PRICE_PER_BYTE,
  VALIDITY_PERIOD_BLOCKS,
  ViewAccessKey,
  failureReason,
  implicitPublicKey,
  isImplicitAccount,
  isValidNearAccountId,
  rpcTxStatus,
  viewAccount,
  type NearAdapter,
  type NearCall,
} from './near.js';

/** Mirrors `near::NearTx` in the core; the core re-checks every field. */
export const NearTx = z.strictObject({
  chainId: z.literal(NEAR_TESTNET),
  from: z.string().regex(/^[0-9a-f]{64}$/),
  to: z
    .string()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9._-]+$/),
  yocto: z.string().regex(/^[0-9]+$/),
  nonce: z.string().regex(/^[0-9]+$/),
  blockHash: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/),
  blockHeight: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type NearTx = z.infer<typeof NearTx>;

/** Ten billion NEAR, several times the total supply; the core enforces the same bound. */
export const MAX_YOCTO = 10_000_000_000n * 10n ** 24n;
const U64_MAX = (1n << 64n) - 1n;
/** Gas of one Transfer: action receipt creation plus the transfer action, send and execution. */
export const TRANSFER_GAS = 446_365_125_000n;
/** A transfer to an absent implicit account also pays CreateAccount and a full-access AddKey. */
export const IMPLICIT_CREATE_GAS = 7_903_530_250_000n;
/** Storage of a fresh implicit account (account record plus one full-access key). */
export const MIN_NEW_IMPLICIT_YOCTO = 182n * STORAGE_PRICE_PER_BYTE;
/** Approval stops this many blocks before the block hash expires. */
const APPROVAL_MARGIN_BLOCKS = 3_600;
const KEY_TYPE_ED25519 = 0;
const ACTION_TRANSFER = 3;

function le(value: bigint, bytes: number): number[] {
  const out: number[] = [];
  let v = value;
  for (let i = 0; i < bytes; i++) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return out;
}

function borshString(s: string): number[] {
  const b = new TextEncoder().encode(s);
  return [...le(BigInt(b.length), 4), ...b];
}

function positive(value: string, max: bigint, what: string): bigint {
  const n = BigInt(value);
  if (n <= 0n || n > max || n.toString() !== value)
    throw new Error(`${what} must be a positive canonical integer within range`);
  return n;
}

/** The same Borsh `Transaction` the core encodes independently from checked fields. */
export function nearTxBorsh(input: NearTx): Uint8Array {
  const tx = NearTx.parse(input);
  if (!isImplicitAccount(tx.from)) throw new Error('NEAR sender must be an implicit account');
  if (!isValidNearAccountId(tx.to) || tx.to === tx.from) throw new Error('Invalid NEAR recipient');
  const deposit = positive(tx.yocto, MAX_YOCTO, 'NEAR amount');
  const nonce = positive(tx.nonce, U64_MAX, 'Nonce');
  const blockHash = base58.decode(tx.blockHash);
  if (blockHash.length !== 32 || base58.encode(blockHash) !== tx.blockHash)
    throw new Error('Block hash must be 32 bytes of canonical base58');
  return Uint8Array.from([
    ...borshString(tx.from),
    KEY_TYPE_ED25519,
    ...hexToBytes(tx.from),
    ...le(nonce, 8),
    ...borshString(tx.to),
    ...blockHash,
    ...le(1n, 4),
    ACTION_TRANSFER,
    ...le(deposit, 16),
  ]);
}

/** sha256 of the Borsh transaction: the signed message. */
export function nearTxHashBytes(tx: NearTx): Uint8Array {
  return sha256(nearTxBorsh(tx));
}

/** The transaction hash as explorers and RPC show it (base58). */
export function nearTxHash(tx: NearTx): string {
  return base58.encode(nearTxHashBytes(tx));
}

/** Network fee of a transfer at `gasPrice`; prepaid at that price, unused gas is refunded. */
export function transferFee(gasPrice: bigint, createsAccount: boolean): bigint {
  return (TRANSFER_GAS + (createsAccount ? IMPLICIT_CREATE_GAS : 0n)) * gasPrice;
}

type AccessKey =
  | { kind: 'full'; nonce: bigint }
  | { kind: 'limited'; nonce: bigint }
  | { kind: 'missing' };

async function accessKey(call: NearCall, account: string): Promise<AccessKey> {
  const r = await call(
    'query',
    {
      request_type: 'view_access_key',
      finality: 'final',
      account_id: account,
      public_key: implicitPublicKey(account),
    },
    ViewAccessKey,
  );
  if (!r.ok) {
    if (r.name === 'UNKNOWN_ACCESS_KEY' || r.name === 'UNKNOWN_ACCOUNT') return { kind: 'missing' };
    throw new Error(`view_access_key failed: ${r.name}`);
  }
  if ('error' in r.result) return { kind: 'missing' };
  return {
    kind: r.result.permission === 'FullAccess' ? 'full' : 'limited',
    nonce: BigInt(r.result.nonce),
  };
}

async function block(call: NearCall, params: Record<string, unknown>): Promise<Block | null> {
  const r = await call('block', params, Block);
  if (r.ok) return r.result;
  if (r.name === 'UNKNOWN_BLOCK') return null;
  throw new Error(`block lookup failed: ${r.name}`);
}

export async function prepareNear(
  adapter: NearAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: NearTx; simulation: Simulation }> {
  if (
    intent.chainId !== NEAR_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${NEAR_TESTNET}:native`
  )
    throw new Error('Only native NEAR transfers on testnet are enabled');
  if (!isImplicitAccount(from)) throw new Error('NEAR sender must be an implicit account');
  if (!isValidNearAccountId(intent.to)) throw new Error('Invalid NEAR recipient');
  return adapter.withNode(intent.chainId, async (call) => {
    const [sender, key, recipient, final] = await Promise.all([
      viewAccount(call, from),
      accessKey(call, from),
      viewAccount(call, intent.to),
      block(call, { finality: 'final' }),
    ]);
    if (!sender) throw new Error('Sender account does not exist on NEAR testnet; fund it first');
    if (key.kind === 'missing') throw new Error('The sender has no access key for this wallet key');
    if (key.kind === 'limited')
      throw new Error('The access key for this wallet key cannot sign transfers');
    if (!final) throw new Error('RPC did not report a final block');
    const amount = BigInt(intent.amount);
    const createsAccount = recipient === null;
    if (createsAccount && !isImplicitAccount(intent.to))
      throw new Error('The recipient account does not exist on NEAR testnet');
    if (createsAccount && amount < MIN_NEW_IMPLICIT_YOCTO)
      throw new Error(
        'The recipient implicit account does not exist yet; send at least 0.00182 NEAR to create it',
      );
    const unsigned = NearTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      yocto: intent.amount,
      nonce: (key.nonce + 1n).toString(),
      blockHash: final.header.hash,
      blockHeight: final.header.height,
    });
    nearTxBorsh(unsigned);
    const fee = transferFee(BigInt(final.header.gas_price), createsAccount);
    const locked = BigInt(sender.storage_usage) * STORAGE_PRICE_PER_BYTE - BigInt(sender.locked);
    const spendable = BigInt(sender.amount) - (locked > 0n ? locked : 0n);
    let error: string | undefined;
    if (spendable < amount + fee)
      error = 'Balance above the storage reserve does not cover the transfer and fee';
    const warnings: Simulation['warnings'] = [];
    if (createsAccount)
      warnings.push({
        kind: 'other',
        message:
          'The recipient implicit account does not exist yet; this transfer creates it and part of the amount covers its storage.',
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
  });
}

/**
 * Approval is refused once the referenced block is close to its validity
 * limit, once the block hash no longer names `blockHeight`, or once the
 * access key's nonce reached the transaction's.
 */
export async function nearApprovalValid(adapter: NearAdapter, tx: NearTx): Promise<boolean> {
  if (tx.chainId !== NEAR_TESTNET) return false;
  return adapter.withNode(tx.chainId, async (call) => {
    const [key, ref, final] = await Promise.all([
      accessKey(call, tx.from),
      block(call, { block_id: tx.blockHash }),
      block(call, { finality: 'final' }),
    ]);
    return (
      key.kind === 'full' &&
      key.nonce < BigInt(tx.nonce) &&
      ref !== null &&
      ref.header.hash === tx.blockHash &&
      ref.header.height === tx.blockHeight &&
      final !== null &&
      final.header.height - tx.blockHeight < VALIDITY_PERIOD_BLOCKS - APPROVAL_MARGIN_BLOCKS
    );
  });
}

const SendResult = z
  .object({
    final_execution_status: z.string().max(64),
    transaction: z
      .object({ hash: z.string().max(64) })
      .loose()
      .optional(),
  })
  .loose();

/**
 * Broadcast only bytes that are exactly this transaction followed by one
 * Ed25519 signature that verifies against the sender's implicit key.
 */
export async function broadcastNear(
  adapter: NearAdapter,
  tx: NearTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== NEAR_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const body = nearTxBorsh(tx);
  const expected = bytesToHex(body) + '00';
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expected.length + 128 || !hex.startsWith(expected))
    throw new Error('Signed bytes are not this NEAR transfer');
  const bytes = hexToBytes(hex);
  const hashBytes = sha256(body);
  if (!ed25519.verify(bytes.subarray(body.length + 1), hashBytes, hexToBytes(tx.from)))
    throw new Error('Signature does not verify against the sender');
  const hash = base58.encode(hashBytes);
  return adapter.withNode(tx.chainId, async (call) => {
    const r = await call(
      'send_tx',
      { signed_tx_base64: base64.encode(bytes), wait_until: 'INCLUDED' },
      SendResult,
    );
    if (r.ok) {
      const reported = r.result.transaction?.hash;
      if (reported !== undefined && reported !== hash)
        throw new Error('RPC reported a different transaction hash');
      return hash;
    }
    // The node stopped waiting; the transaction may still land before its block hash expires.
    if (r.name === 'TIMEOUT_ERROR') return hash;
    const detail = r.name === 'INVALID_TRANSACTION' ? failureReason(r.data) : r.name;
    if (/InvalidNonce/.test(detail)) {
      // A retry of an accepted transfer finds its own nonce consumed.
      const status = await rpcTxStatus(call, hash, tx.from);
      if (status.state === 'confirmed' || status.state === 'pending') return hash;
    }
    throw new Error(`Broadcast rejected: ${detail}`.slice(0, 512));
  });
}

/**
 * Expiry is reported once the referenced block is past the validity period,
 * or the access key's nonce reached the transaction's, and neither RPC nor
 * the archival indexer knows the hash.
 */
export async function nearTransferStatus(
  adapter: NearAdapter,
  tx: NearTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.txStatus(hash, tx.from, tx.chainId);
  if (status.state !== 'unknown') return status;
  const dead = await adapter.withNode(tx.chainId, async (call) => {
    const [key, final] = await Promise.all([
      accessKey(call, tx.from),
      block(call, { finality: 'final' }),
    ]);
    const pastValidity =
      final !== null && final.header.height > tx.blockHeight + VALIDITY_PERIOD_BLOCKS;
    const nonceUsed = key.kind !== 'missing' && key.nonce >= BigInt(tx.nonce);
    return pastValidity || nonceUsed;
  });
  if (!dead) return status;
  const again = await adapter.txStatus(hash, tx.from, tx.chainId);
  if (again.state !== 'unknown') return again;
  // RPC nodes drop old transactions after a few epochs; the indexer keeps them.
  const indexed = await adapter.status(hash, tx.chainId);
  return indexed.state === 'unknown' ? { state: 'expired' } : indexed;
}
