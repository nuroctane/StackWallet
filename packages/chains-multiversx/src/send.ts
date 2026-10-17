import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  MULTIVERSX_DEVNET,
  isMultiversxContract,
  multiversxAddressBytes,
  toStatus,
  type MultiversxAdapter,
} from './multiversx.js';

const PROTOCOL_CHAIN_ID = 'D';
const VERSION = 2;
export const MIN_GAS_LIMIT = 50_000;
export const MAX_GAS_LIMIT = 1_000_000;
export const MIN_GAS_PRICE = 1_000_000_000;
export const MAX_GAS_PRICE = 100 * MIN_GAS_PRICE;
/** The capped EGLD supply, 31,415,926 EGLD. */
export const MAX_ATTOEGLD = 31_415_926n * 10n ** 18n;
const Address = z.string().regex(/^erd1[02-9ac-hj-np-z]{58}$/);

/** Mirrors `multiversx::MultiversxTx` in the core; the core re-checks every field. */
export const MultiversxTx = z.strictObject({
  chainId: z.literal(MULTIVERSX_DEVNET),
  from: Address,
  to: Address,
  attoegld: z.string().regex(/^[1-9][0-9]{0,25}$/),
  nonce: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  gasPrice: z.number().int().min(MIN_GAS_PRICE).max(MAX_GAS_PRICE),
  gasLimit: z.number().int().min(MIN_GAS_LIMIT).max(MAX_GAS_LIMIT),
});
export type MultiversxTx = z.infer<typeof MultiversxTx>;

interface CheckedTx {
  tx: MultiversxTx;
  from: Uint8Array;
  to: Uint8Array;
  value: bigint;
}

function check(input: MultiversxTx): CheckedTx {
  const tx = MultiversxTx.parse(input);
  const from = multiversxAddressBytes(tx.from);
  const to = multiversxAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid EGLD sender or recipient');
  const value = BigInt(tx.attoegld);
  if (value <= 0n || value > MAX_ATTOEGLD) throw new Error('EGLD amount exceeds the supply');
  return { tx, from, to, value };
}

/** The canonical JSON the protocol verifies the signature over, as the core writes it. */
export function signingJson(input: MultiversxTx): string {
  const { tx } = check(input);
  return `{"nonce":${tx.nonce},"value":"${tx.attoegld}","receiver":"${tx.to}","sender":"${tx.from}","gasPrice":${tx.gasPrice},"gasLimit":${tx.gasLimit},"chainID":"${PROTOCOL_CHAIN_ID}","version":${VERSION}}`;
}

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
const bytesField = (field: number, bytes: Uint8Array | number[]) => [
  (field << 3) | 2,
  ...varint(BigInt(bytes.length)),
  ...bytes,
];
const intField = (field: number, value: bigint) =>
  value === 0n ? [] : [(field << 3) | 0, ...varint(value)];

/** mx-chain-go's protobuf `Transaction` with the signature; blake2b-256 of it is the hash. */
export function transferProto(input: MultiversxTx, signature: Uint8Array): Uint8Array {
  const { tx, from, to, value } = check(input);
  if (signature.length !== 64) throw new Error('Signature must be 64 bytes');
  // A 0x00 sign byte, then the minimal big-endian magnitude.
  const hex = value.toString(16);
  const magnitude = hexToBytes(hex.length % 2 ? `0${hex}` : hex);
  return Uint8Array.from([
    ...intField(1, BigInt(tx.nonce)),
    ...bytesField(2, [0, ...magnitude]),
    ...bytesField(3, to),
    ...bytesField(5, from),
    ...intField(7, BigInt(tx.gasPrice)),
    ...intField(8, BigInt(tx.gasLimit)),
    ...bytesField(10, new TextEncoder().encode(PROTOCOL_CHAIN_ID)),
    ...intField(11, BigInt(VERSION)),
    ...bytesField(12, signature),
  ]);
}

export function transferHash(tx: MultiversxTx, signature: Uint8Array): string {
  return bytesToHex(blake2b(transferProto(tx, signature), { dkLen: 32 }));
}

export function transferFee(tx: Pick<MultiversxTx, 'gasLimit' | 'gasPrice'>): bigint {
  // Without data the move-balance cost is the whole gas limit at full price.
  return BigInt(tx.gasLimit) * BigInt(tx.gasPrice);
}

export async function prepareMultiversx(
  adapter: MultiversxAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: MultiversxTx; simulation: Simulation }> {
  if (
    intent.chainId !== MULTIVERSX_DEVNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${MULTIVERSX_DEVNET}:native`
  )
    throw new Error('Only native EGLD transfers on Devnet are enabled');
  return adapter.withNode(intent.chainId, async (node) => {
    const [config, sender] = await Promise.all([node.config(), node.account(from)]);
    if (sender.address !== from) throw new Error('Endpoint returned a different account');
    const gasLimit = config.erd_min_gas_limit;
    const gasPrice = config.erd_min_gas_price;
    if (gasLimit < MIN_GAS_LIMIT || gasLimit > MAX_GAS_LIMIT)
      throw new Error('Network minimum gas limit is outside the transfer bounds');
    if (gasPrice < MIN_GAS_PRICE || gasPrice > MAX_GAS_PRICE)
      throw new Error('Network minimum gas price is outside the transfer bounds');
    const unsigned = MultiversxTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      attoegld: intent.amount,
      nonce: sender.nonce,
      gasPrice,
      gasLimit,
    });
    signingJson(unsigned);
    const fee = transferFee(unsigned);
    let error: string | undefined;
    if (BigInt(sender.balance) < BigInt(intent.amount) + fee)
      error = 'Balance does not cover the transfer and fee';
    const warnings: Simulation['warnings'] = [];
    if (isMultiversxContract(intent.to))
      warnings.push({ kind: 'destinationIsContract', address: intent.to });
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

/** Usable while the sender's nonce has not moved past the prepared one. */
export async function multiversxApprovalValid(
  adapter: MultiversxAdapter,
  tx: MultiversxTx,
): Promise<boolean> {
  return adapter.withNode(tx.chainId, async (node) => {
    const [config, account] = await Promise.all([node.config(), node.account(tx.from)]);
    return (
      account.address === tx.from &&
      account.nonce === tx.nonce &&
      tx.gasPrice >= config.erd_min_gas_price &&
      tx.gasLimit >= config.erd_min_gas_limit
    );
  });
}

const SignedWire = z.strictObject({
  nonce: z.number().int().nonnegative(),
  value: z.string(),
  receiver: z.string(),
  sender: z.string(),
  gasPrice: z.number().int(),
  gasLimit: z.number().int(),
  chainID: z.string(),
  version: z.number().int(),
  signature: z.string().regex(/^[0-9a-f]{128}$/),
});

/**
 * Broadcast only JSON that is exactly the ledger's transfer plus a signature
 * that verifies against the sender over the canonical signing bytes.
 */
export async function broadcastMultiversx(
  adapter: MultiversxAdapter,
  tx: MultiversxTx,
  signedJson: string,
): Promise<string> {
  if (tx.chainId !== MULTIVERSX_DEVNET) throw new Error('Only Devnet broadcasts are enabled');
  const message = signingJson(tx);
  let wire: z.infer<typeof SignedWire>;
  try {
    wire = SignedWire.parse(JSON.parse(signedJson));
  } catch {
    throw new Error('Signed bytes are not this EGLD transfer');
  }
  const { signature, ...unsigned } = wire;
  if (JSON.stringify(unsigned) !== message)
    throw new Error('Signed bytes are not this EGLD transfer');
  const sig = hexToBytes(signature);
  const pub = multiversxAddressBytes(tx.from)!;
  if (!ed25519.verify(sig, new TextEncoder().encode(message), pub, { zip215: false }))
    throw new Error('Signature does not verify against the sender');
  const hash = transferHash(tx, sig);
  const res = await adapter.withNode(tx.chainId, (node) => node.send(wire));
  if ('rejected' in res) {
    // A retry of a transfer the network already holds is not a failure.
    const known = await adapter.status(hash, tx.chainId).catch(() => undefined);
    if (known && known.state !== 'unknown') return hash;
    throw new Error(`Broadcast rejected: ${res.rejected}`);
  }
  if (res.hash !== hash) throw new Error('Node reported a different transaction hash');
  return hash;
}

/**
 * MultiversX transactions never expire, but once the sender's nonce moves past
 * this one without it, it can no longer land. Only a gateway (the node's own
 * view) is trusted to say a hash is absent; the API's index lags execution.
 */
export async function multiversxTransferStatus(
  adapter: MultiversxAdapter,
  tx: MultiversxTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const value = hash.toLowerCase();
  const verdict = await adapter.withKind(tx.chainId, 'gateway', async (node) => {
    const account = await node.account(tx.from);
    if (account.nonce <= tx.nonce) return status;
    const again = toStatus(value, await node.transaction(value));
    return again.state === 'unknown' ? { state: 'expired' as const } : again;
  });
  return verdict ?? status;
}
