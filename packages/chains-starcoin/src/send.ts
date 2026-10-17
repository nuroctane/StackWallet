import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { JsonRpcError, type Simulation, type TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  AccountResource,
  Block,
  ChainInfoResult,
  GasPrice,
  NextSequence,
  RawResource,
  STARCOIN_BARNARD,
  starcoinAddressBytes,
  starcoinAddressFromPublicKey,
  type StarcoinAdapter,
} from './starcoin.js';

const SafeUint = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const StarcoinAddress = z.string().regex(/^0x[0-9a-f]{32}$/);
/** Mirrors the Rust `StarcoinTx` struct field for field. */
export const StarcoinTx = z.strictObject({
  chainId: z.literal(STARCOIN_BARNARD),
  from: StarcoinAddress,
  to: StarcoinAddress,
  nano: z.string().regex(/^\d{1,39}$/),
  sequenceNumber: SafeUint,
  maxGasAmount: z.number().int().min(1).max(50_000_000),
  gasUnitPrice: z.number().int().min(1).max(1_000_000),
  expirationTimestampSecs: z.number().int().positive().max(4_102_444_800),
});
export type StarcoinTx = z.infer<typeof StarcoinTx>;

/** Long enough to review and approve; the node drops the tx afterwards. */
const LIFETIME_SECS = 30 * 60;
/** Conservative cap for a bare STC transfer (actual usage is a few hundred gas). */
const MAX_GAS_AMOUNT = 4_000_000;
const GAS_TOKEN_CODE = '0x1::STC::STC';
const CORE_ADDRESS = hexToBytes('00'.repeat(15) + '01');

function uleb128(len: number): number[] {
  const out: number[] = [];
  let v = len;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v > 0) byte |= 0x80;
    out.push(byte);
  } while (v > 0);
  return out;
}
function pushBytes(out: number[], bytes: Uint8Array): void {
  out.push(...uleb128(bytes.length), ...bytes);
}
function pushStr(out: number[], s: string): void {
  pushBytes(out, new TextEncoder().encode(s));
}
function le64(value: bigint): number[] {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) out.push(Number((value >> BigInt(i * 8)) & 0xffn));
  return out;
}

function prefixHash(name: string): Uint8Array {
  return sha3_256(new TextEncoder().encode(`STARCOIN::${name}`));
}

/** The same BCS `RawUserTransaction` the core encodes independently from checked fields. */
export function rawUserTransactionBytes(input: StarcoinTx): Uint8Array {
  const tx = StarcoinTx.parse(input);
  const from = starcoinAddressBytes(tx.from);
  const to = starcoinAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid STC sender or recipient');
  const amount = BigInt(tx.nano);
  if (amount <= 0n || amount.toString() !== tx.nano)
    throw new Error('STC amount must be a positive canonical integer of nano');
  const out: number[] = [...from, ...le64(BigInt(tx.sequenceNumber))];
  out.push(2); // TransactionPayload::ScriptFunction
  out.push(...CORE_ADDRESS);
  pushStr(out, 'TransferScripts');
  pushStr(out, 'peer_to_peer_with_metadata_v2');
  out.push(...uleb128(1)); // one type arg
  out.push(7); // TypeTag::Struct
  out.push(...CORE_ADDRESS);
  pushStr(out, 'STC');
  pushStr(out, 'STC');
  out.push(0); // no nested type params
  out.push(...uleb128(3)); // args: payee, amount, empty metadata
  pushBytes(out, to);
  const amountBytes = new Uint8Array(16);
  let rest = amount;
  for (let i = 0; i < 16; i++) {
    amountBytes[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  pushBytes(out, amountBytes);
  pushBytes(out, new Uint8Array(0));
  out.push(...le64(BigInt(tx.maxGasAmount)));
  out.push(...le64(BigInt(tx.gasUnitPrice)));
  pushStr(out, GAS_TOKEN_CODE);
  out.push(...le64(BigInt(tx.expirationTimestampSecs)));
  out.push(251); // Barnard chain id
  return Uint8Array.from(out);
}

/** The message ed25519 signs: prefix hash || BCS raw transaction. */
export function signingMessage(tx: StarcoinTx): Uint8Array {
  const raw = rawUserTransactionBytes(tx);
  const msg = new Uint8Array(32 + raw.length);
  msg.set(prefixHash('RawUserTransaction'));
  msg.set(raw, 32);
  return msg;
}

/** sha3-256 of the signing message: the raw transaction's crypto id. */
export function rawTransactionId(tx: StarcoinTx): string {
  return `0x${bytesToHex(sha3_256(signingMessage(tx)))}`;
}

/**
 * Rebuild and verify the exact signed bytes for `tx`: raw || authenticator
 * variant 0 || pubkey || signature, where the pubkey must derive `tx.from`.
 */
export function signedWireBytes(tx: StarcoinTx, signedHex: string): Uint8Array {
  const hex = signedHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) throw new Error('Signed bytes are not hex');
  const wire = hexToBytes(hex);
  const raw = rawUserTransactionBytes(tx);
  const expectedLength = raw.length + 1 + 1 + 32 + 1 + 64;
  if (wire.length !== expectedLength) throw new Error('Signed bytes have the wrong length');
  if (bytesToHex(wire.subarray(0, raw.length)) !== bytesToHex(raw))
    throw new Error('Signed bytes are not this STC transfer');
  let offset = raw.length;
  if (wire[offset++] !== 0) throw new Error('Not an Ed25519 authenticator');
  if (wire[offset++] !== 32) throw new Error('Malformed public key');
  const publicKey = wire.subarray(offset, offset + 32);
  offset += 32;
  if (starcoinAddressFromPublicKey(publicKey) !== tx.from)
    throw new Error('Authenticator key does not own the sender');
  if (wire[offset++] !== 64) throw new Error('Malformed signature');
  return wire;
}

export function signedTxHash(signedWire: Uint8Array): string {
  const msg = new Uint8Array(32 + signedWire.length);
  msg.set(prefixHash('SignedUserTransaction'));
  msg.set(signedWire, 32);
  return `0x${bytesToHex(sha3_256(msg))}`;
}

const SubmitResult = z.union([z.string().max(128), z.null(), z.boolean()]);

async function accountSequence(call: (m: string, p: unknown[]) => Promise<unknown>, from: string) {
  try {
    const res = AccountResource.parse(
      await call('state.get_resource', [from, '0x1::Account::Account', { decode: true }]),
    );
    return { exists: true, sequence: res.json?.sequence_number ?? 0 };
  } catch (err) {
    if (err instanceof JsonRpcError) return { exists: false, sequence: 0 };
    throw err;
  }
}

export async function prepareStarcoin(
  adapter: StarcoinAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: StarcoinTx; simulation: Simulation }> {
  if (
    intent.chainId !== STARCOIN_BARNARD ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${STARCOIN_BARNARD}:native`
  )
    throw new Error('Only native STC transfers on Barnard are enabled');
  if (!starcoinAddressBytes(from)) throw new Error('Invalid sender address');
  return adapter.withNode(intent.chainId, async (call) => {
    const [sender, gasPriceResult, pooled] = await Promise.all([
      accountSequence((m, p) => call(m, p, z.unknown()), from),
      call('txpool.gas_price', [], GasPrice).catch(() => '1'),
      call('txpool.next_sequence_number', [from], NextSequence).catch(() => null),
    ]);
    const gasPrice = BigInt(gasPriceResult) > 0n ? BigInt(gasPriceResult) : 1n;
    const sequenceNumber = BigInt(pooled ?? sender.sequence);
    if (sequenceNumber > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error('Sequence number exceeds the safe range');
    const unsigned = StarcoinTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      nano: intent.amount,
      sequenceNumber: Number(sequenceNumber),
      maxGasAmount: MAX_GAS_AMOUNT,
      gasUnitPrice: Number(gasPrice),
      expirationTimestampSecs: Math.floor(now / 1000) + LIFETIME_SECS,
    });
    const fee = BigInt(unsigned.maxGasAmount) * BigInt(unsigned.gasUnitPrice);
    let balance: bigint | null = null;
    try {
      const res = await call(
        'state.get_resource',
        [from, '0x1::Account::Balance<0x1::STC::STC>'],
        RawResource,
      );
      const bytes = hexToBytes(res.raw.slice(2));
      balance = 0n;
      for (let i = bytes.length - 1; i >= 0; i--) balance = (balance << 8n) | BigInt(bytes[i]!);
    } catch (err) {
      if (!(err instanceof JsonRpcError)) throw err;
    }
    let error: string | undefined;
    if (!sender.exists) error = 'Sender account does not exist on Barnard yet';
    else if (balance !== null && balance < BigInt(intent.amount) + fee)
      error = 'Balance does not cover the transfer and maximum fee';
    const warnings: Simulation['warnings'] = [];
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

/** Approval is refused once the expiration is near or the sequence moved on. */
export async function starcoinApprovalValid(
  adapter: StarcoinAdapter,
  tx: StarcoinTx,
  now = Date.now(),
): Promise<boolean> {
  if (now / 1000 > tx.expirationTimestampSecs - 60) return false;
  return adapter.withNode(tx.chainId, async (call) => {
    const info = await call('chain.info', [], ChainInfoResult);
    const head = Number(info.head.number ?? 0);
    if (head > 0) {
      const block = await call('chain.get_block_by_number', [head], Block);
      const ts = Number(block.header.timestamp ?? 0);
      if (ts > 0 && ts / 1000 > tx.expirationTimestampSecs - 60) return false;
    }
    const sender = await accountSequence((m, p) => call(m, p, z.unknown()), tx.from);
    return sender.exists && sender.sequence === tx.sequenceNumber;
  });
}

/** Broadcast only bytes that are exactly this transfer plus one Ed25519 authenticator. */
export async function broadcastStarcoin(
  adapter: StarcoinAdapter,
  tx: StarcoinTx,
  signedHex: string,
): Promise<string> {
  if (tx.chainId !== STARCOIN_BARNARD) throw new Error('Only Barnard broadcasts are enabled');
  const wire = signedWireBytes(tx, signedHex);
  const txid = signedTxHash(wire);
  await adapter.withNode(tx.chainId, (call) =>
    call('txpool.submit_hex_transaction', [`0x${bytesToHex(wire)}`], SubmitResult),
  );
  return txid;
}

/** Expiry is reported once the head block time is past the expiration and the hash is absent. */
export async function starcoinTransferStatus(
  adapter: StarcoinAdapter,
  tx: StarcoinTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const expired = await adapter.withNode(tx.chainId, async (call) => {
    const info = await call('chain.info', [], ChainInfoResult);
    const head = Number(info.head.number ?? 0);
    if (head === 0) return false;
    const block = await call('chain.get_block_by_number', [head], Block);
    const ts = Number(block.header.timestamp ?? 0);
    return ts > 0 && ts / 1000 > tx.expirationTimestampSecs;
  });
  if (!expired) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
