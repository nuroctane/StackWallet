import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import { TronTx, type TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { Block, decodeMessage, tronAddressBytes, type TronAdapter } from './tron.js';

export const TRON_NILE = 'tron:0xcd8690dc';
const TRANSFER_TYPE_URL = 'type.googleapis.com/protocol.TransferContract';
const MAX_EXPIRATION_MS = 24 * 60 * 60 * 1000;
/** Long enough to review and approve; the reference block stays valid for far longer. */
const LIFETIME_MS = 30 * 60 * 1000;
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

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
const intField = (field: number, value: bigint) => [(field << 3) | 0, ...varint(value)];

/** The same `Transaction.raw` protobuf the core encodes independently from checked fields. */
export function transferRawData(input: TronTx): Uint8Array {
  const tx = TronTx.parse(input);
  const from = tronAddressBytes(tx.from);
  const to = tronAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid TRX sender or recipient');
  const amount = BigInt(tx.sun);
  if (amount <= 0n || amount > 0x7fffffffffffffffn || amount.toString() !== tx.sun)
    throw new Error('TRX amount must be a positive int64 of sun');
  if (
    tx.expiration <= tx.timestamp ||
    tx.expiration - tx.timestamp > MAX_EXPIRATION_MS ||
    /^0+$/.test(tx.refBlockHash)
  )
    throw new Error('Invalid TRX reference block or expiration');
  const transfer = [...bytesField(1, from), ...bytesField(2, to), ...intField(3, amount)];
  const any = [
    ...bytesField(1, new TextEncoder().encode(TRANSFER_TYPE_URL)),
    ...bytesField(2, transfer),
  ];
  const contract = [...intField(1, 1n), ...bytesField(2, any)];
  return Uint8Array.from([
    ...bytesField(1, hexToBytes(tx.refBlockBytes)),
    ...bytesField(4, hexToBytes(tx.refBlockHash)),
    ...intField(8, BigInt(tx.expiration)),
    ...bytesField(11, contract),
    ...intField(14, BigInt(tx.timestamp)),
  ]);
}

export function transferTxId(tx: TronTx): string {
  return bytesToHex(sha256(transferRawData(tx)));
}

const ChainParameters = z.object({
  chainParameter: z
    .array(z.object({ key: z.string().max(64), value: SafeInt.optional() }))
    .max(256),
});
const Resource = z.object({
  freeNetLimit: SafeInt.optional(),
  freeNetUsed: SafeInt.optional(),
  NetLimit: SafeInt.optional(),
  NetUsed: SafeInt.optional(),
});
const AccountInfo = z.object({
  balance: z.union([SafeInt, z.string().regex(/^\d{1,19}$/)]).optional(),
  type: z.string().max(32).optional(),
  address: z.string().optional(),
});

export async function prepareTron(
  adapter: TronAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: TronTx; simulation: Simulation }> {
  if (
    intent.chainId !== TRON_NILE ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${TRON_NILE}:native`
  )
    throw new Error('Only native TRX transfers on Nile are enabled');
  return adapter.withNode(intent.chainId, async (call) => {
    const head = await call('/wallet/getnowblock', {}, Block);
    const number = head.block_header.raw_data.number;
    const headTs = head.block_header.raw_data.timestamp;
    if (number === undefined || headTs === undefined)
      throw new Error('Node did not report a head block');
    const unsigned = TronTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      sun: intent.amount,
      refBlockBytes: number.toString(16).padStart(16, '0').slice(12, 16),
      refBlockHash: head.blockID.slice(16, 32),
      timestamp: now,
      expiration: Math.max(headTs, now) + LIFETIME_MS,
    });
    const raw = transferRawData(unsigned);
    const [params, resource, sender, recipient] = await Promise.all([
      call('/wallet/getchainparameters', {}, ChainParameters),
      call('/wallet/getaccountresource', { address: from, visible: true }, Resource),
      call('/wallet/getaccount', { address: from, visible: true }, AccountInfo),
      call('/wallet/getaccount', { address: intent.to, visible: true }, AccountInfo),
    ]);
    const param = (key: string, fallback: number) =>
      BigInt(params.chainParameter.find((p) => p.key === key)?.value ?? fallback);
    // Signed size plus the 64-byte result allowance java-tron charges bandwidth for.
    const bytes = BigInt(raw.length + 3 + 67 + 64);
    const staked = BigInt((resource.NetLimit ?? 0) - (resource.NetUsed ?? 0));
    const free = BigInt((resource.freeNetLimit ?? 0) - (resource.freeNetUsed ?? 0));
    const activates = recipient.address === undefined;
    let fee: bigint;
    if (activates) {
      // Account creation cannot use free bandwidth: staked bandwidth or a flat burn.
      fee =
        param('getCreateNewAccountFeeInSystemContract', 1_000_000) +
        (staked >= bytes ? 0n : param('getCreateAccountFee', 100_000));
    } else {
      fee = staked >= bytes || free >= bytes ? 0n : bytes * param('getTransactionFee', 1000);
    }
    const balance = BigInt(sender.balance ?? 0);
    let error: string | undefined;
    if (sender.address === undefined) error = 'Sender account is not activated on Nile';
    else if (balance < BigInt(intent.amount) + fee)
      error = 'Balance does not cover the transfer and fee';
    const warnings: Simulation['warnings'] = [];
    if (recipient.type === 'Contract')
      warnings.push({ kind: 'destinationIsContract', address: intent.to });
    if (activates)
      warnings.push({
        kind: 'other',
        message:
          'The recipient has no Tron account yet; this transfer activates it and burns the activation fee.',
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

/** Approval is refused once the network could drop the transaction before it lands. */
export async function tronApprovalValid(
  adapter: TronAdapter,
  tx: TronTx,
  now = Date.now(),
): Promise<boolean> {
  if (now > tx.expiration - 60_000) return false;
  const head = await adapter.withNode(tx.chainId, (call) => call('/wallet/getnowblock', {}, Block));
  const ts = head.block_header.raw_data.timestamp;
  return ts !== undefined && ts < tx.expiration - 60_000;
}

const Broadcast = z.object({
  result: z.boolean().optional(),
  txid: z.string().optional(),
  code: z.string().max(64).optional(),
  message: z.string().max(4096).optional(),
});

/** Broadcast only bytes that are exactly the ledger's transfer plus one 65-byte signature. */
export async function broadcastTron(
  adapter: TronAdapter,
  tx: TronTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== TRON_NILE) throw new Error('Only Nile broadcasts are enabled');
  const raw = transferRawData(tx);
  const expected = bytesToHex(Uint8Array.from([...bytesField(1, raw), 0x12, 65]));
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expected.length + 130 || !hex.startsWith(expected))
    throw new Error('Signed bytes are not this TRX transfer');
  const txid = transferTxId(tx);
  const res = await adapter.withNode(tx.chainId, (call) =>
    call('/wallet/broadcasthex', { transaction: hex }, Broadcast),
  );
  if (res.result !== true) {
    // A retry of an accepted transfer is not a failure.
    if (res.code === 'DUP_TRANSACTION_ERROR') return txid;
    throw new Error(
      `Broadcast rejected: ${res.code ?? 'error'} ${decodeMessage(res.message ?? '')}`.trim(),
    );
  }
  if (res.txid !== undefined && res.txid !== txid)
    throw new Error('Node reported a different transaction id');
  return txid;
}

/** Expiry is reported only once a solidified block is past the expiration and the id is absent. */
export async function tronTransferStatus(
  adapter: TronAdapter,
  tx: TronTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const solid = await adapter.withNode(tx.chainId, (call) =>
    call('/walletsolidity/getnowblock', {}, Block),
  );
  const ts = solid.block_header.raw_data.timestamp;
  if (ts === undefined || ts <= tx.expiration) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
