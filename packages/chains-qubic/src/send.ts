/**
 * Qubic send path. Qubic transfers are fee-free and expire by tick: the
 * network ignores a transaction once its target tick passes, so approval is
 * refused when too few ticks remain and expiry is reported once the tick has
 * gone by without execution.
 */
import { base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';

import {
  DEFAULT_TICK_OFFSET,
  MAX_TICK,
  MIN_REMAINING_TICKS,
  QUBIC_FEE,
  QUBIC_MAINNET,
  QubicAdapter,
  isValidQubicIdentity,
  qubicIdentityBytes,
  qubicTxId,
} from './qubic.js';

/** The transfer fields exactly as the Rust `QubicTx` struct expects them. */
export interface QubicUnsignedTx {
  chainId: string;
  from: string;
  to: string;
  qu: string;
  tick: number;
}

/** The 80 bytes the core signs: source || dest || amount i64le || tick u32le || 0 || 0. */
export function qubicRawBytes(tx: QubicUnsignedTx): Uint8Array {
  const from = qubicIdentityBytes(tx.from);
  const to = qubicIdentityBytes(tx.to);
  if (!from || !to) throw new Error('Invalid Qubic identity');
  const amount = BigInt(tx.qu);
  if (amount <= 0n || amount > BigInt('9223372036854775807')) throw new Error('Invalid amount');
  if (!Number.isInteger(tx.tick) || tx.tick <= 0 || tx.tick > MAX_TICK)
    throw new Error('Invalid tick');
  const raw = new Uint8Array(80);
  raw.set(from, 0);
  raw.set(to, 32);
  new DataView(raw.buffer).setBigUint64(64, amount, true);
  new DataView(raw.buffer).setUint32(72, tx.tick, true);
  return raw;
}

export async function prepareQubic(
  adapter: QubicAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: QubicUnsignedTx; simulation: Simulation }> {
  if (
    intent.chainId !== QUBIC_MAINNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${QUBIC_MAINNET}:native`
  )
    throw new Error('Only native QU transfers on Qubic mainnet are enabled');
  if (!isValidQubicIdentity(from) || !isValidQubicIdentity(intent.to))
    throw new Error('Invalid Qubic identity');
  if (from === intent.to) throw new Error('Sender and recipient must differ');
  const head = await adapter.tickInfo(intent.chainId);
  const tick = head.tick + DEFAULT_TICK_OFFSET;
  const unsigned: QubicUnsignedTx = {
    chainId: intent.chainId,
    from,
    to: intent.to,
    qu: intent.amount,
    tick,
  };
  qubicRawBytes(unsigned); // field validation before the core ever sees them
  const [sender] = await adapter.getBalances(from, intent.chainId);
  const balance = BigInt(sender?.amount ?? '0');
  const amount = BigInt(intent.amount);
  const error = balance < amount ? 'Balance does not cover the transfer' : undefined;
  return {
    unsigned,
    simulation: {
      ok: error === undefined,
      assetDeltas: [{ assetRef: intent.asset, amount: `-${intent.amount}` }],
      fee: { assetRef: intent.asset, amount: QUBIC_FEE },
      warnings: [],
      ...(error ? { error } : {}),
    },
  };
}

/** Approval is refused once the target tick is too close to broadcast safely. */
export async function qubicApprovalValid(
  adapter: QubicAdapter,
  unsigned: QubicUnsignedTx,
): Promise<boolean> {
  const head = await adapter.tickInfo(unsigned.chainId as TxIntent['chainId']);
  return unsigned.tick - head.tick >= MIN_REMAINING_TICKS;
}

/** Broadcast only a 144-byte package whose first 80 bytes are exactly this transfer. */
export async function broadcastQubic(
  adapter: QubicAdapter,
  unsigned: QubicUnsignedTx,
  signedWireBase64: string,
): Promise<string> {
  if (unsigned.chainId !== QUBIC_MAINNET) throw new Error('Only mainnet broadcasts are enabled');
  const pkg = base64.decode(signedWireBase64);
  const expected = qubicRawBytes(unsigned);
  if (pkg.length !== 144 || expected.some((b, i) => pkg[i] !== b))
    throw new Error('Signed bytes are not this QU transfer');
  const txid = qubicTxId(pkg);
  const res = await adapter.broadcastRaw(unsigned.chainId, signedWireBase64);
  if (res.transactionId !== undefined && res.transactionId !== txid)
    throw new Error('Node reported a different transaction id');
  return txid;
}

/** Tick-based expiry: once the target tick passes without execution, the tx is dead. */
export async function qubicTransferStatus(
  adapter: QubicAdapter,
  unsigned: QubicUnsignedTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, unsigned.chainId as TxIntent['chainId']);
  if (status.state !== 'unknown') return status;
  const head = await adapter.tickInfo(unsigned.chainId as TxIntent['chainId']);
  if (head.tick <= unsigned.tick) return { state: 'pending' };
  const again = await adapter.status(hash, unsigned.chainId as TxIntent['chainId']);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
