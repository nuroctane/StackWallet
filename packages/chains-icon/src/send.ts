/**
 * ICON native ICX transfer lifecycle: prepare, approval freshness, broadcast
 * and status. The adapter rebuilds the canonical hash key from the same
 * checked fields the Rust core uses, pins it in tests, and refuses to
 * broadcast a wire object whose fields or signature do not match.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { ICON_LISBON, IconAddress, iconAddressFromPublicKey, type IconAdapter } from './icon.js';

const HexQuantity = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/);
const TxHashHex = z.string().regex(/^0x[0-9a-f]{64}$/);

/** Mirrors the Rust `IconTx` struct field for field (core-client schema is wired by the lead). */
export const IconTx = z.strictObject({
  chainId: z.literal(ICON_LISBON),
  from: IconAddress,
  to: IconAddress,
  loop: z.string().regex(/^[1-9][0-9]{0,26}$/),
  nonce: z.number().int().min(1).max(1_000_000),
  stepLimit: z.number().int().min(100_000).max(25_000_000),
  timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  builtAtMs: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type IconTx = z.infer<typeof IconTx>;

/** A plain ICX transfer always costs exactly the default step price budget. */
const TRANSFER_STEP_LIMIT = 100_000;
/** Governance `getStepPrice` fallback (loop per step); probed live at 0x2e90edd00. */
const FALLBACK_STEP_PRICE = 12_500_000_000n;
const GOVERNANCE = 'cx0000000000000000000000000000000000000001';
/** The node rejects timestamps far from block time; keep the same window as the core. */
const MAX_TIMESTAMP_SKEW_MS = 60 * 60 * 1000;
/** Stop approving while there is still comfortable room before the node window ends. */
const APPROVAL_MARGIN_MS = 60 * 1000;

const hex = (value: bigint | number) => `0x${value.toString(16)}`;

function escape(value: string): string {
  return value.replace(/[\\.{}[\]]/g, (c) => `\\${c}`);
}

/** The canonical `icx_sendTransaction.<k>.<v>...` string; keys sorted, values escaped. */
export function iconHashKey(input: IconTx, signature?: string): string {
  const tx = IconTx.parse(input);
  const pairs: [string, string][] = [
    ['from', tx.from],
    ['nid', tx.chainId === ICON_LISBON ? '0x2' : '0x1'],
    ['nonce', hex(tx.nonce)],
    ['stepLimit', hex(tx.stepLimit)],
    ['timestamp', hex(tx.timestamp)],
    ['to', tx.to],
    ['value', hex(BigInt(tx.loop))],
    ['version', '0x3'],
  ];
  if (signature !== undefined) pairs.push(['signature', signature]);
  pairs.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `icx_sendTransaction.${pairs.map(([k, v]) => `${k}.${escape(v)}`).join('.')}`;
}

/** sha3-256 of the unsigned hash key; the exact digest the core signs. */
export function iconSighashHex(tx: IconTx): string {
  return bytesToHex(sha3_256(new TextEncoder().encode(iconHashKey(tx))));
}

export function iconTxHash(tx: IconTx, signature: string): string {
  return `0x${bytesToHex(sha3_256(new TextEncoder().encode(iconHashKey(tx, signature))))}`;
}

export async function prepareIcon(
  adapter: IconAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: IconTx; simulation: Simulation }> {
  if (
    intent.chainId !== ICON_LISBON ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${ICON_LISBON}:native`
  )
    throw new Error('Only native ICX transfers on Lisbon are enabled');
  return adapter.withNode(intent.chainId, async (call) => {
    const unsigned = IconTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      loop: intent.amount,
      nonce: 1,
      stepLimit: TRANSFER_STEP_LIMIT,
      timestamp: now * 1000,
      builtAtMs: now,
    });
    const [balanceHex, stepPriceHex] = await Promise.all([
      call('icx_getBalance', { address: from }, HexQuantity).catch(() => '0x0'),
      call(
        'icx_call',
        { to: GOVERNANCE, dataType: 'call', data: { method: 'getStepPrice' } },
        HexQuantity,
      ).catch(() => hex(FALLBACK_STEP_PRICE)),
    ]);
    const fee = BigInt(unsigned.stepLimit) * BigInt(stepPriceHex);
    const balance = BigInt(balanceHex);
    let error: string | undefined;
    if (balance === 0n) error = 'Sender holds no ICX on Lisbon';
    else if (balance < BigInt(intent.amount) + fee)
      error = 'Balance does not cover the transfer and fee';
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee}` },
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings: [],
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Approval is refused once the node clock could be outside the timestamp window. */
export async function iconApprovalValid(
  adapter: IconAdapter,
  tx: IconTx,
  now = Date.now(),
): Promise<boolean> {
  if (now > tx.builtAtMs + MAX_TIMESTAMP_SKEW_MS - APPROVAL_MARGIN_MS) return false;
  const head = await adapter.headBlock(tx.chainId);
  return head.timestampMs < tx.timestamp / 1000 + MAX_TIMESTAMP_SKEW_MS - APPROVAL_MARGIN_MS;
}

const WireParams = z.strictObject({
  from: IconAddress,
  to: IconAddress,
  nid: HexQuantity,
  nonce: HexQuantity,
  version: HexQuantity,
  timestamp: HexQuantity,
  stepLimit: HexQuantity,
  value: HexQuantity,
  signature: z.string().regex(/^[A-Za-z0-9+/]{87}=$/),
});

/** Broadcast only a params object that is exactly this transfer, signed by its sender. */
export async function broadcastIcon(
  adapter: IconAdapter,
  input: IconTx,
  wireJson: string,
): Promise<string> {
  const tx = IconTx.parse(input);
  const wire = WireParams.parse(JSON.parse(wireJson));
  const expected: Record<string, string> = {
    from: tx.from,
    to: tx.to,
    nid: tx.chainId === ICON_LISBON ? '0x2' : '0x1',
    nonce: hex(tx.nonce),
    version: '0x3',
    timestamp: hex(tx.timestamp),
    stepLimit: hex(tx.stepLimit),
    value: hex(BigInt(tx.loop)),
  };
  for (const [k, v] of Object.entries(expected)) {
    if ((wire as Record<string, string>)[k] !== v)
      throw new Error(`Signed params differ from this ICX transfer at ${k}`);
  }
  const sig = base64.decode(wire.signature);
  const recovery = sig[64];
  if (sig.length !== 65 || recovery === undefined || recovery > 1)
    throw new Error('Malformed ICON signature');
  const sighash = sha3_256(new TextEncoder().encode(iconHashKey(tx)));
  const recovered = secp256k1.Signature.fromBytes(sig.subarray(0, 64))
    .addRecoveryBit(recovery)
    .recoverPublicKey(sighash);
  if (iconAddressFromPublicKey(recovered.toBytes(false)) !== tx.from)
    throw new Error('Signature does not recover to the sender');
  const hash = iconTxHash(tx, wire.signature);
  try {
    const result = await adapter.withNode(tx.chainId, (call) =>
      call('icx_sendTransaction', { ...wire }, TxHashHex),
    );
    if (result !== hash) throw new Error('Node reported a different transaction hash');
    return result;
  } catch (err) {
    // A retry of an accepted transfer is not a failure.
    if (err instanceof Error && /dup/i.test(err.message)) return hash;
    throw err;
  }
}

/** No on-chain expiry exists; report expired once the timestamp window has clearly passed. */
export async function iconTransferStatus(
  adapter: IconAdapter,
  tx: IconTx,
  hash: string,
  now = Date.now(),
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  if (now > tx.builtAtMs + MAX_TIMESTAMP_SKEW_MS) {
    const again = await adapter.status(hash, tx.chainId);
    return again.state === 'unknown' ? { state: 'expired' } : again;
  }
  return status;
}
