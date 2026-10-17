import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { Builder, Cell, parseBoc, serializeBoc } from './cell.js';
import {
  SUBWALLET_ID,
  TON_TESTNET,
  TonAdapter,
  friendlyAddress,
  normalizeTonAddress,
  normalizedMessageHash,
  parseTonAddress,
  shortReason,
  tonWalletHash,
  walletStateInit,
} from './ton.js';

const equalBytes = (a: Uint8Array, b: Uint8Array) => bytesToHex(a) === bytesToHex(b);
const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
/** Pay forward fees from the wallet balance, and ignore action-phase errors. */
export const SEND_MODE = 3;
/** The core refuses a `validUntil` more than a day after the build time. */
export const MAX_LIFETIME_S = 24 * 60 * 60;
const LIFETIME_S = 30 * 60;
/**
 * Fee bounds for one v4r2 transfer on the basechain: the external message's
 * import and compute, the internal message's forward fee, and storage. A
 * deploying message also pays for the wallet code and data. The real charge
 * is a fraction of these.
 */
export const FEE_BOUND_NANOTON = 10_000_000n;
export const DEPLOY_FEE_BOUND_NANOTON = 30_000_000n;

/** Mirrors `ton::TonTx` in the core; the core re-checks every field. */
export const TonTx = z.strictObject({
  chainId: z.literal(TON_TESTNET),
  from: z.string().regex(/^[A-Za-z0-9_-]{48}$/),
  to: z
    .string()
    .max(66)
    .refine((s) => parseTonAddress(s) !== undefined, 'Invalid TON address'),
  nanoton: z.string().regex(/^[0-9]{1,20}$/),
  seqno: z.number().int().min(0).max(U32_MAX),
  validUntil: z.number().int().positive().max(U32_MAX),
  builtAt: z.number().int().positive().max(U32_MAX),
  bounce: z.boolean(),
  deploy: z.boolean(),
});
export type TonTx = z.infer<typeof TonTx>;

interface Checked {
  from: Uint8Array;
  to: Uint8Array;
  amount: bigint;
}

/** The same refusals as the core's `TonTx::checked`. */
function checked(input: TonTx): Checked {
  const tx = TonTx.parse(input);
  const from = parseTonAddress(tx.from);
  if (!from || friendlyAddress(from.hash, { bounceable: false, testOnly: true }) !== tx.from)
    throw new Error('Sender must be the non-bounceable testnet spelling');
  const to = parseTonAddress(tx.to)!;
  if (equalBytes(from.hash, to.hash)) throw new Error('Sender and recipient must differ');
  const amount = BigInt(tx.nanoton);
  if (amount <= 0n || amount > U64_MAX || amount.toString() !== tx.nanoton)
    throw new Error('Amount must be a positive canonical integer');
  if (tx.deploy && tx.seqno !== 0) throw new Error('Only a wallet at seqno 0 can be deployed');
  if (tx.validUntil <= tx.builtAt || tx.validUntil - tx.builtAt > MAX_LIFETIME_S)
    throw new Error('validUntil must fall within a day of the build time');
  return { from: from.hash, to: to.hash, amount };
}

function internalMessage(c: Checked, bounce: boolean): Cell {
  // int_msg_info$0 ihr_disabled bounce bounced src:addr_none dest value
  // ihr_fee fwd_fee created_lt created_at, init:nothing, body:inline empty
  return new Builder()
    .bit(false)
    .bit(true)
    .bit(bounce)
    .bit(false)
    .uint(0, 2)
    .address(c.to)
    .coins(c.amount)
    .bit(false)
    .coins(0n)
    .coins(0n)
    .uint(0, 64)
    .uint(0, 32)
    .bit(false)
    .bit(false)
    .build();
}

function signingCell(tx: TonTx): Cell {
  const c = checked(tx);
  return new Builder()
    .uint(SUBWALLET_ID, 32)
    .uint(tx.validUntil, 32)
    .uint(tx.seqno, 32)
    .uint(0, 8)
    .uint(SEND_MODE, 8)
    .ref(internalMessage(c, tx.bounce))
    .build();
}

/** The 32 bytes Ed25519 signs: the hash of the wallet's signing cell. */
export function tonSigningHash(tx: TonTx): Uint8Array {
  return signingCell(tx).hash;
}

interface External {
  message: Cell;
  body: Cell;
  initRef: boolean;
  bodyRef: boolean;
}

/** The external message `@ton/core` storeMessage lays out for this signature. */
function external(tx: TonTx, publicKey: Uint8Array, signature: Uint8Array): External {
  const c = checked(tx);
  const signing = signingCell(tx);
  const body = new Builder().bytes(signature).append(signing).build();
  // ext_in_msg_info$10 src:addr_none dest import_fee:0
  const ext = new Builder().uint(0b10, 2).uint(0, 2).address(c.from).coins(0n);
  let initRef = false;
  if (tx.deploy) {
    const init = walletStateInit(publicKey);
    ext.bit(true);
    initRef = 1023 - ext.bits - 2 < init.bits + body.bits;
    if (initRef) ext.bit(true).ref(init);
    else ext.bit(false).append(init);
  } else {
    ext.bit(false);
  }
  const bodyRef = 1023 - ext.bits - 1 < body.bits || ext.refs.length + body.refs.length > 4;
  if (bodyRef) ext.bit(true).ref(body);
  else ext.bit(false).append(body);
  return { message: ext.build(), body, initRef, bodyRef };
}

/** BoC (`0x` hex) and normalized message hash, byte for byte what the core assembles. */
export function tonExternalMessage(
  tx: TonTx,
  publicKey: Uint8Array,
  signature: Uint8Array,
): { boc: string; hash: string } {
  if (publicKey.length !== 32 || signature.length !== 64)
    throw new Error('Ed25519 key or signature has the wrong length');
  const { message, body } = external(tx, publicKey, signature);
  return {
    boc: `0x${bytesToHex(serializeBoc(message))}`,
    hash: normalizedMessageHash(checked(tx).from, body),
  };
}

export async function prepareTon(
  adapter: TonAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: TonTx; simulation: Simulation }> {
  if (
    intent.chainId !== TON_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${TON_TESTNET}:native`
  )
    throw new Error('Only native TON transfers on testnet are enabled');
  const fromRaw = normalizeTonAddress(from);
  const to = parseTonAddress(intent.to);
  const toRaw = normalizeTonAddress(intent.to);
  if (!fromRaw || !to || !toRaw || fromRaw === toRaw)
    throw new Error('Invalid TON sender or recipient');
  return adapter.withNode(intent.chainId, async (node) => {
    const sender = await node.account(fromRaw);
    if (sender.status === 'frozen') throw new Error('The sending wallet is frozen');
    const seqno = sender.status === 'active' ? await node.seqno(fromRaw) : 0;
    const recipient = await node.account(toRaw);
    const deploy = sender.status !== 'active';
    // Value sent to an inactive account with bounce set returns to the sender, minus fees.
    const bounce = recipient.status === 'active' && (to.bounceable ?? true);
    const builtAt = Math.floor(now / 1000);
    const unsigned = TonTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      nanoton: intent.amount,
      seqno,
      validUntil: builtAt + LIFETIME_S,
      builtAt,
      bounce,
      deploy,
    });
    checked(unsigned);
    const fee = deploy ? DEPLOY_FEE_BOUND_NANOTON : FEE_BOUND_NANOTON;
    let error: string | undefined;
    if (sender.balance < BigInt(intent.amount) + fee)
      error = 'Balance does not cover the transfer plus the network fee bound';
    const warnings: Simulation['warnings'] = [
      {
        kind: 'other',
        message:
          'The fee shown is an upper bound; the wallet pays only the forward, compute and storage fees actually charged.',
      },
    ];
    if (deploy)
      warnings.push({
        kind: 'other',
        message:
          'This wallet contract is not deployed yet; this first transfer deploys it and pays for its code and data.',
      });
    if (recipient.status !== 'active')
      warnings.push({
        kind: 'other',
        message:
          'The recipient account is not active; the transfer is sent non-bounceable, so a mistyped address cannot return the funds.',
      });
    if (to.testOnly === false)
      warnings.push({
        kind: 'other',
        message: 'The recipient address is spelled for mainnet; check that it is a testnet wallet.',
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
 * Approval is refused once the message could expire before it lands, or once
 * the wallet's seqno or deployment no longer match the transfer.
 */
export async function tonApprovalValid(
  adapter: TonAdapter,
  tx: TonTx,
  now = Date.now(),
): Promise<boolean> {
  if (now / 1000 > tx.validUntil - 60) return false;
  const fromRaw = normalizeTonAddress(tx.from);
  if (!fromRaw) return false;
  return adapter.withNode(tx.chainId, async (node) => {
    const account = await node.account(fromRaw);
    const active = account.status === 'active';
    if (active === tx.deploy) return false;
    return (active ? await node.seqno(fromRaw) : 0) === tx.seqno;
  });
}

/** The signature and, for a deploying message, the key inside a BoC laid out as `external` lays it out. */
function extract(tx: TonTx, root: Cell): { signature: Uint8Array; publicKey?: Uint8Array } {
  const layout = external(tx, new Uint8Array(32), new Uint8Array(64));
  if (root.bits !== layout.message.bits || root.refs.length !== layout.message.refs.length)
    throw new Error('Signed bytes are not this TON transfer');
  // ext_in_msg_info is 2 + 2 + 267 + 4 bits, then the init flag.
  let at = 276;
  let publicKey: Uint8Array | undefined;
  if (tx.deploy) {
    at += 1;
    const data = layout.initRef ? root.refs[0]?.refs[1] : root.refs[1];
    if (!data || data.bits !== 321) throw new Error('Signed bytes are not this TON transfer');
    publicKey = data.bytes(64, 32);
    if (!layout.initRef) at += walletStateInit(publicKey).bits;
  }
  at += 1;
  const signature = layout.bodyRef
    ? root.refs[root.refs.length - 1]!.bytes(0, 64)
    : root.bytes(at, 64);
  return { signature, ...(publicKey ? { publicKey } : {}) };
}

/**
 * Broadcast only a BoC that is exactly this transfer's external message,
 * signed by the key that owns the sending wallet. The returned hash is the
 * normalized message hash (TEP-467), which `status` and explorers resolve.
 */
export async function broadcastTon(
  adapter: TonAdapter,
  tx: TonTx,
  bocHex: string,
): Promise<string> {
  if (tx.chainId !== TON_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const c = checked(tx);
  const hex = bocHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0 || hex.length > 1 << 14)
    throw new Error('Signed bytes are not this TON transfer');
  const bytes = hexToBytes(hex);
  let root: Cell;
  try {
    root = parseBoc(bytes);
  } catch {
    throw new Error('Signed bytes are not this TON transfer');
  }
  const { signature, publicKey: embedded } = extract(tx, root);
  const fromRaw = normalizeTonAddress(tx.from)!;
  return adapter.withNode(tx.chainId, async (node) => {
    const publicKey = embedded ?? (await node.publicKey(fromRaw));
    if (!publicKey) throw new Error('The sending wallet reports no public key');
    if (!equalBytes(tonWalletHash(publicKey), c.from))
      throw new Error('Signing key is not the sender wallet');
    const rebuilt = tonExternalMessage(tx, publicKey, signature);
    if (rebuilt.boc !== `0x${hex}`) throw new Error('Signed bytes are not this TON transfer');
    if (!ed25519.verify(signature, tonSigningHash(tx), publicKey, { zip215: false }))
      throw new Error('Signature does not verify against the sender');
    const res = await node.send(base64.encode(bytes));
    if (res.accepted) return rebuilt.hash;
    // A retry of an applied message meets a used seqno (exit code 33) or a duplicate.
    if (/exit ?code[=: ]*33\b|duplicate|already/i.test(res.error)) {
      const seen = await node.transaction(rebuilt.hash);
      if (seen) return rebuilt.hash;
    }
    throw new Error(`Broadcast rejected: ${shortReason(res.error)}`);
  });
}

/**
 * Expiry is reported once `validUntil` passed or the wallet's seqno moved past
 * this transfer's, and the message hash is still absent.
 */
export async function tonTransferStatus(
  adapter: TonAdapter,
  tx: TonTx,
  hash: string,
  now = Date.now(),
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const fromRaw = normalizeTonAddress(tx.from);
  if (!fromRaw) return status;
  const dead = await adapter.withNode(tx.chainId, async (node) => {
    if (now / 1000 > tx.validUntil + 60) return true;
    const account = await node.account(fromRaw);
    return account.status === 'active' && (await node.seqno(fromRaw)) > tx.seqno;
  });
  if (!dead) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
