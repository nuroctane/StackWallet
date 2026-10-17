/**
 * The EverWallet native transfer the wallet UI builds, approves and sends —
 * the TS mirror of `crates/stackwallet-core/src/everscale.rs`. The core signs
 * from these checked fields only; the adapter re-derives and byte-verifies
 * the wire BoC before it reaches a node.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { PublicKey, TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { Builder, parseBoc, serializeBoc, type Cell } from './cell.js';
import {
  EVER_WALLET_CODE_HASH,
  VENOM_TESTNET,
  everWalletHash,
  everWalletStateInit,
  intentMatchesEverscaleTx,
  parseEverscaleAddress,
  type EverscaleAdapter,
} from './everscale.js';

const equalBytes = (a: Uint8Array, b: Uint8Array) => bytesToHex(a) === bytesToHex(b);

/** EverWallet `sendTransaction` ABI method id. */
export const SEND_TRANSACTION_ID = 0x4cee646c;
/** send_with_flags: ignore errors (2) + pay fees separately (1). */
export const FLAGS = 3;
/** Wall-clock lifetime of a prepared message. */
export const LIFETIME_MS = 30 * 60 * 1000;

/** Upper bound of what an already-deployed EverWallet pays for one transfer. */
export const FEE_BOUND_EVER = 50_000_000n; // 0.05
/** Upper bound when the message also deploys the wallet contract. */
export const DEPLOY_FEE_BOUND_EVER = 200_000_000n; // 0.2

export const EverscaleTx = z.strictObject({
  chainId: z.literal(VENOM_TESTNET),
  from: z.string().regex(/^0:[0-9a-f]{64}$/),
  to: z.string().regex(/^0:[0-9a-f]{64}$/),
  /** Nano-EVER base units (Venom's decimals: 9). */
  evers: z.string().regex(/^[0-9]{1,20}$/),
  /** Replay watermark: strictly greater than the wallet's stored timestamp. */
  timeMs: z
    .number()
    .int()
    .positive()
    .max(2 ** 53 - 1),
  /** Seconds; the contract refuses the message after it. */
  expireAt: z.number().int().positive().max(0xffffffff),
  /** Wall time the message was built; for display and expiry warnings. */
  builtAtMs: z.number().int().positive(),
  bounce: z.boolean(),
  /** Whether this message carries the wallet's state init. */
  deploy: z.boolean(),
});
export type EverscaleTx = z.infer<typeof EverscaleTx>;

interface Checked {
  from: Uint8Array;
  to: Uint8Array;
  evers: bigint;
}

function checked(input: EverscaleTx): Checked {
  const tx = EverscaleTx.parse(input);
  const from = parseEverscaleAddress(tx.from);
  const to = parseEverscaleAddress(tx.to);
  if (!from || !to) throw new Error('Invalid address in checked fields');
  if (tx.from === tx.to) throw new Error('Self-transfers are not built');
  if (tx.timeMs / 1000 >= tx.expireAt) throw new Error('timeMs is not below expireAt');
  return { from, to, evers: BigInt(tx.evers) };
}

/** `sendTransaction` argument cell: dest, value, bounce, flags, empty payload ref. */
function argsCell(c: Checked, tx: EverscaleTx): Cell {
  return new Builder()
    .address(c.to)
    .uint(c.evers, 128)
    .bit(tx.bounce)
    .uint(FLAGS, 8)
    .ref(new Builder().build()) // empty payload
    .build();
}

/** Everything after the signature bit in the signed body. */
function bodyTail(c: Checked, tx: EverscaleTx, publicKey: Uint8Array): Builder {
  return new Builder()
    .bit(true) // has_pubkey
    .bytes(publicKey)
    .uint(BigInt(tx.timeMs), 64)
    .uint(tx.expireAt, 32)
    .uint(SEND_TRANSACTION_ID, 32)
    .ref(argsCell(c, tx));
}

/**
 * The preimage EverWallet checks: `my address` followed by the body without
 * the signature, hashed with the cell representation hash (the contract's
 * plain `CHKSIGNU` — no global-id mixing, confirmed against nekoton-wasm).
 */
function signingCell(input: EverscaleTx, publicKey: Uint8Array): Cell {
  const tx = EverscaleTx.parse(input);
  const c = checked(tx);
  const b = new Builder().address(c.from);
  b.append(bodyTail(c, tx, publicKey).build());
  return b.build();
}

export function everscaleSigningHash(tx: EverscaleTx, publicKey: PublicKey): Uint8Array {
  const pub = hexToBytes(publicKey.hex);
  return signingCell(tx, pub).hash;
}

interface External {
  message: Cell;
  boc: string;
  hash: string;
}

function external(input: EverscaleTx, publicKey: Uint8Array, signature: Uint8Array): External {
  const tx = EverscaleTx.parse(input);
  const c = checked(tx);
  const body = new Builder().bit(true).bytes(signature);
  body.append(bodyTail(c, tx, publicKey).build());
  const ext = new Builder().uint(0b10, 2).uint(0, 2).address(c.from).coins(0n); // import fee
  if (tx.deploy) {
    // init: (Maybe (Either StateInit ^StateInit)) as the right variant
    ext.bit(true).bit(false).bit(false).bit(false).bit(true).bit(true).bit(false);
    const si = everWalletStateInit({ curve: 'ed25519', hex: bytesToHex(publicKey) });
    ext.ref(si.refs[0]!).ref(si.refs[1]!);
  } else {
    ext.bit(false);
  }
  const message = ext.bit(true).ref(body.build()).build();
  const bytes = serializeBoc(message);
  return { message, boc: bytesToHex(bytes), hash: bytesToHex(message.hash) };
}

export function everscaleExternalMessage(
  tx: EverscaleTx,
  publicKey: PublicKey,
  signature: Uint8Array,
): External {
  return external(tx, hexToBytes(publicKey.hex), signature);
}

export async function prepareEverscale(
  adapter: EverscaleAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: EverscaleTx; simulation: Simulation }> {
  if (
    intent.chainId !== VENOM_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${VENOM_TESTNET}:native`
  )
    throw new Error('Only native transfers on the Venom testnet are enabled');
  if (!parseEverscaleAddress(from) || !parseEverscaleAddress(intent.to) || from === intent.to)
    throw new Error('Invalid sender or recipient');
  return adapter.withNode(intent.chainId, async (node) => {
    const sender = await node.account(from);
    if (sender.status === 'frozen') throw new Error('The sending wallet is frozen');
    const deploy = sender.status !== 'active';
    if (!deploy && sender.codeHash !== EVER_WALLET_CODE_HASH)
      throw new Error('The sending account is not an EverWallet');
    // EverWallet rejects a message whose `time` is not past the stored one.
    const timeMs = deploy ? now : Math.max(now, Number(sender.timestampMs ?? 0n) + 1);
    const recipient = await node.account(intent.to);
    // Value sent to an inactive account with bounce set returns to the sender.
    const bounce = recipient.status === 'active';
    const unsigned = EverscaleTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      evers: intent.amount,
      timeMs,
      expireAt: Math.floor((now + LIFETIME_MS) / 1000),
      builtAtMs: now,
      bounce,
      deploy,
    });
    checked(unsigned);
    const fee = deploy ? DEPLOY_FEE_BOUND_EVER : FEE_BOUND_EVER;
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
 * the wallet's stored timestamp or deployment no longer match the transfer.
 */
export async function everscaleApprovalValid(
  adapter: EverscaleAdapter,
  tx: EverscaleTx,
  now = Date.now(),
): Promise<boolean> {
  if (now > tx.expireAt * 1000 - 60_000) return false;
  return adapter.withNode(tx.chainId, async (node) => {
    const account = await node.account(tx.from);
    const active = account.status === 'active';
    if (active === tx.deploy) return false;
    return active ? Number(account.timestampMs ?? 0n) < tx.timeMs : true;
  });
}

/** The signature and the EverWallet body always carry the signing key. */
function extract(tx: EverscaleTx, root: Cell): { signature: Uint8Array; publicKey: Uint8Array } {
  const layout = external(tx, new Uint8Array(32), new Uint8Array(64));
  if (root.bits !== layout.message.bits || root.refs.length !== layout.message.refs.length)
    throw new Error('Signed bytes are not this transfer');
  const body = root.refs[root.refs.length - 1];
  if (!body || body.bits !== 898) throw new Error('Signed bytes are not this transfer');
  if (tx.deploy) {
    // refs: [code, data, body]; the data init carries the same key.
    const data = root.refs[1];
    if (!data || data.bits !== 320) throw new Error('Signed bytes are not this transfer');
    if (bytesToHex(data.bytes(0, 32)) !== bytesToHex(body.bytes(514, 32)))
      throw new Error('Signed bytes are not this transfer');
  }
  return { signature: body.bytes(1, 64), publicKey: body.bytes(514, 32) };
}

export function shortReason(error: string): string {
  const first = error.split('\n')[0] ?? error;
  return first.length > 160 ? `${first.slice(0, 157)}…` : first;
}

/**
 * Broadcast only a BoC that is exactly this transfer's external message,
 * signed by the key that owns the sending wallet. The returned hash is the
 * external message hash, which `getDstTransaction` resolves.
 */
export async function broadcastEverscale(
  adapter: EverscaleAdapter,
  tx: EverscaleTx,
  bocHex: string,
): Promise<string> {
  if (tx.chainId !== VENOM_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const c = checked(tx);
  const hex = bocHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0 || hex.length > 1 << 14)
    throw new Error('Signed bytes are not this transfer');
  const bytes = hexToBytes(hex);
  let root: Cell;
  try {
    root = parseBoc(bytes);
  } catch {
    throw new Error('Signed bytes are not this transfer');
  }
  const { signature, publicKey } = extract(tx, root);
  return adapter.withNode(tx.chainId, async (node) => {
    if (!equalBytes(everWalletHash({ curve: 'ed25519', hex: bytesToHex(publicKey) }), c.from))
      throw new Error('Signing key is not the sender wallet');
    const pub: PublicKey = { curve: 'ed25519', hex: bytesToHex(publicKey) };
    const rebuilt = everscaleExternalMessage(tx, pub, signature);
    if (rebuilt.boc !== hex) throw new Error('Signed bytes are not this transfer');
    if (!ed25519.verify(signature, everscaleSigningHash(tx, pub), publicKey, { zip215: false }))
      throw new Error('Signature does not verify against the sender');
    const res = await node.send(base64.encode(bytes));
    if (res.accepted) return rebuilt.hash;
    // A retry of an applied message meets a used timestamp or a duplicate.
    if (/duplicate|already|expire/i.test(res.error ?? '')) {
      const seen = await node.transactionByMessage(rebuilt.hash);
      if (seen) return rebuilt.hash;
    }
    throw new Error(`Broadcast rejected: ${shortReason(res.error ?? 'no reason')}`);
  });
}

/**
 * Expiry is reported once `expireAt` passed or the wallet's stored timestamp
 * moved past this transfer's, and the message hash is still absent.
 */
export async function everscaleTransferStatus(
  adapter: EverscaleAdapter,
  tx: EverscaleTx,
  hash: string,
  now = Date.now(),
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'pending') return status;
  const dead = await adapter.withNode(tx.chainId, async (node) => {
    if (now > tx.expireAt * 1000 + 60_000) return true;
    const account = await node.account(tx.from);
    return (
      account.status === 'active' &&
      tx.deploy === false &&
      Number(account.timestampMs ?? 0n) >= tx.timeMs
    );
  });
  if (!dead) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'pending' ? { state: 'expired' } : again;
}
