/**
 * Prepare / approval / broadcast helpers for Chromia FT4 native transfers.
 * The Rust core encodes and signs the same bodies independently; everything
 * here is rebuilt from checked fields so the bytes that leave for broadcast
 * can be verified against the ledger-approved transaction.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  CHROMIA_NETWORKS,
  CHROMIA_TESTNET,
  chromiaAuthDescriptorId,
  gtvEncode,
  gtvHash,
  isValidChromiaAddress,
  type ChromiaAdapter,
  type Gtv,
} from './chromia.js';

const Hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const Hex66 = z.string().regex(/^[0-9a-f]{66}$/);

/** Native transfer: ft_auth + ft4.transfer + nop, signed by `signer`. */
export const ChromiaTx = z.strictObject({
  chainId: z.literal(CHROMIA_TESTNET),
  from: Hex64,
  signer: Hex66,
  to: Hex64,
  /** Decimal micro-CHR (1 CHR = 1_000_000 uchr); never a float. */
  uchr: z.string().regex(/^[1-9][0-9]{0,14}$/),
  /** 32 random bytes carried by the `nop` op for transaction uniqueness. */
  nonce: Hex64,
});
export type ChromiaTx = z.infer<typeof ChromiaTx>;

/** Self-claim registration for an account id with pending inbound transfers. */
export const ChromiaRegisterTx = z.strictObject({
  chainId: z.literal(CHROMIA_TESTNET),
  from: Hex64,
  signer: Hex66,
  register: z.literal(true),
});
export type ChromiaRegisterTx = z.infer<typeof ChromiaRegisterTx>;

const MAX_UCHR = 1_000_000_000_000_000n; // 1e9 CHR, far above total supply

function op(name: string, args: Gtv[]): Gtv {
  return [name, args];
}

function checkedTransfer(tx: ChromiaTx) {
  const parsed = ChromiaTx.parse(tx);
  const net = CHROMIA_NETWORKS[parsed.chainId]!;
  const from = hexToBytes(parsed.from);
  const to = hexToBytes(parsed.to);
  if (parsed.from === parsed.to) throw new Error('Sender and recipient must differ');
  const signer = hexToBytes(parsed.signer);
  if (signer[0] !== 2 && signer[0] !== 3)
    throw new Error('Signer must be a compressed secp256k1 public key');
  const amount = BigInt(parsed.uchr);
  if (amount <= 0n || amount > MAX_UCHR || amount.toString() !== parsed.uchr)
    throw new Error('CHR amount must be a positive integer of uchr');
  const nonce = hexToBytes(parsed.nonce);
  if (nonce.every((b) => b === 0)) throw new Error('Nonce must be random, not zero');
  return { parsed, net, from, to, signer, amount, nonce };
}

function gtxBody(brid: Uint8Array, ops: Gtv[], signer: Uint8Array): Gtv {
  return [brid, ops, [signer]];
}

/** The exact GTX body GTV the core encodes from the same checked fields. */
export function transferBody(input: ChromiaTx): Gtv {
  const { net, from, to, signer, amount, nonce } = checkedTransfer(input);
  return gtxBody(
    hexToBytes(net.brid),
    [
      op('ft4.ft_auth', [from, chromiaAuthDescriptorId(signer)]),
      op('ft4.transfer', [to, hexToBytes(net.assetId), amount]),
      op('nop', [nonce]),
    ],
    signer,
  );
}

export function registerBody(input: ChromiaRegisterTx): Gtv {
  const parsed = ChromiaRegisterTx.parse(input);
  const net = CHROMIA_NETWORKS[parsed.chainId]!;
  const signer = hexToBytes(parsed.signer);
  return gtxBody(
    hexToBytes(net.brid),
    [
      op('ft4.ras_transfer_open', [[0, [['A', 'T'], signer], null], null]),
      op('ft4.register_account', []),
    ],
    signer,
  );
}

export function bodyOf(tx: ChromiaTx | ChromiaRegisterTx): Gtv {
  return 'uchr' in tx ? transferBody(tx) : registerBody(tx);
}

/** The transaction rid: merkle v2 hash of the body. */
export function chromiaTxId(tx: ChromiaTx | ChromiaRegisterTx): string {
  return bytesToHex(gtvHash(bodyOf(tx)));
}

const AccountOrNull = z.union([z.null(), z.looseObject({ id: z.instanceof(Uint8Array) })]);
const BalanceOrNull = z.union([z.null(), z.bigint()]);

export interface PreparedChromia {
  unsigned: ChromiaTx;
  simulation: Simulation;
}

export async function prepareChromia(
  adapter: ChromiaAdapter,
  intent: TxIntent,
  from: string,
  signer: string,
): Promise<PreparedChromia> {
  if (
    intent.chainId !== CHROMIA_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${CHROMIA_TESTNET}:native`
  )
    throw new Error('Only native CHR transfers on Chromia testnet are enabled');
  if (!isValidChromiaAddress(intent.to)) throw new Error('Invalid recipient account id');
  if (!/^[1-9][0-9]{0,14}$/.test(intent.amount)) throw new Error('Invalid uchr amount');
  const unsigned = ChromiaTx.parse({
    chainId: intent.chainId,
    from,
    signer,
    to: intent.to,
    uchr: intent.amount,
    nonce: bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32))),
  });
  const net = CHROMIA_NETWORKS[intent.chainId]!;
  return adapter.withNode(intent.chainId, async (query) => {
    const account = await query('ft4.get_account_by_id', { id: hexToBytes(from) }, AccountOrNull);
    const balance = await query(
      'ft4.get_asset_balance',
      { account_id: hexToBytes(from), asset_id: hexToBytes(net.assetId) },
      BalanceOrNull,
    );
    const warnings: Simulation['warnings'] = [];
    let error: string | undefined;
    if (account === null)
      error =
        'The sender has no FT4 account yet. Receive CHR first; the holder of the key then claims it with a registration transaction (prepareChromiaRegistration).';
    else if ((balance ?? 0n) < BigInt(intent.amount)) error = 'Balance does not cover the transfer';
    const recipient = await query(
      'ft4.get_account_by_id',
      { id: hexToBytes(intent.to) },
      AccountOrNull,
    );
    if (recipient === null)
      warnings.push({
        kind: 'other',
        message:
          'The recipient account id is not registered; the transfer stays pending until the recipient key holder claims it.',
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [{ assetRef: intent.asset, amount: `-${intent.amount}` }],
        // FT4 charges rate-limit points, not tokens.
        fee: { assetRef: intent.asset, amount: '0' },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/**
 * Builds the self-claim registration transaction for an account id that has
 * (or expects) pending inbound transfers but no account yet.
 */
export async function prepareChromiaRegistration(
  adapter: ChromiaAdapter,
  from: string,
  signer: string,
): Promise<{ unsigned: ChromiaRegisterTx; simulation: Simulation }> {
  if (!isValidChromiaAddress(from)) throw new Error('Invalid account id');
  const unsigned = ChromiaRegisterTx.parse({
    chainId: CHROMIA_TESTNET,
    from,
    signer,
    register: true,
  });
  return adapter.withNode(unsigned.chainId, async (query) => {
    const account = await query('ft4.get_account_by_id', { id: hexToBytes(from) }, AccountOrNull);
    const assetRef = `${unsigned.chainId}:native`;
    const registered = account !== null;
    return {
      unsigned,
      simulation: {
        ok: !registered,
        assetDeltas: [],
        fee: { assetRef, amount: '0' },
        warnings: [],
        ...(registered ? { error: 'The account is already registered' } : {}),
      },
    };
  });
}

/**
 * GTX transactions never expire and carry no on-chain nonce to pre-check;
 * approval stays valid while the sender account still exists (or, for a
 * registration, is still missing).
 */
export async function chromiaApprovalValid(
  adapter: ChromiaAdapter,
  tx: ChromiaTx | ChromiaRegisterTx,
): Promise<boolean> {
  const unsigned = 'uchr' in tx ? ChromiaTx.parse(tx) : ChromiaRegisterTx.parse(tx);
  const account = await adapter.withNode(unsigned.chainId, (query) =>
    query('ft4.get_account_by_id', { id: hexToBytes(unsigned.from) }, AccountOrNull),
  );
  return 'register' in unsigned ? account === null : account !== null;
}

/** Minimal-length DER TLV reader over a wire buffer. */
function readTlv(buf: Uint8Array, off: number): { tag: number; start: number; end: number } {
  const tag = buf[off];
  if (tag === undefined) throw new Error('Truncated wire');
  let p = off + 1;
  let len = buf[p++];
  if (len === undefined) throw new Error('Truncated wire');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('Non-canonical wire length');
    len = 0;
    let first = true;
    for (let i = 0; i < n; i++) {
      const b = buf[p++];
      if (b === undefined) throw new Error('Truncated wire');
      if (first && b === 0) throw new Error('Non-canonical wire length');
      first = false;
      len = (len << 8) | b;
    }
    if (len < 128) throw new Error('Non-canonical wire length');
  }
  if (p + len > buf.length) throw new Error('Truncated wire');
  return { tag, start: p, end: p + len };
}

function expectTlv(buf: Uint8Array, off: number, tag: number): { start: number; end: number } {
  const tlv = readTlv(buf, off);
  if (tlv.tag !== tag)
    throw new Error(`Wire tag 0x${tlv.tag.toString(16)} is not 0x${tag.toString(16)}`);
  return tlv;
}

/**
 * Broadcast only bytes that are canonically this ledger's body plus a single
 * 64-byte signature: the body bytes are compared verbatim, so a decoded and
 * re-encoded comparison (which would blur integer/bigInteger tags) is never
 * needed.
 */
export async function broadcastChromia(
  adapter: ChromiaAdapter,
  tx: ChromiaTx | ChromiaRegisterTx,
  wireHex: string,
): Promise<string> {
  const unsigned = 'uchr' in tx ? ChromiaTx.parse(tx) : ChromiaRegisterTx.parse(tx);
  const expectedBody = gtvEncode(bodyOf(unsigned));
  const hex = wireHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length > 8192)
    throw new Error('Signed bytes are not valid hex');
  const wire = hexToBytes(hex);
  const invalid = 'Signed bytes are not this Chromia transaction';
  try {
    const outer = expectTlv(wire, 0, 0xa5);
    if (outer.end !== wire.length) throw new Error(invalid);
    const seq = expectTlv(wire, outer.start, 0x30);
    if (seq.end !== outer.end) throw new Error(invalid);
    const body = readTlv(wire, seq.start);
    if (
      body.end - seq.start !== expectedBody.length ||
      bytesToHex(wire.subarray(seq.start, body.end)) !== bytesToHex(expectedBody)
    )
      throw new Error(invalid);
    const sigs = expectTlv(wire, body.end, 0xa5);
    if (sigs.end !== seq.end) throw new Error('Signed bytes must carry exactly one signature');
    const sigSeq = expectTlv(wire, sigs.start, 0x30);
    if (sigSeq.end !== sigs.end) throw new Error('Signed bytes must carry exactly one signature');
    const sigEntry = expectTlv(wire, sigSeq.start, 0xa1);
    if (sigEntry.end !== sigSeq.end)
      throw new Error('Signed bytes must carry exactly one signature');
    const sigBytes = expectTlv(wire, sigEntry.start, 0x04);
    if (sigBytes.end !== sigEntry.end || sigBytes.end - sigBytes.start !== 64)
      throw new Error('Signed bytes must carry exactly one 64-byte signature');
  } catch (err) {
    if (err instanceof Error && err.message === invalid) throw err;
    if (err instanceof Error && err.message.startsWith('Signed bytes')) throw err;
    throw new Error(invalid);
  }
  const rid = bytesToHex(gtvHash(bodyOf(unsigned)));
  const res = await adapter.postWire(unsigned.chainId, wire);
  if (res.status < 200 || res.status >= 300) {
    const detail = res.text.replace(/[^\x20-\x7e]/g, '').slice(0, 512);
    // A retry of an accepted transaction is not a failure.
    if (!(res.status === 400 && /already|duplicate/i.test(detail)))
      throw new Error(`Broadcast rejected: ${res.status} ${detail}`.trim());
  }
  return rid;
}

/** GTX never expires; unknown stays unknown rather than ageing out. */
export async function chromiaTransferStatus(
  adapter: ChromiaAdapter,
  tx: ChromiaTx | ChromiaRegisterTx,
  hash: string,
): Promise<TxStatus> {
  return adapter.status(hash, tx.chainId);
}
