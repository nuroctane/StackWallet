import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  MIXIN_MAINNET,
  UtxoResult,
  XIN_ASSET_ID,
  isValidMixinAddress,
  type MixinAdapter,
} from './mixin.js';

const Hash32Lower = z.string().regex(/^[0-9a-f]{64}$/);
/** Mirrors the Rust `MixinInput` struct field for field. */
export const MixinInput = z.strictObject({
  hash: Hash32Lower,
  index: z.number().int().min(0).max(1024),
  key: Hash32Lower,
  mask: Hash32Lower,
  xinat: z.string().regex(/^\d{1,20}$/),
});
export type MixinInput = z.infer<typeof MixinInput>;

/** Mirrors the Rust `MixinTx` struct field for field. */
export const MixinTx = z.strictObject({
  chainId: z.literal(MIXIN_MAINNET),
  from: z.string().regex(/^XIN[1-9A-HJ-NP-Za-km-z]{80,100}$/),
  to: z.string().regex(/^XIN[1-9A-HJ-NP-Za-km-z]{80,100}$/),
  xinat: z.string().regex(/^\d{1,20}$/),
  inputs: z.array(MixinInput).min(1).max(8),
  toSeed: z.string().regex(/^[0-9a-f]{128}$/),
  changeSeed: z.string().regex(/^[0-9a-f]{128}$/),
});
export type MixinTx = z.infer<typeof MixinTx>;

const MAX_INPUTS = 8;

/**
 * Strictly walks the version-5 unsigned encoding. Returns the unsigned
 * prefix length and what it carries, so broadcast can prove the signed wire
 * is exactly this transfer before it leaves the device.
 */
export function parseUnsignedPrefix(wire: Uint8Array): {
  unsignedLength: number;
  asset: string;
  inputs: { hash: string; index: number }[];
  outputs: { amount: bigint; keys: number; script: string }[];
} {
  let offset = 0;
  const take = (n: number): Uint8Array => {
    if (offset + n > wire.length) throw new Error('Truncated Mixin transaction');
    const part = wire.subarray(offset, offset + n);
    offset += n;
    return part;
  };
  const u16 = (): number => {
    const b = take(2);
    return (b[0]! << 8) | b[1]!;
  };
  if (bytesToHex(take(4)) !== '77770005') throw new Error('Not a version-5 Mixin transaction');
  const asset = bytesToHex(take(32));
  const inCount = u16();
  if (inCount < 1 || inCount > MAX_INPUTS) throw new Error('Bad input count');
  const inputs = [];
  for (let i = 0; i < inCount; i++) {
    const hash = bytesToHex(take(32));
    const index = u16();
    if (u16() !== 0 || u16() !== 0 || u16() !== 0)
      throw new Error('Deposits, genesis and mint inputs are not transfers');
    inputs.push({ hash, index });
  }
  const outCount = u16();
  if (outCount < 1 || outCount > 2) throw new Error('A transfer has one or two outputs');
  const outputs = [];
  for (let i = 0; i < outCount; i++) {
    if (u16() !== 0) throw new Error('Only script outputs are transfers');
    const size = u16();
    if (size > 8) throw new Error('Output amount exceeds u64');
    const amountBytes = take(size);
    let amount = 0n;
    for (const b of amountBytes) amount = (amount << 8n) | BigInt(b);
    const keyCount = u16();
    if (keyCount < 1 || keyCount > 16) throw new Error('Bad key count');
    take(32 * keyCount);
    take(32); // mask
    const scriptLen = u16();
    const script = bytesToHex(take(scriptLen));
    if (script !== 'fffe01') throw new Error('Only threshold-1 script outputs are transfers');
    if (u16() !== 0) throw new Error('Withdrawal outputs are not transfers');
    outputs.push({ amount, keys: keyCount, script });
  }
  if (u16() !== 0) throw new Error('References are not transfers');
  const extraLen = take(4).reduce((n, b) => n * 256 + b, 0);
  if (extraLen !== 0) throw new Error('Extra data is not a plain transfer');
  return { unsignedLength: offset, asset, inputs, outputs };
}

/**
 * The payload hash (transaction id): blake3 of the unsigned encoding with a
 * nil signature map — Go's payloadMarshal always appends a zero count.
 */
function payloadHash(wire: Uint8Array, unsignedLength: number): string {
  const payload = new Uint8Array(unsignedLength + 2);
  payload.set(wire.subarray(0, unsignedLength));
  return bytesToHex(blake3(payload));
}

/** The kernel transaction id of a signed wire. */
export function mixinTxid(wire: Uint8Array): string {
  const { unsignedLength } = parseUnsignedPrefix(wire);
  return payloadHash(wire, unsignedLength);
}

/**
 * Verifies a signed wire hex is exactly `tx`: magic, XIN asset, the declared
 * inputs in order, one output paying `xinat` plus an optional change output
 * that sums back to the declared inputs, and one signature map per input.
 * Returns the transaction id (blake3 of the payload).
 */
export function verifySignedWire(tx: MixinTx, signedHex: string): string {
  const parsed = MixinTx.parse(tx);
  if (!/^[0-9a-f]+$/.test(signedHex) || signedHex.length % 2 !== 0)
    throw new Error('Signed bytes are not lowercase hex');
  const wire = Uint8Array.from(signedHex.match(/../g)!.map((b) => parseInt(b, 16)));
  const { unsignedLength, asset, inputs, outputs } = parseUnsignedPrefix(wire);
  if (asset !== XIN_ASSET_ID) throw new Error('Signed bytes move another asset');
  if (inputs.length !== parsed.inputs.length) throw new Error('Signed bytes spend other inputs');
  for (let i = 0; i < inputs.length; i++) {
    if (inputs[i]!.hash !== parsed.inputs[i]!.hash || inputs[i]!.index !== parsed.inputs[i]!.index)
      throw new Error('Signed bytes spend other inputs');
  }
  const amount = BigInt(parsed.xinat);
  if (outputs[0]!.amount !== amount) throw new Error('Signed bytes pay a different amount');
  const totalIn = parsed.inputs.reduce((sum, i) => sum + BigInt(i.xinat), 0n);
  if (outputs.length === 2) {
    if (outputs[0]!.amount + outputs[1]!.amount !== totalIn)
      throw new Error('Signed change does not close the inputs');
  } else if (outputs[0]!.amount !== totalIn) {
    throw new Error('Signed bytes burn the change');
  }
  // Exactly one signature map per input, one 64-byte entry each.
  let offset = unsignedLength;
  const u16 = () => (wire[offset++]! << 8) | wire[offset++]!;
  if (offset + 2 > wire.length || u16() !== parsed.inputs.length)
    throw new Error('Bad signature map count');
  for (let i = 0; i < parsed.inputs.length; i++) {
    if (u16() !== 1 || u16() !== 0) throw new Error('Bad signature map entry');
    offset += 64;
  }
  if (offset !== wire.length) throw new Error('Trailing bytes after signatures');
  return payloadHash(wire, unsignedLength);
}

export async function prepareMixin(
  adapter: MixinAdapter,
  intent: TxIntent,
  from: string,
  random: () => Uint8Array = () => crypto.getRandomValues(new Uint8Array(64)),
): Promise<{ unsigned: MixinTx; simulation: Simulation }> {
  if (
    intent.chainId !== MIXIN_MAINNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${MIXIN_MAINNET}:native`
  )
    throw new Error('Only native XIN transfers on the Mixin main kernel are enabled');
  if (!isValidMixinAddress(from)) throw new Error('Invalid sender address');
  if (!isValidMixinAddress(intent.to)) throw new Error('Invalid recipient address');
  const amount = BigInt(intent.amount);
  if (amount <= 0n || amount.toString() !== intent.amount)
    throw new Error('XIN amount must be a positive canonical integer of xinat');
  if (!adapter.utxos)
    throw new Error(
      'UTXO discovery needs view-key scanning in the core (not wired yet); ' +
        'provide MixinAdapterOptions.utxos to prepare Mixin transfers.',
    );
  const candidates = await adapter.utxos(from);
  const inputs: MixinInput[] = [];
  let covered = 0n;
  for (const candidate of candidates) {
    const input = MixinInput.parse({
      hash: candidate.hash,
      index: candidate.index,
      key: candidate.key,
      mask: candidate.mask,
      xinat: candidate.xinat,
    });
    inputs.push(input);
    covered += BigInt(input.xinat);
    if (covered >= amount || inputs.length === MAX_INPUTS) break;
  }
  const unsigned = MixinTx.parse({
    chainId: intent.chainId,
    from,
    to: intent.to,
    xinat: intent.amount,
    inputs,
    toSeed: bytesToHex(random()),
    changeSeed: bytesToHex(random()),
  });
  let error: string | undefined;
  if (covered < amount) error = 'Known UTXOs do not cover the amount';
  return {
    unsigned,
    simulation: {
      ok: error === undefined,
      assetDeltas: [{ assetRef: intent.asset, amount: `-${intent.amount}` }],
      fee: { assetRef: intent.asset, amount: '0' },
      warnings: [
        {
          kind: 'other',
          message:
            'The Mixin kernel charges no fee; inputs must cover the amount exactly through change.',
        },
      ],
      ...(error ? { error } : {}),
    },
  };
}

/** Approval holds while every input is still an unspent, unlocked UTXO. */
export async function mixinApprovalValid(adapter: MixinAdapter, tx: MixinTx): Promise<boolean> {
  const parsed = MixinTx.parse(tx);
  return adapter.withNode(parsed.chainId, async (url) => {
    for (const input of parsed.inputs) {
      const utxo = await adapter.call(url, 'getutxo', [input.hash, input.index], UtxoResult);
      if (!utxo || utxo.lock) return false;
    }
    return true;
  });
}

/**
 * Broadcasts only a wire verified byte-for-byte against the intent-checked
 * tx. The kernel answers `{hash}` for a queued payload; the hash must equal
 * the locally computed payload hash (a substituted envelope would differ).
 */
export async function broadcastMixin(
  adapter: MixinAdapter,
  tx: MixinTx,
  signedHex: string,
): Promise<string> {
  const txid = verifySignedWire(tx, signedHex);
  const accepted = await adapter.withNode(tx.chainId, (url) =>
    adapter.call(url, 'sendrawtransaction', [signedHex], z.object({ hash: Hash32Lower }).loose()),
  );
  if (!accepted?.hash) throw new Error('Kernel did not return the transaction hash');
  if (accepted.hash !== txid)
    throw new Error(`Kernel returned hash ${accepted.hash}, expected ${txid}`);
  return txid;
}

/** Kernel transactions do not expire; status is cache/durable/final only. */
export async function mixinTransferStatus(
  adapter: MixinAdapter,
  tx: MixinTx,
  hash: string,
): Promise<TxStatus> {
  MixinTx.parse(tx);
  return adapter.status(hash, tx.chainId);
}
