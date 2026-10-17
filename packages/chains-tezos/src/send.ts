import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { HttpError, type Simulation, type TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  BlockHash,
  Contract,
  Header,
  ManagerKey,
  OpHash,
  PREFIX,
  TEZOS_SHADOWNET,
  b58checkDecode,
  b58checkEncode,
  isNotFound,
  tezosAddressBytes,
  tezosAddressFromPublicKey,
  type TezosAdapter,
  type TezosGet,
} from './tezos.js';

export const MIN_FEE = 100;
export const MAX_FEE = 100_000;
export const MAX_GAS_LIMIT = 100_000;
export const MAX_REVEAL_GAS_LIMIT = 10_000;
export const MAX_STORAGE_LIMIT = 1_000;
export const MAX_MUTEZ = 0x7fffffffffffffffn;
const MAX_COUNTER = 9_007_199_254_740_990;
const WATERMARK = 0x03;
/** Taquito's tz1 reveal cost plus headroom; the simulation replaces it when it can run. */
const DEFAULT_REVEAL_GAS = 1_000;
const DEFAULT_TRANSFER_GAS = 3_000;
const GAS_BUFFER = 100;
/** Bytes burnt for allocating a new implicit account (`origination_size`). */
const ALLOCATION_BYTES = 257;
const COST_PER_BYTE = 250n;
/** Refuse approval this many blocks before the branch leaves `max_operations_ttl`. */
const TTL_MARGIN = 60;

const Implicit = z.string().regex(/^tz[1-4][1-9A-HJ-NP-Za-km-z]{33}$/);
const Fee = z.number().int().min(MIN_FEE).max(MAX_FEE);
export const TezosReveal = z.strictObject({
  fee: Fee,
  gasLimit: z.number().int().min(1).max(MAX_REVEAL_GAS_LIMIT),
});
export const TezosTx = z.strictObject({
  chainId: z.literal(TEZOS_SHADOWNET),
  from: z.string().regex(/^tz1[1-9A-HJ-NP-Za-km-z]{33}$/),
  to: Implicit,
  mutez: z.string().regex(/^[1-9][0-9]{0,18}$/),
  branch: BlockHash,
  counter: z.number().int().min(1).max(MAX_COUNTER),
  fee: Fee,
  gasLimit: z.number().int().min(1).max(MAX_GAS_LIMIT),
  storageLimit: z.number().int().min(0).max(MAX_STORAGE_LIMIT),
  reveal: TezosReveal.optional(),
});
export type TezosTx = z.infer<typeof TezosTx>;

function zarith(out: number[], value: bigint | number): void {
  let v = BigInt(value);
  for (;;) {
    const byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v === 0n) {
      out.push(byte);
      return;
    }
    out.push(byte | 0x80);
  }
}

interface Checked {
  tx: TezosTx;
  from: Uint8Array;
  to: Uint8Array;
  branch: Uint8Array;
}

function check(input: TezosTx): Checked {
  const tx = TezosTx.parse(input);
  const from = tezosAddressBytes(tx.from);
  const to = tezosAddressBytes(tx.to);
  if (!from || !to || from[0] !== 0 || tx.from === tx.to)
    throw new Error('Invalid tez sender or recipient');
  if (BigInt(tx.mutez) > MAX_MUTEZ) throw new Error('Amount exceeds int64 mutez');
  const branch = b58checkDecode(tx.branch, PREFIX.block, 32);
  if (!branch || branch.every((b) => b === 0)) throw new Error('Invalid branch');
  return { tx, from, to, branch };
}

/** Offset of the revealed public key inside the forged bytes, or undefined without a reveal. */
function forgeParts(input: TezosTx, publicKey: Uint8Array): { bytes: Uint8Array; keyAt?: number } {
  const { tx, from, to, branch } = check(input);
  const out: number[] = [...branch];
  let counter = tx.counter;
  let keyAt: number | undefined;
  if (tx.reveal) {
    out.push(0x6b, ...from);
    zarith(out, tx.reveal.fee);
    zarith(out, counter);
    zarith(out, tx.reveal.gasLimit);
    zarith(out, 0);
    out.push(0);
    keyAt = out.length;
    out.push(...publicKey, 0);
    counter += 1;
  }
  out.push(0x6c, ...from);
  zarith(out, tx.fee);
  zarith(out, counter);
  zarith(out, tx.gasLimit);
  zarith(out, tx.storageLimit);
  zarith(out, BigInt(tx.mutez));
  out.push(0, ...to, 0);
  return { bytes: Uint8Array.from(out), ...(keyAt !== undefined ? { keyAt } : {}) };
}

/** The same forged operation the core builds independently from checked fields. */
export function forgeTezos(tx: TezosTx, publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32 || tezosAddressFromPublicKey(publicKey) !== tx.from)
    throw new Error('Public key does not derive the sender address');
  return forgeParts(tx, publicKey).bytes;
}

export function tezosSigningDigest(forged: Uint8Array): Uint8Array {
  return blake2b(Uint8Array.from([WATERMARK, ...forged]), { dkLen: 32 });
}

export function tezosOperationHash(signed: Uint8Array): string {
  return b58checkEncode(PREFIX.operation, blake2b(signed, { dkLen: 32 }));
}

export function tezosTotalFee(tx: TezosTx): bigint {
  return BigInt(tx.fee) + BigInt(tx.reveal?.fee ?? 0);
}

const ZERO_SIG = b58checkEncode(PREFIX.edsig, new Uint8Array(64));
const Result = z
  .object({
    status: z.enum(['applied', 'failed', 'skipped', 'backtracked']),
    consumed_milligas: z
      .string()
      .regex(/^\d{1,16}$/)
      .optional(),
    paid_storage_size_diff: z
      .string()
      .regex(/^\d{1,16}$/)
      .optional(),
    allocated_destination_contract: z.boolean().optional(),
    errors: z
      .array(z.object({ id: z.string().max(256) }).loose())
      .max(32)
      .optional(),
  })
  .loose();
const RunOperation = z.object({
  contents: z
    .array(
      z
        .object({
          kind: z.string().max(32),
          metadata: z.object({ operation_result: Result }).loose(),
        })
        .loose(),
    )
    .min(1)
    .max(2),
});
const RpcErrors = z.array(z.object({ id: z.string().max(256) }).loose()).max(32);

function rpcError(err: unknown): string | undefined {
  if (!(err instanceof HttpError)) return undefined;
  try {
    const ids = RpcErrors.parse(JSON.parse(err.body)).map((e) => e.id);
    return ids.length
      ? ids
          .join(', ')
          .replace(/[^\x20-\x7e]/g, '')
          .slice(0, 512)
      : undefined;
  } catch {
    return undefined;
  }
}

const contentJson = (tx: TezosTx, publicKey: string | undefined, sim: boolean) => {
  const reveal = tx.reveal
    ? [
        {
          kind: 'reveal',
          source: tx.from,
          fee: sim ? '0' : String(tx.reveal.fee),
          counter: String(tx.counter),
          gas_limit: String(sim ? MAX_REVEAL_GAS_LIMIT : tx.reveal.gasLimit),
          storage_limit: '0',
          public_key: publicKey,
        },
      ]
    : [];
  return [
    ...reveal,
    {
      kind: 'transaction',
      source: tx.from,
      fee: sim ? '0' : String(tx.fee),
      counter: String(tx.counter + (tx.reveal ? 1 : 0)),
      gas_limit: String(sim ? MAX_GAS_LIMIT : tx.gasLimit),
      storage_limit: String(sim ? MAX_STORAGE_LIMIT : tx.storageLimit),
      amount: tx.mutez,
      destination: tx.to,
    },
  ];
};

function gasOf(milligas: string | undefined, fallback: number): number {
  if (milligas === undefined) return fallback;
  return Math.ceil(Number(milligas) / 1000) + GAS_BUFFER;
}

/**
 * Minimal mempool fee is 100 mutez + 0.1 mutez per gas unit + 1 mutez per
 * byte of the signed operation. The reveal pays its own base and gas; the
 * transfer pays its base, gas and the whole operation's bytes.
 */
function priced(tx: TezosTx, publicKey: Uint8Array): TezosTx {
  const reveal = tx.reveal
    ? { fee: MIN_FEE + Math.ceil(tx.reveal.gasLimit / 10), gasLimit: tx.reveal.gasLimit }
    : undefined;
  let out = TezosTx.parse({ ...tx, ...(reveal ? { reveal } : {}) });
  // The fee's own zarith length feeds back into the size; settle on a fixed point.
  for (let i = 0; i < 4; i++) {
    const size = forgeParts(out, publicKey).bytes.length + 64;
    const fee = Math.min(MIN_FEE + Math.ceil(tx.gasLimit / 10) + size + 10, MAX_FEE);
    if (fee === out.fee) break;
    out = TezosTx.parse({ ...out, fee });
  }
  return out;
}

/**
 * Builds the transfer fields, revealing the sender's key first when the
 * account has none on chain. `publicKeyHex` is the sender's 32-byte Ed25519
 * key; it is required only when a reveal is needed.
 */
export async function prepareTezos(
  adapter: TezosAdapter,
  intent: TxIntent,
  from: string,
  publicKeyHex?: string,
): Promise<{ unsigned: TezosTx; simulation: Simulation }> {
  if (
    intent.chainId !== TEZOS_SHADOWNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${TEZOS_SHADOWNET}:native`
  )
    throw new Error('Only native tez transfers on Shadownet are enabled');
  const publicKey = publicKeyHex ? hexToBytes(publicKeyHex.replace(/^0x/, '')) : undefined;
  if (publicKey && (publicKey.length !== 32 || tezosAddressFromPublicKey(publicKey) !== from))
    throw new Error('Public key does not derive the sender address');
  return adapter.withNode(intent.chainId, async (get, post) => {
    const head = await get('/chains/main/blocks/head/header', Header);
    const [sender, managerKey] = await Promise.all([
      get(`/chains/main/blocks/head/context/contracts/${from}`, Contract),
      get(`/chains/main/blocks/head/context/contracts/${from}/manager_key`, ManagerKey),
    ]);
    const needsReveal = managerKey === null;
    if (needsReveal && !publicKey)
      throw new Error('The sender key is not revealed yet; its public key is required');
    const edpk = publicKey ? b58checkEncode(PREFIX.edpk, publicKey) : undefined;
    if (managerKey !== null && edpk !== undefined && managerKey !== edpk)
      throw new Error('The account reveals a different key');
    const counter = Number(sender.counter ?? '0') + 1;
    const draft = TezosTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      mutez: intent.amount,
      branch: head.hash,
      counter,
      fee: MIN_FEE,
      gasLimit: DEFAULT_TRANSFER_GAS,
      storageLimit: ALLOCATION_BYTES,
      ...(needsReveal ? { reveal: { fee: MIN_FEE, gasLimit: DEFAULT_REVEAL_GAS } } : {}),
    });
    const warnings: Simulation['warnings'] = [];
    let error: string | undefined;
    let gasLimit = DEFAULT_TRANSFER_GAS;
    let revealGas = DEFAULT_REVEAL_GAS;
    let storageLimit = ALLOCATION_BYTES;
    let allocates: boolean | undefined;
    try {
      const run = await post(
        '/chains/main/blocks/head/helpers/scripts/run_operation',
        {
          operation: {
            branch: head.hash,
            contents: contentJson(draft, edpk, true),
            signature: ZERO_SIG,
          },
          chain_id: head.chain_id,
        },
        RunOperation,
      );
      const results = run.contents.map((c) => c.metadata.operation_result);
      const transfer = results.at(-1)!;
      if (needsReveal) revealGas = gasOf(results[0]?.consumed_milligas, DEFAULT_REVEAL_GAS);
      gasLimit = gasOf(transfer.consumed_milligas, DEFAULT_TRANSFER_GAS);
      allocates = transfer.allocated_destination_contract === true;
      storageLimit =
        Number(transfer.paid_storage_size_diff ?? '0') + (allocates ? ALLOCATION_BYTES : 0);
      const bad = results.find((r) => r.status !== 'applied');
      if (bad)
        error = `Simulation failed: ${(bad.errors ?? []).map((e) => e.id).join(', ') || bad.status}`;
    } catch (err) {
      const ids = rpcError(err);
      if (!ids) throw err;
      error = ids.includes('empty_implicit_contract')
        ? 'Sender account is empty on Shadownet'
        : ids.includes('balance_too_low')
          ? 'Balance does not cover the transfer and fee'
          : `Simulation failed: ${ids}`;
    }
    const base = TezosTx.parse({
      ...draft,
      gasLimit: Math.min(gasLimit, MAX_GAS_LIMIT),
      storageLimit: Math.min(storageLimit, MAX_STORAGE_LIMIT),
      ...(needsReveal
        ? { reveal: { fee: MIN_FEE, gasLimit: Math.min(revealGas, MAX_REVEAL_GAS_LIMIT) } }
        : {}),
    });
    // Size depends only on field lengths, so any 32-byte key prices the operation.
    const unsigned = priced(base, publicKey ?? new Uint8Array(32));
    const fee = tezosTotalFee(unsigned);
    const burn = allocates ? BigInt(ALLOCATION_BYTES) * COST_PER_BYTE : 0n;
    const balance = BigInt(sender.balance);
    if (error === undefined && balance < BigInt(intent.amount) + fee + burn)
      error = 'Balance does not cover the transfer, fee and storage burn';
    if (allocates !== false)
      warnings.push({
        kind: 'other',
        message:
          allocates === true
            ? 'The recipient has never held tez; this transfer allocates it and burns 0.06425 tez of storage.'
            : 'The simulation did not run, so a possible 0.06425 tez allocation burn for a new recipient is not confirmed.',
      });
    if (needsReveal)
      warnings.push({
        kind: 'other',
        message: 'This is the first transfer from this account, so it also reveals its public key.',
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee + burn}` },
        ],
        fee: { assetRef: intent.asset, amount: (fee + burn).toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

const MaxTtl = z.object({ max_operations_time_to_live: z.number().int().min(1).max(100_000) });

async function branchWindow(
  get: TezosGet,
  branch: string,
): Promise<{ head: number; last: number } | 'gone'> {
  const [head, constants] = await Promise.all([
    get('/chains/main/blocks/head/header', Header),
    get('/chains/main/blocks/head/context/constants', MaxTtl),
  ]);
  let level: number;
  try {
    level = (await get(`/chains/main/blocks/${branch}/header`, Header)).level;
  } catch (err) {
    if (isNotFound(err)) return 'gone';
    throw err;
  }
  return { head: head.level, last: level + constants.max_operations_time_to_live };
}

/**
 * Approval holds while the branch is comfortably inside `max_operations_ttl`,
 * the counter has not moved and the reveal state still matches.
 */
export async function tezosApprovalValid(adapter: TezosAdapter, tx: TezosTx): Promise<boolean> {
  const t = TezosTx.parse(tx);
  return adapter.withNode(t.chainId, async (get) => {
    const window = await branchWindow(get, t.branch);
    if (window === 'gone' || window.head >= window.last - TTL_MARGIN) return false;
    const [sender, managerKey] = await Promise.all([
      get(`/chains/main/blocks/head/context/contracts/${t.from}`, Contract),
      get(`/chains/main/blocks/head/context/contracts/${t.from}/manager_key`, ManagerKey),
    ]);
    return Number(sender.counter ?? '0') + 1 === t.counter && (managerKey === null) === !!t.reveal;
  });
}

/**
 * Broadcast only bytes that are exactly the ledger's operation plus one
 * signature that verifies for the sender. Without a reveal the key is not in
 * the bytes, so pass `publicKeyHex` to verify the signature as well.
 */
export async function broadcastTezos(
  adapter: TezosAdapter,
  tx: TezosTx,
  rawHex: string,
  publicKeyHex?: string,
): Promise<string> {
  const t = TezosTx.parse(tx);
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  if (!/^(?:[0-9a-f]{2})+$/.test(hex)) throw new Error('Signed bytes are not hex');
  const raw = hexToBytes(hex);
  const placeholder = forgeParts(t, new Uint8Array(32));
  if (raw.length !== placeholder.bytes.length + 64)
    throw new Error('Signed bytes are not this tez transfer');
  let publicKey = publicKeyHex ? hexToBytes(publicKeyHex.replace(/^0x/, '')) : undefined;
  if (placeholder.keyAt !== undefined) {
    const embedded = raw.slice(placeholder.keyAt, placeholder.keyAt + 32);
    if (publicKey && bytesToHex(publicKey) !== bytesToHex(embedded))
      throw new Error('Signed bytes reveal a different key');
    publicKey = embedded;
  }
  const forged = raw.slice(0, raw.length - 64);
  if (publicKey) {
    if (bytesToHex(forgeTezos(t, publicKey)) !== bytesToHex(forged))
      throw new Error('Signed bytes are not this tez transfer');
    const signature = raw.slice(raw.length - 64);
    if (!ed25519.verify(signature, tezosSigningDigest(forged), publicKey, { zip215: false }))
      throw new Error('Signature does not verify for the sender');
  } else if (bytesToHex(placeholder.bytes) !== bytesToHex(forged)) {
    throw new Error('Signed bytes are not this tez transfer');
  }
  const hash = tezosOperationHash(raw);
  const injected = await adapter.withNode(t.chainId, async (_get, post) => {
    try {
      return await post('/injection/operation', hex, OpHash);
    } catch (err) {
      const ids = rpcError(err);
      if (ids) throw new Error(`Broadcast rejected: ${ids}`);
      throw err;
    }
  });
  if (injected !== hash) throw new Error('Node reported a different operation hash');
  return hash;
}

/**
 * TzKT decides confirmed or failed. Expiry is reported only once the head is
 * past the branch's `max_operations_ttl` (or the branch left the chain) and
 * the hash is still unknown.
 */
export async function tezosTransferStatus(
  adapter: TezosAdapter,
  tx: TezosTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const t = TezosTx.parse(tx);
  const status = await adapter.status(hash, t.chainId);
  if (status.state !== 'unknown') return status;
  const window = await adapter.withNode(t.chainId, (get) => branchWindow(get, t.branch));
  if (window !== 'gone' && window.head <= window.last) return status;
  const again = await adapter.status(hash, t.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
