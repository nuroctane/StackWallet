import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import { SubstrateTx, type TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  H256Hex,
  Header,
  RuntimeVersion,
  StorageValue,
  SUBSTRATE_WESTEND,
  SUBSTRATE_WESTEND_ASSET_HUB,
  TIMESTAMP_NOW,
  accountStorageKey,
  decodeAccount,
  spendable,
  ss58Decode,
  substrateNetwork,
  type SubstrateAdapter,
  type SubstrateCall,
} from './substrate.js';

const Ss58 = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{40,50}$/);
const U32 = z.number().int().nonnegative().max(0xffffffff);
const Decimal = z.string().regex(/^(0|[1-9][0-9]{0,38})$/);

export { SubstrateTx };

interface Runtime {
  genesis: string;
  /** Balances pallet index and `transfer_keep_alive` call index. */
  call: readonly [number, number];
  transactionVersion: number;
  /** `ChargeAssetTxPayment` appends `Option<Location>::None` after the tip. */
  assetFee: boolean;
}

/** The same per-chain layout table the core pins (see `substrate.rs`). */
const RUNTIMES: Readonly<Record<SubstrateTx['chainId'], Runtime>> = {
  [SUBSTRATE_WESTEND]: {
    genesis: '0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e',
    call: [0x04, 0x03],
    transactionVersion: 27,
    assetFee: false,
  },
  [SUBSTRATE_WESTEND_ASSET_HUB]: {
    genesis: '0x67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9',
    call: [0x0a, 0x03],
    transactionVersion: 16,
    assetFee: true,
  },
};

const SS58_WESTEND = 42;
const MAX_TIP = 1_000_000_000_000n;
const U128_MAX = (1n << 128n) - 1n;
/** About 25 minutes of 6-second blocks: room to review and approve before the era dies. */
export const ERA_PERIOD = 256;
/** Approval and broadcast stop this many blocks before the era's last valid block. */
const SAFETY_BLOCKS = 10;

export function scaleCompact(value: bigint): number[] {
  if (value < 0n || value > U128_MAX) throw new RangeError('compact value out of range');
  if (value < 1n << 6n) return [Number(value) << 2];
  if (value < 1n << 14n) {
    const v = (Number(value) << 2) | 1;
    return [v & 0xff, v >> 8];
  }
  if (value < 1n << 30n) {
    const v = ((Number(value) << 2) | 2) >>> 0;
    return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, v >>> 24];
  }
  const bytes: number[] = [];
  for (let v = value; v > 0n; v >>= 8n) bytes.push(Number(v & 0xffn));
  return [((bytes.length - 4) << 2) | 3, ...bytes];
}

const u32le = (v: number) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, v >>> 24];

export function mortalEra(blockNumber: number, period: number): number[] {
  if (period < 4 || period > 4096 || (period & (period - 1)) !== 0)
    throw new Error('Era period must be a power of two from 4 to 4096');
  const phase = blockNumber % period;
  const low = Math.min(Math.max(Math.log2(period) - 1, 1), 15);
  const encoded = low | (phase << 4);
  return [encoded & 0xff, encoded >> 8];
}

function canonical(value: string, what: string): bigint {
  const n = BigInt(value);
  if (n.toString() !== value || n > U128_MAX) throw new Error(`${what} must be a canonical u128`);
  return n;
}

interface Parts {
  runtime: Runtime;
  from: Uint8Array;
  call: number[];
  extra: number[];
  implicit: number[];
}

function parts(input: SubstrateTx): Parts {
  const tx = SubstrateTx.parse(input);
  const runtime = RUNTIMES[tx.chainId];
  const from = ss58Decode(tx.from);
  const to = ss58Decode(tx.to);
  if (!from || !to || from.prefix !== SS58_WESTEND || to.prefix !== SS58_WESTEND)
    throw new Error('Sender and recipient must be Westend-format SS58 addresses');
  if (bytesToHex(from.account) === bytesToHex(to.account))
    throw new Error('Sender and recipient must differ');
  const amount = canonical(tx.planck, 'amount');
  if (amount === 0n) throw new Error('Amount must be positive');
  const tip = canonical(tx.tip, 'tip');
  if (tip > MAX_TIP) throw new Error('Tip is unreasonably large');
  if (tx.transactionVersion !== runtime.transactionVersion)
    throw new Error('Transaction version differs from the verified runtime layout');
  if (tx.genesisHash !== runtime.genesis) throw new Error('Genesis hash differs from the chain id');
  if (/^0x0+$/.test(tx.blockHash)) throw new Error('Zero block hash');
  const call = [...runtime.call, 0x00, ...to.account, ...scaleCompact(amount)];
  const extra = [
    ...mortalEra(tx.blockNumber, tx.eraPeriod),
    ...scaleCompact(BigInt(tx.nonce)),
    ...scaleCompact(tip),
    ...(runtime.assetFee ? [0x00] : []),
    tx.metadataHashMode,
  ];
  const implicit = [
    ...u32le(tx.specVersion),
    ...u32le(tx.transactionVersion),
    ...hexToBytes(runtime.genesis.slice(2)),
    ...hexToBytes(tx.blockHash.slice(2)),
    0x00,
  ];
  return { runtime, from: from.account, call, extra, implicit };
}

/** `call ++ extra ++ implicit`, encoded independently of the core from the same fields. */
export function signingPayload(tx: SubstrateTx): Uint8Array {
  const p = parts(tx);
  return Uint8Array.from([...p.call, ...p.extra, ...p.implicit]);
}

/** Signed extrinsic v4 with the given 64-byte Ed25519 signature. */
export function assembleExtrinsic(tx: SubstrateTx, signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) throw new Error('Ed25519 signature must be 64 bytes');
  const p = parts(tx);
  const body = [0x84, 0x00, ...p.from, 0x00, ...signature, ...p.extra, ...p.call];
  return Uint8Array.from([...scaleCompact(BigInt(body.length)), ...body]);
}

export function extrinsicHash(wire: Uint8Array): string {
  return `0x${bytesToHex(blake2b(wire, { dkLen: 32 }))}`;
}

const NextIndex = U32;
const QueryInfo = z.object({
  partialFee: z.union([
    z.string().regex(/^\d{1,39}$/),
    z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  ]),
});

async function head(call: SubstrateCall, finalized: boolean) {
  const params = finalized ? [await call('chain_getFinalizedHead', [], H256Hex)] : [];
  const header = await call('chain_getHeader', params, Header);
  return { ...header, hash: params[0] as string | undefined };
}

async function liveRuntime(call: SubstrateCall, chainId: SubstrateTx['chainId']) {
  const rv = await call('state_getRuntimeVersion', [], RuntimeVersion);
  if (rv.transactionVersion !== RUNTIMES[chainId].transactionVersion)
    throw new Error(
      `The ${rv.specName} runtime moved to transaction version ${rv.transactionVersion}; transfers stay disabled until its layout is re-verified`,
    );
  return rv;
}

async function accountAt(call: SubstrateCall, chainId: string, addr: string, at?: string) {
  const net = substrateNetwork(chainId)!;
  const decoded = ss58Decode(addr);
  if (!decoded) throw new Error('Invalid address');
  const raw = await call(
    'state_getStorage',
    at ? [accountStorageKey(decoded.account), at] : [accountStorageKey(decoded.account)],
    StorageValue,
  );
  return decodeAccount(raw, net);
}

export async function prepareSubstrate(
  adapter: SubstrateAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: SubstrateTx; simulation: Simulation }> {
  if (
    (intent.chainId !== SUBSTRATE_WESTEND && intent.chainId !== SUBSTRATE_WESTEND_ASSET_HUB) ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${intent.chainId}:native`
  )
    throw new Error('Only native WND transfers on Westend and Westend Asset Hub are enabled');
  const chainId = intent.chainId;
  const net = adapter.network(chainId);
  return adapter.withNode(chainId, async (call) => {
    const rv = await liveRuntime(call, chainId);
    // The finalized head is the era birth: its hash cannot be reorged away under the signature.
    const birth = await head(call, true);
    const nonce = await call('system_accountNextIndex', [from], NextIndex);
    const unsigned = SubstrateTx.parse({
      chainId,
      from,
      to: intent.to,
      planck: intent.amount,
      tip: '0',
      nonce,
      specVersion: rv.specVersion,
      transactionVersion: rv.transactionVersion,
      genesisHash: net.genesis,
      blockHash: birth.hash,
      blockNumber: birth.number,
      eraPeriod: ERA_PERIOD,
      metadataHashMode: 0,
    });
    // Fee estimation ignores the signature, so a zero one stands in.
    const probe = assembleExtrinsic(unsigned, new Uint8Array(64));
    const [info, sender, recipient] = await Promise.all([
      call('payment_queryInfo', [`0x${bytesToHex(probe)}`], QueryInfo),
      accountAt(call, chainId, from),
      accountAt(call, chainId, intent.to),
    ]);
    const fee = BigInt(info.partialFee);
    const amount = BigInt(intent.amount);
    let error: string | undefined;
    const warnings: Simulation['warnings'] = [];
    const recipientNew = recipient.free + recipient.reserved === 0n;
    if (spendable(sender, net.existentialDeposit) < amount + fee)
      error =
        'Transferable balance does not cover the amount and fee while keeping the sender alive';
    else if (recipientNew && amount < net.existentialDeposit)
      error = `The recipient has no account yet; send at least the existential deposit (${net.existentialDeposit} planck)`;
    if (recipientNew && !error)
      warnings.push({
        kind: 'other',
        message: 'The recipient has no account on this chain yet; this transfer creates it.',
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

/** Usable while the runtime, the nonce and the era all still match what was signed. */
export async function substrateApprovalValid(
  adapter: SubstrateAdapter,
  tx: SubstrateTx,
): Promise<boolean> {
  parts(tx);
  return adapter.withNode(tx.chainId, async (call) => {
    const rv = await call('state_getRuntimeVersion', [], RuntimeVersion);
    if (rv.specVersion !== tx.specVersion || rv.transactionVersion !== tx.transactionVersion)
      return false;
    const best = await head(call, false);
    if (best.number >= tx.blockNumber + tx.eraPeriod - 1 - SAFETY_BLOCKS) return false;
    const nonce = await call('system_accountNextIndex', [tx.from], NextIndex);
    return nonce === tx.nonce;
  });
}

const Submitted = H256Hex;

/** Broadcast only bytes that are exactly the ledger's transfer with a valid sender signature. */
export async function broadcastSubstrate(
  adapter: SubstrateAdapter,
  tx: SubstrateTx,
  signedHex: string,
): Promise<string> {
  const hex = signedHex.replace(/^0x/, '');
  if (!/^(?:[0-9a-f]{2})+$/.test(hex)) throw new Error('Signed bytes are not lowercase hex');
  const wire = hexToBytes(hex);
  const template = assembleExtrinsic(tx, new Uint8Array(64));
  if (wire.length !== template.length) throw new Error('Signed bytes are not this transfer');
  const p = parts(tx);
  const bodyLength = 99 + p.extra.length + p.call.length;
  // The signature follows the length prefix, version, MultiAddress::Id, signer and variant byte.
  const sigStart = scaleCompact(BigInt(bodyLength)).length + 35;
  const signature = wire.slice(sigStart, sigStart + 64);
  const expected = assembleExtrinsic(tx, signature);
  if (bytesToHex(expected) !== hex) throw new Error('Signed bytes are not this transfer');
  const payload = signingPayload(tx);
  const message = payload.length > 256 ? blake2b(payload, { dkLen: 32 }) : payload;
  if (!ed25519.verify(signature, message, p.from, { zip215: false }))
    throw new Error('Signature does not verify for the sender');
  const hash = extrinsicHash(wire);
  return adapter.withNode(tx.chainId, async (call) => {
    const rv = await call('state_getRuntimeVersion', [], RuntimeVersion);
    if (rv.specVersion !== tx.specVersion || rv.transactionVersion !== tx.transactionVersion)
      throw new Error('The runtime upgraded after signing; prepare the transfer again');
    let submitted: string;
    try {
      submitted = await call('author_submitExtrinsic', [`0x${hex}`], Submitted);
    } catch (err) {
      // A retry of an extrinsic the pool already holds is not a failure.
      if (err instanceof Error && /already imported|1013/i.test(err.message)) return hash;
      throw err;
    }
    if (submitted !== hash) throw new Error('Node reported a different extrinsic hash');
    return hash;
  });
}

const BlockBody = z.object({
  block: z.object({
    header: Header,
    extrinsics: z
      .array(
        z
          .string()
          .max(1 << 19)
          .regex(/^0x(?:[0-9a-f]{2})*$/),
      )
      .max(10_000),
  }),
});

/**
 * Inclusion is found by bisecting the sender's nonce over the era's blocks,
 * then matching the extrinsic hash in the block where it advanced. Dispatch
 * success is read from the recipient's balance change in that block, since
 * decoding events would need the runtime metadata.
 */
export async function substrateTransferStatus(
  adapter: SubstrateAdapter,
  tx: SubstrateTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error('Invalid Substrate extrinsic hash');
  parts(tx);
  return adapter.withNode(tx.chainId, async (call) => {
    const finalized = await head(call, true);
    const lastValid = tx.blockNumber + tx.eraPeriod - 1;
    const nonceAt = async (hashAt: string) =>
      (await accountAt(call, tx.chainId, tx.from, hashAt)).nonce;
    const hashOf = (n: number) => call('chain_getBlockHash', [n], H256Hex);
    if ((await nonceAt(finalized.hash!)) <= tx.nonce)
      return finalized.number >= lastValid ? { state: 'expired' } : { state: 'pending' };
    let lo = tx.blockNumber;
    let hi = Math.min(finalized.number, lastValid);
    if ((await nonceAt(await hashOf(lo))) > tx.nonce) return { state: 'expired' };
    if ((await nonceAt(await hashOf(hi))) <= tx.nonce) return { state: 'expired' };
    // Invariant: nonce at lo has not advanced, nonce at hi has.
    while (hi - lo > 1) {
      const mid = Math.floor((lo + hi) / 2);
      if ((await nonceAt(await hashOf(mid))) > tx.nonce) hi = mid;
      else lo = mid;
    }
    const blockHash = await hashOf(hi);
    const { block } = await call('chain_getBlock', [blockHash], BlockBody);
    const included = block.extrinsics.some((x) => extrinsicHash(hexToBytes(x.slice(2))) === hash);
    // Another extrinsic took this nonce; this one can never be included.
    if (!included) return { state: 'expired' };
    const [after, before, now] = await Promise.all([
      accountAt(call, tx.chainId, tx.to, blockHash),
      accountAt(call, tx.chainId, tx.to, block.header.parentHash),
      call('state_getStorage', [TIMESTAMP_NOW, blockHash], StorageValue),
    ]);
    const credited = after.free + after.reserved - (before.free + before.reserved);
    if (credited < BigInt(tx.planck))
      return { state: 'failed', reason: 'Included, but the recipient was not credited' };
    const ms =
      now?.length === 18
        ? Number(BigInt(`0x${now.slice(2).match(/../g)!.reverse().join('')}`))
        : undefined;
    return {
      state: 'confirmed',
      blockNumber: hi,
      ...(ms !== undefined && Number.isSafeInteger(ms) ? { timestampMs: ms } : {}),
    };
  });
}
