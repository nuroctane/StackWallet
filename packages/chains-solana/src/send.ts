import { base58, base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import { SolanaTx, type TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { isValidSolanaAddress, type SolanaAdapter } from './solana.js';

export const SOLANA_DEVNET = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
const SYSTEM = '11111111111111111111111111111111';
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Address = z.string().refine(isValidSolanaAddress);
const Signature = z
  .string()
  .max(88)
  .refine((s) => {
    try {
      return base58.decode(s).length === 64;
    } catch {
      return false;
    }
  });

/** The same bounded message the core constructs independently. */
export function nativeTransferMessage(input: SolanaTx): Uint8Array {
  const tx = SolanaTx.parse(input);
  const amount = BigInt(tx.lamports);
  if (amount <= 0n || amount > 0xffffffffffffffffn || amount.toString() !== tx.lamports)
    throw new Error('SOL amount must be a positive u64 integer');
  if (
    ![tx.from, tx.to, tx.recentBlockhash].every(isValidSolanaAddress) ||
    tx.from === tx.to ||
    tx.from === SYSTEM ||
    tx.to === SYSTEM ||
    tx.recentBlockhash === SYSTEM
  )
    throw new Error('Invalid SOL sender, recipient or blockhash');
  const bytes = new Uint8Array(150);
  bytes.set([1, 0, 1, 3]);
  bytes.set(base58.decode(tx.from), 4);
  bytes.set(base58.decode(tx.to), 36);
  bytes.set(base58.decode(tx.recentBlockhash), 100);
  bytes.set([1, 2, 2, 0, 1, 12], 132);
  const view = new DataView(bytes.buffer);
  view.setUint32(138, 2, true);
  view.setBigUint64(142, amount, true);
  if (tx.messageVersion === 'v0') {
    const versioned = new Uint8Array(152);
    versioned[0] = 0x80;
    versioned.set(bytes, 1);
    return versioned;
  }
  return bytes;
}

function unsignedWire(message: Uint8Array): Uint8Array {
  const wire = new Uint8Array(65 + message.length);
  wire[0] = 1;
  wire.set(message, 65);
  return wire;
}

export async function prepareSolana(
  adapter: SolanaAdapter,
  intent: TxIntent,
  from: string,
  options: SolanaPrepareOptions = {},
): Promise<{
  unsigned: SolanaTx;
  simulation: Simulation;
}> {
  const checkedOptions = z
    .strictObject({ messageVersion: z.enum(['legacy', 'v0']).optional() })
    .parse(options);
  if (
    intent.chainId !== SOLANA_DEVNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${SOLANA_DEVNET}:native`
  )
    throw new Error('Only native SOL transfers on Devnet are enabled');
  const rpc = <T>(method: string, params: unknown[], schema: z.ZodType<T>) =>
    adapter.clusterCall(intent.chainId, method, params, schema);
  const latest = await rpc(
    'getLatestBlockhash',
    [{ commitment: 'confirmed' }],
    z.object({
      value: z.object({ blockhash: Address, lastValidBlockHeight: SafeInt.positive() }),
    }),
  );
  const unsigned = SolanaTx.parse({
    chainId: intent.chainId,
    from,
    to: intent.to,
    lamports: intent.amount,
    recentBlockhash: latest.value.blockhash,
    lastValidBlockHeight: latest.value.lastValidBlockHeight,
    ...(checkedOptions.messageVersion ? { messageVersion: checkedOptions.messageVersion } : {}),
  });
  const message = nativeTransferMessage(unsigned);
  const [fee, balance, recipient] = await Promise.all([
    rpc(
      'getFeeForMessage',
      [base64.encode(message), { commitment: 'confirmed' }],
      z.object({ value: SafeInt.nullable() }),
    ),
    rpc('getBalance', [from, { commitment: 'confirmed' }], z.object({ value: SafeInt })),
    rpc(
      'getAccountInfo',
      [intent.to, { commitment: 'confirmed', encoding: 'base64' }],
      z.object({
        value: z.object({ owner: Address, executable: z.boolean() }).nullable(),
      }),
    ),
  ]);
  if (fee.value === null) throw new Error('Blockhash expired while preparing; propose again');
  const simulated = await rpc(
    'simulateTransaction',
    [
      base64.encode(unsignedWire(message)),
      {
        encoding: 'base64',
        commitment: 'confirmed',
        sigVerify: false,
        replaceRecentBlockhash: false,
      },
    ],
    z.object({ value: z.object({ err: z.json() }) }),
  );
  let error =
    simulated.value.err == null ? undefined : JSON.stringify(simulated.value.err).slice(0, 512);
  if (BigInt(balance.value) < BigInt(intent.amount) + BigInt(fee.value))
    error ??= 'Balance does not cover the transfer and fee';
  return {
    unsigned,
    simulation: {
      ok: error === undefined,
      assetDeltas: [
        { assetRef: intent.asset, amount: `-${intent.amount}` },
        { assetRef: intent.asset, amount: `-${fee.value}` },
      ],
      fee: { assetRef: intent.asset, amount: String(fee.value) },
      warnings:
        recipient.value && (recipient.value.executable || recipient.value.owner !== SYSTEM)
          ? [{ kind: 'destinationIsContract', address: intent.to }]
          : [],
      ...(error ? { error } : {}),
    },
  };
}

export async function solanaBlockhashValid(adapter: SolanaAdapter, tx: SolanaTx): Promise<boolean> {
  const result = await adapter.clusterCall(
    tx.chainId,
    'isBlockhashValid',
    [tx.recentBlockhash, { commitment: 'confirmed' }],
    z.object({ value: z.boolean() }),
  );
  return result.value;
}

export interface SolanaPrepareOptions {
  messageVersion?: 'legacy' | 'v0';
}

export async function broadcastSolana(
  adapter: SolanaAdapter,
  chainId: string,
  rawHex: string,
): Promise<string> {
  if (!/^0x(?:[0-9a-fA-F]{430}|[0-9a-fA-F]{434})$/.test(rawHex))
    throw new Error('Invalid native SOL wire transaction');
  const bytes = Uint8Array.from(rawHex.slice(2).match(/../g)!, (b) => parseInt(b, 16));
  const message = bytes.slice(65);
  const v0 = message[0] === 0x80;
  if (bytes[0] !== 1 || message.length !== (v0 ? 152 : 150))
    throw new Error('Invalid native SOL wire transaction');
  const offset = v0 ? 1 : 0;
  const expected = nativeTransferMessage({
    chainId: SOLANA_DEVNET,
    from: base58.encode(message.slice(offset + 4, offset + 36)),
    to: base58.encode(message.slice(offset + 36, offset + 68)),
    recentBlockhash: base58.encode(message.slice(offset + 100, offset + 132)),
    lamports: new DataView(message.buffer, message.byteOffset)
      .getBigUint64(offset + 142, true)
      .toString(),
    lastValidBlockHeight: 1,
    ...(v0 ? { messageVersion: 'v0' as const } : {}),
  });
  if (
    chainId !== SOLANA_DEVNET ||
    bytes[0] !== 1 ||
    message.length !== expected.length ||
    !expected.every((b, i) => message[i] === b)
  )
    throw new Error('Invalid native SOL wire transaction');
  return adapter.clusterCall(
    chainId,
    'sendTransaction',
    [
      base64.encode(bytes),
      {
        encoding: 'base64',
        preflightCommitment: 'confirmed',
        skipPreflight: false,
      },
    ],
    Signature,
  );
}

/** Expiry is checked only after the finalized height and a fresh history lookup. */
export async function solanaTransferStatus(
  adapter: SolanaAdapter,
  tx: SolanaTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  Signature.parse(hash);
  return adapter.withCluster<TxStatus | { state: 'expired' }>(tx.chainId, async (rpc) => {
    const finalizedSlot = await rpc('getSlot', [{ commitment: 'finalized' }], SafeInt);
    const height = await rpc('getBlockHeight', [{ commitment: 'finalized' }], SafeInt);
    const result = await rpc(
      'getSignatureStatuses',
      [
        [hash],
        {
          searchTransactionHistory: true,
        },
      ],
      z.object({
        context: z.object({ slot: SafeInt }),
        value: z
          .array(
            z
              .object({
                slot: SafeInt,
                err: z.json(),
                confirmationStatus: z.enum(['processed', 'confirmed', 'finalized']).nullable(),
              })
              .nullable(),
          )
          .length(1),
      }),
    );
    const entry = result.value[0];
    // A processed fork can disappear. Wait for finalized evidence before retiring the signed bytes.
    if (entry?.confirmationStatus === 'finalized') {
      return entry.err == null
        ? { state: 'confirmed', blockNumber: entry.slot }
        : { state: 'failed', reason: JSON.stringify(entry.err).slice(0, 512) };
    }
    if (entry) return { state: 'pending' };
    // A load-balanced or lagging response cannot prove absence after expiry.
    if (result.context.slot < finalizedSlot) return { state: 'unknown' };
    return height > tx.lastValidBlockHeight ? { state: 'expired' } : { state: 'unknown' };
  });
}
