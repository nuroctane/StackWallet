/**
 * Turning a transfer intent into an unsigned EIP-1559 transaction plus a
 * simulation. The core re-checks every field that moves value (destination,
 * amount, calldata) and refuses a mismatch, so this module only has to get
 * gas, fees and nonce right; it never sees a key.
 */
import {
  JsonRpcError,
  RpcFailoverError,
  withFailover,
  type AssetDelta,
  type Simulation,
  type SimulationWarning,
} from '@stackwallet/chains';
import type { EvmTx, TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { isValidEvmAddress, type EvmAdapter } from './evm.js';

const Hex = z
  .string()
  .regex(/^0x[0-9a-fA-F]*$/)
  .max(200_000);
const Block = z.object({ baseFeePerGas: Hex.optional() }).nullable();

/** `transfer(address,uint256)` */
export const ERC20_TRANSFER = '0xa9059cbb';
const FALLBACK_PRIORITY_FEE = 1_500_000_000n;
/** Estimates are padded so a small state change between estimate and inclusion does not run out. */
const GAS_PAD_NUM = 12n;
const GAS_PAD_DEN = 10n;

export function erc20Of(asset: string, chainId: string): string | null {
  const prefix = `${chainId}:erc20:`;
  return asset.startsWith(prefix) ? asset.slice(prefix.length) : null;
}

export function encodeErc20Transfer(to: string, amount: bigint): string {
  if (!isValidEvmAddress(to)) throw new TypeError(`invalid recipient ${to}`);
  return (
    ERC20_TRANSFER +
    to.slice(2).toLowerCase().padStart(64, '0') +
    amount.toString(16).padStart(64, '0')
  );
}

export interface CallShape {
  to: string;
  value: bigint;
  data: string;
  /** What leaves the sender, for the simulated deltas. */
  delta: AssetDelta;
}

/** The on-chain call an intent becomes; the core performs the same mapping to check it. */
export function callFor(intent: TxIntent): CallShape {
  if (intent.kind === 'transfer') {
    const amount = BigInt(intent.amount);
    const token = erc20Of(intent.asset, intent.chainId);
    if (intent.asset === `${intent.chainId}:native`) {
      return {
        to: intent.to,
        value: amount,
        data: '0x',
        delta: { assetRef: intent.asset, amount: `-${intent.amount}` },
      };
    }
    if (token) {
      return {
        to: token,
        value: 0n,
        data: encodeErc20Transfer(intent.to, amount),
        delta: { assetRef: intent.asset, amount: `-${intent.amount}` },
      };
    }
    throw new TypeError(`unsupported asset ${intent.asset}`);
  }
  if (intent.kind === 'contractCall') {
    return {
      to: intent.to,
      value: BigInt(intent.value),
      data: intent.dataHex.startsWith('0x') ? intent.dataHex : `0x${intent.dataHex}`,
      delta: { assetRef: `${intent.chainId}:native`, amount: `-${intent.value}` },
    };
  }
  throw new TypeError(`${intent.kind} has no EVM form yet`);
}

const hex = (n: bigint) => `0x${n.toString(16)}`;

/**
 * What the node said, without the failover bookkeeping: the first JSON-RPC
 * error any endpoint returned (that is the chain talking), else the first
 * transport failure.
 */
export function nodeMessage(err: unknown): string {
  if (err instanceof RpcFailoverError) {
    const rpc = err.causes.find((c) => c.error instanceof JsonRpcError)?.error as
      | JsonRpcError
      | undefined;
    if (rpc) return rpc.message.replace(/^json-rpc error -?\d+ from \S+: /, '');
    const first = err.causes[0]?.error;
    return first instanceof Error ? first.message : 'no endpoint answered';
  }
  if (err instanceof JsonRpcError)
    return err.message.replace(/^json-rpc error -?\d+ from \S+: /, '');
  return err instanceof Error ? err.message : String(err);
}

export interface Prepared {
  unsigned: EvmTx;
  simulation: Simulation;
}

/**
 * Nonce from the pending pool, fees from the latest base fee (2x headroom plus
 * the node's tip), gas from `eth_estimateGas`. A failed estimate does not stop
 * the proposal: it is recorded as a failed simulation for the approver to see.
 */
export async function prepareEvm(
  adapter: EvmAdapter,
  intent: TxIntent,
  from: string,
): Promise<Prepared> {
  const chainId = intent.chainId;
  const chainNum = Number(chainId.split(':')[1]);
  const call = callFor(intent);
  const rpc = <T>(method: string, params: unknown[], schema: z.ZodType<T>) =>
    adapter.call(chainId, method, params, schema);

  const [nonceHex, block, balanceHex, code] = await Promise.all([
    rpc('eth_getTransactionCount', [from, 'pending'], Hex),
    rpc('eth_getBlockByNumber', ['latest', false], Block),
    rpc('eth_getBalance', [from, 'latest'], Hex),
    rpc('eth_getCode', [call.to, 'latest'], Hex),
  ]);
  const tip = await rpc('eth_maxPriorityFeePerGas', [], Hex)
    .then((h) => BigInt(h))
    .catch(() => FALLBACK_PRIORITY_FEE);
  const base = block?.baseFeePerGas ? BigInt(block.baseFeePerGas) : 0n;
  const maxFee = base * 2n + tip;

  const warnings: SimulationWarning[] = [];
  let error: string | undefined;
  let gas = call.data === '0x' ? 21_000n : 100_000n;
  try {
    const est = BigInt(
      await rpc(
        'eth_estimateGas',
        [{ from, to: call.to, value: hex(call.value), data: call.data }],
        Hex,
      ),
    );
    gas = est === 21_000n ? est : (est * GAS_PAD_NUM + GAS_PAD_DEN - 1n) / GAS_PAD_DEN;
  } catch (err) {
    error = nodeMessage(err);
  }
  if (code !== '0x' && intent.kind === 'transfer' && !erc20Of(intent.asset, chainId)) {
    warnings.push({ kind: 'destinationIsContract', address: call.to });
  }
  const balance = BigInt(balanceHex);
  const worstFee = gas * maxFee;
  if (balance < call.value + worstFee) {
    error ??= `balance ${balance} wei does not cover ${call.value + worstFee} wei (value + max fee)`;
  }
  const expectedFee = gas * (base + tip);
  return {
    unsigned: {
      chainId: chainNum,
      nonce: Number(BigInt(nonceHex)),
      maxPriorityFeePerGas: tip.toString(),
      maxFeePerGas: maxFee.toString(),
      gasLimit: Number(gas),
      to: call.to,
      value: call.value.toString(),
      dataHex: call.data === '0x' ? '' : call.data.slice(2),
    },
    simulation: {
      ok: error === undefined,
      assetDeltas: [call.delta, { assetRef: `${chainId}:native`, amount: `-${expectedFee}` }],
      fee: { assetRef: `${chainId}:native`, amount: expectedFee.toString() },
      warnings,
      ...(error ? { error } : {}),
    },
  };
}

/** Hand the core's signed bytes to the network; returns the hash the node reports. */
export async function broadcastEvm(
  adapter: EvmAdapter,
  chainId: string,
  rawHex: string,
): Promise<string> {
  return withFailover(adapter.rpc, chainId, (url) =>
    adapter.rawCall(url, 'eth_sendRawTransaction', [rawHex], Hex),
  );
}

const DECIMALS = '0x313ce567';
const SYMBOL = '0x95d89b41';

/** Decode an ABI `string` return, or a bytes32 symbol from older tokens. */
export function decodeAbiString(hexData: string): string | null {
  const h = hexData.startsWith('0x') ? hexData.slice(2) : hexData;
  if (h.length === 64) {
    const bytes = h
      .match(/../g)!
      .map((b) => parseInt(b, 16))
      .filter((b) => b !== 0);
    return new TextDecoder().decode(new Uint8Array(bytes)) || null;
  }
  if (h.length < 128) return null;
  const len = Number(BigInt(`0x${h.slice(64, 128)}`));
  if (len > 64) return null;
  const body = h.slice(128, 128 + len * 2);
  if (body.length !== len * 2) return null;
  return new TextDecoder().decode(
    new Uint8Array(body.match(/../g)?.map((b) => parseInt(b, 16)) ?? []),
  );
}

/** Symbol and decimals of an ERC-20, read from the chain (untrusted text, sanitize before display). */
export async function tokenInfo(
  adapter: EvmAdapter,
  chainId: string,
  token: string,
): Promise<{ symbol: string; decimals: number }> {
  if (!isValidEvmAddress(token)) throw new TypeError('not a token address');
  const call = (data: string) =>
    adapter.call(chainId, 'eth_call', [{ to: token, data }, 'latest'], Hex);
  const [d, s] = await Promise.all([call(DECIMALS), call(SYMBOL).catch(() => '0x')]);
  const decimals = Number(BigInt(d));
  if (!Number.isInteger(decimals) || decimals > 36)
    throw new Error('token reports no sane decimals');
  const symbol =
    (decodeAbiString(s) ?? 'TOKEN').replace(/[^\x20-\x7e]/g, '').slice(0, 12) || 'TOKEN';
  return { symbol, decimals };
}
