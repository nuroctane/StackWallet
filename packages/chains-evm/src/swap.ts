/**
 * Single-pool Uniswap v3 swaps on the testnets the core knows a router for.
 * The core holds the same router table and decodes the calldata itself, so
 * this module only quotes and builds; it cannot widen what a swap may do.
 */
import { z } from 'zod';

import { isValidEvmAddress, type EvmAdapter } from './evm.js';

export interface SwapRoute {
  router: string;
  quoter: string;
  weth: string;
}

/** Mirrors `evm::SWAP_ROUTES` in the core; a chain missing here has no swaps. */
export const SWAP_ROUTES: Readonly<Record<string, SwapRoute>> = {
  'eip155:11155111': {
    router: '0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E',
    quoter: '0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3',
    weth: '0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14',
  },
};

export const POOL_FEES = [100, 500, 3000, 10000] as const;
export type PoolFee = (typeof POOL_FEES)[number];

const EXACT_INPUT_SINGLE = '0x04e45aaf';
const QUOTE_EXACT_INPUT_SINGLE = '0xc6a5026a';
const ALLOWANCE = '0xdd62ed3e';
const APPROVE = '0x095ea7b3';
const UINT256_MAX = (1n << 256n) - 1n;

const Hex = z
  .string()
  .regex(/^0x[0-9a-fA-F]*$/)
  .max(4096);

function word(v: bigint): string {
  if (v < 0n || v > UINT256_MAX) throw new RangeError('value does not fit in 256 bits');
  return v.toString(16).padStart(64, '0');
}

function addr(a: string): string {
  if (!isValidEvmAddress(a)) throw new TypeError(`invalid address ${a}`);
  return a.slice(2).toLowerCase().padStart(64, '0');
}

export function swapRoute(chainId: string): SwapRoute | null {
  return SWAP_ROUTES[chainId] ?? null;
}

/** `uniswap-v3:<fee>` names the pool in the intent, so the core can bind the fee too. */
export function swapAggregator(fee: PoolFee): string {
  return `uniswap-v3:${fee}`;
}

export function feeOfAggregator(aggregator: string): PoolFee {
  const fee = Number(aggregator.replace(/^uniswap-v3:/, ''));
  if (!aggregator.startsWith('uniswap-v3:') || !POOL_FEES.includes(fee as PoolFee))
    throw new TypeError(`unknown aggregator ${aggregator}`);
  return fee as PoolFee;
}

export function encodeExactInputSingle(p: {
  tokenIn: string;
  tokenOut: string;
  fee: PoolFee;
  recipient: string;
  amountIn: bigint;
  minOut: bigint;
}): string {
  return (
    EXACT_INPUT_SINGLE +
    addr(p.tokenIn) +
    addr(p.tokenOut) +
    word(BigInt(p.fee)) +
    addr(p.recipient) +
    word(p.amountIn) +
    word(p.minOut) +
    word(0n)
  );
}

export function encodeApprove(spender: string, amount: bigint): string {
  return APPROVE + addr(spender) + word(amount);
}

/** The floor the swap reverts below: the quote less the slippage the user allows. */
export function minOutFor(quoted: bigint, slippageBps: number): bigint {
  if (!Number.isInteger(slippageBps) || slippageBps < 0 || slippageBps > 5000)
    throw new RangeError('slippage must be between 0 and 5000 bps');
  return (quoted * BigInt(10_000 - slippageBps)) / 10_000n;
}

export interface Quote {
  fee: PoolFee;
  amountOut: bigint;
}

/**
 * Ask QuoterV2 for every fee tier and keep the best. A tier without a pool
 * reverts, which counts as no quote rather than an error.
 */
export async function quoteSwap(
  adapter: EvmAdapter,
  chainId: string,
  tokenIn: string,
  tokenOut: string,
  amountIn: bigint,
): Promise<Quote | null> {
  const route = swapRoute(chainId);
  if (!route) throw new Error(`No swap router is known on ${chainId}`);
  const results = await Promise.all(
    POOL_FEES.map(async (fee) => {
      const data =
        QUOTE_EXACT_INPUT_SINGLE +
        addr(tokenIn) +
        addr(tokenOut) +
        word(amountIn) +
        word(BigInt(fee)) +
        word(0n);
      try {
        const out = await adapter.call(
          chainId,
          'eth_call',
          [{ to: route.quoter, data }, 'latest'],
          Hex,
        );
        if (out.length < 2 + 64) return null;
        return { fee, amountOut: BigInt(`0x${out.slice(2, 66)}`) };
      } catch {
        return null;
      }
    }),
  );
  return results.reduce<Quote | null>(
    (best, q) => (q && q.amountOut > 0n && (!best || q.amountOut > best.amountOut) ? q : best),
    null,
  );
}

export async function allowanceOf(
  adapter: EvmAdapter,
  chainId: string,
  token: string,
  owner: string,
  spender: string,
): Promise<bigint> {
  const out = await adapter.call(
    chainId,
    'eth_call',
    [{ to: token, data: ALLOWANCE + addr(owner) + addr(spender) }, 'latest'],
    Hex,
  );
  return out === '0x' ? 0n : BigInt(out.slice(0, 66));
}
