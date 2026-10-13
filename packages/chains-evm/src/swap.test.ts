import { describe, expect, it } from 'vitest';

import {
  encodeApprove,
  encodeExactInputSingle,
  feeOfAggregator,
  minOutFor,
  swapAggregator,
} from './swap.js';
import { callFor } from './send.js';

// Shared with `evm.rs` in the core, so both sides agree byte for byte.
const SWAP_VECTOR =
  '0x04e45aaf000000000000000000000000fff9976782d46cc05630d1f6ebab18b2324d6b140000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000038d7ea4c6800000000000000000000000000000000000000000000000000000000000002625a00000000000000000000000000000000000000000000000000000000000000000';
const WETH = '0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14';
const USDC = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';
const ME = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const CHAIN = 'eip155:11155111';

describe('uniswap v3 swaps', () => {
  it('encodes exactInputSingle exactly as the core does', () => {
    expect(
      encodeExactInputSingle({
        tokenIn: WETH,
        tokenOut: USDC,
        fee: 3000,
        recipient: ME,
        amountIn: 10n ** 15n,
        minOut: 2_500_000n,
      }),
    ).toBe(SWAP_VECTOR);
  });

  it('turns a native swap intent into a router call paid to the sender', () => {
    const call = callFor(
      {
        id: 't',
        walletId: 'w',
        accountId: 'a',
        chainId: CHAIN,
        proposer: { kind: 'human', deviceId: 'd' },
        kind: 'swap',
        sell: `${CHAIN}:native`,
        sellAmount: '1000000000000000',
        buy: `${CHAIN}:erc20:${USDC}`,
        minBuyAmount: '2500000',
        maxSlippageBps: 100,
        aggregator: swapAggregator(3000),
        usdMicros: null,
        untrustedDestinations: [],
        createdAtMs: 0,
      },
      ME,
    );
    expect(call.to).toBe('0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E');
    expect(call.value).toBe(10n ** 15n);
    expect(call.data).toBe(SWAP_VECTOR);
  });

  it('bounds slippage and fee tiers', () => {
    expect(minOutFor(10_000n, 50)).toBe(9_950n);
    expect(() => minOutFor(1n, 6000)).toThrow();
    expect(feeOfAggregator('uniswap-v3:500')).toBe(500);
    expect(() => feeOfAggregator('uniswap-v3:42')).toThrow();
    expect(encodeApprove(ME, 5n).slice(0, 10)).toBe('0x095ea7b3');
  });
});
