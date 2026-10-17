import { MemoryRpcPool } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import { ChainlinkReader, findFeed, ticksToCandles } from './chainlink.js';

/**
 * Live verification of the ABI path against Ethereum mainnet. Never runs in
 * CI or the normal suite; run it deliberately after changing the reader:
 *
 *   CHAINLINK_LIVE=1 pnpm --filter @stackwallet/market exec vitest run src/chainlink.live.test.ts
 */
const LIVE = process.env.CHAINLINK_LIVE === '1';
const feed = findFeed('eip155:1', 'ETH');

const curated = () => {
  const pool = new MemoryRpcPool([]);
  pool.setEndpoints('eip155:1', ['https://ethereum-rpc.publicnode.com', 'https://eth.drpc.org']);
  return pool;
};

describe.skipIf(!LIVE)('chainlink live mainnet', () => {
  it('reads the latest ETH / USD round, cross-checked across operators', async () => {
    const reader = new ChainlinkReader({ pool: curated() });
    const latest = await reader.latest(feed!);
    expect(latest.price).toBeGreaterThan(10);
    expect(latest.price).toBeLessThan(1_000_000);
    expect(Date.now() - latest.t).toBeLessThan(6 * 3_600_000);
    expect(latest.provenance).toBe('agreed');
  }, 30_000);

  it('walks recent rounds and candles them', async () => {
    const reader = new ChainlinkReader({ pool: curated() });
    const { ticks, exhausted } = await reader.roundsBack(feed!, 24);
    expect(exhausted).toBe(false);
    expect(ticks.length).toBeGreaterThan(10);
    for (let i = 1; i < ticks.length; i++) {
      expect(ticks[i]!.t).toBeLessThanOrEqual(ticks[i - 1]!.t);
    }
    const candles = ticksToCandles([...ticks].reverse(), 3_600_000);
    expect(candles.length).toBeGreaterThan(1);
  }, 60_000);
});
