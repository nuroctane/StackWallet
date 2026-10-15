import { describe, expect, it } from 'vitest';

import { coinIdFor, fetchUsdPrices, formatUsd, parsePrices, usdMicros } from './prices.js';

describe('prices', () => {
  it('never prices a testnet and only known natives', () => {
    expect(
      coinIdFor({ testnet: true, nativeAsset: { ref: 'x', symbol: 'ETH', decimals: 18 } }),
    ).toBeNull();
    expect(
      coinIdFor({ testnet: false, nativeAsset: { ref: 'x', symbol: 'ETH', decimals: 18 } }),
    ).toBe('ethereum');
    expect(
      coinIdFor({ testnet: false, nativeAsset: { ref: 'x', symbol: 'ZZZ', decimals: 18 } }),
    ).toBeNull();
  });

  it("prefers the chain's own price id over a shared symbol", () => {
    const native = { ref: 'x', symbol: 'S', decimals: 18 };
    expect(coinIdFor({ testnet: false, nativeAsset: native, priceId: 'other-s' })).toBe('other-s');
    expect(coinIdFor({ testnet: true, nativeAsset: native, priceId: 'other-s' })).toBeNull();
  });

  it('values base units with integer math', () => {
    expect(usdMicros('1500000000000000000', 18, 2000)).toBe(3_000_000_000n);
    expect(usdMicros('1', 8, 60000)).toBe(600n);
    expect(formatUsd(3_000_000_000n)).toBe('$3,000.00');
    expect(formatUsd(1_234_567_891n)).toBe('$1,234.57');
  });

  it('parses and requests only well-formed ids', async () => {
    expect(parsePrices({ ethereum: { usd: 1 }, junk: {} }, 5)).toEqual([
      { id: 'ethereum', usd: 1, fetchedAtMs: 5 },
    ]);
    expect(() => parsePrices({ ethereum: { usd: -1 } }, 5)).toThrow();
    let url = '';
    const fetch = (async (u: RequestInfo | URL) => {
      url = String(u);
      return new Response(JSON.stringify({ bitcoin: { usd: 3 } }));
    }) as typeof globalThis.fetch;
    const got = await fetchUsdPrices(['bitcoin', 'bad id', 'bitcoin'], {
      fetchOptions: { fetch },
      now: () => 1,
    });
    expect(url).toContain('ids=bitcoin&');
    expect(got).toEqual([{ id: 'bitcoin', usd: 3, fetchedAtMs: 1 }]);
  });
});
