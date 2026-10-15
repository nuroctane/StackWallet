/**
 * Well-known mainnet tokens, so the common stablecoins and wrapped coins get a
 * symbol, decimals and a price without the user tracking them first. Keys are
 * the asset refs adapters emit (lowercase EVM contracts).
 */
export const KNOWN_TOKENS: Readonly<
  Record<string, { symbol: string; decimals: number; coinId: string }>
> = {
  'eip155:1:erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': {
    symbol: 'USDC',
    decimals: 6,
    coinId: 'usd-coin',
  },
  'eip155:1:erc20:0xdac17f958d2ee523a2206206994597c13d831ec7': {
    symbol: 'USDT',
    decimals: 6,
    coinId: 'tether',
  },
  'eip155:1:erc20:0x6b175474e89094c44da98b954eedeac495271d0f': {
    symbol: 'DAI',
    decimals: 18,
    coinId: 'dai',
  },
  'eip155:1:erc20:0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': {
    symbol: 'WETH',
    decimals: 18,
    coinId: 'weth',
  },
  'eip155:1:erc20:0x2260fac5e5542a773aa44fbcfedf7c193bc2c599': {
    symbol: 'WBTC',
    decimals: 8,
    coinId: 'wrapped-bitcoin',
  },
  'eip155:8453:erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': {
    symbol: 'USDC',
    decimals: 6,
    coinId: 'usd-coin',
  },
  'eip155:8453:erc20:0x4200000000000000000000000000000000000006': {
    symbol: 'WETH',
    decimals: 18,
    coinId: 'weth',
  },
  'eip155:42161:erc20:0xaf88d065e77c8cc2239327c5edb3a432268e5831': {
    symbol: 'USDC',
    decimals: 6,
    coinId: 'usd-coin',
  },
  'eip155:42161:erc20:0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9': {
    symbol: 'USDT',
    decimals: 6,
    coinId: 'tether',
  },
  'eip155:42161:erc20:0x82af49447d8a07e3bd95bd0d56f35241523fbab1': {
    symbol: 'WETH',
    decimals: 18,
    coinId: 'weth',
  },
  'eip155:10:erc20:0x0b2c639c533813f4aa9d7837caf62653d097ff85': {
    symbol: 'USDC',
    decimals: 6,
    coinId: 'usd-coin',
  },
  'eip155:10:erc20:0x4200000000000000000000000000000000000006': {
    symbol: 'WETH',
    decimals: 18,
    coinId: 'weth',
  },
  'eip155:137:erc20:0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': {
    symbol: 'USDC',
    decimals: 6,
    coinId: 'usd-coin',
  },
  'eip155:137:erc20:0xc2132d05d31c914a87c6611c10748aeb04b58e8f': {
    symbol: 'USDT',
    decimals: 6,
    coinId: 'tether',
  },
};
