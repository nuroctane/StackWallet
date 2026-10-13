import { describe, expect, it } from 'vitest';
import { MemoryRpcPool, chainsForFamily } from '@stackwallet/chains';
import {
  createSolanaAdapter,
  solanaTokenInfo,
  SPL_TOKEN_PROGRAM,
  SPL_TOKEN_2022_PROGRAM,
} from './solana.js';

const GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
const CHAIN = `solana:${GENESIS.slice(0, 32)}`;
const WALLET = '11111111111111111111111111111111';
const MINT = 'So11111111111111111111111111111111111111112';
function account(pubkey: string, amount: string, program = SPL_TOKEN_PROGRAM) {
  return {
    pubkey,
    account: {
      executable: false,
      owner: program,
      data: {
        parsed: {
          type: 'account',
          info: {
            mint: MINT,
            owner: WALLET,
            state: 'initialized',
            tokenAmount: { amount, decimals: 9 },
          },
        },
      },
    },
  };
}
function setup(
  program = SPL_TOKEN_PROGRAM,
  change: (method: string, result: any, url: string) => unknown = (_m, r) => r,
) {
  const calls: { method: string; params: unknown[] }[] = [];
  const pool = new MemoryRpcPool(chainsForFamily('solana'));
  pool.setEndpoints(CHAIN, ['https://one.example', 'https://two.example']);
  const sol = createSolanaAdapter({
    rpc: pool,
    fetch: async (url, init) => {
      const { method, params } = JSON.parse(String(init?.body));
      calls.push({ method, params });
      const result =
        method === 'getGenesisHash'
          ? GENESIS
          : method === 'getBalance'
            ? { context: { slot: 50 }, value: 123 }
            : method === 'getAccountInfo'
              ? {
                  context: { slot: 50 },
                  value: {
                    executable: false,
                    owner: program,
                    data: {
                      parsed: {
                        type: 'mint',
                        info: { decimals: 9, isInitialized: true, supply: '0' },
                      },
                    },
                  },
                }
              : {
                  context: { slot: 51 },
                  value: [
                    account(SPL_TOKEN_PROGRAM, '9007199254740993', program),
                    account(SPL_TOKEN_2022_PROGRAM, '7', program),
                  ],
                };
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, result: change(method, result, String(url)) }),
      );
    },
  });
  sol.setTrackedTokens([
    {
      chainId: CHAIN,
      address: MINT,
      symbol: 'WSOL',
      decimals: 9,
      programId: program as typeof SPL_TOKEN_PROGRAM,
    },
  ]);
  return { sol, calls };
}
describe('explicit Solana token reads', () => {
  it.each([SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM])(
    'sums exact public amounts for %s and cross-checks endpoints',
    async (program) => {
      const { sol, calls } = setup(program);
      expect(await solanaTokenInfo(sol, CHAIN, MINT)).toEqual({
        programId: program,
        decimals: 9,
        slot: 50,
      });
      const [native, token] = await sol.getBalances(WALLET, CHAIN);
      expect(native?.amount).toBe('123');
      expect(token).toMatchObject({
        assetRef: `${CHAIN}:spl:${MINT}`,
        amount: '9007199254741000',
        provenance: { kind: 'agreed' },
        metadata: { symbol: 'WSOL', decimals: 9 },
      });
      expect(token?.notice).toContain('Token transfers are not enabled');
      expect(calls.find((c) => c.method === 'getTokenAccountsByOwner')?.params).toEqual([
        WALLET,
        { mint: MINT },
        { commitment: 'confirmed', encoding: 'jsonParsed', minContextSlot: 50 },
      ]);
    },
  );
  it('returns known zero only after both endpoints confirm no accounts', async () => {
    const { sol } = setup(SPL_TOKEN_PROGRAM, (m, r) =>
      m === 'getTokenAccountsByOwner' ? { ...r, value: [] } : r,
    );
    expect((await sol.getBalances(WALLET, CHAIN))[1]).toMatchObject({
      amount: '0',
      provenance: { kind: 'agreed' },
    });
  });
  it.each([
    'cluster',
    'mint',
    'owner',
    'program',
    'decimals',
    'duplicate',
    'amount',
    'overflow',
    'slot',
    'mint-change',
    'missing-mint',
  ])('keeps invalid %s observations on a failed token row', async (fault) => {
    const { sol } = setup(SPL_TOKEN_PROGRAM, (m, r) => {
      if (fault === 'cluster' && m === 'getGenesisHash') return WALLET;
      if (m === 'getAccountInfo') {
        if (fault === 'missing-mint') r.value = null;
        if (fault === 'mint-change') r.value.data.parsed.info.decimals = 6;
      }
      if (m === 'getTokenAccountsByOwner') {
        const entry = r.value[0],
          info = entry.account.data.parsed.info;
        if (fault === 'mint') info.mint = WALLET;
        if (fault === 'owner') info.owner = MINT;
        if (fault === 'program') entry.account.owner = SPL_TOKEN_2022_PROGRAM;
        if (fault === 'decimals') info.tokenAmount.decimals = 6;
        if (fault === 'duplicate') r.value[1].pubkey = entry.pubkey;
        if (fault === 'amount') info.tokenAmount.amount = 123;
        if (fault === 'overflow') info.tokenAmount.amount = '18446744073709551615';
        if (fault === 'slot') r.context.slot = 49;
      }
      return r;
    });
    const rows = await sol.getBalances(WALLET, CHAIN);
    expect(rows[0]?.amount).toBe('123');
    expect(rows[1]?.error).toBeTruthy();
    expect(rows[1]?.provenance).toBeUndefined();
  });
  it('preserves disagreement provenance and keeps frozen amounts explicitly qualified', async () => {
    const { sol } = setup(SPL_TOKEN_PROGRAM, (m, r, url) => {
      if (m === 'getTokenAccountsByOwner') {
        r.value[0].account.data.parsed.info.state = 'frozen';
        if (url.includes('two')) r.value[0].account.data.parsed.info.tokenAmount.amount = '3';
      }
      return r;
    });
    const token = (await sol.getBalances(WALLET, CHAIN))[1];
    expect(token?.provenance?.kind).toBe('disagreed');
    expect(token?.notice).toContain('frozen');
  });
});
