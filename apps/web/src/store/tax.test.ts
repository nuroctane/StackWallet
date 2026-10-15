import { describe, expect, it } from 'vitest';
import type { ChainInfo, ChainRegistry, Page, TxRecord } from '@stackwallet/chains';
import type { ProvenanceTable } from '@stackwallet/core-client';

import type { DirectoryState } from './schema.js';
import {
  assetInfoFor,
  readAccountHistory,
  readAllPages,
  scopeAccounts,
  scopeWallets,
  TAX_OVERRIDES_KEY,
  TAX_PREFS_KEY,
  TaxStore,
} from './tax.js';

function memory(seed: Record<string, string> = {}) {
  const m = new Map(Object.entries(seed));
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    m,
  };
}

const chain = (
  chainId: string,
  family: ChainInfo['family'],
  symbol: string,
  testnet = false,
): ChainInfo => ({
  chainId,
  family,
  name: chainId,
  nativeAsset: { ref: `${chainId}:native`, symbol, decimals: family === 'bitcoin' ? 8 : 18 },
  testnet,
  defaultRpcs: [],
});

const CHAINS = [
  chain('eip155:1', 'evm', 'ETH'),
  chain('eip155:11155111', 'evm', 'ETH', true),
  chain('eip155:999999', 'evm', 'XYZ'),
  chain('bip122:000000000019d6689c085ae165831e93', 'bitcoin', 'BTC'),
];

const rec = (hash: string, extra: Partial<TxRecord> = {}): TxRecord => ({
  hash,
  chainId: 'eip155:1',
  from: '0xa',
  assetDeltas: [],
  feeAssetRef: 'eip155:1:native',
  fee: null,
  status: 'confirmed',
  ...extra,
});

function registry(
  getHistory: (
    cursor: string | undefined,
    opts: unknown,
    address: string,
  ) => Promise<Page<TxRecord>>,
  extra: Record<string, unknown> = {},
) {
  return {
    chainInfo: (id: string) => {
      const c = CHAINS.find((x) => x.chainId === id);
      if (!c) throw new Error('unknown chain');
      return c;
    },
    adapterFor: () => ({
      getHistory: (a: string, _c: string, cursor: string | undefined, opts: unknown) =>
        getHistory(cursor, opts, a),
      ...extra,
    }),
  } as unknown as ChainRegistry;
}

describe('readAllPages', () => {
  it('follows cursors to the end and reports completeness', async () => {
    const pages: Record<string, Page<TxRecord>> = {
      start: { items: [rec('0x1')], nextCursor: 'b', source: 'https://idx.example/api' },
      b: { items: [rec('0x2')] },
    };
    const out = await readAllPages(async (c) => pages[c ?? 'start']!, 10);
    expect(out.records.map((r) => r.hash)).toEqual(['0x1', '0x2']);
    expect(out.complete).toBe(true);
    expect(out.sources).toEqual(['https://idx.example/api']);
  });

  it('keeps what it read when a later page fails, and never claims completeness', async () => {
    let tries = 0;
    const out = await readAllPages(
      async (c) => {
        if (c) {
          tries++;
          throw new Error('boom');
        }
        return { items: [rec('0x1')], nextCursor: 'n' };
      },
      10,
      undefined,
      [0, 0],
    );
    expect(out.records).toHaveLength(1);
    expect(out.complete).toBe(false);
    expect(out.error).toBe('boom');
    expect(tries).toBe(3);
  });

  it('retries a page that timed out once and finishes the stream', async () => {
    let failed = false;
    const out = await readAllPages(
      async (c) => {
        if (c && !failed) {
          failed = true;
          throw new Error('timed out after 8000ms');
        }
        return c ? { items: [rec('0x2')] } : { items: [rec('0x1')], nextCursor: 'n' };
      },
      10,
      undefined,
      [0],
    );
    expect(out.complete).toBe(true);
    expect(out.records.map((r) => r.hash)).toEqual(['0x1', '0x2']);
  });

  it('stops at the page limit as incomplete', async () => {
    let n = 0;
    const out = await readAllPages(
      async () => ({ items: [rec('0x' + n)], nextCursor: String(++n) }),
      3,
    );
    expect(out.records).toHaveLength(3);
    expect(out.complete).toBe(false);
  });
});

describe('readAccountHistory', () => {
  it('reads every indexer stream on EVM chains, with NFTs, then the live balances', async () => {
    const seen: { stream?: string; nfts?: boolean }[] = [];
    const r = registry(
      async (_c, opts) => {
        const o = opts as { stream?: string; nfts?: boolean };
        seen.push(o);
        return { items: [rec('0x' + o.stream)] };
      },
      {
        getBalances: async () => [
          { assetRef: 'eip155:1:native', amount: '5' },
          { assetRef: 'eip155:1:erc20:0xbad', amount: '1', error: 'rpc down' },
        ],
      },
    );
    const h = await readAccountHistory(r, CHAINS[0]!, {
      accountId: 'a',
      chainId: 'eip155:1',
      address: '0xa',
    });
    expect(h.complete).toBe(true);
    expect(seen.map((s) => s.stream)).toEqual([
      'transactions',
      'tokens',
      'internal',
      'withdrawals',
    ]);
    expect(seen.every((s) => s.nfts)).toBe(true);
    expect(h.records).toHaveLength(4);
    expect(h.balances).toEqual([{ assetRef: 'eip155:1:native', amount: '5' }]);
  });

  it('skips beacon withdrawals on chains without them', async () => {
    const streams: string[] = [];
    const r = registry(async (_c, opts) => {
      streams.push((opts as { stream: string }).stream);
      return { items: [] };
    });
    await readAccountHistory(
      r,
      { ...CHAINS[0]!, chainId: 'eip155:8453' },
      {
        accountId: 'a',
        chainId: 'eip155:8453',
        address: '0xa',
      },
    );
    expect(streams).not.toContain('withdrawals');
  });

  it('reads Solana token accounts on behalf of the owner and leaves SOL out of the balance check', async () => {
    const calls: [string, unknown][] = [];
    const sol = chain('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 'solana', 'SOL');
    const r = registry(
      async (_c, opts, address) => {
        calls.push([address, opts]);
        return { items: [] };
      },
      {
        historyAddresses: async () => ['TokAcc1', 'TokAcc2'],
        getBalances: async () => [
          { assetRef: sol.nativeAsset.ref, amount: '9' },
          { assetRef: `${sol.chainId}:spl:Mint`, amount: '3' },
        ],
      },
    );
    const h = await readAccountHistory(r, sol, {
      accountId: 'a',
      chainId: sol.chainId,
      address: 'Owner',
    });
    expect(calls.map((c) => c[0])).toEqual(['Owner', 'TokAcc1', 'TokAcc2']);
    expect(calls[1]![1]).toMatchObject({ owner: 'Owner' });
    expect(h.complete).toBe(true);
    expect(h.balances).toEqual([{ assetRef: `${sol.chainId}:spl:Mint`, amount: '3' }]);
  });

  it('marks history incomplete when token accounts cannot be listed', async () => {
    const sol = chain('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 'solana', 'SOL');
    const r = registry(async () => ({ items: [] }), {
      historyAddresses: async () => {
        throw new Error('429');
      },
    });
    const h = await readAccountHistory(r, sol, {
      accountId: 'a',
      chainId: sol.chainId,
      address: 'Owner',
    });
    expect(h.complete).toBe(false);
    expect(h.error).toMatch(/Token accounts/);
  });

  it('marks RPC-only EVM history incomplete', async () => {
    const r = registry(async () => ({ items: [rec('0x1')], nextCursor: 'older' }));
    const h = await readAccountHistory(r, CHAINS[2]!, {
      accountId: 'a',
      chainId: 'eip155:999999',
      address: '0xa',
    });
    expect(h.complete).toBe(false);
    expect(h.error).toMatch(/indexer/);
  });
});

describe('assetInfoFor', () => {
  const r = registry(async () => ({ items: [] }));
  it('prices mainnet natives and leaves testnets unpriced', () => {
    expect(assetInfoFor(r, 'eip155:1:native')).toMatchObject({
      symbol: 'ETH',
      decimals: 18,
      priceKey: 'ethereum',
    });
    expect(assetInfoFor(r, 'eip155:11155111:native')).toMatchObject({
      priceKey: null,
      testnet: true,
    });
  });
  it('knows common tokens and never asks prices for untracked contracts', () => {
    expect(
      assetInfoFor(r, 'eip155:1:erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'),
    ).toMatchObject({
      symbol: 'USDC',
      decimals: 6,
      priceKey: 'usd-coin',
    });
    const unknown = assetInfoFor(r, 'eip155:1:erc20:0x1111111111111111111111111111111111111111');
    expect(unknown.decimals).toBeNull();
    expect(unknown.priceKey).toBeNull();
  });
  it('reads untracked amounts with reported decimals but tags claimed symbols and never prices them', () => {
    const fake = assetInfoFor(r, 'eip155:1:erc20:0xabcdef0000000000000000000000000000000001', {
      symbol: 'USDC',
      decimals: 6,
    });
    expect(fake).toMatchObject({ symbol: 'USDC·abcd', decimals: 6, priceKey: null });
  });
  it('treats NFTs as whole units and keeps them unpriced', () => {
    const nft = assetInfoFor(r, 'eip155:1:erc721:0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1234', {
      symbol: 'BAYC',
    });
    expect(nft).toMatchObject({ symbol: 'BAYC·bc4c #1234', decimals: 0, priceKey: null });
  });
  it('keeps case in Solana mints and IBC denoms', () => {
    expect(
      assetInfoFor(
        r,
        'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:spl:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      ),
    ).toMatchObject({ symbol: 'USDC', decimals: 6, priceKey: 'usd-coin' });
    expect(
      assetInfoFor(
        r,
        'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:spl:epjfwdd5aufqssqem2qn1xzybapc8g4wegGkzwytdt1v',
      ).priceKey,
    ).toBeNull();
    expect(
      assetInfoFor(
        r,
        'cosmos:osmosis-1:ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2',
      ).symbol,
    ).toBe('ATOM');
    const denom = assetInfoFor(r, 'cosmos:osmosis-1:factory/osmo1xyz/coin', { decimals: 6 });
    expect(denom).toMatchObject({ decimals: 6, priceKey: null });
  });
});

describe('scope', () => {
  const state = {
    folders: [
      {
        id: 'root',
        parentId: null,
        name: 'root',
        tags: [],
        defaultPolicyIds: [],
        createdAtMs: 0,
        updatedAtMs: 0,
      },
      {
        id: 'f',
        parentId: 'root',
        name: 'family',
        tags: [],
        defaultPolicyIds: [],
        createdAtMs: 0,
        updatedAtMs: 0,
      },
    ],
    wallets: [
      {
        id: 'w1',
        folderId: 'f',
        name: 'one',
        kind: 'single',
        keyGroupId: null,
        tags: [],
        createdAtMs: 0,
        updatedAtMs: 0,
      },
      {
        id: 'w2',
        folderId: 'root',
        name: 'two',
        kind: 'watch',
        keyGroupId: null,
        tags: [],
        createdAtMs: 0,
        updatedAtMs: 0,
      },
    ],
    accounts: [
      {
        id: 'a1',
        walletId: 'w1',
        family: 'evm',
        chainId: 'eip155:1',
        address: '0xa',
        publicKeyHex: '',
        hidden: false,
      },
      {
        id: 'a2',
        walletId: 'w1',
        family: 'evm',
        chainId: 'eip155:11155111',
        address: '0xa',
        publicKeyHex: '',
        hidden: false,
      },
      {
        id: 'a3',
        walletId: 'w2',
        family: 'evm',
        chainId: 'eip155:1',
        address: '0xb',
        publicKeyHex: '',
        hidden: false,
      },
    ],
  } as unknown as DirectoryState;
  const provenance = {
    wallets: [
      { walletId: 'w1', origin: { kind: 'importedPhrase', atMs: 1 }, exposures: [], transfers: [] },
    ],
    sets: [
      { folderId: 'f', origin: { kind: 'created' }, transfers: [{ toDeviceId: 'd', atMs: 2 }] },
    ],
  } as unknown as ProvenanceTable;

  it('derives imported and exported from sealed provenance, including directory sets', () => {
    const { wallets, folders } = scopeWallets(state, provenance);
    expect(wallets.find((w) => w.id === 'w1')).toMatchObject({ imported: true, exported: false });
    expect(folders.find((f) => f.id === 'f')).toMatchObject({ exported: true });
  });

  it('builds accounts with folder paths and drops testnets unless asked', () => {
    const r = registry(async () => ({ items: [] }));
    const accounts = scopeAccounts(state, r, new Set(['w1']), false);
    expect(accounts.map((a) => a.accountId)).toEqual(['a1']);
    expect(accounts[0]!.folderPath).toBe('family');
    expect(scopeAccounts(state, r, new Set(['w1']), true)).toHaveLength(2);
  });
});

describe('TaxStore', () => {
  it('persists preferences and review decisions, and drops emptied ones', () => {
    const storage = memory();
    const store = new TaxStore(storage, async () => []);
    store.setSettings({ jurisdiction: 'de', fiat: 'eur', method: 'fifo' });
    store.setScope({ tags: ['watched'] });
    store.review('eip155:1|0x1', { label: 'staking', note: 'validator' });
    expect(JSON.parse(storage.m.get(TAX_PREFS_KEY)!).settings.jurisdiction).toBe('de');
    const again = new TaxStore(storage, async () => []);
    expect(again.getSnapshot().prefs.scope.tags).toEqual(['watched']);
    expect(again.getSnapshot().overrides['eip155:1|0x1']).toEqual({
      label: 'staking',
      note: 'validator',
    });
    again.review('eip155:1|0x1', { label: undefined, note: '' });
    expect(again.getSnapshot().overrides['eip155:1|0x1']).toBeUndefined();
    expect(JSON.parse(storage.m.get(TAX_OVERRIDES_KEY)!)).toEqual({});
  });

  it('round-trips review decisions through a file and rejects foreign files', () => {
    const a = new TaxStore(memory(), async () => []);
    a.reviewMany([
      ['x|1', { label: 'spam' }],
      ['x|2', { label: 'gift-out', note: 'mum' }],
    ]);
    const b = new TaxStore(memory(), async () => []);
    expect(b.importOverrides(a.exportOverrides())).toBe(2);
    expect(b.getSnapshot().overrides['x|2']?.label).toBe('gift-out');
    expect(() => b.importOverrides('{"overrides":{}}')).toThrow();
  });

  it('ignores corrupt storage', () => {
    const store = new TaxStore(
      memory({ [TAX_PREFS_KEY]: '{nope', [TAX_OVERRIDES_KEY]: '[1]' }),
      async () => [],
    );
    expect(store.getSnapshot().prefs.settings.jurisdiction).toBe('us');
    expect(store.getSnapshot().overrides).toEqual({});
  });

  it('loads each price series once per fiat and records failures', async () => {
    const calls: string[] = [];
    const store = new TaxStore(memory(), async (key, fiat) => {
      calls.push(`${fiat}|${key}`);
      if (key === 'bad') throw new Error('404');
      return [{ t: 1, v: 2 }];
    });
    await store.loadPrices(['ethereum', 'bad', 'ethereum'], 'usd');
    await store.loadPrices(['ethereum'], 'usd');
    expect(calls).toEqual(['usd|ethereum', 'usd|bad']);
    expect(store.getSnapshot().prices.get('usd|ethereum')).toEqual([{ t: 1, v: 2 }]);
    expect(store.getSnapshot().priceErrors.get('usd|bad')).toBe('404');
    expect(store.getSnapshot().pricing).toBeNull();
  });

  it('syncs only accounts it has not read for that address', async () => {
    let reads = 0;
    const r = registry(async () => {
      reads++;
      return { items: [] };
    });
    const store = new TaxStore(memory(), async () => []);
    const t = {
      accountId: 'a',
      chainId: 'bip122:000000000019d6689c085ae165831e93',
      address: 'bc1q',
    };
    await store.syncHistories(r, [t]);
    await store.syncHistories(r, [t]);
    expect(reads).toBe(1);
    await store.syncHistories(r, [{ ...t, address: 'bc1z' }]);
    expect(reads).toBe(2);
    expect(store.getSnapshot().histories.get('a')?.history.complete).toBe(true);
    expect(store.getSnapshot().syncing).toBeNull();
  });
});
