import { describe, expect, it } from 'vitest';
import { readIndexedHistory } from './indexed-history.js';
import { catalogChain } from './catalog.js';
const chain = catalogChain('eip155:8453')!;
const account = '0x' + '11'.repeat(20);
const other = '0x' + '22'.repeat(20);
const hash = '0x' + 'aa'.repeat(32);
const fetcher =
  (payload: unknown): typeof fetch =>
  async () =>
    new Response(JSON.stringify(payload));
const tx = {
  hash,
  from: { hash: account },
  to: { hash: other },
  value: '1000000000000000000',
  block_number: 1,
  timestamp: '2026-01-01T00:00:00.000000Z',
  status: 'ok',
  fee: { type: 'actual', value: '100' },
};
describe('indexed EVM history', () => {
  it('uses indexed cursors and native net changes without SDK keys', async () => {
    let requested = '';
    const page = await readIndexedHistory(
      chain,
      account,
      'https://indexer.example',
      {
        fetch: async (url) => {
          requested = String(url);
          return new Response(
            JSON.stringify({
              items: [tx],
              next_page_params: { block_number: 1, index: 0, items_count: 50 },
            }),
          );
        },
      },
      '{"block_number":2,"index":1}',
    );
    expect(new URL(requested).searchParams.get('index')).toBe('1');
    expect(page.items[0]).toMatchObject({
      fee: '100',
      status: 'confirmed',
      assetDeltas: [{ amount: '-1000000000000000100' }],
    });
    expect(page.nextCursor).toContain('items_count');
  });
  it('does not present a maximum fee as an actual payment or a pending debit as settled', async () => {
    const page = await readIndexedHistory(chain, account, 'https://indexer.example', {
      fetch: fetcher({
        items: [
          {
            ...tx,
            block_number: null,
            status: null,
            timestamp: null,
            fee: { type: 'maximum', value: '100' },
          },
        ],
        next_page_params: null,
      }),
    });
    expect(page.items[0]).toMatchObject({ fee: null, status: 'pending', assetDeltas: [] });
    expect(page.items[0]?.timestampMs).toBeUndefined();
  });
  it('subtracts only an actual fee on failed transactions', async () => {
    const page = await readIndexedHistory(chain, account, 'https://indexer.example', {
      fetch: fetcher({ items: [{ ...tx, status: 'error' }], next_page_params: null }),
    });
    expect(page.items[0]).toMatchObject({ status: 'failed', assetDeltas: [{ amount: '-100' }] });
  });
  it('keeps separate transfer-event identities for the same transaction across pages', async () => {
    const token = '0x' + '33'.repeat(20);
    const event = {
      transaction_hash: hash,
      from: { hash: other },
      to: { hash: account },
      token: { type: 'ERC-20', address_hash: token },
      total: { value: '123' },
      block_number: 1,
      timestamp: tx.timestamp,
    };
    const page = await readIndexedHistory(
      chain,
      account,
      'https://indexer.example',
      {
        fetch: fetcher({
          items: [
            { ...event, log_index: 2 },
            { ...event, log_index: 3 },
          ],
          next_page_params: null,
        }),
      },
      undefined,
      true,
    );
    expect(page.items).toHaveLength(2);
    expect(page.items[0]?.entryId).not.toBe(page.items[1]?.entryId);
    expect(page.items[0]?.fee).toBeNull();
    expect(page.items[0]?.assetDeltas).toEqual([
      { assetRef: chain.chainId + ':erc20:' + token, amount: '123' },
    ]);
  });
  it('does not invent fungible NFT amounts', async () => {
    const page = await readIndexedHistory(
      chain,
      account,
      'https://indexer.example',
      {
        fetch: fetcher({
          items: [
            {
              transaction_hash: hash,
              log_index: 0,
              from: { hash: other },
              to: { hash: account },
              token: { type: 'ERC-721', address_hash: other },
              total: { token_id: '123' },
              block_number: 1,
              timestamp: tx.timestamp,
            },
          ],
          next_page_params: null,
        }),
      },
      undefined,
      true,
    );
    expect(page.items[0]?.assetDeltas).toEqual([]);
  });
  it('accepts transfers whose indexer total carries null fields', async () => {
    const page = await readIndexedHistory(
      chain,
      account,
      'https://indexer.example',
      {
        fetch: fetcher({
          items: [
            {
              transaction_hash: hash,
              log_index: 0,
              from: { hash: other },
              to: { hash: account },
              token: { type: 'ERC-20', address_hash: other },
              total: { value: '5', token_id: null },
              block_number: 1,
              timestamp: tx.timestamp,
            },
            {
              transaction_hash: hash,
              log_index: 1,
              from: { hash: other },
              to: { hash: account },
              token: { type: 'ERC-20', address_hash: other },
              total: { value: null, token_id: null },
              block_number: 1,
              timestamp: tx.timestamp,
            },
          ],
          next_page_params: null,
        }),
      },
      undefined,
      true,
    );
    expect(page.items[0]?.assetDeltas).toEqual([
      { assetRef: chain.chainId + ':erc20:' + other.toLowerCase(), amount: '5' },
    ]);
    expect(page.items[1]?.assetDeltas).toEqual([]);
  });
  it('rejects credentials, non-HTTPS endpoints and cursor injection', async () => {
    for (const url of [
      'http://indexer.example',
      'https://key@indexer.example',
      'https://indexer.example?key=secret',
    ])
      await expect(
        readIndexedHistory(chain, account, url, { fetch: fetcher({}) }),
      ).rejects.toThrow();
    await expect(
      readIndexedHistory(
        chain,
        account,
        'https://indexer.example',
        { fetch: fetcher({}) },
        '{"../../other":"value"}',
      ),
    ).rejects.toThrow();
  });
});
it('accepts a large indexed page without relaxing ordinary RPC response limits', async () => {
  const payload = JSON.stringify({
    items: [tx],
    next_page_params: null,
    metadata: 'x'.repeat(2 * 1024 * 1024),
  });
  const page = await readIndexedHistory(chain, account, 'https://indexer.example', {
    fetch: async () => new Response(payload),
  });
  expect(page.items).toHaveLength(1);
  const { fetchJson } = await import('./rpc.js');
  await expect(
    fetchJson('https://rpc.example', { fetch: async () => new Response(payload) }),
  ).rejects.toThrow('body too large');
});
describe('indexed EVM streams beyond external transactions', () => {
  const internal = (over: Record<string, unknown>) => ({
    transaction_hash: hash,
    index: 1,
    block_number: 5,
    timestamp: tx.timestamp,
    type: 'call',
    success: true,
    error: null,
    from: { hash: other },
    to: { hash: account },
    value: '7',
    ...over,
  });
  it('counts native value paid out or spent by contracts, and nothing from reverted or delegate frames', async () => {
    const page = await readIndexedHistory(
      chain,
      account,
      'https://indexer.example',
      {
        fetch: fetcher({
          items: [
            internal({ index: 1 }),
            internal({ index: 2, from: { hash: account }, to: { hash: other }, value: '3' }),
            internal({ index: 3, success: false }),
            internal({ index: 4, type: 'delegatecall' }),
            internal({ index: 5, to: null, created_contract: { hash: account }, type: 'create' }),
          ],
          next_page_params: null,
        }),
      },
      undefined,
      'internal',
    );
    expect(page.items.map((i) => i.entryId)).toEqual(
      [1, 2, 3, 4, 5].map((n) => `${hash}:internal:${n}`),
    );
    expect(page.items.map((i) => i.assetDeltas[0]?.amount)).toEqual([
      '7',
      '-3',
      undefined,
      undefined,
      '7',
    ]);
    expect(page.items.every((i) => i.fee === null)).toBe(true);
    expect(page.source).toContain('/internal-transactions');
  });
  it('rejects internal transfers unrelated to the account', async () => {
    await expect(
      readIndexedHistory(
        chain,
        account,
        'https://indexer.example',
        {
          fetch: fetcher({
            items: [internal({ to: { hash: other } })],
            next_page_params: null,
          }),
        },
        undefined,
        'internal',
      ),
    ).rejects.toThrow('unrelated');
  });
  it('reads beacon withdrawals as receipts keyed by withdrawal index', async () => {
    const page = await readIndexedHistory(
      chain,
      account,
      'https://indexer.example',
      {
        fetch: fetcher({
          items: [
            {
              index: 99,
              amount: '1234',
              block_number: 7,
              timestamp: tx.timestamp,
              validator_index: 42,
            },
          ],
          next_page_params: null,
        }),
      },
      undefined,
      'withdrawals',
    );
    expect(page.items[0]).toMatchObject({
      hash: 'withdrawal-99',
      entryId: 'withdrawal-99',
      fee: null,
      assetDeltas: [{ assetRef: chain.nativeAsset.ref, amount: '1234' }],
    });
  });
  it('reports NFTs as one asset per token ID and keeps token metadata bounded', async () => {
    const nft = (type: string, total: Record<string, string>, symbol: string) => ({
      transaction_hash: hash,
      log_index: Math.floor(Math.random() * 1e6),
      from: { hash: account },
      to: { hash: other },
      token: { type, address_hash: other, symbol, decimals: null },
      total,
      block_number: 1,
      timestamp: tx.timestamp,
    });
    const page = await readIndexedHistory(
      chain,
      account,
      'https://indexer.example',
      {
        fetch: fetcher({
          items: [
            nft('ERC-721', { token_id: '5' }, 'APE'),
            nft('ERC-1155', { token_id: '9', value: '3' }, 'ITEM\u202e evil<script>'),
          ],
          next_page_params: null,
        }),
      },
      undefined,
      'tokens',
      true,
    );
    expect(page.items.map((i) => i.assetDeltas[0])).toEqual([
      { assetRef: `${chain.chainId}:erc721:${other}:5`, amount: '-1', symbol: 'APE', decimals: 0 },
      {
        assetRef: `${chain.chainId}:erc1155:${other}:9`,
        amount: '-3',
        symbol: 'ITEMevil<scr',
        decimals: 0,
      },
    ]);
  });
});
it('still rejects oversized indexed bodies under the larger bounded limit', async () => {
  await expect(
    readIndexedHistory(chain, account, 'https://indexer.example', {
      fetch: async () =>
        new Response('{}', { headers: { 'content-length': String(9 * 1024 * 1024) } }),
    }),
  ).rejects.toThrow('body too large');
});
