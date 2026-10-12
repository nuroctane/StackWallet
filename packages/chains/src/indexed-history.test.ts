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
it('still rejects oversized indexed bodies under the larger bounded limit', async () => {
  await expect(
    readIndexedHistory(chain, account, 'https://indexer.example', {
      fetch: async () =>
        new Response('{}', { headers: { 'content-length': String(9 * 1024 * 1024) } }),
    }),
  ).rejects.toThrow('body too large');
});
