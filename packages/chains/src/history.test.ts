import { describe, expect, it } from 'vitest';
import { catalogChain } from './catalog.js';
import { readHistory, HistoryPage, solanaDeltas } from './history.js';
import { MemoryRpcPool } from './rpc.js';

const address = '0x' + '11'.repeat(20);
const other = '0x' + '22'.repeat(20);
const txHash = '0x' + 'aa'.repeat(32);
const btcHash = 'aa'.repeat(32);
const json = (value: unknown) => new Response(JSON.stringify(value));
function fixture(
  chainId: string,
  handler: (url: string, method: string, params: unknown[]) => unknown,
) {
  const chain = catalogChain(chainId)!;
  const pool = new MemoryRpcPool([{ ...chain, defaultRpcs: ['https://node.example'] }]);
  const calls: { method: string; params: unknown[] }[] = [];
  const fetcher: typeof fetch = async (url, init) => {
    const body = init?.body
      ? (JSON.parse(String(init.body)) as { method: string; params: unknown[] })
      : { method: '', params: [] };
    calls.push(body);
    const value = handler(String(url), body.method, body.params);
    return body.method
      ? json({ jsonrpc: '2.0', id: 1, result: value })
      : value instanceof Response
        ? value
        : json(value);
  };
  return { chain, pool, calls, options: { fetch: fetcher } };
}

describe('public transaction history', () => {
  it('scans a bounded EVM block range with exact native deltas, fees and older cursor', async () => {
    const f = fixture('eip155:8453', (_url, method, params) => {
      if (method === 'eth_chainId') return '0x2105';
      if (method === 'eth_blockNumber') return '0x14';
      if (method === 'eth_getBlockByNumber')
        return {
          number: params[0],
          timestamp: '0x10',
          transactions:
            params[0] === '0x14'
              ? [{ hash: txHash, from: address, to: other, value: '0x20000000000001' }]
              : [],
        };
      return {
        transactionHash: txHash,
        status: '0x1',
        gasUsed: '0x5208',
        effectiveGasPrice: '0x2',
      };
    });
    const page = HistoryPage.parse(await readHistory(f.chain, address, f.pool, f.options));
    expect(f.calls.filter((c) => c.method === 'eth_getBlockByNumber')).toHaveLength(12);
    expect(page.nextCursor).toBe('8');
    expect(page.items[0]).toMatchObject({
      fee: '42000',
      assetDeltas: [{ amount: '-9007199254782993' }],
      timestampMs: 16000,
      status: 'confirmed',
    });
    expect(page.coverage).toContain('not an indexed lifetime history');
  });
  it('does not count value transfer on an EVM revert or self-transfer', async () => {
    const f = fixture('eip155:1', (_url, method, params) => {
      if (method === 'eth_chainId') return '0x1';
      if (method === 'eth_blockNumber') return '0x0';
      if (method === 'eth_getBlockByNumber')
        return {
          number: params[0],
          timestamp: '0x0',
          transactions: [{ hash: txHash, from: address, to: address, value: '0x100' }],
        };
      return { transactionHash: txHash, status: '0x0', gasUsed: '0x1', effectiveGasPrice: '0x2' };
    });
    const page = await readHistory(f.chain, address, f.pool, f.options);
    expect(page.items[0]).toMatchObject({ status: 'failed', assetDeltas: [{ amount: '-2' }] });
    expect(page.nextCursor).toBeUndefined();
  });
  it('refuses another chain, malformed receipts and unsafe RPC quantities', async () => {
    const wrong = fixture('eip155:1', () => '0x2');
    await expect(readHistory(wrong.chain, address, wrong.pool, wrong.options)).rejects.toThrow();
    expect(wrong.calls).toHaveLength(1);
    const huge = fixture('eip155:1', (_u, m) =>
      m === 'eth_chainId' ? '0x1' : '0xffffffffffffffffff',
    );
    await expect(readHistory(huge.chain, address, huge.pool, huge.options)).rejects.toThrow();
    expect(huge.calls).toHaveLength(2);
  });
  it('decodes Bitcoin-family net changes and paginates confirmed transactions past mempool entries', async () => {
    const f = fixture('bip122:00000008819873e925422c1ff0f99f7c', (url) => {
      if (url.endsWith('/block-height/0'))
        return new Response('00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6');
      return Array.from({ length: 26 }, (_, i) => ({
        txid: i === 25 ? btcHash : i.toString(16).padStart(64, '0'),
        fee: 100,
        vin: [{ prevout: { scriptpubkey_address: 'tb1fixture', value: 1000 } }],
        vout: [{ scriptpubkey_address: 'tb1fixture', value: 400 }],
        status: { confirmed: i > 0, ...(i > 0 ? { block_height: i, block_time: 100 } : {}) },
      }));
    });
    const page = await readHistory(f.chain, 'tb1fixture', f.pool, f.options);
    expect(page.nextCursor).toBe(btcHash);
    expect(page.items[0]).toMatchObject({
      status: 'pending',
      fee: '100',
      assetDeltas: [{ amount: '-600' }],
    });
    expect(page.items[1]?.timestampMs).toBe(100000);
  });
  it('keeps Solana pruned transaction details unknown and requests versioned transactions', async () => {
    const sig = '2'.repeat(88);
    const f = fixture('solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1', (_url, method) => {
      if (method === 'getGenesisHash') return 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
      if (method === 'getSignaturesForAddress')
        return [{ signature: sig, slot: 9, blockTime: null, err: null }];
      return null;
    });
    const page = await readHistory(f.chain, 'publicAccount', f.pool, f.options);
    expect(page.items[0]).toMatchObject({ fee: null, assetDeltas: [], from: '', blockNumber: 9 });
    expect(page.items[0]?.timestampMs).toBeUndefined();
    expect(f.calls.at(-1)?.params[1]).toMatchObject({ maxSupportedTransactionVersion: 0 });
  });
  it('decodes SOL net balances including rent and fee without floating point', async () => {
    const f = fixture('solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1', (_url, method) => {
      if (method === 'getGenesisHash') return 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
      if (method === 'getSignaturesForAddress')
        return [{ signature: '2'.repeat(88), slot: 9, blockTime: 100, err: null }];
      return {
        meta: { fee: 5000, err: null, preBalances: [10000000], postBalances: [9995000] },
        transaction: { message: { accountKeys: [{ pubkey: 'publicAccount', signer: true }] } },
      };
    });
    const page = await readHistory(f.chain, 'publicAccount', f.pool, f.options);
    expect(page.items[0]).toMatchObject({
      fee: '5000',
      timestampMs: 100000,
      assetDeltas: [{ amount: '-5000' }],
    });
  });
  it('deduplicates Cosmos sender/recipient pages and uses modern and legacy pagination', async () => {
    const urls: string[] = [];
    const f = fixture('cosmos:osmosis-1', (url) => {
      urls.push(url);
      if (url.endsWith('/node_info')) return { default_node_info: { network: 'osmosis-1' } };
      return {
        txs: [{ auth_info: { fee: { amount: [{ denom: 'uosmo', amount: '10' }] } } }],
        total: '1',
        tx_responses: [
          {
            txhash: btcHash,
            height: '42',
            code: 0,
            timestamp: '2026-01-01T00:00:00Z',
            events: [
              {
                type: 'transfer',
                attributes: [
                  { key: 'sender', value: 'osmoFixture' },
                  { key: 'recipient', value: 'osmoOther' },
                  { key: 'amount', value: '123uosmo' },
                ],
              },
            ],
          },
        ],
      };
    });
    const page = await readHistory(f.chain, 'osmoFixture', f.pool, f.options, '20');
    expect(page.items).toHaveLength(1);
    // No fee transfer event and no named payer: the sender paid, so the fee is in the net change.
    expect(page.items[0]).toMatchObject({
      fee: '10',
      from: 'osmoFixture',
      assetDeltas: [{ amount: '-133', assetRef: f.chain.nativeAsset.ref }],
    });
    expect(new URL(urls[1]!).searchParams.get('page')).toBe('2');
    expect(new URL(urls[1]!).searchParams.get('pagination.offset')).toBe('20');
  });
  describe('Cosmos fee variants', () => {
    const run = async (
      events: { type: string; attributes: { key: string; value: string }[] }[],
      fee: Record<string, unknown>,
      code = 0,
    ) => {
      const f = fixture('cosmos:osmosis-1', (url) => {
        if (url.endsWith('/node_info')) return { default_node_info: { network: 'osmosis-1' } };
        return {
          txs: [{ auth_info: { fee } }],
          total: '1',
          tx_responses: [
            { txhash: btcHash, height: '42', code, timestamp: '2026-01-01T00:00:00Z', events },
          ],
        };
      });
      return (await readHistory(f.chain, 'osmoMe', f.pool, f.options)).items[0]!;
    };
    const transfer = (sender: string, recipient: string, amount: string, msg?: string) => ({
      type: 'transfer',
      attributes: [
        { key: 'sender', value: sender },
        { key: 'recipient', value: recipient },
        { key: 'amount', value: amount },
        ...(msg !== undefined ? [{ key: 'msg_index', value: msg }] : []),
      ],
    });
    const signer = { type: 'tx', attributes: [{ key: 'acc_seq', value: 'osmoMe/7' }] };
    const native = 'cosmos:osmosis-1:native';

    it('counts the ante fee transfer once on modern SDKs', async () => {
      const r = await run(
        [
          signer,
          transfer('osmoMe', 'osmoFees', '10uosmo'),
          transfer('osmoMe', 'osmoOther', '10uosmo', '0'),
        ],
        { amount: [{ denom: 'uosmo', amount: '10' }] },
      );
      expect(r).toMatchObject({ fee: '10', from: 'osmoMe' });
      expect(r.assetDeltas).toEqual([{ assetRef: native, amount: '-20' }]);
    });
    it('keeps only the fee of a failed transaction', async () => {
      const r = await run(
        [
          signer,
          transfer('osmoMe', 'osmoFees', '10uosmo'),
          transfer('osmoMe', 'osmoOther', '999uosmo', '0'),
        ],
        { amount: [{ denom: 'uosmo', amount: '10' }] },
        5,
      );
      expect(r.status).toBe('failed');
      expect(r.assetDeltas).toEqual([{ assetRef: native, amount: '-10' }]);
    });
    it('leaves a granted fee to the granter', async () => {
      const r = await run(
        [
          transfer('osmoGranter', 'osmoFees', '10uosmo'),
          transfer('osmoMe', 'osmoOther', '10uosmo', '0'),
        ],
        { amount: [{ denom: 'uosmo', amount: '10' }], granter: 'osmoGranter' },
      );
      expect(r.from).not.toBe('osmoMe');
      expect(r.assetDeltas).toEqual([{ assetRef: native, amount: '-10' }]);
    });
    it('names a non-native fee denom, a zero fee, and an ambiguous multi-coin fee', async () => {
      const ibc = 'ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2';
      const paid = await run([signer, transfer('osmoMe', 'osmoFees', '5' + ibc)], {
        amount: [{ denom: ibc, amount: '5' }],
      });
      expect(paid).toMatchObject({ fee: '5', feeAssetRef: 'cosmos:osmosis-1:' + ibc });
      expect(paid.assetDeltas).toEqual([{ assetRef: 'cosmos:osmosis-1:' + ibc, amount: '-5' }]);
      expect((await run([signer], { amount: [] })).fee).toBe('0');
      const multi = await run([signer], {
        amount: [
          { denom: 'uosmo', amount: '1' },
          { denom: ibc, amount: '1' },
        ],
      });
      expect(multi.fee).toBeNull();
    });
  });
  it('credits SPL tokens to their owner and counts token-account rent as SOL', async () => {
    const mint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
    const chain = catalogChain('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')!;
    const keys = [{ pubkey: 'Owner' }, { pubkey: 'NewTokAcc' }, { pubkey: 'Sender' }];
    const bal = (accountIndex: number, owner: string | undefined, amount: string, m = mint) => ({
      accountIndex,
      mint: m,
      ...(owner ? { owner } : {}),
      uiTokenAmount: { amount, decimals: 6 },
    });
    const deltas = solanaDeltas(chain, 'Owner', keys, {
      // The owner funds a new token account with 2039280 lamports of rent.
      preBalances: [10_000_000, 0, 1],
      postBalances: [10_000_000 - 5000 - 2_039_280, 2_039_280, 1],
      preTokenBalances: [bal(2, 'Sender', '1000')],
      postTokenBalances: [
        bal(1, 'Owner', '1'),
        bal(2, 'Sender', '999'),
        bal(1, 'Owner', '0', 'So11111111111111111111111111111111111111112'),
      ],
    });
    expect(deltas).toEqual([
      { assetRef: chain.nativeAsset.ref, amount: '-5000' },
      { assetRef: `${chain.chainId}:spl:${mint}`, amount: '1', decimals: 6 },
    ]);
    // Old transactions without owners still credit the listed token account.
    const legacy = solanaDeltas(
      chain,
      'Owner',
      keys,
      {
        preBalances: [1, 5, 1],
        postBalances: [1, 5, 1],
        preTokenBalances: [bal(1, undefined, '0')],
        postTokenBalances: [bal(1, undefined, '7')],
      },
      'NewTokAcc',
    );
    expect(legacy).toContainEqual({
      assetRef: `${chain.chainId}:spl:${mint}`,
      amount: '7',
      decimals: 6,
    });
  });
  it('propagates caller cancellation instead of reading other endpoints', async () => {
    const controller = new AbortController();
    controller.abort();
    const f = fixture('eip155:1', () => '0x1');
    await expect(
      readHistory(f.chain, address, f.pool, { ...f.options, signal: controller.signal }),
    ).rejects.toThrow();
    expect(f.calls).toHaveLength(0);
  });
  it('validates history boundary payloads instead of accepting negative fees or noninteger dates', () => {
    const bad = {
      hash: txHash,
      chainId: 'eip155:1',
      from: address,
      feeAssetRef: 'native',
      fee: '-1',
      status: 'confirmed',
      assetDeltas: [],
    };
    expect(HistoryPage.safeParse({ items: [bad] }).success).toBe(false);
    expect(
      HistoryPage.safeParse({ items: [{ ...bad, fee: null, timestampMs: 0.5 }] }).success,
    ).toBe(false);
  });
});
it('does not retry an indexer failure on healthy RPC endpoints', async () => {
  let indexed = 0;
  const f = fixture('eip155:1', (url, method) => {
    if (method === 'eth_chainId') return '0x1';
    if (url.startsWith('https://indexer.example')) {
      indexed++;
      return new Response('too large', { status: 503 });
    }
    throw new Error('unexpected request');
  });
  await expect(
    readHistory(f.chain, address, f.pool, f.options, undefined, {
      indexerUrl: 'https://indexer.example',
    }),
  ).rejects.toThrow('HTTP 503');
  expect(indexed).toBe(1);
  expect(f.pool.endpoints(f.chain.chainId)[0]?.healthy).toBe(true);
});
