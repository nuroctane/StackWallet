import { z } from 'zod';
import { readIndexedHistory, type HistoryOptions } from './indexed-history.js';
import { fetchJson, fetchJsonRpc, fetchText, withFailover, type FetchOptions } from './rpc.js';
import type { AssetDelta, ChainInfo, Page, RpcPool, TxRecord } from './types.js';

const text = z.string().max(512);
const uint = z.number().int().nonnegative().safe();
const decimal = z.string().regex(/^\d{1,78}$/);
const hex = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const hash = z.string().regex(/^[0-9a-fA-F]{64}$/);
const evmHash = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const evmAddress = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const signature = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{64,88}$/);
const timestamp = (seconds: number) => uint.parse(seconds * 1000);
const numericHex = (value: string) => uint.parse(Number(BigInt(value)));
const base = (chain: ChainInfo, txHash: string): TxRecord => ({
  hash: txHash,
  chainId: chain.chainId,
  from: '',
  assetDeltas: [],
  feeAssetRef: chain.nativeAsset.ref,
  fee: null,
  status: 'confirmed',
});

/** Bounded public reads share the adapter's timeout, body limit, identity check and failover. */
export async function readHistory(
  chain: ChainInfo,
  address: string,
  pool: RpcPool,
  opts: FetchOptions,
  cursor?: string,
  options?: HistoryOptions,
): Promise<Page<TxRecord>> {
  z.string()
    .regex(/^[A-Za-z0-9]{1,128}$/)
    .parse(address);
  opts.signal?.throwIfAborted();
  if (chain.family === 'evm' && options?.indexerUrl !== undefined) {
    await withFailover(
      pool,
      chain.chainId,
      async (url) => {
        const identity = hex.parse(await fetchJsonRpc(url, 'eth_chainId', [], opts));
        if (BigInt(identity) !== BigInt(chain.chainId.slice(7)))
          throw new Error('History endpoint is on a different EVM chain');
      },
      { maxAttempts: 2, ...(opts.signal ? { signal: opts.signal } : {}) },
    );
    return readIndexedHistory(
      chain,
      address,
      options.indexerUrl,
      opts,
      cursor,
      options.tokenTransfers,
    );
  }
  return withFailover(
    pool,
    chain.chainId,
    async (endpoint) => {
      const url = endpoint.replace(/\/$/, '');
      const rest = async <T>(path: string, schema: z.ZodType<T>) => {
        opts.signal?.throwIfAborted();
        const result = await fetchJson(url + path, opts);
        opts.signal?.throwIfAborted();
        return schema.parse(result);
      };
      const rpc = async <T>(method: string, params: unknown[], schema: z.ZodType<T>) => {
        opts.signal?.throwIfAborted();
        const result = await fetchJsonRpc(url, method, params, opts);
        opts.signal?.throwIfAborted();
        return schema.parse(result);
      };
      let page: Page<TxRecord>;
      if (chain.family === 'bitcoin') {
        const genesis = hash.parse(await fetchText(url + '/block-height/0', opts));
        if (!genesis.toLowerCase().startsWith(chain.chainId.slice(7)))
          throw new Error('History endpoint is on a different Bitcoin-family chain');
        if (cursor) hash.parse(cursor);
        const output = z.object({ scriptpubkey_address: text.optional(), value: uint });
        const records = await rest(
          '/address/' + encodeURIComponent(address) + '/txs' + (cursor ? '/chain/' + cursor : ''),
          z
            .array(
              z.object({
                txid: hash,
                fee: uint,
                vin: z.array(z.object({ prevout: output.nullable().optional() })).max(10000),
                vout: z.array(output).max(10000),
                status: z.object({
                  confirmed: z.boolean(),
                  block_height: uint.optional(),
                  block_time: uint.optional(),
                }),
              }),
            )
            .max(100),
        );
        page = {
          items: records.map((t) => {
            const incoming = t.vout
              .filter((o) => o.scriptpubkey_address === address)
              .reduce((n, o) => n + BigInt(o.value), 0n);
            const outgoing = t.vin
              .filter((i) => i.prevout?.scriptpubkey_address === address)
              .reduce((n, i) => n + BigInt(i.prevout!.value), 0n);
            return {
              ...base(chain, t.txid),
              from: outgoing ? address : (t.vin[0]?.prevout?.scriptpubkey_address ?? ''),
              ...(incoming ? { to: address } : {}),
              fee: String(t.fee),
              assetDeltas: [
                { assetRef: chain.nativeAsset.ref, amount: String(incoming - outgoing) },
              ],
              status: t.status.confirmed ? 'confirmed' : 'pending',
              ...(t.status.block_height !== undefined
                ? { blockNumber: t.status.block_height }
                : {}),
              ...(t.status.block_time !== undefined
                ? { timestampMs: timestamp(t.status.block_time) }
                : {}),
            };
          }),
          coverage:
            'Esplora address history. Native net balance changes include fees paid by this address; fees shown separately are the whole transaction fee.',
        };
        const confirmed = records.filter((t) => t.status.confirmed);
        if (confirmed.length >= 25) page.nextCursor = confirmed.at(-1)!.txid;
      } else if (chain.family === 'solana') {
        const genesis = await rpc(
          'getGenesisHash',
          [],
          z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/),
        );
        if ('solana:' + genesis.slice(0, 32) !== chain.chainId)
          throw new Error('History endpoint is on a different Solana cluster');
        if (cursor) signature.parse(cursor);
        const records = await rpc(
          'getSignaturesForAddress',
          [address, { limit: 20, commitment: 'confirmed', ...(cursor ? { before: cursor } : {}) }],
          z
            .array(
              z.object({
                signature,
                slot: uint,
                blockTime: uint.nullable(),
                err: z.unknown(),
              }),
            )
            .max(20),
        );
        // Signature discovery includes program calls; missing/pruned details remain unknown, not zero.
        const items: TxRecord[] = [];
        const txSchema = z
          .object({
            meta: z
              .object({
                fee: uint,
                preBalances: z.array(uint).max(256),
                postBalances: z.array(uint).max(256),
                err: z.unknown(),
              })
              .nullable(),
            transaction: z.object({
              message: z.object({
                accountKeys: z.array(z.object({ pubkey: text, signer: z.boolean() })).max(256),
              }),
            }),
          })
          .nullable();
        for (const t of records) {
          const tx = await rpc(
            'getTransaction',
            [
              t.signature,
              {
                encoding: 'jsonParsed',
                commitment: 'confirmed',
                maxSupportedTransactionVersion: 0,
              },
            ],
            txSchema,
          );
          const keys = tx?.transaction.message.accountKeys ?? [];
          const index = keys.findIndex((k) => k.pubkey === address);
          const before = index >= 0 ? tx?.meta?.preBalances[index] : undefined;
          const after = index >= 0 ? tx?.meta?.postBalances[index] : undefined;
          items.push({
            ...base(chain, t.signature),
            from: keys.find((k) => k.signer)?.pubkey ?? '',
            blockNumber: t.slot,
            ...(t.blockTime !== null ? { timestampMs: timestamp(t.blockTime) } : {}),
            status: t.err != null ? 'failed' : 'confirmed',
            fee: tx?.meta ? String(tx.meta.fee) : null,
            assetDeltas:
              before !== undefined && after !== undefined
                ? [
                    {
                      assetRef: chain.nativeAsset.ref,
                      amount: String(BigInt(after) - BigInt(before)),
                    },
                  ]
                : [],
          });
        }
        page = {
          items,
          coverage:
            'Confirmed signatures referencing this account, including program calls. SOL net changes include fees/rent; SPL token changes are not decoded. Pruned details are unknown.',
        };
        if (records.length === 20) page.nextCursor = records.at(-1)!.signature;
      } else if (chain.family === 'cosmos') {
        const node = await rest(
          '/cosmos/base/tendermint/v1beta1/node_info',
          z.object({ default_node_info: z.object({ network: text }) }),
        );
        if ('cosmos:' + node.default_node_info.network !== chain.chainId)
          throw new Error('History endpoint is on a different Cosmos chain');
        const offset = cursor === undefined ? 0 : uint.parse(Number(decimal.parse(cursor)));
        const coin = z.object({ denom: text, amount: decimal });
        const txSchema = z.object({
          txs: z
            .array(
              z.object({
                auth_info: z.object({ fee: z.object({ amount: z.array(coin).max(100) }) }),
              }),
            )
            .max(20),
          tx_responses: z
            .array(
              z.object({
                txhash: hash,
                height: decimal,
                code: uint,
                timestamp: z.string().datetime({ offset: true }),
                events: z
                  .array(
                    z.object({
                      type: text,
                      attributes: z
                        .array(z.object({ key: text, value: z.string().max(10000) }))
                        .max(1000),
                    }),
                  )
                  .max(1000),
              }),
            )
            .max(20),
          pagination: z.object({ total: decimal.optional() }).nullable().optional(),
          total: decimal.optional(),
        });
        const pages = [];
        for (const key of ['message.sender', 'transfer.recipient']) {
          const query = key + "='" + address + "'";
          const params = new URLSearchParams({
            query,
            'pagination.offset': String(offset),
            'pagination.limit': '20',
            'pagination.count_total': 'true',
            page: String(Math.floor(offset / 20) + 1),
            limit: '20',
            order_by: 'ORDER_BY_DESC',
          });
          // Events keeps older LCD versions compatible; new versions use query.
          params.append('events', query);
          pages.push(await rest('/cosmos/tx/v1beta1/txs?' + params, txSchema));
        }
        const items = new Map<string, TxRecord>();
        for (const p of pages)
          for (const [i, t] of p.tx_responses.entries()) {
            const deltas = new Map<string, bigint>();
            let from = '';
            let to = '';
            if (t.code === 0)
              for (const event of t.events.filter((e) => e.type === 'transfer')) {
                const fields = Object.fromEntries(event.attributes.map((a) => [a.key, a.value]));
                const sender = fields['sender'];
                const recipient = fields['recipient'];
                if (sender !== address && recipient !== address) continue;
                from ||= sender ?? '';
                to ||= recipient ?? '';
                for (const part of (fields['amount'] ?? '').split(',')) {
                  const match = /^(\d{1,78})([A-Za-z][A-Za-z0-9/:._-]{0,255})$/.exec(part);
                  if (!match) continue;
                  const ref =
                    match[2] === chain.extra?.baseDenom
                      ? chain.nativeAsset.ref
                      : chain.chainId + ':' + match[2];
                  const change =
                    BigInt(match[1]!) *
                    BigInt((recipient === address ? 1 : 0) - (sender === address ? 1 : 0));
                  deltas.set(ref, (deltas.get(ref) ?? 0n) + change);
                }
              }
            const fee = p.txs[i]?.auth_info.fee.amount.find(
              (c) => c.denom === chain.extra?.baseDenom,
            );
            items.set(t.txhash, {
              ...base(chain, t.txhash),
              from,
              ...(to ? { to } : {}),
              blockNumber: uint.parse(Number(t.height)),
              timestampMs: uint.parse(Date.parse(t.timestamp)),
              status: t.code === 0 ? 'confirmed' : 'failed',
              fee: fee?.amount ?? null,
              assetDeltas: [...deltas].map(
                ([assetRef, amount]): AssetDelta => ({ assetRef, amount: String(amount) }),
              ),
            });
          }
        page = {
          items: [...items.values()].sort((a, b) => (b.blockNumber ?? 0) - (a.blockNumber ?? 0)),
          coverage:
            'LCD indexed sender and recipient events. Bank transfer events only; IBC lifecycle, staking and contract effects are not fully decoded. Fees use the native denom when available.',
        };
        if (
          pages.some(
            (p) =>
              p.tx_responses.length === 20 &&
              ((p.total ?? p.pagination?.total) === undefined ||
                BigInt((p.total ?? p.pagination?.total)!) > BigInt(offset + 20)),
          )
        )
          page.nextCursor = String(offset + 20);
      } else {
        const identity = await rpc('eth_chainId', [], hex);
        if (BigInt(identity) !== BigInt(chain.chainId.slice(7)))
          throw new Error('History endpoint is on a different EVM chain');
        const head =
          cursor === undefined
            ? numericHex(await rpc('eth_blockNumber', [], hex))
            : uint.parse(Number(decimal.parse(cursor)));
        const start = Math.max(0, head - 11);
        const txSchema = z.object({
          hash: evmHash,
          from: evmAddress,
          to: evmAddress.nullable(),
          value: hex,
        });
        const blockSchema = z.object({
          number: hex,
          timestamp: hex,
          transactions: z.array(txSchema).max(10000),
        });
        const receiptSchema = z.object({
          transactionHash: evmHash,
          status: z.enum(['0x0', '0x1']),
          gasUsed: hex,
          effectiveGasPrice: hex,
        });
        const items: TxRecord[] = [];
        for (let n = head; n >= start; n--) {
          const block = await rpc(
            'eth_getBlockByNumber',
            ['0x' + n.toString(16), true],
            blockSchema,
          );
          if (numericHex(block.number) !== n)
            throw new Error('History endpoint returned a different block');
          const matching = block.transactions.filter(
            (t) =>
              t.from.toLowerCase() === address.toLowerCase() ||
              t.to?.toLowerCase() === address.toLowerCase(),
          );
          if (items.length + matching.length > 100)
            throw new Error('Too many transactions in this scan; use an address indexer');
          for (const t of matching) {
            const receipt = await rpc('eth_getTransactionReceipt', [t.hash], receiptSchema);
            if (receipt.transactionHash.toLowerCase() !== t.hash.toLowerCase())
              throw new Error('Mismatched transaction receipt');
            const fee = BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice);
            const sent = t.from.toLowerCase() === address.toLowerCase();
            const received = t.to?.toLowerCase() === address.toLowerCase();
            const value = receipt.status === '0x1' ? BigInt(t.value) : 0n;
            const delta = value * BigInt((received ? 1 : 0) - (sent ? 1 : 0)) - (sent ? fee : 0n);
            items.push({
              ...base(chain, t.hash),
              from: t.from,
              ...(t.to ? { to: t.to } : {}),
              fee: String(fee),
              status: receipt.status === '0x1' ? 'confirmed' : 'failed',
              timestampMs: timestamp(numericHex(block.timestamp)),
              blockNumber: n,
              assetDeltas: [{ assetRef: chain.nativeAsset.ref, amount: String(delta) }],
            });
          }
        }
        page = {
          items,
          coverage:
            'RPC scan of blocks ' +
            start +
            '–' +
            head +
            '. External transactions only, with native net changes including execution fees. Token logs, internal calls and extra L2 fees are not decoded; this is not an indexed lifetime history.',
        };
        if (start > 0) page.nextCursor = String(start - 1);
      }
      return { ...page, source: url };
    },
    { maxAttempts: 2, ...(opts.signal ? { signal: opts.signal } : {}) },
  );
}
export const HistoryPage = z.object({
  items: z
    .array(
      z.object({
        entryId: text.optional(),
        description: text.optional(),
        hash: text.min(1),
        chainId: text.min(1),
        from: text,
        to: text.optional(),
        blockNumber: uint.optional(),
        timestampMs: uint.optional(),
        assetDeltas: z
          .array(z.object({ assetRef: text, amount: z.string().regex(/^-?\d{1,100}$/) }))
          .max(1000),
        feeAssetRef: text,
        fee: decimal.nullable(),
        status: z.enum(['pending', 'confirmed', 'failed']),
      }),
    )
    .max(1000),
  nextCursor: text.optional(),
  coverage: z.string().max(2000).optional(),
  source: z.string().url().optional(),
});
