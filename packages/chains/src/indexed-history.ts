import { z } from 'zod';
import { fetchJson, MAX_BODY_BYTES, type FetchOptions } from './rpc.js';
import type { ChainInfo, Page, TxRecord } from './types.js';

// Bundled from Blockscout's chain directory; no registry is fetched at runtime.
export const HISTORY_INDEXERS: Readonly<Record<string, string>> = {
  'eip155:1': 'https://eth.blockscout.com',
  'eip155:11155111': 'https://eth-sepolia.blockscout.com',
  'eip155:8453': 'https://base.blockscout.com',
  'eip155:84532': 'https://base-sepolia.blockscout.com',
  'eip155:42161': 'https://arbitrum.blockscout.com',
  'eip155:42170': 'https://arbitrum-nova.blockscout.com',
  'eip155:10': 'https://explorer.optimism.io',
  'eip155:137': 'https://polygon.blockscout.com',
  'eip155:324': 'https://zksync.blockscout.com',
  'eip155:42220': 'https://celo.blockscout.com',
  'eip155:130': 'https://unichain.blockscout.com',
};

export interface HistoryOptions {
  signal?: AbortSignal;
  indexerUrl?: string;
  tokenTransfers?: boolean;
}

const amount = z.string().regex(/^\d{1,78}$/);
const hash = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const address = z.object({ hash: z.string().regex(/^0x[0-9a-fA-F]{40}$/) });
const time = z.string().datetime({ offset: true }).nullable();
const block = z.number().int().nonnegative().safe().nullable();
const next = z
  .record(
    z.string().regex(/^[a-z_]{1,64}$/),
    z.union([z.string().max(256), z.number().int().safe(), z.boolean()]),
  )
  .nullable();
const recordBase = (chain: ChainInfo, txHash: string): TxRecord => ({
  chainId: chain.chainId,
  hash: txHash,
  from: '',
  assetDeltas: [],
  feeAssetRef: chain.nativeAsset.ref,
  fee: null,
  status: 'confirmed',
});

export async function readIndexedHistory(
  chain: ChainInfo,
  account: string,
  indexer: string,
  opts: FetchOptions,
  cursor?: string,
  tokens = false,
): Promise<Page<TxRecord>> {
  if (chain.family !== 'evm') throw new Error('This history indexer requires an EVM chain');
  address.shape.hash.parse(account);
  const base = new URL(z.string().url().max(2000).parse(indexer));
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash)
    throw new Error('Use an HTTPS Blockscout base URL without credentials, query or fragment');
  base.pathname =
    base.pathname.replace(/\/$/, '') +
    '/api/v2/addresses/' +
    encodeURIComponent(account) +
    (tokens ? '/token-transfers' : '/transactions');
  const query = cursor ? next.parse(JSON.parse(cursor)) : null;
  if (query)
    for (const [key, value] of Object.entries(query)) base.searchParams.set(key, String(value));
  opts.signal?.throwIfAborted();
  const payload = await fetchJson(base.toString(), { ...opts, maxBodyBytes: 8 * MAX_BODY_BYTES });
  opts.signal?.throwIfAborted();
  let items: TxRecord[];
  let cursorParams: z.infer<typeof next>;
  if (tokens) {
    const response = z
      .object({
        next_page_params: next,
        items: z
          .array(
            z.object({
              log_index: z.number().int().nonnegative().safe(),
              transaction_hash: hash,
              block_number: block,
              timestamp: time,
              from: address,
              to: address,
              token: z.object({ address_hash: address.shape.hash, type: z.string().max(32) }),
              total: z.object({ value: amount.optional(), token_id: amount.optional() }).nullable(),
            }),
          )
          .max(50),
      })
      .parse(payload);
    items = [];
    for (const t of response.items) {
      // ERC-721/1155 identities are not fungible asset deltas.
      if (
        t.from.hash.toLowerCase() !== account.toLowerCase() &&
        t.to.hash.toLowerCase() !== account.toLowerCase()
      )
        throw new Error('Indexer returned a transfer unrelated to this account');
      const tx: TxRecord = {
        description:
          t.token.type +
          ' · ' +
          t.token.address_hash +
          (t.total?.token_id ? ' · token ID ' + t.total.token_id : ''),
        ...recordBase(chain, t.transaction_hash),
        entryId: t.transaction_hash + ':' + t.log_index,
        status: t.block_number === null ? 'pending' : 'confirmed',
        from: t.from.hash,
        to: t.to.hash,
        ...(t.block_number !== null ? { blockNumber: t.block_number } : {}),
        ...(t.timestamp !== null ? { timestampMs: Date.parse(t.timestamp) } : {}),
      };
      if (t.token.type === 'ERC-20' && t.total?.value !== undefined) {
        const direction =
          Number(t.to.hash.toLowerCase() === account.toLowerCase()) -
          Number(t.from.hash.toLowerCase() === account.toLowerCase());
        const ref = chain.chainId + ':erc20:' + t.token.address_hash.toLowerCase();
        const prior = tx.assetDeltas.find((d) => d.assetRef === ref);
        const value = BigInt(t.total.value) * BigInt(direction);
        if (prior) prior.amount = String(BigInt(prior.amount) + value);
        else tx.assetDeltas.push({ assetRef: ref, amount: String(value) });
      }
      items.push(tx);
    }
    cursorParams = response.next_page_params;
  } else {
    const response = z
      .object({
        next_page_params: next,
        items: z
          .array(
            z.object({
              hash,
              from: address,
              to: address.nullable(),
              value: amount,
              block_number: block,
              timestamp: time,
              status: z.string().max(64).nullable(),
              fee: z.object({ type: z.string().max(32), value: amount.nullable() }),
            }),
          )
          .max(50),
      })
      .parse(payload);
    items = response.items.map((t) => {
      if (
        t.from.hash.toLowerCase() !== account.toLowerCase() &&
        t.to?.hash.toLowerCase() !== account.toLowerCase()
      )
        throw new Error('Indexer returned a transaction unrelated to this account');
      const failed = t.status === 'error';
      const confirmed = t.status === 'ok' && t.block_number !== null;
      const sent = t.from.hash.toLowerCase() === account.toLowerCase();
      const received = t.to?.hash.toLowerCase() === account.toLowerCase();
      const fee = t.fee.type === 'actual' ? t.fee.value : null;
      const delta =
        BigInt(t.value) * BigInt(failed ? 0 : Number(received) - Number(sent)) -
        (sent && fee ? BigInt(fee) : 0n);
      return {
        ...recordBase(chain, t.hash),
        from: t.from.hash,
        ...(t.to ? { to: t.to.hash } : {}),
        status: failed ? 'failed' : confirmed ? 'confirmed' : 'pending',
        fee,
        // Pending transactions and unknown outgoing fees cannot give a completed net change.
        assetDeltas:
          confirmed || failed
            ? !sent || fee !== null
              ? [{ assetRef: chain.nativeAsset.ref, amount: String(delta) }]
              : []
            : [],
        ...(t.block_number !== null ? { blockNumber: t.block_number } : {}),
        ...(t.timestamp !== null ? { timestampMs: Date.parse(t.timestamp) } : {}),
      };
    });
    cursorParams = response.next_page_params;
  }
  return {
    items,
    ...(cursorParams ? { nextCursor: JSON.stringify(cursorParams) } : {}),
    source: base.origin + base.pathname,
    coverage: tokens
      ? 'Blockscout indexed token-transfer events. ERC-20 net deltas only; NFT events appear without fungible amounts. Transaction fees and internal/native calls are not decoded. A page may contain only part of a transaction’s token events.'
      : 'Blockscout indexed external transactions. Native net changes use reported actual fees; token transfers and internal calls have separate coverage. Indexer records are unverified and may lag or omit data.',
  };
}
