import { base58 } from '@scure/base';
import {
  fetchJson,
  fetchJsonRpc,
  withFailover,
  type ChainRegistry,
  type FetchOptions,
} from '@stackwallet/chains';
import { sns } from '@stackwallet/chains-solana';
import { z } from 'zod';

import { cleanText } from './text.js';
import type { Collectible, CollectibleAccount, CollectibleSource } from './types.js';

export const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const METAPLEX_METADATA = 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s';
export const SOLANA_PAGE_SIZE = 24;
const MAX_HOLDINGS = 2000;

const TokenAccounts = z.object({
  value: z
    .array(
      z.object({
        account: z.object({
          data: z.object({
            parsed: z.object({
              info: z.object({
                mint: z.string().max(64),
                tokenAmount: z.object({ amount: z.string().max(40), decimals: z.number().int() }),
              }),
            }),
          }),
        }),
      }),
    )
    .max(MAX_HOLDINGS * 2),
});

const Accounts = z.object({
  value: z.array(z.object({ data: z.tuple([z.string(), z.literal('base64')]) }).nullable()),
});

export function metadataKey(mint: string): string {
  return sns.findProgramAddress(
    [new TextEncoder().encode('metadata'), base58.decode(METAPLEX_METADATA), base58.decode(mint)],
    METAPLEX_METADATA,
  );
}

export interface MetaplexMetadata {
  name: string;
  symbol: string;
  uri: string;
}

/**
 * Borsh layout of a Metaplex metadata account: key u8, update authority,
 * mint, then three length-prefixed strings that are NUL-padded on chain.
 */
export function parseMetaplex(data: Uint8Array): MetaplexMetadata | null {
  let o = 1 + 32 + 32;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const str = (max: number): string | null => {
    if (o + 4 > data.length) return null;
    const len = view.getUint32(o, true);
    o += 4;
    if (len > max || o + len > data.length) return null;
    const s = new TextDecoder('utf-8', { fatal: false }).decode(data.subarray(o, o + len));
    o += len;
    // On-chain strings are fixed-width and padded with NULs.
    let end = s.length;
    while (end > 0 && s.charCodeAt(end - 1) === 0) end--;
    return s.slice(0, end);
  };
  const name = str(64);
  const symbol = str(32);
  const uri = str(400);
  if (name === null || symbol === null || uri === null) return null;
  return { name, symbol, uri };
}

function base64Bytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const OffChain = z
  .object({
    name: z.unknown().optional(),
    image: z.unknown().optional(),
    collection: z.unknown().optional(),
  })
  .passthrough();

async function mapLimit<T, R>(
  items: readonly T[],
  n: number,
  fn: (t: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  });
  await Promise.all(workers);
  return out;
}

export function solanaSource(opts: {
  registry: ChainRegistry;
  fetchOptions?: FetchOptions;
}): CollectibleSource {
  const rpc = <T>(chainId: string, method: string, params: unknown[], schema: z.ZodType<T>) =>
    withFailover(opts.registry.adapterFor(chainId).rpc, chainId, async (url) =>
      schema.parse(await fetchJsonRpc(url, method, params, opts.fetchOptions)),
    );

  return {
    id: 'solana-metaplex',
    appliesTo: (a: CollectibleAccount) =>
      a.family === 'solana' && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a.address),
    async list(account, cursor) {
      const offset = cursor ? Number.parseInt(cursor, 10) || 0 : 0;
      const holdings: string[] = [];
      for (const programId of [TOKEN_PROGRAM, TOKEN_2022_PROGRAM]) {
        const r = await rpc(
          account.chainId,
          'getTokenAccountsByOwner',
          [account.address, { programId }, { encoding: 'jsonParsed' }],
          TokenAccounts,
        );
        for (const v of r.value) {
          const info = v.account.data.parsed.info;
          // Non-fungible: a whole, single, indivisible unit.
          if (info.tokenAmount.decimals === 0 && info.tokenAmount.amount === '1') {
            holdings.push(info.mint);
          }
        }
      }
      const mints = [...new Set(holdings)].sort().slice(offset, offset + SOLANA_PAGE_SIZE);
      if (mints.length === 0) return { items: [], cursor: null };

      const metas = await rpc(
        account.chainId,
        'getMultipleAccounts',
        [mints.map(metadataKey), { encoding: 'base64' }],
        Accounts,
      );
      const indexed = mints.map((mint, i) => ({ mint, acct: metas.value[i] ?? null }));
      const items = await mapLimit(
        indexed,
        6,
        async ({ mint, acct }): Promise<Collectible | null> => {
          const meta = acct ? parseMetaplex(base64Bytes(acct.data[0])) : null;
          if (!meta) return null;
          let image: string | null = null;
          let name = cleanText(meta.name);
          let collection = cleanText(meta.symbol);
          if (/^https:\/\//.test(meta.uri) || /^(ipfs|ar):\/\//.test(meta.uri)) {
            try {
              const off = OffChain.parse(await fetchJson(gatewayUrl(meta.uri), opts.fetchOptions));
              if (typeof off.image === 'string') image = off.image;
              name = cleanText(off.name) || name;
              const c = off.collection as { name?: unknown } | undefined;
              collection = cleanText(c?.name) || collection;
            } catch {
              // Metadata hosts go away; the on-chain name still identifies the token.
            }
          }
          return {
            key: `${account.chainId}:${mint}:${mint}`,
            chainId: account.chainId,
            standard: 'spl-nft',
            contract: mint,
            tokenId: mint,
            name: name || `${mint.slice(0, 4)}…${mint.slice(-4)}`,
            collection: collection || 'unnamed collection',
            image,
            amount: '1',
            suspicious: false,
            source: 'solana-metaplex',
          };
        },
      );
      const total = new Set(holdings).size;
      return {
        items: items.filter((x): x is Collectible => x !== null),
        cursor: offset + SOLANA_PAGE_SIZE < total ? String(offset + SOLANA_PAGE_SIZE) : null,
      };
    },
  };
}

/**
 * Public IPFS gateways that answer with CORS, tried in order. Gateways come
 * and go and rate-limit hard, so no single one is trusted to be up.
 */
export const IPFS_GATEWAYS: readonly string[] = [
  'https://ipfs.filebase.io',
  'https://gateway.pinata.cloud',
  'https://ipfs.io',
];

/** The `<cid>/<path>` of an ipfs:// URI or of any https gateway URL, else null. */
export function ipfsPath(uri: string): string | null {
  if (uri.startsWith('ipfs://')) return uri.slice('ipfs://'.length).replace(/^ipfs\//, '');
  const m = /^https:\/\/[^/]+\/ipfs\/(.+)$/.exec(uri);
  return m ? m[1]! : null;
}

/** Every URL worth trying for `uri`, best first. */
export function gatewayCandidates(uri: string): string[] {
  const path = ipfsPath(uri);
  if (path) return IPFS_GATEWAYS.map((g) => `${g}/ipfs/${path}`);
  if (uri.startsWith('ar://')) return [`https://arweave.net/${uri.slice('ar://'.length)}`];
  return [uri];
}

/** Content-addressed schemes go through public gateways so the browser can fetch them. */
export function gatewayUrl(uri: string): string {
  return gatewayCandidates(uri)[0]!;
}
