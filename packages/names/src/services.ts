import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { bech32 } from '@scure/base';
import {
  fetchJson,
  fetchJsonRpc,
  JsonRpcError,
  withFailover,
  type ChainRegistry,
  type FetchOptions,
} from '@stackwallet/chains';
import { sns } from '@stackwallet/chains-solana';
import { z } from 'zod';

import { cleanName } from './sanitize.js';
import type { NameAccount, NameRecord, NameService, NameServiceId } from './types.js';

export const ETHEREUM_MAINNET = 'eip155:1';
export const SOLANA_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
export const OSMOSIS = 'cosmos:osmosis-1';
export const THORCHAIN = 'cosmos:thorchain-1';

/** ENS Universal Resolver; `reverse` checks the forward record before answering. */
export const ENS_UNIVERSAL_RESOLVER = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe';
export const ICNS_RESOLVER = 'osmo1xk0s8xgktn9x5vwcgtjdxqzadg88fgn33p8u9cnpdxwemvxscvast52cdd';
export const MIDGARD_URLS: readonly string[] = [
  'https://gateway.liquify.com/chain/thorchain_midgard',
];

const ETH_COIN_TYPE = 60n;
const MAX_THORNAMES = 4;

export interface NameContext {
  registry: ChainRegistry;
  now?: () => number;
  fetchOptions?: FetchOptions;
  midgardUrls?: readonly string[];
}

function record(
  ctx: NameContext,
  service: NameServiceId,
  raw: unknown,
  account: NameAccount,
  chainId: string,
): NameRecord | null {
  const clean = cleanName(raw);
  if (!clean) return null;
  return {
    service,
    name: clean.name,
    nonAscii: clean.nonAscii,
    address: account.address,
    chainId,
    resolvedAtMs: (ctx.now ?? Date.now)(),
  };
}

function poolFor(ctx: NameContext, chainId: string) {
  try {
    return ctx.registry.adapterFor(chainId).rpc;
  } catch {
    return null;
  }
}

const selector = (sig: string) => bytesToHex(keccak_256(new TextEncoder().encode(sig))).slice(0, 8);
const word = (hex: string) => hex.padStart(64, '0');
const REVERSE_SELECTOR = selector('reverse(bytes,uint256)');

/** Calldata for `reverse(bytes lookupAddress, uint256 coinType)`. */
export function encodeEnsReverse(address: string, coinType: bigint = ETH_COIN_TYPE): string {
  const body = address.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(body)) throw new TypeError('expected a 20-byte address');
  return (
    '0x' +
    REVERSE_SELECTOR +
    word((64).toString(16)) +
    word(coinType.toString(16)) +
    word((20).toString(16)) +
    body.padEnd(64, '0')
  );
}

/** First return value of `reverse`, an ABI string. */
export function decodeEnsReverse(result: string): string | null {
  const hex = result.replace(/^0x/, '');
  if (hex.length < 192 || !/^[0-9a-f]*$/i.test(hex)) return null;
  const off = Number.parseInt(hex.slice(0, 64), 16) * 2;
  if (!Number.isSafeInteger(off) || off + 64 > hex.length) return null;
  const len = Number.parseInt(hex.slice(off, off + 64), 16);
  if (!Number.isSafeInteger(len) || len === 0 || len > 512) return null;
  const start = off + 64;
  if (start + len * 2 > hex.length) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(
      hexToBytes(hex.slice(start, start + len * 2)),
    );
  } catch {
    return null;
  }
}

const HexData = z.string().regex(/^0x[0-9a-fA-F]*$/);

export function ensService(ctx: NameContext): NameService {
  return {
    id: 'ens',
    // A primary ENS name follows the address onto every EVM chain.
    appliesTo: (a) => a.family === 'evm' && /^0x[0-9a-fA-F]{40}$/.test(a.address),
    async resolve(account) {
      const pool = poolFor(ctx, ETHEREUM_MAINNET);
      if (!pool) return [];
      const data = encodeEnsReverse(account.address);
      const result = await withFailover(pool, ETHEREUM_MAINNET, async (url) => {
        try {
          return HexData.parse(
            await fetchJsonRpc(
              url,
              'eth_call',
              [{ to: ENS_UNIVERSAL_RESOLVER, data }, 'latest'],
              ctx.fetchOptions,
            ),
          );
        } catch (err) {
          // A revert is the resolver's answer ("no verified name"), not a broken endpoint.
          if (err instanceof JsonRpcError && (err.code === 3 || /revert/i.test(err.message))) {
            return null;
          }
          throw err;
        }
      });
      if (!result) return [];
      const r = record(ctx, 'ens', decodeEnsReverse(result), account, ETHEREUM_MAINNET);
      return r ? [r] : [];
    },
  };
}

const AccountsResult = z.object({
  value: z.array(z.object({ data: z.tuple([z.string(), z.literal('base64')]) }).nullable()),
});

function base64Bytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function snsService(ctx: NameContext): NameService {
  return {
    id: 'sns',
    appliesTo: (a) => a.family === 'solana' && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a.address),
    async resolve(account) {
      const pool = poolFor(ctx, SOLANA_MAINNET);
      if (!pool) return [];
      const fetchAccounts = (keys: readonly string[]) =>
        withFailover(pool, SOLANA_MAINNET, async (url) => {
          const raw = AccountsResult.parse(
            await fetchJsonRpc(
              url,
              'getMultipleAccounts',
              [keys, { encoding: 'base64' }],
              ctx.fetchOptions,
            ),
          );
          if (raw.value.length !== keys.length) throw new Error('account count mismatch');
          return raw.value.map((v) => (v ? base64Bytes(v.data[0]) : null));
        });
      const name = await sns.primarySolName(account.address, fetchAccounts);
      const r = name ? record(ctx, 'sns', name, account, SOLANA_MAINNET) : null;
      return r ? [r] : [];
    },
  };
}

function bech32Parts(address: string): { prefix: string; words: number[] } | null {
  try {
    const d = bech32.decode(address as `${string}1${string}`, 120);
    return { prefix: d.prefix, words: Array.from(d.words) };
  } catch {
    return null;
  }
}

const SmartData = <T extends z.ZodType>(inner: T) => z.object({ data: inner });

async function cosmwasmQuery<T>(
  ctx: NameContext,
  chainId: string,
  contract: string,
  query: unknown,
  schema: z.ZodType<T>,
): Promise<T | null> {
  const pool = poolFor(ctx, chainId);
  if (!pool) return null;
  const q = btoa(JSON.stringify(query));
  return withFailover(pool, chainId, async (base) =>
    SmartData(schema).parse(
      await fetchJson(
        `${base.replace(/\/$/, '')}/cosmwasm/wasm/v1/contract/${contract}/smart/${encodeURIComponent(q)}`,
        ctx.fetchOptions,
      ),
    ),
  ).then((r) => r.data);
}

export function icnsService(ctx: NameContext): NameService {
  return {
    id: 'icns',
    appliesTo: (a) => a.family === 'cosmos' && bech32Parts(a.address) !== null,
    async resolve(account) {
      const parts = bech32Parts(account.address);
      if (!parts) return [];
      // ICNS keys names by account bytes; the Osmosis spelling of the same bytes asks for them.
      const osmo = bech32.encode('osmo', parts.words, 120);
      const primary = await cosmwasmQuery(
        ctx,
        OSMOSIS,
        ICNS_RESOLVER,
        { primary_name: { address: osmo } },
        z.object({ name: z.string().max(256) }),
      );
      if (!primary?.name) return [];
      const forward = await cosmwasmQuery(
        ctx,
        OSMOSIS,
        ICNS_RESOLVER,
        { address: { name: primary.name, bech32_prefix: parts.prefix } },
        z.object({ address: z.string().max(128) }),
      );
      if (forward?.address !== account.address) return [];
      const r = record(ctx, 'icns', `${primary.name}.${parts.prefix}`, account, OSMOSIS);
      return r ? [r] : [];
    },
  };
}

const ThorLookup = z.object({
  entries: z.array(z.object({ chain: z.string().max(16), address: z.string().max(128) })).max(64),
  owner: z.string().max(128).optional(),
});

async function midgard<T>(ctx: NameContext, path: string, schema: z.ZodType<T>): Promise<T> {
  const urls = ctx.midgardUrls ?? MIDGARD_URLS;
  let last: unknown = new Error('no midgard endpoints');
  for (const base of urls) {
    try {
      return schema.parse(await fetchJson(`${base}${path}`, ctx.fetchOptions));
    } catch (err) {
      last = err;
    }
  }
  throw last;
}

function sameAddress(a: string, b: string): boolean {
  return a.startsWith('0x') ? a.toLowerCase() === b.toLowerCase() : a === b;
}

export function thornameService(ctx: NameContext): NameService {
  return {
    id: 'thorname',
    // THORNames alias addresses on every chain THORChain swaps, not just THOR itself.
    appliesTo: (a) => a.address.length >= 26 && a.address.length <= 128,
    async resolve(account) {
      let names: string[];
      try {
        names = await midgard(
          ctx,
          `/v2/thorname/rlookup/${encodeURIComponent(account.address)}`,
          z.array(z.string().max(64)).max(64),
        );
      } catch {
        // Midgard answers 404 for addresses with no names.
        return [];
      }
      const out: NameRecord[] = [];
      for (const name of names.slice(0, MAX_THORNAMES)) {
        if (!/^[a-zA-Z0-9+_.-]{1,30}$/.test(name)) continue;
        const lookup = await midgard(
          ctx,
          `/v2/thorname/lookup/${encodeURIComponent(name)}`,
          ThorLookup,
        ).catch(() => null);
        if (!lookup?.entries.some((e) => sameAddress(account.address, e.address))) continue;
        const r = record(ctx, 'thorname', name, account, THORCHAIN);
        if (r) out.push(r);
      }
      return out;
    },
  };
}

export function defaultNameServices(ctx: NameContext): NameService[] {
  return [ensService(ctx), snsService(ctx), icnsService(ctx), thornameService(ctx)];
}
