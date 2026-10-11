/**
 * Cosmos SDK adapter. Addresses are derived offline from the catalog's bech32
 * prefix and address algorithm; reads go to LCD (REST) endpoints. Native Osmosis
 * Testnet sends use public DIRECT codecs while the vault signs in Rust.
 */
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bech32 } from '@scure/base';
import {
  BaseAdapter,
  preferIndexedSide,
  publicKeyBytes,
  requireCurve,
  secp256k1Compressed,
  secp256k1Uncompressed,
  withCrossCheck,
  withFailover,
  fetchJson,
  HttpError,
  type Address,
  type BaseAdapterOptions,
  type ChainInfo,
  type Holding,
  type HoldingProvenance,
  type TxHash,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export type CosmosAddressAlgo = 'secp256k1' | 'ethsecp256k1';

export interface CosmosChainMeta {
  prefix: string;
  algo: CosmosAddressAlgo;
  baseDenom: string;
}

export function cosmosMetaOf(chain: ChainInfo): CosmosChainMeta {
  const x = chain.extra;
  if (!x?.bech32Prefix || !x.baseDenom) {
    throw new Error(`${chain.chainId} is missing bech32Prefix/baseDenom in its catalog entry`);
  }
  return { prefix: x.bech32Prefix, algo: x.addressAlgo ?? 'secp256k1', baseDenom: x.baseDenom };
}

/** 20-byte account id for a secp256k1 key under either Cosmos address scheme. */
export function cosmosAccountBytes(key: Uint8Array, algo: CosmosAddressAlgo): Uint8Array {
  if (algo === 'ethsecp256k1')
    return keccak_256(secp256k1Uncompressed(key).subarray(1)).subarray(12);
  return ripemd160(sha256(secp256k1Compressed(key)));
}

export function encodeCosmosAddress(prefix: string, data: Uint8Array): string {
  return bech32.encode(prefix, bech32.toWords(data));
}

export function decodeCosmosAddress(addr: string): { prefix: string; data: Uint8Array } | null {
  const decoded = bech32.decodeUnsafe(addr, 90);
  if (!decoded) return null;
  const data = bech32.fromWordsUnsafe(decoded.words);
  if (!data) return null;
  return { prefix: decoded.prefix, data };
}

/** Accounts are 20 bytes; module and ICA accounts are 32. Anything else is not an address. */
export function isValidCosmosAddress(addr: string, prefix: string): boolean {
  const decoded = decodeCosmosAddress(addr);
  return (
    decoded !== null &&
    decoded.prefix === prefix &&
    (decoded.data.length === 20 || decoded.data.length === 32)
  );
}

// Bounds are defence against a hostile LCD, not protocol limits.
const Balances = z.object({
  balances: z
    .array(
      z.object({
        denom: z.string().min(1).max(128),
        amount: z
          .string()
          .regex(/^[0-9]+$/)
          .max(80),
      }),
    )
    .max(1000),
});

const TxResponse = z.object({
  tx_response: z.object({
    height: z
      .string()
      .regex(/^[0-9]+$/)
      .max(20),
    code: z.number().int(),
    timestamp: z.string().max(64).optional(),
    raw_log: z.string().max(512).optional(),
  }),
});

export function assetRefForDenom(chainId: ChainId, baseDenom: string, denom: string): string {
  if (denom === baseDenom) return `${chainId}:native`;
  if (denom.startsWith('ibc/')) return `${chainId}:ibc:${denom.slice(4)}`;
  if (denom.startsWith('factory/')) return `${chainId}:factory:${denom.slice(8)}`;
  return `${chainId}:native:${denom}`;
}

export type CosmosAdapterOptions = BaseAdapterOptions;
export type LcdQuery = <T>(path: string, schema: z.ZodType<T>, body?: unknown) => Promise<T | null>;

/** LCDs answer "not found" with 400 or 404 depending on SDK version. */
const NOT_FOUND: readonly number[] = [404, 400];

/** Asset ref to base-unit amount, as one LCD reported it. */
type BalanceMap = Map<string, string>;

function sameBalances(a: BalanceMap, b: BalanceMap): boolean {
  if (a.size !== b.size) return false;
  for (const [ref, amount] of a) if (b.get(ref) !== amount) return false;
  return true;
}

/**
 * Narrows a whole-response provenance to one asset: when the two LCDs
 * disagreed, only the denoms whose amounts actually differ are flagged.
 */
function provenanceFor(
  whole: HoldingProvenance,
  ref: string,
  mine: string,
  theirs: BalanceMap | undefined,
): HoldingProvenance {
  if (whole.kind !== 'disagreed' || !theirs) return whole;
  const other = theirs.get(ref) ?? '0';
  return other === mine
    ? { kind: 'agreed', endpoints: whole.endpoints }
    : { kind: 'disagreed', endpoints: whole.endpoints, other };
}

export class CosmosAdapter extends BaseAdapter<'cosmos'> {
  constructor(opts: CosmosAdapterOptions = {}) {
    super('cosmos', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    const meta = cosmosMetaOf(this.requireChain(chainId));
    requireCurve(pub, 'secp256k1');
    return encodeCosmosAddress(meta.prefix, cosmosAccountBytes(publicKeyBytes(pub), meta.algo));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    return isValidCosmosAddress(addr, cosmosMetaOf(this.requireChain(chainId)).prefix);
  }

  private get<T>(chainId: ChainId, path: string, schema: z.ZodType<T>): Promise<T | null> {
    return withFailover(this.rpc, chainId, this.rest(path, schema, NOT_FOUND));
  }

  /** Dependent signing-flow reads stay on one chain-verified endpoint. */
  withChain<T>(chainId: ChainId, query: (lcd: LcdQuery) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      const lcd: LcdQuery = async (path, schema, body) => {
        const opts = this.fetchOptions();
        const fetchImpl = this.fetchImpl ?? fetch;
        try {
          const raw = await fetchJson(`${url.replace(/\/$/, '')}${path}`, {
            ...opts,
            fetch: async (input, init) => {
              const response = await fetchImpl(input, {
                ...init,
                ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
                headers: {
                  'Content-Type': 'application/json',
                },
              });
              return response;
            },
          });
          return schema.parse(raw);
        } catch (err) {
          if (body === undefined && err instanceof HttpError && err.status === 404) return null;
          throw err;
        }
      };
      const info = await lcd(
        '/cosmos/base/tendermint/v1beta1/node_info',
        z.object({
          default_node_info: z.object({ network: z.string().max(64) }),
        }),
      );
      if (!info || `cosmos:${info.default_node_info.network}` !== chainId)
        throw new Error('LCD network does not match the requested Cosmos chain');
      return query(lcd);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const meta = cosmosMetaOf(chain);
    if (!isValidCosmosAddress(addr, meta.prefix))
      throw new TypeError(`invalid address ${addr} for ${chainId}`);
    const balancesFor = this.rest(
      `/cosmos/bank/v1beta1/balances/${encodeURIComponent(addr)}?pagination.limit=1000`,
      Balances,
      NOT_FOUND,
    );
    const native = chain.nativeAsset.ref;
    const { value, provenance, other } = preferIndexedSide(
      await withCrossCheck(
        this.rpc,
        chainId,
        async (base) => {
          const res = await balancesFor(base);
          if (res === null) return null;
          const map: BalanceMap = new Map();
          for (const b of res.balances) {
            map.set(assetRefForDenom(chainId, meta.baseDenom, b.denom), b.amount);
          }
          return map;
        },
        {
          equal: (a, b) => (a === null || b === null ? a === b : sameBalances(a, b)),
          describe: (v) => v?.get(native) ?? '0',
        },
      ),
    );
    if (value === null) throw new Error(`bank balances endpoint rejected ${addr} on ${chainId}`);
    const now = Date.now();
    const theirs = other ?? undefined;
    const holdings: Holding[] = [...value].map(([assetRef, amount]) => ({
      assetRef,
      amount,
      updatedAtMs: now,
      provenance: provenanceFor(provenance, assetRef, amount, theirs),
    }));
    // The native asset leads the list even when the account holds none of it.
    const nativeAt = holdings.findIndex((h) => h.assetRef === native);
    if (nativeAt < 0) {
      holdings.unshift({
        assetRef: native,
        amount: '0',
        updatedAtMs: now,
        provenance: provenanceFor(provenance, native, '0', theirs),
      });
    } else if (nativeAt > 0) {
      holdings.unshift(...holdings.splice(nativeAt, 1));
    }
    return holdings;
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.requireChain(chainId);
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) return { state: 'unknown' };
    const res = await this.get(chainId, `/cosmos/tx/v1beta1/txs/${hash.toUpperCase()}`, TxResponse);
    if (res === null) return { state: 'unknown' };
    const { height, code, timestamp, raw_log } = res.tx_response;
    if (code !== 0) return { state: 'failed', ...(raw_log ? { reason: raw_log } : {}) };
    const ts = timestamp ? Date.parse(timestamp) : Number.NaN;
    return {
      state: 'confirmed',
      blockNumber: Number(height),
      ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
    };
  }
}

export function createCosmosAdapter(opts?: CosmosAdapterOptions): CosmosAdapter {
  return new CosmosAdapter(opts);
}
