/**
 * Cosmos SDK adapter. Addresses are derived offline from the catalog's bech32
 * prefix and address algorithm; reads go to LCD (REST) endpoints. Message
 * encoding, SIGN_MODE_DIRECT sign docs and IBC channel discovery arrive with
 * cosmjs and chain-registry in a later phase.
 */
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bech32 } from '@scure/base';
import {
  MemoryRpcPool,
  NotImplementedError,
  UnknownChainError,
  chainsForFamily,
  fetchJson,
  HttpError,
  publicKeyBytes,
  requireCurve,
  secp256k1Compressed,
  secp256k1Uncompressed,
  withFailover,
  type Address,
  type ChainAdapter,
  type ChainInfo,
  type Holding,
  type Page,
  type RpcPool,
  type SignedTx,
  type Simulation,
  type TxHash,
  type TxRecord,
  type TxStatus,
  type UnsignedTx,
} from '@stackwallet/chains';
import type {
  ChainId,
  PublicKey,
  Signature,
  SignRequest,
  TxIntent,
} from '@stackwallet/core-client';
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

export interface CosmosAdapterOptions {
  rpc?: RpcPool;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export class CosmosAdapter implements ChainAdapter {
  readonly family = 'cosmos' as const;
  readonly rpc: RpcPool;
  private readonly fetchImpl: typeof fetch | undefined;
  private readonly timeoutMs: number | undefined;

  constructor(opts: CosmosAdapterOptions = {}) {
    this.rpc = opts.rpc ?? new MemoryRpcPool(chainsForFamily('cosmos'));
    this.fetchImpl = opts.fetch;
    this.timeoutMs = opts.timeoutMs;
  }

  chains(): ChainInfo[] {
    return chainsForFamily('cosmos');
  }

  private chain(chainId: ChainId): ChainInfo {
    const c = this.chains().find((x) => x.chainId === chainId);
    if (!c) throw new UnknownChainError(chainId);
    return c;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    const meta = cosmosMetaOf(this.chain(chainId));
    requireCurve(pub, 'secp256k1');
    return encodeCosmosAddress(meta.prefix, cosmosAccountBytes(publicKeyBytes(pub), meta.algo));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    return isValidCosmosAddress(addr, cosmosMetaOf(this.chain(chainId)).prefix);
  }

  /**
   * Schema validation runs inside failover so a node returning garbage is
   * skipped like a dead one. LCD answers "not found" with 400 or 404 depending
   * on SDK version; both are real answers and return null.
   */
  private get<T>(chainId: ChainId, path: string, schema: z.ZodType<T>): Promise<T | null> {
    const opts = {
      ...(this.fetchImpl ? { fetch: this.fetchImpl } : {}),
      ...(this.timeoutMs !== undefined ? { timeoutMs: this.timeoutMs } : {}),
    };
    return withFailover(this.rpc, chainId, async (base) => {
      try {
        return schema.parse(await fetchJson(`${base.replace(/\/$/, '')}${path}`, opts));
      } catch (error) {
        if (error instanceof HttpError && (error.status === 404 || error.status === 400))
          return null;
        throw error;
      }
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.chain(chainId);
    const meta = cosmosMetaOf(chain);
    if (!isValidCosmosAddress(addr, meta.prefix))
      throw new TypeError(`invalid address ${addr} for ${chainId}`);
    const res = await this.get(
      chainId,
      `/cosmos/bank/v1beta1/balances/${encodeURIComponent(addr)}?pagination.limit=1000`,
      Balances,
    );
    if (res === null) throw new Error(`bank balances endpoint rejected ${addr} on ${chainId}`);
    const now = Date.now();
    const holdings: Holding[] = res.balances.map((b) => ({
      assetRef: assetRefForDenom(chainId, meta.baseDenom, b.denom),
      amount: b.amount,
      updatedAtMs: now,
    }));
    if (!holdings.some((h) => h.assetRef === chain.nativeAsset.ref)) {
      holdings.unshift({ assetRef: chain.nativeAsset.ref, amount: '0', updatedAtMs: now });
    }
    return holdings;
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.chain(chainId);
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

  getHistory(_addr: Address, _chainId: ChainId, _cursor?: string): Promise<Page<TxRecord>> {
    return Promise.reject(new NotImplementedError('chains-cosmos.getHistory', 'phase 4'));
  }

  build(_intent: TxIntent, _chainId: ChainId): Promise<UnsignedTx> {
    return Promise.reject(new NotImplementedError('chains-cosmos.build', 'phase 4'));
  }

  simulate(_tx: UnsignedTx): Promise<Simulation> {
    return Promise.reject(new NotImplementedError('chains-cosmos.simulate', 'phase 4'));
  }

  sighashes(_tx: UnsignedTx): SignRequest[] {
    throw new NotImplementedError('chains-cosmos.sighashes', 'phase 4');
  }

  attach(_tx: UnsignedTx, _sigs: Signature[]): SignedTx {
    throw new NotImplementedError('chains-cosmos.attach', 'phase 4');
  }

  broadcast(_tx: SignedTx): Promise<TxHash> {
    return Promise.reject(new NotImplementedError('chains-cosmos.broadcast', 'phase 4'));
  }
}

export function createCosmosAdapter(opts?: CosmosAdapterOptions): CosmosAdapter {
  return new CosmosAdapter(opts);
}
