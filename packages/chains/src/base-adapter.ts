/**
 * Shared skeleton for family adapters: catalog lookup, the RPC pool, fetch
 * options and `NotImplementedError` stubs for the signing path. A family
 * adapter extends it and implements address work plus the read methods.
 */
import type {
  ChainFamily,
  ChainId,
  PublicKey,
  Signature,
  SignRequest,
  TxIntent,
} from '@stackwallet/core-client';

import type { z } from 'zod';

import { chainsForFamily } from './catalog.js';
import { NotImplementedError, UnknownChainError } from './errors.js';
import { readHistory } from './history.js';
import type { HistoryOptions } from './indexed-history.js';
import {
  HttpError,
  MemoryRpcPool,
  fetchJson,
  fetchJsonRpc,
  hasHealthTracking,
  type CrossChecked,
  type FetchOptions,
} from './rpc.js';
import type {
  Address,
  ChainAdapter,
  ChainInfo,
  Holding,
  HoldingProvenance,
  Page,
  RpcPool,
  SignedTx,
  Simulation,
  TxHash,
  TxRecord,
  TxStatus,
  UnsignedTx,
} from './types.js';

export interface BaseAdapterOptions {
  rpc?: RpcPool;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/** Phase in which each family's signing path lands; quoted in `NotImplementedError`. */
const SIGNING_PHASE: Record<ChainFamily, string> = {
  evm: 'phase 3',
  bitcoin: 'phase 4',
  solana: 'phase 4',
  cosmos: 'phase 4',
};

export abstract class BaseAdapter<F extends ChainFamily = ChainFamily> implements ChainAdapter {
  readonly rpc: RpcPool;
  protected readonly fetchImpl: typeof fetch | undefined;
  protected readonly timeoutMs: number | undefined;
  private readonly verified = new Map<string, number>();
  private readonly verifying = new Map<string, Promise<void>>();

  protected async verifyEndpoint(
    chainId: ChainId,
    url: string,
    check: () => Promise<void>,
  ): Promise<void> {
    const key = JSON.stringify([chainId, url]);
    const verifiedAt = this.verified.get(key);
    if (verifiedAt !== undefined && Date.now() >= verifiedAt && Date.now() - verifiedAt < 60_000)
      return;
    let pending = this.verifying.get(key);
    if (!pending) {
      pending = check()
        .then(() => {
          if (this.verified.size >= 256) this.verified.clear();
          this.verified.set(key, Date.now());
        })
        .finally(() => {
          this.verifying.delete(key);
        });
      this.verifying.set(key, pending);
    }
    await pending;
  }

  protected constructor(
    readonly family: F,
    opts: BaseAdapterOptions = {},
  ) {
    this.rpc = opts.rpc ?? new MemoryRpcPool(chainsForFamily(family));
    this.fetchImpl = opts.fetch;
    this.timeoutMs = opts.timeoutMs;
  }

  chains(): ChainInfo[] {
    return chainsForFamily(this.family);
  }

  protected requireChain(chainId: ChainId): ChainInfo {
    const c = this.chains().find((x) => x.chainId === chainId);
    if (!c) throw new UnknownChainError(chainId);
    return c;
  }

  protected fetchOptions(): FetchOptions {
    return {
      ...(this.fetchImpl ? { fetch: this.fetchImpl } : {}),
      ...(this.timeoutMs !== undefined ? { timeoutMs: this.timeoutMs } : {}),
    };
  }

  /** Forwards a head block to the pool when it tracks one; a no-op otherwise. */
  protected noteBlock(url: string, block: number): void {
    if (hasHealthTracking(this.rpc)) this.rpc.markBlock?.(url, block);
  }

  /**
   * One JSON-RPC call bound to an endpoint url, for `withFailover` and
   * `withCrossCheck`. Schema validation runs inside so a node returning
   * garbage is skipped like a dead one.
   */
  protected jsonRpc<T>(
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): (url: string) => Promise<T> {
    const opts = this.fetchOptions();
    return async (url) => schema.parse(await fetchJsonRpc(url, method, params, opts));
  }

  /**
   * One REST GET of `path` under an endpoint base url. Schema validation runs
   * inside so a node returning garbage is skipped like a dead one, while a
   * status in `notFoundStatuses` is a real answer ("not indexed here") and
   * yields null rather than demoting the endpoint.
   */
  protected rest<T>(
    path: string,
    schema: z.ZodType<T>,
    notFoundStatuses: readonly number[],
  ): (url: string) => Promise<T | null> {
    const opts = this.fetchOptions();
    return async (base) => {
      try {
        return schema.parse(await fetchJson(`${base.replace(/\/$/, '')}${path}`, opts));
      } catch (error) {
        if (error instanceof HttpError && notFoundStatuses.includes(error.status)) return null;
        throw error;
      }
    };
  }

  protected notImplemented(capability: string): NotImplementedError {
    return new NotImplementedError(
      `chains-${this.family}.${capability}`,
      SIGNING_PHASE[this.family],
    );
  }

  abstract deriveAddress(pub: PublicKey, chainId: ChainId): Address;
  abstract validateAddress(addr: string, chainId: ChainId): boolean;
  abstract getBalances(addr: Address, chainId: ChainId): Promise<Holding[]>;
  abstract status(hash: TxHash, chainId: ChainId): Promise<TxStatus>;

  getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!this.validateAddress(addr, chainId))
      return Promise.reject(new Error('Invalid history address'));
    return readHistory(
      chain,
      addr,
      this.rpc,
      { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) },
      cursor,
      options,
    );
  }

  build(_intent: TxIntent, _chainId: ChainId): Promise<UnsignedTx> {
    return Promise.reject(this.notImplemented('build'));
  }

  simulate(_tx: UnsignedTx): Promise<Simulation> {
    return Promise.reject(this.notImplemented('simulate'));
  }

  sighashes(_tx: UnsignedTx): SignRequest[] {
    throw this.notImplemented('sighashes');
  }

  attach(_tx: UnsignedTx, _sigs: Signature[]): SignedTx {
    throw this.notImplemented('attach');
  }

  broadcast(_tx: SignedTx): Promise<TxHash> {
    return Promise.reject(this.notImplemented('broadcast'));
  }
}

/**
 * A REST endpoint that has not indexed an address answers "not found", which
 * the adapters surface as `null`. When exactly one of two cross-checked
 * answers is null the pair did not disagree about the balance; that side had
 * no opinion, so the other stands alone as `single` instead of a dispute.
 */
export function preferIndexedSide<T>(res: CrossChecked<T | null>): CrossChecked<T | null> {
  if (res.provenance.kind !== 'disagreed') return res;
  const [keptUrl, otherUrl] = res.provenance.endpoints;
  if (res.value === null && res.other !== null && res.other !== undefined) {
    return { value: res.other, provenance: { kind: 'single', endpoint: otherUrl } };
  }
  if (res.value !== null && res.other === null) {
    return { value: res.value, provenance: { kind: 'single', endpoint: keptUrl } };
  }
  return res;
}

/** Builds a native holding with the provenance a cross-check reported. */
export function nativeHolding(
  chain: ChainInfo,
  amount: string,
  provenance: HoldingProvenance,
  updatedAtMs = Date.now(),
): Holding {
  return { assetRef: chain.nativeAsset.ref, amount, updatedAtMs, provenance };
}
