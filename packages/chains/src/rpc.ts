import type { ChainId } from '@stackwallet/core-client';
import { z } from 'zod';

import { CHAIN_CATALOG } from './catalog.js';
import type { ChainInfo, RpcEndpoint, RpcPool } from './types.js';

export interface HealthTrackingRpcPool extends RpcPool {
  pick(chainId: ChainId, exclude?: Iterable<string>): RpcEndpoint | undefined;
  markHealthy(url: string, latencyMs: number): void;
  markFailed(url: string): void;
}

export function hasHealthTracking(pool: RpcPool): pool is HealthTrackingRpcPool {
  const p = pool as Partial<HealthTrackingRpcPool>;
  return (
    typeof p.pick === 'function' &&
    typeof p.markHealthy === 'function' &&
    typeof p.markFailed === 'function'
  );
}

/**
 * In-memory endpoint pool. Selection prefers healthy endpoints with the lowest
 * measured latency and round-robins among ties so unmeasured endpoints share
 * load until latency data separates them. When every endpoint has failed the
 * pool still returns the least recently failed one: a chain with flaky
 * endpoints must stay reachable rather than go silent.
 */
export class MemoryRpcPool implements HealthTrackingRpcPool {
  static readonly RETRY_AFTER_MS = 60_000;

  private readonly byChain = new Map<ChainId, RpcEndpoint[]>();
  private readonly cursor = new Map<ChainId, number>();

  constructor(
    seed: readonly ChainInfo[] = [],
    private readonly now: () => number = () => Date.now(),
  ) {
    for (const chain of seed) this.setEndpoints(chain.chainId, chain.defaultRpcs);
  }

  static fromCatalog(): MemoryRpcPool {
    return new MemoryRpcPool(CHAIN_CATALOG);
  }

  endpoints(chainId: ChainId): RpcEndpoint[] {
    return (this.byChain.get(chainId) ?? []).map((e) => ({ ...e }));
  }

  setEndpoints(chainId: ChainId, urls: string[]): void {
    const unique = [...new Set(urls)];
    this.byChain.set(
      chainId,
      unique.map((url) => ({ url, healthy: true })),
    );
    this.cursor.set(chainId, 0);
  }

  markHealthy(url: string, latencyMs: number): void {
    for (const e of this.find(url)) {
      e.healthy = true;
      e.latencyMs = latencyMs;
    }
  }

  markFailed(url: string): void {
    const at = this.now();
    for (const e of this.find(url)) {
      e.healthy = false;
      e.lastErrorAtMs = at;
    }
  }

  pick(chainId: ChainId, exclude: Iterable<string> = []): RpcEndpoint | undefined {
    const skip = new Set(exclude);
    const all = (this.byChain.get(chainId) ?? []).filter((e) => !skip.has(e.url));
    if (all.length === 0) return undefined;

    // A failed endpoint becomes eligible again after a cooldown so one timeout
    // does not bench it for the rest of the session.
    const at = this.now();
    const healthy = all.filter(
      (e) => e.healthy || at - (e.lastErrorAtMs ?? 0) >= MemoryRpcPool.RETRY_AFTER_MS,
    );
    if (healthy.length === 0) {
      const sorted = [...all].sort((a, b) => (a.lastErrorAtMs ?? 0) - (b.lastErrorAtMs ?? 0));
      return { ...sorted[0]! };
    }

    const best = Math.min(...healthy.map((e) => e.latencyMs ?? Number.POSITIVE_INFINITY));
    const ties = healthy.filter((e) => (e.latencyMs ?? Number.POSITIVE_INFINITY) === best);
    const i = this.cursor.get(chainId) ?? 0;
    this.cursor.set(chainId, i + 1);
    return { ...ties[i % ties.length]! };
  }

  private *find(url: string): Iterable<RpcEndpoint> {
    for (const list of this.byChain.values()) {
      for (const e of list) if (e.url === url) yield e;
    }
  }
}

export class NoRpcEndpointsError extends Error {
  override readonly name = 'NoRpcEndpointsError';

  constructor(readonly chainId: ChainId) {
    super(`no rpc endpoints configured for ${chainId}`);
  }
}

export class RpcFailoverError extends Error {
  override readonly name = 'RpcFailoverError';

  constructor(
    readonly chainId: ChainId,
    readonly causes: { url: string; error: unknown }[],
  ) {
    super(
      `all ${causes.length} rpc endpoint(s) for ${chainId} failed: ` +
        causes.map((c) => `${c.url} (${describe(c.error)})`).join('; '),
    );
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

export interface FailoverOptions {
  /** Upper bound on distinct endpoints tried. Defaults to every endpoint. */
  maxAttempts?: number;
  /** Caller cancellation; an abort stops failover instead of trying the next endpoint. */
  signal?: AbortSignal;
}

/**
 * Runs `fn` against endpoints for `chainId` until one succeeds. Only thrown
 * errors count against an endpoint: `fn` must turn semantic responses such as
 * "transaction not found" into values, not exceptions.
 */
export async function withFailover<T>(
  pool: RpcPool,
  chainId: ChainId,
  fn: (url: string) => Promise<T>,
  opts: FailoverOptions = {},
): Promise<T> {
  const tracking = hasHealthTracking(pool) ? pool : undefined;
  const ordered = pool.endpoints(chainId).map((e) => e.url);
  if (ordered.length === 0) throw new NoRpcEndpointsError(chainId);

  const limit = Math.min(opts.maxAttempts ?? ordered.length, ordered.length);
  const tried = new Set<string>();
  const causes: { url: string; error: unknown }[] = [];

  while (tried.size < limit) {
    const url = tracking ? tracking.pick(chainId, tried)?.url : ordered.find((u) => !tried.has(u));
    if (url === undefined) break;
    tried.add(url);

    const started = Date.now();
    try {
      const value = await fn(url);
      tracking?.markHealthy(url, Date.now() - started);
      return value;
    } catch (error) {
      if (opts.signal?.aborted) throw error;
      tracking?.markFailed(url);
      causes.push({ url, error });
    }
  }
  throw new RpcFailoverError(chainId, causes);
}

export interface FetchOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export const DEFAULT_TIMEOUT_MS = 8000;

export class HttpError extends Error {
  override readonly name = 'HttpError';

  constructor(
    readonly url: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(`HTTP ${status} from ${url}`);
  }
}

export class RpcTimeoutError extends Error {
  override readonly name = 'RpcTimeoutError';

  constructor(
    readonly url: string,
    readonly timeoutMs: number,
  ) {
    super(`request to ${url} timed out after ${timeoutMs}ms`);
  }
}

export class JsonRpcError extends Error {
  override readonly name = 'JsonRpcError';

  constructor(
    readonly url: string,
    readonly code: number,
    message: string,
    readonly data?: unknown,
  ) {
    super(`json-rpc error ${code} from ${url}: ${message}`);
  }
}

export class MalformedResponseError extends Error {
  override readonly name = 'MalformedResponseError';

  constructor(
    readonly url: string,
    detail: string,
  ) {
    super(`malformed response from ${url}: ${detail}`);
  }
}

const JsonRpcEnvelope = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
  result: z.unknown().optional(),
  error: z
    .object({
      code: z.number().int(),
      message: z.string().transform((m) => m.slice(0, 512)),
      data: z.unknown().optional(),
    })
    .optional(),
});

/** Largest response body accepted from any endpoint. Balances and receipts are tiny. */
export const MAX_BODY_BYTES = 1 << 20;

/**
 * Fetch and read the whole body under one timeout. The timer must outlive the
 * headers: an endpoint that answers quickly and then trickles the body would
 * otherwise hold the request (and the failover loop) open forever.
 */
async function fetchJsonBody(url: string, init: RequestInit, opts: FetchOptions): Promise<unknown> {
  const doFetch = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const onAbort = () => controller.abort(opts.signal?.reason);
  if (opts.signal?.aborted) onAbort();
  else opts.signal?.addEventListener('abort', onAbort, { once: true });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new RpcTimeoutError(url, timeoutMs));
  }, timeoutMs);
  try {
    const res = await doFetch(url, { ...init, signal: controller.signal });
    const text = await readBody(url, res);
    if (!res.ok) throw new HttpError(url, res.status, text.slice(0, 512));
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new MalformedResponseError(url, 'body is not JSON');
    }
  } catch (error) {
    if (timedOut) throw new RpcTimeoutError(url, timeoutMs);
    throw error;
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener('abort', onAbort);
  }
}

async function readBody(url: string, res: Response): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw new MalformedResponseError(url, 'body too large');
  if (!res.body) return res.text();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new MalformedResponseError(url, 'body too large');
    }
    chunks.push(value);
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    joined.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(joined);
}

/** GET a JSON document. The caller validates the shape with zod. */
export async function fetchJson(url: string, opts: FetchOptions = {}): Promise<unknown> {
  return fetchJsonBody(url, { method: 'GET', headers: { accept: 'application/json' } }, opts);
}

/** POST a JSON-RPC 2.0 call and return `result`. The caller validates the shape with zod. */
export async function fetchJsonRpc(
  url: string,
  method: string,
  params: unknown[] | Record<string, unknown> = [],
  opts: FetchOptions = {},
): Promise<unknown> {
  const raw = await fetchJsonBody(
    url,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    },
    opts,
  );
  const parsed = JsonRpcEnvelope.safeParse(raw);
  if (!parsed.success) throw new MalformedResponseError(url, 'not a JSON-RPC 2.0 envelope');
  if (parsed.data.error) {
    const { code, message, data } = parsed.data.error;
    throw new JsonRpcError(url, code, message, data);
  }
  if (typeof raw !== 'object' || raw === null || !('result' in raw)) {
    throw new MalformedResponseError(url, 'envelope has neither result nor error');
  }
  return parsed.data.result;
}
