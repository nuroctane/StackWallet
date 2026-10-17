import type { ChainId } from '@stackwallet/core-client';
import { z } from 'zod';

import { CHAIN_CATALOG, catalogChain } from './catalog.js';
import type { ChainInfo, HoldingProvenance, RpcEndpoint, RpcPool } from './types.js';

export interface HealthTrackingRpcPool extends RpcPool {
  pick(chainId: ChainId, exclude?: Iterable<string>): RpcEndpoint | undefined;
  markHealthy(url: string, latencyMs: number): void;
  markFailed(url: string): void;
  /** Records the chain head an endpoint reported; optional because older pools predate it. */
  markBlock?(url: string, block: number): void;
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
 * In-memory endpoint pool. Selection prefers healthy endpoints, then the
 * lowest rolling error rate, then the lowest measured latency, and
 * round-robins among ties so unmeasured endpoints share load until data
 * separates them. When every endpoint has failed the pool still returns the
 * least recently failed one: a chain with flaky endpoints must stay reachable
 * rather than go silent.
 */
export class MemoryRpcPool implements HealthTrackingRpcPool {
  static readonly RETRY_AFTER_MS = 60_000;
  /** Attempts remembered per endpoint for the rolling error rate. */
  static readonly HISTORY = 10;

  private readonly byChain = new Map<ChainId, RpcEndpoint[]>();
  private readonly cursor = new Map<ChainId, number>();
  /** Catalog (or seed) defaults per chain; anything else a user sets is `custom`. */
  private readonly defaults = new Map<ChainId, readonly string[]>();
  private readonly history = new WeakMap<RpcEndpoint, boolean[]>();

  constructor(
    seed: readonly ChainInfo[] = [],
    private readonly now: () => number = () => Date.now(),
  ) {
    for (const chain of seed) {
      this.defaults.set(chain.chainId, [...chain.defaultRpcs]);
      this.setEndpoints(chain.chainId, chain.defaultRpcs);
    }
  }

  static fromCatalog(): MemoryRpcPool {
    return new MemoryRpcPool(CHAIN_CATALOG);
  }

  allChainIds(): ChainId[] {
    return [...this.byChain.keys()];
  }

  endpoints(chainId: ChainId): RpcEndpoint[] {
    return (this.byChain.get(chainId) ?? []).map((e) => ({ ...e }));
  }

  /**
   * Replaces the list for a chain. Endpoints that survive the edit keep their
   * health history so adding one url does not reset what is known about the rest.
   */
  setEndpoints(chainId: ChainId, urls: string[]): void {
    const previous = new Map((this.byChain.get(chainId) ?? []).map((e) => [e.url, e]));
    const defaults = new Set(this.defaultsFor(chainId));
    const next: RpcEndpoint[] = [];
    for (const url of new Set(urls)) {
      const kept = previous.get(url);
      const e: RpcEndpoint = kept ?? { url, healthy: true };
      if (defaults.has(url)) delete e.custom;
      else e.custom = true;
      next.push(e);
    }
    this.byChain.set(chainId, next);
    this.cursor.set(chainId, 0);
  }

  /** Restores the catalog (or seed) defaults for a chain, discarding user edits. */
  resetEndpoints(chainId: ChainId): void {
    this.setEndpoints(chainId, [...this.defaultsFor(chainId)]);
  }

  markHealthy(url: string, latencyMs: number): void {
    for (const e of this.find(url)) {
      e.healthy = true;
      e.latencyMs = latencyMs;
      this.record(e, true);
    }
  }

  markFailed(url: string): void {
    const at = this.now();
    for (const e of this.find(url)) {
      e.healthy = false;
      e.lastErrorAtMs = at;
      this.record(e, false);
    }
  }

  markBlock(url: string, block: number): void {
    if (!Number.isSafeInteger(block) || block < 0) return;
    for (const e of this.find(url)) e.lastBlock = block;
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

    // Unmeasured endpoints rank as error-free and infinitely slow: they lose to
    // anything measured but still get picked (round-robin) when nothing is.
    const rank = (e: RpcEndpoint): [number, number] => [
      e.errorRate ?? 0,
      e.latencyMs ?? Number.POSITIVE_INFINITY,
    ];
    let ties: RpcEndpoint[] = [];
    let best: [number, number] | undefined;
    for (const e of healthy) {
      const r = rank(e);
      const cmp =
        best === undefined ? -1 : compareNumbers(r[0], best[0]) || compareNumbers(r[1], best[1]);
      if (cmp < 0) {
        best = r;
        ties = [e];
      } else if (cmp === 0) {
        ties.push(e);
      }
    }
    const i = this.cursor.get(chainId) ?? 0;
    this.cursor.set(chainId, i + 1);
    return { ...ties[i % ties.length]! };
  }

  private defaultsFor(chainId: ChainId): readonly string[] {
    return this.defaults.get(chainId) ?? catalogChain(chainId)?.defaultRpcs ?? [];
  }

  private record(e: RpcEndpoint, ok: boolean): void {
    const ring = this.history.get(e) ?? [];
    ring.push(ok);
    if (ring.length > MemoryRpcPool.HISTORY) ring.splice(0, ring.length - MemoryRpcPool.HISTORY);
    this.history.set(e, ring);
    e.errorRate = ring.filter((x) => !x).length / ring.length;
  }

  private *find(url: string): Iterable<RpcEndpoint> {
    for (const list of this.byChain.values()) {
      for (const e of list) if (e.url === url) yield e;
    }
  }
}

/** Total order that treats equal infinities as ties, unlike subtraction. */
function compareNumbers(a: number, b: number): number {
  return a === b ? 0 : a < b ? -1 : 1;
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

interface Attempt<T> {
  url: string;
  value: T;
  latencyMs: number;
}

/** One request against one endpoint with the pool bookkeeping failover does. */
async function attempt<T>(
  tracking: HealthTrackingRpcPool | undefined,
  url: string,
  fn: (url: string) => Promise<T>,
  signal: AbortSignal | undefined,
): Promise<Attempt<T>> {
  const started = Date.now();
  try {
    const value = await fn(url);
    const latencyMs = Date.now() - started;
    tracking?.markHealthy(url, latencyMs);
    return { url, value, latencyMs };
  } catch (error) {
    if (!signal?.aborted) tracking?.markFailed(url);
    throw error;
  }
}

async function failover<T>(
  pool: RpcPool,
  chainId: ChainId,
  fn: (url: string) => Promise<T>,
  opts: FailoverOptions,
  tried: Set<string>,
  causes: { url: string; error: unknown }[],
): Promise<Attempt<T>> {
  const tracking = hasHealthTracking(pool) ? pool : undefined;
  const ordered = pool.endpoints(chainId).map((e) => e.url);
  if (ordered.length === 0) throw new NoRpcEndpointsError(chainId);

  const limit = Math.min(opts.maxAttempts ?? ordered.length, ordered.length);
  while (tried.size < limit) {
    const url = tracking ? tracking.pick(chainId, tried)?.url : ordered.find((u) => !tried.has(u));
    if (url === undefined) break;
    tried.add(url);
    try {
      return await attempt(tracking, url, fn, opts.signal);
    } catch (error) {
      if (opts.signal?.aborted) throw error;
      causes.push({ url, error });
    }
  }
  throw new RpcFailoverError(chainId, causes);
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
  return (await failover(pool, chainId, fn, opts, new Set(), [])).value;
}

export interface CrossCheckOptions<T> {
  /** Semantic equality of two answers; `===` on decimal strings is usually right. */
  equal: (a: T, b: T) => boolean;
  /** Turns a disagreeing answer into the `other` value recorded on the provenance. */
  describe?: (other: T) => string;
  signal?: AbortSignal;
}

export interface CrossChecked<T> {
  value: T;
  provenance: HoldingProvenance;
  /** The losing answer when the endpoints disagreed, for callers that need more than a string. */
  other?: T;
}

/**
 * Registrable domain (last two labels) rather than the full hostname: two
 * sub-hosts of one operator share an upstream and an incentive, so they do
 * not count as independent witnesses. Public-suffix lists are not consulted;
 * `co.uk`-style suffixes merely make the check stricter, never looser.
 */
export function operatorOf(url: string): string {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return url;
  }
  const labels = host.split('.');
  return labels.length <= 2 ? host : labels.slice(-2).join('.');
}

/**
 * Asks two endpoints run by different operators the same question so a single
 * lying or lagging node cannot pass off a wrong answer as the truth. Both
 * requests run in parallel with the same health bookkeeping as `withFailover`.
 * When only one endpoint is usable, or the second one fails, the answer is
 * reported as `single`. When both answer but differ, a catalog default beats
 * a user-added endpoint (a hostile custom url must not win just by being
 * fast); between two of the same kind the faster answer wins. The other value
 * is recorded, and neither endpoint is marked failed because a head one block
 * behind is normal, not malicious.
 */
export async function withCrossCheck<T>(
  pool: RpcPool,
  chainId: ChainId,
  fn: (url: string) => Promise<T>,
  opts: CrossCheckOptions<T>,
): Promise<CrossChecked<T>> {
  const tracking = hasHealthTracking(pool) ? pool : undefined;
  const all = pool.endpoints(chainId);
  if (all.length === 0) throw new NoRpcEndpointsError(chainId);
  const failoverOpts: FailoverOptions = opts.signal ? { signal: opts.signal } : {};

  const single = async (tried: Set<string>, causes: { url: string; error: unknown }[]) => {
    const a = await failover(pool, chainId, fn, failoverOpts, tried, causes);
    return { value: a.value, provenance: { kind: 'single', endpoint: a.url } as const };
  };
  if (all.length < 2) return single(new Set(), []);

  const first = tracking ? tracking.pick(chainId) : all[0];
  if (!first) return single(new Set(), []);
  const sameOperator = all
    .filter((e) => operatorOf(e.url) === operatorOf(first.url))
    .map((e) => e.url);
  const second = tracking
    ? tracking.pick(chainId, sameOperator)
    : all.find((e) => !sameOperator.includes(e.url));
  if (!second) return single(new Set(), []);
  const isCustom = new Map(all.map((e) => [e.url, e.custom === true]));

  const [a, b] = await Promise.allSettled([
    attempt(tracking, first.url, fn, opts.signal),
    attempt(tracking, second.url, fn, opts.signal),
  ]);
  if (opts.signal?.aborted) {
    throw a.status === 'rejected'
      ? a.reason
      : b.status === 'rejected'
        ? b.reason
        : opts.signal.reason;
  }

  if (a.status === 'fulfilled' && b.status === 'fulfilled') {
    const aCustom = isCustom.get(a.value.url) ?? false;
    const bCustom = isCustom.get(b.value.url) ?? false;
    const preferA =
      aCustom === bCustom ? a.value.latencyMs <= b.value.latencyMs : bCustom && !aCustom;
    const [keep, other] = preferA ? [a.value, b.value] : [b.value, a.value];
    if (opts.equal(a.value.value, b.value.value)) {
      return {
        value: keep.value,
        provenance: { kind: 'agreed', endpoints: [keep.url, other.url] },
      };
    }
    const describe = opts.describe ?? ((v: T) => String(v));
    return {
      value: keep.value,
      other: other.value,
      provenance: {
        kind: 'disagreed',
        endpoints: [keep.url, other.url],
        other: describe(other.value),
      },
    };
  }
  if (a.status === 'fulfilled') {
    return { value: a.value.value, provenance: { kind: 'single', endpoint: a.value.url } };
  }
  if (b.status === 'fulfilled') {
    return { value: b.value.value, provenance: { kind: 'single', endpoint: b.value.url } };
  }
  return single(new Set([first.url, second.url]), [
    { url: first.url, error: a.reason },
    { url: second.url, error: b.reason },
  ]);
}

export interface FetchOptions {
  /** Larger indexed pages may opt in; never above 8 MiB. */
  maxBodyBytes?: number;
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
async function fetchJsonBody(
  url: string,
  init: RequestInit,
  opts: FetchOptions,
  rawText = false,
): Promise<unknown> {
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
    const limit = opts.maxBodyBytes ?? MAX_BODY_BYTES;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 8 * MAX_BODY_BYTES)
      throw new Error('Invalid response body limit');
    const text = await readBody(url, res, limit);
    if (!res.ok) throw new HttpError(url, res.status, text.slice(0, 512));
    if (rawText) return text;
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

async function readBody(url: string, res: Response, limit: number): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > limit) {
    await res.body?.cancel();
    throw new MalformedResponseError(url, 'body too large');
  }
  if (!res.body) return res.text();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
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

/**
 * POST a JSON body and return the raw response text, for REST APIs whose
 * integers can exceed 2^53 and must be read before `JSON.parse` rounds them.
 */
export async function postJsonText(
  url: string,
  body: unknown,
  opts: FetchOptions = {},
): Promise<string> {
  return (await fetchJsonBody(
    url,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
    },
    opts,
    true,
  )) as string;
}

/** Bounded Esplora text reads and raw-transaction broadcasts share the JSON timeout. */
export async function fetchText(
  url: string,
  opts: FetchOptions = {},
  body?: string,
): Promise<string> {
  return (await fetchJsonBody(
    url,
    {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        accept: 'text/plain',
        ...(body === undefined ? {} : { 'Content-Type': 'text/plain' }),
      },
      ...(body === undefined ? {} : { body }),
    },
    opts,
    true,
  )) as string;
}

export interface JsonRpcBatchResult {
  ok: boolean;
  result?: unknown;
  error?: JsonRpcError;
}

/**
 * POST a JSON-RPC 2.0 batch and return one slot per call, in call order. A
 * call whose method reverts (an unset Chainlink round, an empty storage slot)
 * comes back as `ok: false` instead of failing the batch; only a transport or
 * envelope-level failure throws. Batches beyond this size are rejected so a
 * caller cannot exceed the body limit by accident.
 */
export const MAX_JSONRPC_BATCH = 400;

export async function fetchJsonRpcBatch(
  url: string,
  calls: readonly { method: string; params?: unknown[] }[],
  opts: FetchOptions = {},
): Promise<JsonRpcBatchResult[]> {
  if (calls.length === 0) return [];
  if (calls.length > MAX_JSONRPC_BATCH)
    throw new Error(`batch of ${calls.length} exceeds ${MAX_JSONRPC_BATCH}`);
  const raw = await fetchJsonBody(
    url,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(
        calls.map((c, i) => ({
          jsonrpc: '2.0',
          id: i + 1,
          method: c.method,
          params: c.params ?? [],
        })),
      ),
    },
    opts,
  );
  if (!Array.isArray(raw)) throw new MalformedResponseError(url, 'batch answer is not an array');
  const byId = new Map<number, z.infer<typeof JsonRpcEnvelope>>();
  for (const entry of raw) {
    const parsed = JsonRpcEnvelope.safeParse(entry);
    if (!parsed.success) throw new MalformedResponseError(url, 'batch entry is not an envelope');
    const id = typeof parsed.data.id === 'number' ? parsed.data.id : NaN;
    if (!Number.isInteger(id) || id < 1 || id > calls.length || byId.has(id)) {
      throw new MalformedResponseError(url, 'batch entry has a bad id');
    }
    byId.set(id, parsed.data);
  }
  return calls.map((_, i) => {
    const entry = byId.get(i + 1);
    if (!entry) throw new MalformedResponseError(url, `batch answer misses id ${i + 1}`);
    if (entry.error) {
      const { code, message, data } = entry.error;
      return { ok: false, error: new JsonRpcError(url, code, message, data) };
    }
    return { ok: true, result: entry.result };
  });
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
