import { useSyncExternalStore } from 'react';
import {
  HistoryPage,
  HISTORY_INDEXERS,
  type ChainInfo,
  type ChainRegistry,
  type Page,
  type TxRecord,
} from '@stackwallet/chains';
import type { ProvenanceTable } from '@stackwallet/core-client';
import { coinIdFor, RateLimitedError } from '@stackwallet/market';
import {
  EMPTY_SCOPE,
  EventOverride,
  fetchPriceSeries,
  FIATS,
  jurisdiction,
  Overrides,
  SCOPE_TAGS,
  taxYearOf,
  tokenPriceKey,
  walletTagsOf,
  type AccountHistory,
  type AssetInfo,
  type Fiat,
  type PricePoint,
  type ScopeAccount,
  type ScopeFilter,
  type ScopeFolder,
  type ScopeTag,
  type ScopeWallet,
  type TaxSettings,
} from '@stackwallet/tax';
import { z } from 'zod';

import { marketClient } from './market.js';
import type { StorageLike } from './persist.js';
import type { DirectoryState } from './schema.js';
import { KNOWN_TOKENS } from './taxTokens.js';
import { tokenStore } from './tokens.js';

/**
 * Tax reports are computed on this device from public chain history and
 * public daily prices. What persists is only the user's own choices (period,
 * method, scope) and their review decisions per transaction; chain history and
 * prices are re-read on demand and live in memory.
 */
export const TAX_PREFS_KEY = 'stackwallet.tax.v1';
export const TAX_OVERRIDES_KEY = 'stackwallet.tax.overrides.v1';
export const MAX_OVERRIDES = 20_000;
/** Pages per history stream; at 25–50 records a page this covers active accounts. */
export const MAX_HISTORY_PAGES = 40;
const SYNC_CONCURRENCY = 3;

const Settings = z.object({
  jurisdiction: z.string().regex(/^[a-z]{2,8}$/),
  method: z.enum(['fifo', 'lifo', 'hifo', 'acb']),
  fiat: z.enum(FIATS as unknown as [Fiat, ...Fiat[]]),
  pooling: z.enum(['wallet', 'universal']),
  fees: z.enum(['dispose', 'ignore']),
  year: z.number().int().min(2009).max(2200),
  includeTestnets: z.boolean(),
});

const Scope = z.object({
  tags: z.array(z.enum(SCOPE_TAGS)).max(SCOPE_TAGS.length),
  folderIds: z.array(z.string().max(200)).max(500),
  excluded: z.array(z.string().max(200)).max(5000),
});

export const TaxPrefs = z.object({ settings: Settings, scope: Scope });
export type TaxPrefs = z.infer<typeof TaxPrefs>;

export function defaultTaxPrefs(now = Date.now()): TaxPrefs {
  const j = jurisdiction('us');
  return {
    settings: {
      jurisdiction: j.id,
      method: j.method,
      fiat: j.fiat,
      pooling: 'wallet',
      fees: 'dispose',
      year: taxYearOf(j, now),
      includeTestnets: false,
    },
    scope: { ...EMPTY_SCOPE },
  };
}

function safeStorage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

function read<T>(storage: StorageLike | null, key: string, schema: z.ZodType<T>): T | null {
  try {
    const raw = storage?.getItem(key);
    if (!raw) return null;
    const parsed = schema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function write(storage: StorageLike | null, key: string, value: unknown): void {
  try {
    storage?.setItem(key, JSON.stringify(value));
  } catch {
    // Quota or private mode: the value lives for this session only.
  }
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

export interface StreamResult {
  records: TxRecord[];
  complete: boolean;
  sources: string[];
  error?: string;
}

/** Validation dumps are long JSON and mean nothing to the person filing. */
export function readError(e: unknown, fallback: string): string {
  if (e instanceof z.ZodError) return 'The indexer answered in a format this version cannot read.';
  return e instanceof Error ? e.message.slice(0, 300) : fallback;
}

/** Follows cursors until the stream ends, a page limit is hit, or a read fails. */
export async function readAllPages(
  readPage: (cursor: string | undefined) => Promise<Page<TxRecord>>,
  maxPages: number,
  signal?: AbortSignal,
): Promise<StreamResult> {
  const records: TxRecord[] = [];
  const sources = new Set<string>();
  let cursor: string | undefined;
  for (let i = 0; i < maxPages; i++) {
    try {
      signal?.throwIfAborted();
      const page = HistoryPage.parse(await readPage(cursor));
      records.push(...page.items);
      if (page.source) sources.add(page.source);
      if (!page.nextCursor) return { records, complete: true, sources: [...sources] };
      if (page.nextCursor === cursor) break;
      cursor = page.nextCursor;
    } catch (e) {
      if (signal?.aborted) throw e;
      return {
        records,
        complete: false,
        sources: [...sources],
        error: readError(e, 'History read failed'),
      };
    }
  }
  return {
    records,
    complete: false,
    sources: [...sources],
    error: `Stopped after ${maxPages} pages; older activity was not read.`,
  };
}

export interface SyncTarget {
  accountId: string;
  chainId: string;
  address: string;
}

/**
 * Everything public about one account. EVM chains need two indexer streams
 * (transactions for the native coin and fees, token-transfer events for
 * ERC-20s); without a keyless indexer only recent blocks are reachable over
 * RPC, and the history is marked incomplete rather than presented as whole.
 */
export async function readAccountHistory(
  registry: ChainRegistry,
  chain: ChainInfo,
  target: SyncTarget,
  signal?: AbortSignal,
): Promise<AccountHistory> {
  const adapter = registry.adapterFor(target.chainId);
  const read =
    (extra: { indexerUrl?: string; tokenTransfers?: boolean }) => (cursor: string | undefined) =>
      adapter.getHistory(target.address, target.chainId, cursor, {
        ...(signal ? { signal } : {}),
        ...extra,
      });
  if (chain.family === 'evm') {
    const indexer = HISTORY_INDEXERS[target.chainId];
    if (!indexer) {
      const recent = await readAllPages(read({}), 1, signal);
      return {
        accountId: target.accountId,
        records: recent.records,
        complete: false,
        sources: recent.sources,
        error: 'No keyless history indexer for this chain: only recent blocks were read over RPC.',
      };
    }
    const txs = await readAllPages(read({ indexerUrl: indexer }), MAX_HISTORY_PAGES, signal);
    const tokens = await readAllPages(
      read({ indexerUrl: indexer, tokenTransfers: true }),
      MAX_HISTORY_PAGES,
      signal,
    );
    const error = [txs.error, tokens.error].filter(Boolean).join(' · ');
    return {
      accountId: target.accountId,
      records: [...txs.records, ...tokens.records],
      complete: txs.complete && tokens.complete,
      sources: [...new Set([...txs.sources, ...tokens.sources])],
      ...(error ? { error } : {}),
    };
  }
  const all = await readAllPages(read({}), MAX_HISTORY_PAGES, signal);
  return {
    accountId: target.accountId,
    records: all.records,
    complete: all.complete,
    sources: all.sources,
    ...(all.error ? { error: all.error } : {}),
  };
}

// ---------------------------------------------------------------------------
// Assets and scope
// ---------------------------------------------------------------------------

function chainOf(registry: ChainRegistry, chainId: string): ChainInfo | undefined {
  try {
    return registry.chainInfo(chainId);
  } catch {
    return undefined;
  }
}

/** Symbol, decimals and price key of an asset ref, from trusted local sources only. */
export function assetInfoFor(registry: ChainRegistry, ref: string): AssetInfo {
  if (ref.endsWith(':native')) {
    const chain = chainOf(registry, ref.slice(0, -':native'.length));
    if (chain)
      return {
        ref,
        symbol: chain.nativeAsset.symbol,
        decimals: chain.nativeAsset.decimals,
        priceKey: coinIdFor(chain),
        testnet: chain.testnet,
      };
    return { ref, symbol: ref, decimals: null, priceKey: null, testnet: false };
  }
  const m = /^(.+):(erc20|spl):([^:]+)$/.exec(ref);
  if (!m)
    return {
      ref,
      symbol: ref.slice(ref.lastIndexOf(':') + 1, 12),
      decimals: null,
      priceKey: null,
      testnet: false,
    };
  const [, chainId = '', standard, contract = ''] = m;
  const chain = chainOf(registry, chainId);
  const testnet = chain?.testnet ?? false;
  const known = KNOWN_TOKENS[ref.toLowerCase()];
  if (known)
    return { ref, symbol: known.symbol, decimals: known.decimals, priceKey: known.coinId, testnet };
  const tracked = tokenStore.find(ref);
  // Untracked contracts are mostly airdropped spam, and without known decimals a price could
  // not value them anyway; asking about each would also tell the price API what this
  // address holds.
  const key =
    testnet || !tracked
      ? null
      : tokenPriceKey(chainId, standard === 'erc20' ? contract.toLowerCase() : contract);
  const short = `${contract.slice(0, 6)}…${contract.slice(-4)}`;
  return {
    ref,
    symbol: tracked?.symbol ?? short,
    decimals: tracked?.decimals ?? null,
    priceKey: key,
    testnet,
  };
}

export function scopeWallets(
  state: DirectoryState,
  provenance: ProvenanceTable,
): { wallets: ScopeWallet[]; folders: ScopeFolder[] } {
  const wallets = state.wallets.map((w) => {
    const p = provenance.wallets.find((x) => x.walletId === w.id);
    return {
      id: w.id,
      name: w.name,
      kind: w.kind,
      folderId: w.folderId,
      imported: p?.origin.kind === 'importedFromDevice' || p?.origin.kind === 'importedPhrase',
      exported: (p?.transfers.length ?? 0) > 0,
    };
  });
  const folders = state.folders.map((f) => {
    const s = provenance.sets.find((x) => x.folderId === f.id);
    return {
      id: f.id,
      parentId: f.parentId,
      name: f.name,
      imported: s?.origin.kind === 'importedFromDevice',
      exported: (s?.transfers.length ?? 0) > 0,
    };
  });
  return { wallets, folders };
}

export function tagsFor(wallet: ScopeWallet, folders: readonly ScopeFolder[]): ScopeTag[] {
  return [...walletTagsOf(wallet, new Map(folders.map((f) => [f.id, f])))];
}

function folderPath(state: DirectoryState, folderId: string): string {
  const names: string[] = [];
  const seen = new Set<string>();
  let cur = state.folders.find((f) => f.id === folderId);
  while (cur && cur.parentId !== null && !seen.has(cur.id)) {
    seen.add(cur.id);
    names.unshift(cur.name);
    const parent: string = cur.parentId;
    cur = state.folders.find((f) => f.id === parent);
  }
  return names.join(' / ');
}

export function scopeAccounts(
  state: DirectoryState,
  registry: ChainRegistry,
  walletIds: ReadonlySet<string>,
  includeTestnets: boolean,
): ScopeAccount[] {
  const out: ScopeAccount[] = [];
  for (const a of state.accounts) {
    if (!walletIds.has(a.walletId)) continue;
    const w = state.wallets.find((x) => x.id === a.walletId);
    const chain = chainOf(registry, a.chainId);
    if (!w || !chain) continue;
    if (chain.testnet && !includeTestnets) continue;
    out.push({
      accountId: a.id,
      walletId: w.id,
      walletName: w.name,
      walletKind: w.kind,
      folderPath: folderPath(state, w.folderId),
      chainId: a.chainId,
      chainName: chain.name,
      address: a.address,
      testnet: chain.testnet,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export interface SyncedHistory {
  /** Chain and address the history was read for; a changed account is re-read. */
  key: string;
  history: AccountHistory;
  syncedAtMs: number;
}

export interface TaxState {
  prefs: TaxPrefs;
  overrides: Overrides;
  histories: ReadonlyMap<string, SyncedHistory>;
  syncing: { done: number; total: number } | null;
  /** Daily series per `fiat|priceKey`. */
  prices: ReadonlyMap<string, readonly PricePoint[]>;
  priceErrors: ReadonlyMap<string, string>;
  pricing: { done: number; total: number } | null;
}

export const historyKey = (t: SyncTarget) => `${t.chainId}|${t.address}`;
export const priceBookKey = (fiat: Fiat, key: string) => `${fiat}|${key}`;

export class TaxStore {
  private state: TaxState;
  private listeners = new Set<() => void>();
  private sync: AbortController | null = null;
  private priceRun = 0;

  constructor(
    private readonly storage: StorageLike | null,
    private readonly fetchSeries: (key: string, fiat: Fiat) => Promise<PricePoint[]> = (k, f) =>
      fetchPriceSeries(marketClient, k, f),
  ) {
    this.state = {
      prefs: read(storage, TAX_PREFS_KEY, TaxPrefs) ?? defaultTaxPrefs(),
      overrides: read(storage, TAX_OVERRIDES_KEY, Overrides) ?? {},
      histories: new Map(),
      syncing: null,
      prices: new Map(),
      priceErrors: new Map(),
      pricing: null,
    };
  }

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  getSnapshot = () => this.state;

  private set(patch: Partial<TaxState>): void {
    this.state = { ...this.state, ...patch };
    for (const l of this.listeners) l();
  }

  setSettings(patch: Partial<TaxSettings>): void {
    const prefs = TaxPrefs.parse({
      ...this.state.prefs,
      settings: { ...this.state.prefs.settings, ...patch },
    });
    write(this.storage, TAX_PREFS_KEY, prefs);
    this.set({ prefs });
  }

  setScope(patch: Partial<ScopeFilter>): void {
    const prefs = TaxPrefs.parse({
      ...this.state.prefs,
      scope: { ...this.state.prefs.scope, ...patch },
    });
    write(this.storage, TAX_PREFS_KEY, prefs);
    this.set({ prefs });
  }

  /** Merge a decision into one event; an emptied decision is removed. */
  review(eventId: string, patch: Partial<EventOverride> | null): void {
    const next = { ...this.state.overrides };
    if (patch === null) delete next[eventId];
    else {
      const merged: Record<string, unknown> = { ...next[eventId], ...patch };
      for (const k of Object.keys(merged))
        if (merged[k] === undefined || merged[k] === '') delete merged[k];
      if (Object.keys(merged).length === 0) delete next[eventId];
      else next[eventId] = EventOverride.parse(merged);
    }
    if (Object.keys(next).length > MAX_OVERRIDES) throw new Error('Too many review decisions');
    write(this.storage, TAX_OVERRIDES_KEY, next);
    this.set({ overrides: next });
  }

  reviewMany(entries: readonly (readonly [string, Partial<EventOverride>])[]): void {
    const next = { ...this.state.overrides };
    for (const [id, patch] of entries) next[id] = EventOverride.parse({ ...next[id], ...patch });
    if (Object.keys(next).length > MAX_OVERRIDES) throw new Error('Too many review decisions');
    write(this.storage, TAX_OVERRIDES_KEY, next);
    this.set({ overrides: next });
  }

  /** Review decisions for backup or for another device; they hold no addresses or keys. */
  exportOverrides(): string {
    return JSON.stringify({ stackwalletTaxReview: 1, overrides: this.state.overrides });
  }

  importOverrides(text: string): number {
    const parsed = z
      .object({ stackwalletTaxReview: z.literal(1), overrides: Overrides })
      .parse(JSON.parse(text));
    const next = { ...this.state.overrides, ...parsed.overrides };
    if (Object.keys(next).length > MAX_OVERRIDES) throw new Error('Too many review decisions');
    write(this.storage, TAX_OVERRIDES_KEY, next);
    this.set({ overrides: next });
    return Object.keys(parsed.overrides).length;
  }

  cancelSync(): void {
    this.sync?.abort();
    this.sync = null;
    this.set({ syncing: null });
  }

  /** Reads public history for each target; fresh reads are skipped unless forced. */
  async syncHistories(
    registry: ChainRegistry,
    targets: readonly SyncTarget[],
    force = false,
  ): Promise<void> {
    this.sync?.abort();
    const controller = new AbortController();
    this.sync = controller;
    const todo = targets.filter((t) => {
      const have = this.state.histories.get(t.accountId);
      return force || !have || have.key !== historyKey(t);
    });
    if (todo.length === 0) {
      this.set({ syncing: null });
      return;
    }
    let done = 0;
    this.set({ syncing: { done, total: todo.length } });
    const queue = [...todo];
    const worker = async () => {
      for (let t = queue.shift(); t; t = queue.shift()) {
        const chain = chainOf(registry, t.chainId);
        let history: AccountHistory;
        try {
          history = chain
            ? await readAccountHistory(registry, chain, t, controller.signal)
            : {
                accountId: t.accountId,
                records: [],
                complete: false,
                sources: [],
                error: 'Unknown chain',
              };
        } catch (e) {
          if (controller.signal.aborted) return;
          history = {
            accountId: t.accountId,
            records: [],
            complete: false,
            sources: [],
            error: readError(e, 'History read failed'),
          };
        }
        if (controller.signal.aborted) return;
        const histories = new Map(this.state.histories);
        histories.set(t.accountId, { key: historyKey(t), history, syncedAtMs: Date.now() });
        done++;
        this.set({ histories, syncing: { done, total: todo.length } });
      }
    };
    await Promise.all(Array.from({ length: Math.min(SYNC_CONCURRENCY, todo.length) }, worker));
    if (this.sync === controller) {
      this.sync = null;
      this.set({ syncing: null });
    }
  }

  /**
   * Fetches daily series for price keys not yet held in this fiat. CoinGecko
   * is asked one coin at a time through the shared rate gate; a rate limit
   * waits out the pause once before the key is reported as failed.
   */
  async loadPrices(keys: readonly string[], fiat: Fiat): Promise<void> {
    const run = ++this.priceRun;
    const todo = [...new Set(keys)].filter((k) => !this.state.prices.has(priceBookKey(fiat, k)));
    if (todo.length === 0) return;
    let done = 0;
    this.set({ pricing: { done, total: todo.length } });
    for (const key of todo) {
      if (run !== this.priceRun) return;
      const bookKey = priceBookKey(fiat, key);
      try {
        let series: PricePoint[];
        try {
          series = await this.fetchSeries(key, fiat);
        } catch (e) {
          if (!(e instanceof RateLimitedError)) throw e;
          await new Promise((r) => setTimeout(r, Math.max(0, e.untilMs - Date.now()) + 500));
          series = await this.fetchSeries(key, fiat);
        }
        if (run !== this.priceRun) return;
        const prices = new Map(this.state.prices);
        prices.set(bookKey, series);
        const priceErrors = new Map(this.state.priceErrors);
        priceErrors.delete(bookKey);
        this.set({ prices, priceErrors });
      } catch (e) {
        if (run !== this.priceRun) return;
        const priceErrors = new Map(this.state.priceErrors);
        priceErrors.set(
          bookKey,
          e instanceof Error ? e.message.slice(0, 200) : 'Price read failed',
        );
        // An empty series stops the key being asked again this session.
        const prices = new Map(this.state.prices);
        prices.set(bookKey, []);
        this.set({ prices, priceErrors });
      }
      done++;
      this.set({ pricing: { done, total: todo.length } });
    }
    if (run === this.priceRun) this.set({ pricing: null });
  }

  retryPrices(): void {
    const prices = new Map(this.state.prices);
    for (const k of this.state.priceErrors.keys()) prices.delete(k);
    this.set({ prices, priceErrors: new Map() });
  }
}

export const taxStore = new TaxStore(safeStorage());

export function useTax(): TaxState {
  return useSyncExternalStore(taxStore.subscribe, taxStore.getSnapshot, taxStore.getSnapshot);
}
