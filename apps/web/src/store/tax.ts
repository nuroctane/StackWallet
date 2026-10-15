import { useSyncExternalStore } from 'react';
import {
  HistoryPage,
  HISTORY_INDEXERS,
  WITHDRAWAL_CHAINS,
  type ChainInfo,
  type ChainRegistry,
  type HistoryOptions,
  type IndexedStream,
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
const RETRY_DELAYS_MS = [1500, 4000];

/** One page, retried after a pause: public indexers time out and rate-limit under load. */
async function readPageWithRetry(
  readPage: (cursor: string | undefined) => Promise<Page<TxRecord>>,
  cursor: string | undefined,
  delays: readonly number[],
  signal?: AbortSignal,
): Promise<Page<TxRecord>> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await readPage(cursor);
    } catch (e) {
      // A malformed answer stays malformed; only transport failures are worth repeating.
      if (signal?.aborted || e instanceof z.ZodError || attempt >= delays.length) throw e;
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, delays[attempt]);
        signal?.addEventListener(
          'abort',
          () => {
            clearTimeout(t);
            reject(signal.reason);
          },
          { once: true },
        );
      });
    }
  }
}

export async function readAllPages(
  readPage: (cursor: string | undefined) => Promise<Page<TxRecord>>,
  maxPages: number,
  signal?: AbortSignal,
  retryDelaysMs: readonly number[] = RETRY_DELAYS_MS,
): Promise<StreamResult> {
  const records: TxRecord[] = [];
  const sources = new Set<string>();
  let cursor: string | undefined;
  for (let i = 0; i < maxPages; i++) {
    try {
      signal?.throwIfAborted();
      const page = HistoryPage.parse(
        await readPageWithRetry(readPage, cursor, retryDelaysMs, signal),
      );
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

/** Token accounts read per Solana wallet, and pages per token account. */
export const MAX_TOKEN_ACCOUNTS = 100;
export const TOKEN_ACCOUNT_PAGES = 10;

function combine(accountId: string, streams: readonly StreamResult[], extraError?: string) {
  const error = [...new Set([...streams.map((s) => s.error), extraError].filter(Boolean))].join(
    ' · ',
  );
  return {
    accountId,
    records: streams.flatMap((s) => s.records),
    complete: streams.every((s) => s.complete) && !extraError,
    sources: [...new Set(streams.flatMap((s) => s.sources))],
    ...(error ? { error } : {}),
  };
}

/**
 * Everything public about one account. EVM chains need several indexer
 * streams: external transactions (native value and fees), token transfers
 * (ERC-20 and NFTs), internal transfers (ETH paid out by contracts, and the
 * spending of contract wallets) and, on Ethereum, beacon withdrawals. Solana
 * token transfers name the wallet's token accounts rather than the wallet, so
 * each token account's signatures are read too. Without a keyless indexer only
 * recent blocks are reachable over RPC, and the history is marked incomplete.
 * The current balances are read last so the report can check that the
 * history adds up to them.
 */
export async function readAccountHistory(
  registry: ChainRegistry,
  chain: ChainInfo,
  target: SyncTarget,
  signal?: AbortSignal,
): Promise<AccountHistory> {
  const adapter = registry.adapterFor(target.chainId);
  const read =
    (extra: HistoryOptions, address = target.address) =>
    (cursor: string | undefined) =>
      adapter.getHistory(address, target.chainId, cursor, {
        ...(signal ? { signal } : {}),
        ...extra,
      });
  let history: AccountHistory;
  if (chain.family === 'evm') {
    const indexer = HISTORY_INDEXERS[target.chainId];
    if (!indexer) {
      const recent = await readAllPages(read({}), 1, signal);
      history = {
        accountId: target.accountId,
        records: recent.records,
        complete: false,
        sources: recent.sources,
        error: 'No keyless history indexer for this chain: only recent blocks were read over RPC.',
      };
    } else {
      const streams: StreamResult[] = [];
      const kinds: IndexedStream[] = ['transactions', 'tokens', 'internal'];
      if (WITHDRAWAL_CHAINS.has(target.chainId)) kinds.push('withdrawals');
      for (const stream of kinds)
        streams.push(
          await readAllPages(
            read({ indexerUrl: indexer, stream, nfts: true }),
            MAX_HISTORY_PAGES,
            signal,
          ),
        );
      history = combine(target.accountId, streams);
    }
  } else {
    const streams = [await readAllPages(read({}), MAX_HISTORY_PAGES, signal)];
    let extraError: string | undefined;
    if (adapter.historyAddresses) {
      try {
        const accounts = await adapter.historyAddresses(target.address, target.chainId, signal);
        if (accounts.length > MAX_TOKEN_ACCOUNTS)
          extraError = `Only ${MAX_TOKEN_ACCOUNTS} of ${accounts.length} token accounts were read.`;
        for (const a of accounts.slice(0, MAX_TOKEN_ACCOUNTS))
          streams.push(
            await readAllPages(read({ owner: target.address }, a), TOKEN_ACCOUNT_PAGES, signal),
          );
      } catch (e) {
        if (signal?.aborted) throw e;
        extraError = 'Token accounts could not be listed: ' + readError(e, 'request failed');
      }
    }
    history = combine(target.accountId, streams, extraError);
  }
  try {
    const held = await adapter.getBalances(target.address, target.chainId);
    history.balances = held
      .filter((h) => !h.error && /^\d{1,78}$/.test(h.amount))
      // History counts rent locked in token accounts as SOL still owned; the
      // wallet's SOL balance leaves it out, so the two never agree exactly.
      .filter((h) => !(chain.family === 'solana' && h.assetRef === chain.nativeAsset.ref))
      .map((h) => ({ assetRef: h.assetRef, amount: h.amount }));
    history.balancesAtMs = Date.now();
  } catch (e) {
    if (signal?.aborted) throw e;
  }
  return history;
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

/** What the history itself reported about an asset: untrusted display metadata. */
export interface ReportedAsset {
  symbol?: string | undefined;
  decimals?: number | undefined;
}

/** First reported symbol and decimals per asset ref across the given histories. */
export function reportedAssets(
  histories: readonly AccountHistory[],
): ReadonlyMap<string, ReportedAsset> {
  const out = new Map<string, ReportedAsset>();
  for (const h of histories)
    for (const r of h.records)
      for (const d of r.assetDeltas) {
        if (d.symbol === undefined && d.decimals === undefined) continue;
        const prior = out.get(d.assetRef) ?? {};
        out.set(d.assetRef, {
          symbol: prior.symbol ?? d.symbol,
          decimals: prior.decimals ?? d.decimals,
        });
      }
  return out;
}

const shorten = (s: string) => (s.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s);
// Reported symbols are claims anyone can make ("USDC"); a contract tag keeps a lookalike apart.
const claimed = (symbol: string, id: string) =>
  `${symbol.replace(/[^\x21-\x7e]/g, '').slice(0, 10)}·${id.replace(/^0x/, '').slice(0, 4)}`;

/**
 * Symbol, decimals and price key of an asset ref. Prices come only from
 * trusted local sources (native coins, the known-token table, tokens the user
 * tracks); history-reported decimals make untracked amounts readable.
 */
export function assetInfoFor(
  registry: ChainRegistry,
  ref: string,
  reported: ReportedAsset = {},
): AssetInfo {
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
    return { ref, symbol: shorten(ref), decimals: null, priceKey: null, testnet: false };
  }
  const nft = /^(.+):(erc721|erc1155):(0x[0-9a-f]{40}):(\d{1,78})$/.exec(ref);
  if (nft) {
    const [, chainId = '', , contract = '', id = ''] = nft;
    const label = reported.symbol ? claimed(reported.symbol, contract) : shorten(contract);
    return {
      ref,
      symbol: `${label} #${shorten(id)}`,
      decimals: 0,
      priceKey: null,
      testnet: chainOf(registry, chainId)?.testnet ?? false,
    };
  }
  const m = /^(.+):(erc20|spl):([^:]+)$/.exec(ref);
  const evm = ref.startsWith('eip155:');
  const known = KNOWN_TOKENS[evm ? ref.toLowerCase() : ref];
  if (!m) {
    // Cosmos bank denoms (`ibc/…`, `factory/…`) and anything else an adapter names.
    const lastColon = ref.lastIndexOf(':');
    const chainId = ref.slice(0, lastColon);
    const denom = ref.slice(lastColon + 1);
    const testnet = chainOf(registry, chainId)?.testnet ?? false;
    if (known)
      return {
        ref,
        symbol: known.symbol,
        decimals: known.decimals,
        priceKey: testnet ? null : known.coinId,
        testnet,
      };
    return {
      ref,
      symbol: reported.symbol ? claimed(reported.symbol, denom) : shorten(denom || ref),
      decimals: reported.decimals ?? null,
      priceKey: null,
      testnet,
    };
  }
  const [, chainId = '', standard, contract = ''] = m;
  const chain = chainOf(registry, chainId);
  const testnet = chain?.testnet ?? false;
  if (known)
    return { ref, symbol: known.symbol, decimals: known.decimals, priceKey: known.coinId, testnet };
  const tracked = tokenStore.find(ref);
  // Untracked contracts are mostly airdropped spam; asking the price API about each would
  // also tell it what this address holds.
  const key =
    testnet || !tracked
      ? null
      : tokenPriceKey(chainId, standard === 'erc20' ? contract.toLowerCase() : contract);
  return {
    ref,
    symbol:
      tracked?.symbol ?? (reported.symbol ? claimed(reported.symbol, contract) : shorten(contract)),
    decimals: tracked?.decimals ?? reported.decimals ?? null,
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
