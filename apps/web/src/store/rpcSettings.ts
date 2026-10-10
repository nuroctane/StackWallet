import type { ChainRegistry, RpcEndpoint, RpcPool } from '@stackwallet/chains';
import { z } from 'zod';

import type { StorageLike } from './persist.js';

export const RPC_STORAGE_KEY = 'stackwallet.rpc.v1';
export const MAX_RPC_URL_LENGTH = 2048;
export const MAX_ENDPOINTS_PER_CHAIN = 32;
const MAX_CHAINS = 500;

/**
 * Chain id -> the complete endpoint list the user wants for that chain. The
 * persisted shape enforces the same rules as the add form so a blob edited
 * by hand (or by an extension) cannot smuggle in a url the form would refuse.
 */
export const RpcSettings = z
  .record(
    z.string(),
    z
      .array(
        z
          .string()
          .max(MAX_RPC_URL_LENGTH)
          .refine((u) => rpcUrlProblem(u) === null, 'not an allowed endpoint url'),
      )
      .max(MAX_ENDPOINTS_PER_CHAIN),
  )
  .refine((rec) => Object.keys(rec).length <= MAX_CHAINS, 'too many chains');
export type RpcSettings = z.infer<typeof RpcSettings>;

export interface RpcLoadResult {
  settings: RpcSettings;
  quarantinedKey?: string;
}

export function loadRpcSettings(
  storage: StorageLike | null,
  now = () => Date.now(),
): RpcLoadResult {
  if (!storage) return { settings: {} };
  let raw: string | null = null;
  try {
    raw = storage.getItem(RPC_STORAGE_KEY);
  } catch {
    return { settings: {} };
  }
  if (raw === null || raw === '') return { settings: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  const result = parsed === undefined ? undefined : RpcSettings.safeParse(parsed);
  if (result?.success) return { settings: result.data };
  const quarantinedKey = `${RPC_STORAGE_KEY}.corrupt-${now()}`;
  try {
    storage.setItem(quarantinedKey, raw);
    // Left in place, the bad blob would be quarantined again under a new key
    // on every load and grow storage without bound.
    storage.removeItem(RPC_STORAGE_KEY);
  } catch {
    // Storage full or blocked; the defaults still work.
  }
  return { settings: {}, quarantinedKey };
}

export function saveRpcSettings(storage: StorageLike, settings: RpcSettings): boolean {
  try {
    storage.setItem(RPC_STORAGE_KEY, JSON.stringify(settings));
    return true;
  } catch {
    return false;
  }
}

/**
 * The same endpoint lists are meant to feed the desktop shell and the headless
 * CLI later, and those run outside the browser's same-origin sandbox where a
 * loopback or LAN address is reachable. Refusing non-https, raw IPs and
 * localhost from the start is cheaper than migrating stored lists once a
 * pasted URL could turn the wallet into a probe of its own network.
 */
export function rpcUrlProblem(input: string): string | null {
  const trimmed = input.trim();
  if (trimmed.length > MAX_RPC_URL_LENGTH)
    return `URL is longer than ${MAX_RPC_URL_LENGTH} characters`;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return 'Not a valid URL';
  }
  if (url.protocol !== 'https:') return 'Endpoint must use https';
  const host = url.hostname.toLowerCase();
  if (host === '') return 'Endpoint needs a host name';
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    return 'Local host names are not allowed';
  }
  if (host.startsWith('[') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return 'IP literals are not allowed; use a host name';
  }
  if (!host.includes('.')) return 'Endpoint needs a fully qualified host name';
  if (url.username || url.password) return 'Credentials in the URL are not allowed';
  return null;
}

export function normalizeRpcUrl(input: string): string {
  return new URL(input.trim()).toString();
}

interface ResettablePool extends RpcPool {
  resetEndpoints(chainId: string): void;
}

function canReset(pool: RpcPool): pool is ResettablePool {
  return typeof (pool as Partial<ResettablePool>).resetEndpoints === 'function';
}

export function poolFor(registry: ChainRegistry, chainId: string): RpcPool | null {
  try {
    return registry.adapterFor(chainId).rpc;
  } catch {
    return null;
  }
}

export function endpointsFor(registry: ChainRegistry, chainId: string): RpcEndpoint[] {
  const pool = poolFor(registry, chainId);
  if (!pool) return [];
  try {
    return pool.endpoints(chainId);
  } catch {
    return [];
  }
}

/** Push every persisted list into the adapters' pools; unknown chains are skipped silently. */
export function applyRpcSettings(registry: ChainRegistry, settings: RpcSettings): void {
  for (const [chainId, urls] of Object.entries(settings)) {
    const pool = poolFor(registry, chainId);
    if (!pool) continue;
    try {
      pool.setEndpoints(chainId, urls);
    } catch {
      // A pool that rejects a list keeps its defaults; nothing else to do.
    }
  }
}

/** Back to catalog defaults, using the pool's own reset when it has one. */
export function resetChainEndpoints(registry: ChainRegistry, chainId: string): boolean {
  const pool = poolFor(registry, chainId);
  if (!pool) return false;
  if (canReset(pool)) {
    pool.resetEndpoints(chainId);
    return true;
  }
  let defaults: string[] = [];
  try {
    defaults = registry.chainInfo(chainId)?.defaultRpcs ?? [];
  } catch {
    defaults = [];
  }
  pool.setEndpoints(chainId, defaults);
  return true;
}

export type RpcSettingsListener = () => void;

/**
 * Tiny external store so the network view re-renders after an edit. The
 * pools themselves are not observable; the view re-reads them when this
 * store notifies and on a slow interval for health changes.
 */
export class RpcSettingsStore {
  private settings: RpcSettings;
  private readonly listeners = new Set<RpcSettingsListener>();

  constructor(
    initial: RpcSettings,
    private readonly storage: StorageLike | null,
  ) {
    this.settings = initial;
  }

  readonly subscribe = (l: RpcSettingsListener): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getSnapshot = (): RpcSettings => this.settings;

  private commit(next: RpcSettings): void {
    this.settings = next;
    if (this.storage) saveRpcSettings(this.storage, next);
    for (const l of this.listeners) l();
  }

  setChain(chainId: string, urls: string[]): void {
    this.commit({ ...this.settings, [chainId]: urls });
  }

  clearChain(chainId: string): void {
    if (!(chainId in this.settings)) {
      // Still notify so a reset of an untouched chain refreshes the view.
      for (const l of this.listeners) l();
      return;
    }
    const next = { ...this.settings };
    delete next[chainId];
    this.commit(next);
  }
}

function safeStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${RPC_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

const storage = safeStorage();
const loaded = loadRpcSettings(storage);

export const rpcSettings = new RpcSettingsStore(loaded.settings, storage);
export const rpcSettingsQuarantinedKey: string | undefined = loaded.quarantinedKey;
