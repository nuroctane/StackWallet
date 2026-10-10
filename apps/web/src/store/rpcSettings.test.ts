import { describe, expect, it } from 'vitest';
import { ChainRegistry, type ChainAdapter, type RpcEndpoint } from '@stackwallet/chains';

import type { StorageLike } from './persist.js';
import {
  applyRpcSettings,
  loadRpcSettings,
  MAX_ENDPOINTS_PER_CHAIN,
  MAX_RPC_URL_LENGTH,
  resetChainEndpoints,
  RPC_STORAGE_KEY,
  RpcSettings,
  rpcUrlProblem,
  RpcSettingsStore,
} from './rpcSettings.js';

class MemoryStorage implements StorageLike {
  readonly map = new Map<string, string>();
  getItem(key: string) {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.map.set(key, value);
  }
  removeItem(key: string) {
    this.map.delete(key);
  }
}

function fakePool(extra: Record<string, unknown> = {}) {
  const lists = new Map<string, string[]>();
  return {
    lists,
    pool: {
      endpoints: (chainId: string): RpcEndpoint[] =>
        (lists.get(chainId) ?? []).map((url) => ({ url, healthy: true })),
      setEndpoints: (chainId: string, urls: string[]) => {
        lists.set(chainId, urls);
      },
      ...extra,
    },
  };
}

function registryWith(pool: unknown, defaults: string[]): ChainRegistry {
  const adapter = {
    family: 'evm',
    chains: () => [
      {
        chainId: 'eip155:1',
        family: 'evm',
        name: 'Ethereum',
        nativeAsset: { ref: 'eip155:1/slip44:60', symbol: 'ETH', decimals: 18 },
        testnet: false,
        defaultRpcs: defaults,
      },
    ],
    rpc: pool,
  } as unknown as ChainAdapter;
  return new ChainRegistry().register(adapter);
}

describe('rpcUrlProblem', () => {
  it('accepts https host names only', () => {
    expect(rpcUrlProblem('https://rpc.example.org/v1')).toBeNull();
    expect(rpcUrlProblem('  https://a.b.c  ')).toBeNull();
  });
  it('rejects everything else with a reason', () => {
    expect(rpcUrlProblem('not a url')).toMatch(/valid URL/);
    expect(rpcUrlProblem('http://rpc.example.org')).toMatch(/https/);
    expect(rpcUrlProblem('https://localhost:8545')).toMatch(/Local/);
    expect(rpcUrlProblem('https://node.local')).toMatch(/Local/);
    expect(rpcUrlProblem('https://127.0.0.1')).toMatch(/IP literal/);
    expect(rpcUrlProblem('https://[::1]/')).toMatch(/IP literal/);
    expect(rpcUrlProblem('https://intranet')).toMatch(/fully qualified/);
    expect(rpcUrlProblem('https://user:pw@rpc.example.org')).toMatch(/Credentials/);
    expect(rpcUrlProblem(`https://rpc.example.org/${'a'.repeat(MAX_RPC_URL_LENGTH)}`)).toMatch(
      /longer than/,
    );
  });
});

describe('RpcSettings schema', () => {
  const urls = (n: number) => Array.from({ length: n }, (_, i) => `https://rpc${i}.example.org`);

  it('accepts lists the add form would accept', () => {
    expect(
      RpcSettings.safeParse({ 'eip155:1': urls(MAX_ENDPOINTS_PER_CHAIN), 'solana:x': [] }).success,
    ).toBe(true);
  });

  it('enforces the add-form rules on persisted blobs', () => {
    expect(RpcSettings.safeParse({ 'eip155:1': urls(MAX_ENDPOINTS_PER_CHAIN + 1) }).success).toBe(
      false,
    );
    const tooManyChains = Object.fromEntries(
      Array.from({ length: 501 }, (_, i) => [`eip155:${i}`, ['https://rpc.example.org']]),
    );
    expect(RpcSettings.safeParse(tooManyChains).success).toBe(false);
    expect(RpcSettings.safeParse({ 'eip155:1': ['http://localhost:8545'] }).success).toBe(false);
    expect(RpcSettings.safeParse({ 'eip155:1': ['https://user:pw@host.example'] }).success).toBe(
      false,
    );
    expect(
      RpcSettings.safeParse({
        'eip155:1': [`https://rpc.example.org/${'a'.repeat(MAX_RPC_URL_LENGTH)}`],
      }).success,
    ).toBe(false);
  });
});

describe('loadRpcSettings', () => {
  it('starts empty and round-trips', () => {
    expect(loadRpcSettings(null).settings).toEqual({});
    const storage = new MemoryStorage();
    storage.setItem(RPC_STORAGE_KEY, JSON.stringify({ 'eip155:1': ['https://x.example'] }));
    expect(loadRpcSettings(storage).settings).toEqual({ 'eip155:1': ['https://x.example'] });
  });

  it('quarantines a bad blob once and clears the live key', () => {
    for (const bad of [
      '{nope',
      JSON.stringify({ 'eip155:1': ['not a url'] }),
      JSON.stringify({ 'eip155:1': ['http://localhost:8545'] }),
    ]) {
      const s = new MemoryStorage();
      s.setItem(RPC_STORAGE_KEY, bad);
      const loaded = loadRpcSettings(s, () => 7);
      expect(loaded.settings).toEqual({});
      expect(loaded.quarantinedKey).toBe(`${RPC_STORAGE_KEY}.corrupt-7`);
      expect(s.getItem(loaded.quarantinedKey!)).toBe(bad);
      expect(s.getItem(RPC_STORAGE_KEY)).toBeNull();

      const again = loadRpcSettings(s, () => 8);
      expect(again.quarantinedKey).toBeUndefined();
      expect([...s.map.keys()]).toEqual([`${RPC_STORAGE_KEY}.corrupt-7`]);
    }
  });
});

describe('pool helpers', () => {
  it('applies persisted lists and skips unknown chains', () => {
    const { pool, lists } = fakePool();
    const registry = registryWith(pool, ['https://default.example']);
    applyRpcSettings(registry, {
      'eip155:1': ['https://mine.example'],
      'solana:unknown': ['https://skip.example'],
    });
    expect(lists.get('eip155:1')).toEqual(['https://mine.example']);
    expect(lists.has('solana:unknown')).toBe(false);
  });

  it('reset prefers the pool method and falls back to catalog defaults', () => {
    const basic = fakePool();
    const registry = registryWith(basic.pool, ['https://default.example']);
    basic.pool.setEndpoints('eip155:1', ['https://mine.example']);
    expect(resetChainEndpoints(registry, 'eip155:1')).toBe(true);
    expect(basic.lists.get('eip155:1')).toEqual(['https://default.example']);

    let resetCalls = 0;
    const smart = fakePool({ resetEndpoints: () => (resetCalls += 1) });
    expect(resetChainEndpoints(registryWith(smart.pool, []), 'eip155:1')).toBe(true);
    expect(resetCalls).toBe(1);
    expect(resetChainEndpoints(registry, 'cosmos:nope')).toBe(false);
  });
});

describe('RpcSettingsStore', () => {
  it('persists on every change and notifies', () => {
    const storage = new MemoryStorage();
    const store = new RpcSettingsStore({}, storage);
    let n = 0;
    store.subscribe(() => (n += 1));
    store.setChain('eip155:1', ['https://a.example']);
    expect(JSON.parse(storage.getItem(RPC_STORAGE_KEY)!)).toEqual({
      'eip155:1': ['https://a.example'],
    });
    store.clearChain('eip155:1');
    expect(store.getSnapshot()).toEqual({});
    store.clearChain('eip155:1');
    expect(n).toBe(3);
  });
});
