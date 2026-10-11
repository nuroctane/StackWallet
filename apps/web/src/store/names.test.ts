import type { Account } from '@stackwallet/core-client';
import type { NameRecord, NameService } from '@stackwallet/names';
import { describe, expect, it, vi } from 'vitest';

import { CollectiblesStore } from './collectibles.js';
import { NAMES_STORAGE_KEY, NAMES_TTL_MS, NamesStore, nameKey, walletLabel } from './names.js';

function account(id: string, walletId: string, chainId: string, address: string): Account {
  const family = chainId.startsWith('eip155')
    ? 'evm'
    : chainId.startsWith('solana')
      ? 'solana'
      : 'cosmos';
  return {
    id,
    walletId,
    family,
    chainId,
    address,
    publicKeyHex: '',
    hidden: false,
  } as Account;
}

function memStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    map: m,
  };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

function ensService(calls: string[], name = 'a.eth'): NameService {
  return {
    id: 'ens',
    appliesTo: (a) => a.family === 'evm',
    resolve: async (a): Promise<NameRecord[]> => {
      calls.push(a.address);
      return [
        {
          service: 'ens',
          name,
          address: a.address,
          chainId: 'eip155:1',
          nonAscii: false,
          resolvedAtMs: 1,
        },
      ];
    },
  };
}

describe('names store', () => {
  it('resolves an address once across chains and checksum spellings', async () => {
    const calls: string[] = [];
    let now = 1000;
    const store = new NamesStore(memStorage(), () => now);
    store.configure(null as never, [ensService(calls)]);
    const accts = [
      account('1', 'w', 'eip155:1', '0xAbC0000000000000000000000000000000000001'),
      account('2', 'w', 'eip155:8453', '0xabc0000000000000000000000000000000000001'),
    ];
    store.ensure(accts);
    await flush();
    await flush();
    expect(calls).toHaveLength(1);
    store.ensure(accts);
    await flush();
    expect(calls).toHaveLength(1);
    now += NAMES_TTL_MS + 1;
    store.ensure(accts);
    await flush();
    await flush();
    expect(calls).toHaveLength(2);
    expect(nameKey(accts[0]!)).toBe(nameKey(accts[1]!));
  });

  it('labels a wallet with its verified name and keeps the tag', async () => {
    const storage = memStorage();
    const store = new NamesStore(storage, () => 1);
    store.configure(null as never, [ensService([], 'vitalik.eth')]);
    const accts = [account('1', 'w1', 'eip155:1', '0x0000000000000000000000000000000000000001')];
    store.ensure(accts);
    await flush();
    await flush();
    const label = walletLabel(store.getSnapshot(), { id: 'w1', name: 'my tag' }, accts);
    expect(label).toMatchObject({ text: 'vitalik.eth', tag: 'my tag' });
    expect(walletLabel(store.getSnapshot(), { id: 'w2', name: 'other' }, accts).text).toBe('other');
    expect(JSON.parse(storage.map.get(NAMES_STORAGE_KEY)!).version).toBe(1);
    // A fresh store reads the cache back.
    expect(new NamesStore(storage).entry(accts[0]!)?.records[0]?.name).toBe('vitalik.eth');
  });

  it('ignores a corrupt cache', () => {
    const storage = memStorage();
    storage.setItem(NAMES_STORAGE_KEY, '{"version":1,"entries":{"x":{"records":[{"name":5}]}}}');
    expect(new NamesStore(storage).getSnapshot().entries).toEqual({});
  });
});

describe('collectibles store', () => {
  it('marks accounts without a source unsupported and caches answers', async () => {
    const list = vi.fn(async () => ({ items: [], cursor: null }));
    const store = new CollectiblesStore(() => 5);
    store.configure(null as never, [{ id: 'x', appliesTo: (a) => a.family === 'evm', list }]);
    const evm = account('1', 'w', 'eip155:1', '0x0000000000000000000000000000000000000001');
    const btc = {
      ...evm,
      id: '2',
      family: 'bitcoin',
      chainId: 'bip122:x',
      address: 'bc1q',
    } as Account;
    await store.load(evm);
    await store.load(evm);
    await store.load(btc);
    expect(list).toHaveBeenCalledTimes(1);
    expect(store.get(btc).supported).toBe(false);
    expect(store.get(evm).supported).toBe(true);
    await store.load(evm, true);
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('keeps the previous list when a refresh fails', async () => {
    let fail = false;
    const item = {
      key: 'k',
      chainId: 'eip155:1',
      standard: 'erc721' as const,
      contract: '0x',
      tokenId: '1',
      name: 'n',
      collection: 'c',
      image: null,
      amount: '1',
      suspicious: false,
      source: 'x',
    };
    const store = new CollectiblesStore(() => 5);
    store.configure(null as never, [
      {
        id: 'x',
        appliesTo: () => true,
        list: async () => {
          if (fail) throw new Error('down');
          return { items: [item], cursor: null };
        },
      },
    ]);
    const evm = account('1', 'w', 'eip155:1', '0x0000000000000000000000000000000000000001');
    await store.load(evm);
    fail = true;
    await store.load(evm, true);
    expect(store.get(evm).items).toHaveLength(1);
    expect(store.get(evm).error).toBe('down');
  });
});
