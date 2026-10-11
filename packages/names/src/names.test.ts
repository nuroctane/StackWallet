import { ChainRegistry } from '@stackwallet/chains';
import { createCosmosAdapter } from '@stackwallet/chains-cosmos';
import { createEvmAdapter } from '@stackwallet/chains-evm';
import { describe, expect, it } from 'vitest';

import {
  cleanName,
  decodeEnsReverse,
  displayName,
  encodeEnsReverse,
  ensService,
  icnsService,
  resolveAccountNames,
  thornameService,
  type NameRecord,
} from './index.js';

const VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const UR_RESULT =
  '0x0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000231b0ee14048e9dccd1d247744d114a4eb5e8e630000000000000000000000005fbb459c49bb06083c33109fa4f14810ec2cf358000000000000000000000000000000000000000000000000000000000000000b766974616c696b2e657468000000000000000000000000000000000000000000';

const ch = (code: number) => String.fromCharCode(code);

function fakeFetch(handler: (url: string) => unknown): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const body = handler(String(input));
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}

function registry(): ChainRegistry {
  return new ChainRegistry().register(createEvmAdapter()).register(createCosmosAdapter());
}

describe('sanitize', () => {
  it('refuses control, bidi and zero-width characters', () => {
    expect(cleanName('vitalik.eth')).toEqual({ name: 'vitalik.eth', nonAscii: false });
    expect(cleanName(`evil${ch(0x202e)}gnp.eth`)).toBeNull();
    expect(cleanName(`a${ch(0x200b)}b.eth`)).toBeNull();
    expect(cleanName(`a${ch(0x07)}b.eth`)).toBeNull();
    expect(cleanName('two words')).toBeNull();
    expect(cleanName('')).toBeNull();
    expect(cleanName(42)).toBeNull();
    expect(cleanName(`caf${ch(0xe9)}.eth`)).toEqual({ name: `caf${ch(0xe9)}.eth`, nonAscii: true });
  });
});

describe('ens', () => {
  it('encodes reverse() and decodes the universal resolver answer', () => {
    expect(encodeEnsReverse(VITALIK).slice(0, 10)).toBe('0x5d78a217');
    expect(decodeEnsReverse(UR_RESULT)).toBe('vitalik.eth');
    expect(decodeEnsReverse('0x')).toBeNull();
  });

  it('treats a revert as no name rather than a dead endpoint', async () => {
    const fetch = fakeFetch(() => ({
      jsonrpc: '2.0',
      id: 1,
      error: { code: 3, message: 'execution reverted' },
    }));
    const svc = ensService({ registry: registry(), fetchOptions: { fetch }, now: () => 1 });
    await expect(
      svc.resolve({ family: 'evm', chainId: 'eip155:8453', address: VITALIK }),
    ).resolves.toEqual([]);
  });

  it('resolves a verified primary name for any EVM chain', async () => {
    const fetch = fakeFetch(() => ({ jsonrpc: '2.0', id: 1, result: UR_RESULT }));
    const svc = ensService({ registry: registry(), fetchOptions: { fetch }, now: () => 5 });
    const out = await svc.resolve({ family: 'evm', chainId: 'eip155:10', address: VITALIK });
    expect(out).toEqual([
      {
        service: 'ens',
        name: 'vitalik.eth',
        nonAscii: false,
        address: VITALIK,
        chainId: 'eip155:1',
        resolvedAtMs: 5,
      },
    ]);
  });
});

describe('icns', () => {
  const OSMO = 'osmo15hndzyqykg09fturlkgayw0849xu686mmjrqns';
  const COSMOS = 'cosmos15hndzyqykg09fturlkgayw0849xu686mnfss9z';
  const decodeQuery = (url: string) =>
    JSON.parse(atob(decodeURIComponent(url.split('/smart/')[1]!))) as Record<string, unknown>;

  it('asks with the osmo spelling and forward-checks with the account prefix', async () => {
    const seen: string[] = [];
    const fetch = fakeFetch((url) => {
      const q = decodeQuery(url);
      seen.push(JSON.stringify(q));
      return q['primary_name'] ? { data: { name: 'rj' } } : { data: { address: COSMOS } };
    });
    const svc = icnsService({ registry: registry(), fetchOptions: { fetch }, now: () => 1 });
    const out = await svc.resolve({
      family: 'cosmos',
      chainId: 'cosmos:cosmoshub-4',
      address: COSMOS,
    });
    expect(out.map((r) => r.name)).toEqual(['rj.cosmos']);
    expect(seen[0]).toContain(OSMO);
    expect(seen[1]).toContain('"bech32_prefix":"cosmos"');
  });

  it('drops a name whose forward record points elsewhere', async () => {
    const fetch = fakeFetch((url) =>
      decodeQuery(url)['primary_name'] ? { data: { name: 'rj' } } : { data: { address: OSMO } },
    );
    const svc = icnsService({ registry: registry(), fetchOptions: { fetch } });
    await expect(
      svc.resolve({ family: 'cosmos', chainId: 'cosmos:cosmoshub-4', address: COSMOS }),
    ).resolves.toEqual([]);
  });
});

describe('thorname', () => {
  it('keeps only names whose lookup lists the address', async () => {
    const addr = '0x335fd459eadf098f8b2f26692936ee3d5bb425a2';
    const fetch = fakeFetch((url) => {
      if (url.includes('/rlookup/')) return ['t', 'liar'];
      if (url.endsWith('/lookup/t'))
        return { entries: [{ chain: 'ETH', address: addr.toUpperCase().replace('0X', '0x') }] };
      return { entries: [{ chain: 'ETH', address: '0x0000000000000000000000000000000000000001' }] };
    });
    const svc = thornameService({
      registry: new ChainRegistry(),
      fetchOptions: { fetch },
      midgardUrls: ['https://midgard.test'],
    });
    const out = await svc.resolve({ family: 'evm', chainId: 'eip155:1', address: addr });
    expect(out.map((r) => r.name)).toEqual(['t']);
  });
});

describe('resolve', () => {
  it('collects every applicable service and reports failures separately', async () => {
    const rec: NameRecord = {
      service: 'ens',
      name: 'a.eth',
      address: 'x',
      chainId: 'c',
      nonAscii: false,
      resolvedAtMs: 1,
    };
    const ok = { id: 'ens' as const, appliesTo: () => true, resolve: async () => [rec] };
    const bad = {
      id: 'sns' as const,
      appliesTo: () => true,
      resolve: () => Promise.reject(new Error('x')),
    };
    const skip = {
      id: 'icns' as const,
      appliesTo: () => false,
      resolve: () => Promise.reject(new Error('no')),
    };
    const out = await resolveAccountNames([bad, ok, skip], {
      family: 'evm',
      chainId: 'c',
      address: 'x',
    });
    expect(out.records.map((r) => r.name)).toEqual(['a.eth']);
    expect(out.failed).toEqual(['sns']);
    expect(displayName(out.records)?.name).toBe('a.eth');
  });
});
