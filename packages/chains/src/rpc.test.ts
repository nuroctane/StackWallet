import { describe, expect, it } from 'vitest';

import {
  HttpError,
  JsonRpcError,
  MAX_BODY_BYTES,
  MalformedResponseError,
  MemoryRpcPool,
  NoRpcEndpointsError,
  RpcFailoverError,
  RpcTimeoutError,
  fetchJson,
  fetchJsonRpc,
  withFailover,
} from './rpc.js';
import type { ChainInfo } from './types.js';

const chain: ChainInfo = {
  chainId: 'eip155:1',
  family: 'evm',
  name: 'Ethereum',
  nativeAsset: { ref: 'eip155:1:native', symbol: 'ETH', decimals: 18 },
  testnet: false,
  defaultRpcs: ['https://a.example', 'https://b.example', 'https://c.example'],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('MemoryRpcPool', () => {
  it('seeds from chain info and round-robins among unmeasured endpoints', () => {
    const pool = new MemoryRpcPool([chain]);
    expect(pool.endpoints('eip155:1')).toHaveLength(3);
    const picks = [0, 1, 2, 3].map(() => pool.pick('eip155:1')?.url);
    expect(picks).toEqual([
      'https://a.example',
      'https://b.example',
      'https://c.example',
      'https://a.example',
    ]);
  });

  it('prefers the lowest measured latency and demotes failures', () => {
    const pool = new MemoryRpcPool([chain]);
    pool.markHealthy('https://a.example', 80);
    pool.markHealthy('https://b.example', 20);
    pool.markHealthy('https://c.example', 20);
    const picks = [0, 1, 2].map(() => pool.pick('eip155:1')?.url);
    expect(picks.every((u) => u !== 'https://a.example')).toBe(true);
    expect(new Set(picks)).toEqual(new Set(['https://b.example', 'https://c.example']));

    pool.markFailed('https://b.example');
    pool.markFailed('https://c.example');
    expect(pool.pick('eip155:1')?.url).toBe('https://a.example');
    expect(pool.endpoints('eip155:1').find((e) => e.url === 'https://b.example')?.healthy).toBe(
      false,
    );
  });

  it('falls back to the least recently failed endpoint when all are down', () => {
    let t = 1000;
    const pool = new MemoryRpcPool([chain], () => t);
    pool.markFailed('https://a.example');
    t = 2000;
    pool.markFailed('https://b.example');
    t = 3000;
    pool.markFailed('https://c.example');
    expect(pool.pick('eip155:1')?.url).toBe('https://a.example');
    expect(pool.pick('eip155:1', ['https://a.example'])?.url).toBe('https://b.example');
  });

  it('replaces endpoints per chain and returns copies', () => {
    const pool = new MemoryRpcPool([chain]);
    pool.setEndpoints('eip155:1', ['https://x.example', 'https://x.example']);
    const eps = pool.endpoints('eip155:1');
    expect(eps.map((e) => e.url)).toEqual(['https://x.example']);
    eps[0]!.healthy = false;
    expect(pool.endpoints('eip155:1')[0]?.healthy).toBe(true);
    expect(pool.pick('eip155:999')).toBeUndefined();
  });
});

describe('withFailover', () => {
  it('moves to the next endpoint after a failure and records health', async () => {
    const pool = new MemoryRpcPool([chain]);
    const seen: string[] = [];
    const value = await withFailover(pool, 'eip155:1', async (url) => {
      seen.push(url);
      if (url === 'https://a.example') throw new Error('boom');
      return `ok from ${url}`;
    });
    expect(seen).toHaveLength(2);
    expect(seen[0]).toBe('https://a.example');
    expect(value).toBe(`ok from ${seen[1]}`);
    const eps = pool.endpoints('eip155:1');
    expect(eps.find((e) => e.url === 'https://a.example')?.healthy).toBe(false);
    expect(eps.find((e) => e.url === seen[1])?.latencyMs).toBeTypeOf('number');
  });

  it('aggregates every cause when all endpoints fail', async () => {
    const pool = new MemoryRpcPool([chain]);
    await expect(
      withFailover(pool, 'eip155:1', async (url) => {
        throw new Error(`down ${url}`);
      }),
    ).rejects.toBeInstanceOf(RpcFailoverError);
    await expect(withFailover(pool, 'eip155:2', async () => 1)).rejects.toBeInstanceOf(
      NoRpcEndpointsError,
    );
  });

  it('works with a plain RpcPool that has no health tracking', async () => {
    const plain = {
      endpoints: () => [{ url: 'https://p.example', healthy: true }],
      setEndpoints: () => undefined,
    };
    expect(await withFailover(plain, 'eip155:1', async (url) => url)).toBe('https://p.example');
  });
});

describe('fetchJsonRpc / fetchJson', () => {
  it('unwraps result and validates the envelope', async () => {
    const calls: { url: string; body: unknown }[] = [];
    const fake: typeof fetch = async (input, init) => {
      calls.push({ url: String(input), body: JSON.parse(String(init?.body)) });
      return jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x10' });
    };
    const result = await fetchJsonRpc('https://a.example', 'eth_getBalance', ['0xabc', 'latest'], {
      fetch: fake,
    });
    expect(result).toBe('0x10');
    expect(calls[0]?.body).toMatchObject({ jsonrpc: '2.0', method: 'eth_getBalance' });
  });

  it('surfaces json-rpc errors, http errors and malformed bodies as typed errors', async () => {
    const rpcErr: typeof fetch = async () =>
      jsonResponse({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'nope' } });
    await expect(
      fetchJsonRpc('https://a.example', 'x', [], { fetch: rpcErr }),
    ).rejects.toBeInstanceOf(JsonRpcError);

    const http500: typeof fetch = async () => jsonResponse('upstream down', 500);
    await expect(fetchJson('https://a.example/x', { fetch: http500 })).rejects.toMatchObject({
      name: 'HttpError',
      status: 500,
    });
    await expect(fetchJson('https://a.example/x', { fetch: http500 })).rejects.toBeInstanceOf(
      HttpError,
    );

    const notJson: typeof fetch = async () => jsonResponse('<html>', 200);
    await expect(fetchJson('https://a.example/x', { fetch: notJson })).rejects.toBeInstanceOf(
      MalformedResponseError,
    );

    const noEnvelope: typeof fetch = async () => jsonResponse({ hello: 'world' });
    await expect(
      fetchJsonRpc('https://a.example', 'x', [], { fetch: noEnvelope }),
    ).rejects.toBeInstanceOf(MalformedResponseError);

    const nullResult: typeof fetch = async () =>
      jsonResponse({ jsonrpc: '2.0', id: 1, result: null });
    expect(await fetchJsonRpc('https://a.example', 'x', [], { fetch: nullResult })).toBeNull();
  });

  it('rejects oversized bodies, declared or streamed', async () => {
    const declared: typeof fetch = async () =>
      new Response('{}', {
        status: 200,
        headers: { 'content-length': String(MAX_BODY_BYTES + 1) },
      });
    await expect(fetchJson('https://a.example/x', { fetch: declared })).rejects.toBeInstanceOf(
      MalformedResponseError,
    );

    const streamed: typeof fetch = async () =>
      new Response(`"${'x'.repeat(MAX_BODY_BYTES + 16)}"`, { status: 200 });
    await expect(fetchJson('https://a.example/x', { fetch: streamed })).rejects.toBeInstanceOf(
      MalformedResponseError,
    );
  });

  it('re-admits a failed endpoint after the cooldown', () => {
    let t = 0;
    const pool = new MemoryRpcPool([chain], () => t);
    pool.markHealthy('https://b.example', 10);
    pool.markHealthy('https://c.example', 10);
    pool.markHealthy('https://a.example', 1);
    pool.markFailed('https://a.example');
    expect(pool.pick('eip155:1')?.url).not.toBe('https://a.example');
    t = MemoryRpcPool.RETRY_AFTER_MS;
    expect(pool.pick('eip155:1')?.url).toBe('https://a.example');
  });

  it('aborts on timeout', async () => {
    const hanging: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError')),
        );
      });
    await expect(
      fetchJson('https://a.example/x', { fetch: hanging, timeoutMs: 10 }),
    ).rejects.toBeInstanceOf(RpcTimeoutError);
  });
});
