import { describe, expect, it } from 'vitest';

import {
  HttpError,
  JsonRpcError,
  MAX_BODY_BYTES,
  MAX_JSONRPC_BATCH,
  MalformedResponseError,
  MemoryRpcPool,
  NoRpcEndpointsError,
  RpcFailoverError,
  RpcTimeoutError,
  fetchJson,
  fetchJsonRpc,
  fetchJsonRpcBatch,
  operatorOf,
  withCrossCheck,
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

  it('tracks a rolling error rate over the last ten attempts', () => {
    const pool = new MemoryRpcPool([chain]);
    const rate = () => pool.endpoints('eip155:1')[0]?.errorRate;
    expect(rate()).toBeUndefined();
    pool.markHealthy('https://a.example', 5);
    pool.markFailed('https://a.example');
    expect(rate()).toBe(0.5);
    for (let i = 0; i < 10; i++) pool.markHealthy('https://a.example', 5);
    expect(rate()).toBe(0);
    for (let i = 0; i < 3; i++) pool.markFailed('https://a.example');
    expect(rate()).toBeCloseTo(0.3);
  });

  it('ranks healthy endpoints by error rate before latency', () => {
    const pool = new MemoryRpcPool([chain]);
    // a: fast but flaky (1 failure in 2); b: slower, clean; c: unmeasured.
    pool.markHealthy('https://a.example', 1);
    pool.markFailed('https://a.example');
    pool.markHealthy('https://a.example', 1);
    pool.markHealthy('https://b.example', 50);
    expect(pool.pick('eip155:1')?.url).toBe('https://b.example');
    // Unmeasured c ties with b on error rate (0) but loses on latency.
    expect(pool.pick('eip155:1')?.url).toBe('https://b.example');
    expect(pool.pick('eip155:1', ['https://b.example'])?.url).toBe('https://c.example');
  });

  it('records the head block an endpoint reported', () => {
    const pool = new MemoryRpcPool([chain]);
    pool.markBlock('https://a.example', 123);
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      pool.markBlock('https://b.example', bad);
    }
    expect(pool.endpoints('eip155:1').find((e) => e.url === 'https://a.example')?.lastBlock).toBe(
      123,
    );
    expect(
      pool.endpoints('eip155:1').find((e) => e.url === 'https://b.example')?.lastBlock,
    ).toBeUndefined();
  });

  it('re-admits a failed endpoint after the cooldown', () => {
    let t = 0;
    const pool = new MemoryRpcPool([chain], () => t);
    // Every endpoint carries one failure in three attempts so only latency separates them.
    for (const url of ['https://b.example', 'https://c.example']) {
      pool.markHealthy(url, 10);
      pool.markFailed(url);
      pool.markHealthy(url, 10);
    }
    pool.markHealthy('https://a.example', 1);
    pool.markHealthy('https://a.example', 1);
    pool.markFailed('https://a.example');
    expect(pool.pick('eip155:1')?.url).not.toBe('https://a.example');
    t = MemoryRpcPool.RETRY_AFTER_MS;
    expect(pool.pick('eip155:1')?.url).toBe('https://a.example');
  });

  it('flags user-added endpoints as custom and restores defaults on reset', () => {
    const pool = new MemoryRpcPool([chain]);
    expect(pool.endpoints('eip155:1').every((e) => e.custom === undefined)).toBe(true);
    pool.markHealthy('https://a.example', 7);
    pool.setEndpoints('eip155:1', ['https://a.example', 'https://mine.example']);
    const eps = pool.endpoints('eip155:1');
    expect(eps.map((e) => [e.url, e.custom ?? false])).toEqual([
      ['https://a.example', false],
      ['https://mine.example', true],
    ]);
    // Health survives an edit for endpoints that stay.
    expect(eps[0]?.latencyMs).toBe(7);

    pool.resetEndpoints('eip155:1');
    expect(pool.endpoints('eip155:1').map((e) => e.url)).toEqual(chain.defaultRpcs);
    expect(pool.endpoints('eip155:1').every((e) => e.custom === undefined)).toBe(true);

    // A chain the pool was not seeded with falls back to the bundled catalog.
    pool.setEndpoints('eip155:8453', ['https://mainnet.base.org', 'https://mine.example']);
    expect(pool.endpoints('eip155:8453').map((e) => e.custom ?? false)).toEqual([false, true]);
    expect(pool.allChainIds()).toEqual(['eip155:1', 'eip155:8453']);
    pool.resetEndpoints('eip155:8453');
    expect(pool.endpoints('eip155:8453').length).toBeGreaterThanOrEqual(2);
    expect(pool.endpoints('eip155:8453').some((e) => e.custom)).toBe(false);
  });
});

describe('withCrossCheck', () => {
  const same = { equal: (a: string, b: string) => a === b };

  it('reports agreed when two hosts answer alike and ranks both healthy', async () => {
    const pool = new MemoryRpcPool([chain]);
    const seen: string[] = [];
    const res = await withCrossCheck(
      pool,
      'eip155:1',
      async (url) => {
        seen.push(url);
        return '42';
      },
      same,
    );
    expect(res.value).toBe('42');
    expect(res.provenance.kind).toBe('agreed');
    expect(seen).toHaveLength(2);
    expect(new Set(seen).size).toBe(2);
    if (res.provenance.kind === 'agreed') {
      expect(new Set(res.provenance.endpoints)).toEqual(new Set(seen));
    }
    expect(pool.endpoints('eip155:1').filter((e) => e.latencyMs !== undefined)).toHaveLength(2);
  });

  it('reports disagreed with the other amount and marks neither endpoint failed', async () => {
    const pool = new MemoryRpcPool([chain]);
    const res = await withCrossCheck(
      pool,
      'eip155:1',
      async (url) => (url === 'https://a.example' ? '100' : '99'),
      same,
    );
    expect(res.provenance.kind).toBe('disagreed');
    if (res.provenance.kind === 'disagreed') {
      const kept = res.provenance.endpoints[0] === 'https://a.example' ? '100' : '99';
      expect(res.value).toBe(kept);
      expect(res.provenance.other).toBe(kept === '100' ? '99' : '100');
      expect(res.other).toBe(res.provenance.other);
    }
    expect(pool.endpoints('eip155:1').every((e) => e.healthy)).toBe(true);
    expect(pool.endpoints('eip155:1').every((e) => (e.errorRate ?? 0) === 0)).toBe(true);
  });

  it('prefers the catalog default over a faster custom endpoint when they disagree', async () => {
    const pool = new MemoryRpcPool([chain]);
    pool.setEndpoints('eip155:1', ['https://a.example', 'https://mine.example']);
    const res = await withCrossCheck(
      pool,
      'eip155:1',
      async (url) => {
        if (url === 'https://a.example') {
          await new Promise((r) => setTimeout(r, 25));
          return '100';
        }
        return '99';
      },
      same,
    );
    expect(res.value).toBe('100');
    expect(res.other).toBe('99');
    expect(res.provenance).toEqual({
      kind: 'disagreed',
      endpoints: ['https://a.example', 'https://mine.example'],
      other: '99',
    });

    // Two custom endpoints fall back to the latency rule.
    pool.setEndpoints('eip155:1', ['https://x.example', 'https://y.example']);
    const both = await withCrossCheck(
      pool,
      'eip155:1',
      async (url) => {
        if (url === 'https://x.example') await new Promise((r) => setTimeout(r, 25));
        return url;
      },
      same,
    );
    expect(both.value).toBe('https://y.example');
  });

  it('treats sub-hosts of one operator as a single witness', async () => {
    expect(operatorOf('https://eth.drpc.org/x')).toBe('drpc.org');
    expect(operatorOf('https://LB.DRPC.org')).toBe('drpc.org');
    expect(operatorOf('https://rpc.cosmos.lavenderfive.com:443')).toBe('lavenderfive.com');
    expect(operatorOf('https://example.org')).toBe('example.org');
    expect(operatorOf('not a url')).toBe('not a url');

    const oneOperator = new MemoryRpcPool([
      { ...chain, defaultRpcs: ['https://eth.drpc.org', 'https://lb.drpc.org'] },
    ]);
    let calls = 0;
    const r1 = await withCrossCheck(
      oneOperator,
      'eip155:1',
      async () => {
        calls++;
        return '5';
      },
      same,
    );
    expect(r1.provenance.kind).toBe('single');
    expect(calls).toBe(1);

    const twoOperators = new MemoryRpcPool([
      { ...chain, defaultRpcs: ['https://eth.drpc.org', 'https://rpc.lavenderfive.com'] },
    ]);
    calls = 0;
    const r2 = await withCrossCheck(
      twoOperators,
      'eip155:1',
      async () => {
        calls++;
        return '5';
      },
      same,
    );
    expect(r2.provenance.kind).toBe('agreed');
    expect(calls).toBe(2);
  });

  it('falls back to single when the second endpoint fails, and demotes it', async () => {
    const pool = new MemoryRpcPool([chain]);
    let calls = 0;
    const res = await withCrossCheck(
      pool,
      'eip155:1',
      async () => {
        calls++;
        if (calls === 2) throw new Error('second down');
        return '1';
      },
      same,
    );
    expect(res).toMatchObject({ value: '1', provenance: { kind: 'single' } });
    expect(calls).toBe(2);
    expect(pool.endpoints('eip155:1').filter((e) => !e.healthy)).toHaveLength(1);
  });

  it('keeps the plain failover path when only one endpoint exists or hosts coincide', async () => {
    const one = new MemoryRpcPool([{ ...chain, defaultRpcs: ['https://only.example'] }]);
    let calls = 0;
    const res = await withCrossCheck(
      one,
      'eip155:1',
      async () => {
        calls++;
        return '5';
      },
      same,
    );
    expect(res).toEqual({
      value: '5',
      provenance: { kind: 'single', endpoint: 'https://only.example' },
    });
    expect(calls).toBe(1);

    const sameHost = new MemoryRpcPool([
      { ...chain, defaultRpcs: ['https://h.example/a', 'https://h.example/b'] },
    ]);
    calls = 0;
    const r2 = await withCrossCheck(
      sameHost,
      'eip155:1',
      async () => {
        calls++;
        return '5';
      },
      same,
    );
    expect(r2.provenance.kind).toBe('single');
    expect(calls).toBe(1);
  });

  it('continues failover past both probes and aggregates every cause', async () => {
    const pool = new MemoryRpcPool([chain]);
    let calls = 0;
    const res = await withCrossCheck(
      pool,
      'eip155:1',
      async () => {
        calls++;
        if (calls <= 2) throw new Error(`down ${calls}`);
        return '7';
      },
      same,
    );
    expect(res).toMatchObject({ value: '7', provenance: { kind: 'single' } });
    expect(calls).toBe(3);

    const dead = new MemoryRpcPool([chain]);
    await expect(
      withCrossCheck(
        dead,
        'eip155:1',
        async () => {
          throw new Error('nope');
        },
        same,
      ),
    ).rejects.toThrow(/all 3 rpc endpoint/);
    await expect(withCrossCheck(dead, 'eip155:2', async () => '', same)).rejects.toBeInstanceOf(
      NoRpcEndpointsError,
    );
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

describe('fetchJsonRpcBatch', () => {
  const calls = [
    { method: 'eth_call', params: [{ to: '0x1', data: '0xaa' }, 'latest'] },
    { method: 'eth_call', params: [{ to: '0x1', data: '0xbb' }, 'latest'] },
  ];

  it('sends one batch envelope and matches replies by id, even reordered', async () => {
    let body: { id: number; method: string }[] = [];
    const fake: typeof fetch = async (_input, init) => {
      body = JSON.parse(String(init?.body));
      // Reply in reverse order on purpose.
      return jsonResponse(
        [...body].reverse().map((r, i) => ({ jsonrpc: '2.0', id: r.id, result: `0x${i}` })),
      );
    };
    const out = await fetchJsonRpcBatch('https://a.example', calls, { fetch: fake });
    expect(body).toHaveLength(2);
    expect(body.map((b) => b.method)).toEqual(['eth_call', 'eth_call']);
    // First reply (id 2) is 0x0, second (id 1) is 0x1: slots follow the request order.
    expect(out.map((r) => (r.ok ? r.result : null))).toEqual(['0x1', '0x0']);
  });

  it('keeps per-call failures as error slots instead of failing the batch', async () => {
    const fake: typeof fetch = async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { id: number }[];
      return jsonResponse([
        { jsonrpc: '2.0', id: body[0]!.id, error: { code: -32000, message: 'execution reverted' } },
        { jsonrpc: '2.0', id: body[1]!.id, result: '0x10' },
      ]);
    };
    const out = await fetchJsonRpcBatch('https://a.example', calls, { fetch: fake });
    expect(out[0]).toMatchObject({ ok: false, error: { code: -32000 } });
    expect(out[1]).toMatchObject({ ok: true, result: '0x10' });
  });

  it('rejects non-array replies and batches over the cap', async () => {
    const single: typeof fetch = async () => jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x0' });
    await expect(fetchJsonRpcBatch('https://a.example', calls, { fetch: single })).rejects.toThrow(
      MalformedResponseError,
    );
    await expect(
      fetchJsonRpcBatch(
        'https://a.example',
        Array.from({ length: MAX_JSONRPC_BATCH + 1 }, () => ({ method: 'm' })),
        { fetch: single },
      ),
    ).rejects.toThrow(/exceeds/);
    await expect(fetchJsonRpcBatch('https://a.example', [], { fetch: single })).resolves.toEqual(
      [],
    );
  });
});
