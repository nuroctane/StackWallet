/**
 * Probes every default endpoint in the chain catalog with one request and
 * checks that it serves the chain the catalog claims. Run from the repo root:
 *
 *   node --experimental-strip-types scripts/probe-rpcs.ts [--json]
 *
 * Only type-only imports reach `catalog.ts`, so no bundler is needed. The
 * script talks to the network and is not part of any test suite.
 */
import { CURATED_CATALOG } from '../packages/chains/src/catalog-curated.ts';
import {
  CHAIN_META,
  GENERATED_COSMOS,
  GENERATED_EVM,
  GENERATED_SVM,
} from '../packages/chains/src/catalog-generated.ts';
import { mergeCatalog } from '../packages/chains/src/catalog-merge.ts';
import type { ChainInfo } from '../packages/chains/src/types.ts';

// catalog.ts imports its siblings with `.js` specifiers, which Node cannot map to source.
const CHAIN_CATALOG = mergeCatalog({
  curated: CURATED_CATALOG,
  evm: GENERATED_EVM,
  cosmos: GENERATED_COSMOS,
  svm: GENERATED_SVM,
  meta: CHAIN_META,
});

const TIMEOUT_MS = 8000;

type Outcome = {
  chain: string;
  url: string;
  ok: boolean;
  ms: number;
  reason: string;
};

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status} ${text.slice(0, 80).replace(/\s+/g, ' ')}`);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`not JSON: ${text.slice(0, 60).replace(/\s+/g, ' ')}`);
  }
}

async function jsonRpc(url: string, method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = (await readJson(res)) as { result?: unknown; error?: { message?: string } };
  if (body.error) throw new Error(`rpc error: ${body.error.message ?? JSON.stringify(body.error)}`);
  if (!('result' in body)) throw new Error('no result in envelope');
  return body.result;
}

async function getJson(url: string): Promise<unknown> {
  const res = await fetchWithTimeout(url, {
    method: 'GET',
    headers: { accept: 'application/json' },
  });
  return readJson(res);
}

async function getText(url: string): Promise<string> {
  const res = await fetchWithTimeout(url, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status} ${text.slice(0, 80).replace(/\s+/g, ' ')}`);
  return text;
}

async function verify(chain: ChainInfo, url: string): Promise<string | undefined> {
  const base = url.replace(/\/$/, '');
  switch (chain.family) {
    case 'evm': {
      const expected = BigInt(chain.chainId.slice('eip155:'.length));
      const got = await jsonRpc(url, 'eth_chainId');
      if (typeof got !== 'string' || !/^0x[0-9a-fA-F]+$/.test(got)) {
        return `eth_chainId returned ${JSON.stringify(got)}`;
      }
      if (BigInt(got) !== expected)
        return `WRONG CHAIN: eth_chainId=${BigInt(got)} want ${expected}`;
      return undefined;
    }
    case 'solana': {
      const got = await jsonRpc(url, 'getGenesisHash');
      const prefix = chain.chainId.slice('solana:'.length);
      if (typeof got !== 'string' || got.slice(0, 32) !== prefix)
        return `WRONG CHAIN: genesis=${String(got)} want ${prefix}...`;
      return undefined;
    }
    case 'cosmos': {
      const expected = chain.chainId.slice('cosmos:'.length);
      const body = (await getJson(`${base}/cosmos/base/tendermint/v1beta1/node_info`)) as {
        default_node_info?: { network?: string };
      };
      const got = body.default_node_info?.network;
      if (got !== expected) return `WRONG CHAIN: network=${String(got)} want ${expected}`;
      return undefined;
    }
    case 'bitcoin': {
      const text = (await getText(`${base}/blocks/tip/height`)).trim();
      if (!/^[0-9]+$/.test(text)) return `tip height not an integer: ${text.slice(0, 40)}`;
      return undefined;
    }
  }
}

async function probe(chain: ChainInfo, url: string): Promise<Outcome> {
  const started = Date.now();
  try {
    const reason = await verify(chain, url);
    return {
      chain: chain.chainId,
      url,
      ok: reason === undefined,
      ms: Date.now() - started,
      reason: reason ?? '',
    };
  } catch (error) {
    const e = error as Error & { cause?: { code?: string; message?: string } };
    const detail =
      e.name === 'AbortError'
        ? `timeout after ${TIMEOUT_MS}ms`
        : e.cause?.code
          ? `${e.message} (${e.cause.code})`
          : e.cause?.message
            ? `${e.message} (${e.cause.message})`
            : e.message;
    return { chain: chain.chainId, url, ok: false, ms: Date.now() - started, reason: detail };
  }
}

async function main(): Promise<void> {
  const asJson = process.argv.includes('--json');
  const jobs: Promise<Outcome>[] = [];
  for (const chain of CHAIN_CATALOG) {
    for (const url of chain.defaultRpcs) jobs.push(probe(chain, url));
  }
  const outcomes = await Promise.all(jobs);

  if (asJson) {
    console.log(JSON.stringify(outcomes, null, 2));
    return;
  }

  const w1 = Math.max(...outcomes.map((o) => o.chain.length), 5);
  const w2 = Math.max(...outcomes.map((o) => o.url.length), 3);
  console.log(`${'chain'.padEnd(w1)}  ${'url'.padEnd(w2)}  ok    ms     reason`);
  for (const o of outcomes) {
    console.log(
      `${o.chain.padEnd(w1)}  ${o.url.padEnd(w2)}  ${o.ok ? 'ok  ' : 'FAIL'}  ${String(o.ms).padStart(5)}  ${o.reason}`,
    );
  }
  const failed = outcomes.filter((o) => !o.ok);
  console.log(`\n${outcomes.length - failed.length}/${outcomes.length} endpoints ok`);
  const uncovered = CHAIN_CATALOG.filter(
    (c) => c.defaultRpcs.length > 0 && !outcomes.some((o) => o.chain === c.chainId && o.ok),
  );
  if (uncovered.length > 0) {
    console.log(`chains with no working endpoint: ${uncovered.map((c) => c.chainId).join(', ')}`);
  }
}

await main();
