import { MemoryRpcPool, UnsupportedKeyError, type ChainInfo } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  GAS_TOKEN,
  NEO3_MAGIC,
  NEO3_MAINNET,
  NEO3_TESTNET,
  NEO_TOKEN,
  NeoAdapter,
  createNeoAdapter,
  isValidNeoAddress,
  neoAddressFromPublicKey,
  neoAddressToScriptHashHex,
  neoVerificationScriptHex,
} from './neo.js';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

// `@cityofzion/neon-core` 5.10.1 vectors (run in .nur/neo-scratch/oracle.mjs);
// the Rust core (`neo.rs`) pins the same bytes.
const PUB_ONE = '036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296';
const VS_ONE = `0c21${PUB_ONE}4156e7b327`;
const ADDR_ONE = 'NVHt5YtAnadMwntAVAJLUy36M2nLYKHUeK';
// Raw hash160 of the verification script (the byte reversal of neon-core's
// display form 7efe7ee0d3e349e085388c351955e5172605de66).
const SCRIPTHASH_ONE = '0x66de052617e55519358c3885e049e3d3e07efe7e';
const PUB_TWO = '02d3d9c0ca31fdaf9e9151d5f1c56fb273f068d3db515fa99101ab00609ccaf5dd';
const ADDR_TWO = 'NXTTm4Y92jbKRgw7yB2rnDF1kGi9m5uHrF';

const RPC_A = 'https://rpc-a.test';
const RPC_B = 'https://rpc-b.test';

const CHAINS: ChainInfo[] = [
  {
    chainId: NEO3_MAINNET,
    family: 'neo',
    name: 'NEO N3',
    nativeAsset: { ref: `${NEO3_MAINNET}:native`, symbol: 'NEO', decimals: 0 },
    testnet: false,
    defaultRpcs: [RPC_A, RPC_B],
  },
  {
    chainId: NEO3_TESTNET,
    family: 'neo',
    name: 'NEO N3 Testnet',
    nativeAsset: { ref: `${NEO3_TESTNET}:native`, symbol: 'NEO', decimals: 0 },
    testnet: true,
    defaultRpcs: [RPC_A, RPC_B],
  },
];

class TestAdapter extends NeoAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type JsonRpc = { method: string; params: unknown[] };

function node(routes: Record<string, (params: unknown[]) => unknown>, magic = 894710606) {
  const calls: JsonRpc[] = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as JsonRpc;
    calls.push(body);
    if (body.method === 'getversion')
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: { protocol: { addressversion: 53, network: magic } },
      });
    const route = routes[body.method];
    if (!route)
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        error: { code: -32601, message: 'Method not found' },
      });
    const out = route(body.params);
    if (out instanceof Error)
      return Response.json({ jsonrpc: '2.0', id: 1, error: { code: -103, message: out.message } });
    return Response.json({ jsonrpc: '2.0', id: 1, result: out });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const adapter = (fetchImpl: typeof fetch) =>
  new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });

describe('neo addresses', () => {
  it('matches the neon-core vectors byte for byte', () => {
    expect(neoVerificationScriptHex(hexToBytes(PUB_ONE))).toBe(VS_ONE);
    expect(neoAddressFromPublicKey(hexToBytes(PUB_ONE))).toBe(ADDR_ONE);
    expect(neoAddressFromPublicKey(hexToBytes(PUB_TWO))).toBe(ADDR_TWO);
    // script hash is the raw hash160 of the verification script, big-endian hex.
    expect(neoAddressToScriptHashHex(ADDR_ONE)).toMatch(/^0x[0-9a-f]{40}$/);
    expect(neoAddressToScriptHashHex(ADDR_ONE)).toBe(SCRIPTHASH_ONE);
  });

  it('validates syntactically and by checksum', () => {
    expect(isValidNeoAddress(ADDR_ONE)).toBe(true);
    expect(isValidNeoAddress(ADDR_TWO)).toBe(true);
    expect(isValidNeoAddress(ADDR_ONE.slice(0, 33))).toBe(false);
    expect(isValidNeoAddress(`O${ADDR_ONE.slice(1)}`)).toBe(false); // wrong version byte
    expect(isValidNeoAddress(`${ADDR_ONE.slice(0, 10)}x${ADDR_ONE.slice(11)}`)).toBe(false);
  });

  it('rejects malformed public keys', () => {
    expect(() => neoAddressFromPublicKey(new Uint8Array(32))).toThrow();
    const offCurve = hexToBytes(PUB_ONE);
    offCurve[32] = offCurve[32]! ^ 0xff;
    expect(() => neoAddressFromPublicKey(offCurve)).toThrow();
  });

  it('cannot derive from any key the core holds', () => {
    const a = new TestAdapter();
    expect(() => a.deriveAddress({ curve: 'secp256k1', hex: PUB_ONE }, NEO3_TESTNET)).toThrow(
      UnsupportedKeyError,
    );
    expect(createNeoAdapter()).toBeInstanceOf(NeoAdapter);
    expect(a.validateAddress(ADDR_ONE, NEO3_TESTNET)).toBe(true);
  });
});

describe('neo balances', () => {
  const balances = (neo: string, gas: string) => ({
    getnep17balances: () => ({
      balance: [
        { assethash: NEO_TOKEN, amount: neo, decimals: '0', name: 'NEO', symbol: 'NEO' },
        { assethash: GAS_TOKEN, amount: gas, decimals: '8', name: 'GAS', symbol: 'GAS' },
      ],
      address: ADDR_ONE,
    }),
  });

  it('reads NEO and GAS, cross-checked across endpoints', async () => {
    const { fetchImpl, calls } = node(balances('12', '34500000000'));
    const holdings = await adapter(fetchImpl).getBalances(ADDR_ONE, NEO3_TESTNET);
    expect(holdings[0]).toMatchObject({
      assetRef: `${NEO3_TESTNET}:native`,
      amount: '12',
      provenance: { kind: 'agreed' },
    });
    expect(holdings[1]).toMatchObject({ amount: '34500000000', metadata: { symbol: 'GAS' } });
    expect(calls.filter((c) => c.method === 'getversion')).toHaveLength(2);
    expect(calls.filter((c) => c.method === 'getnep17balances')).toHaveLength(2);
  });

  it('reports zero for an address with no tokens', async () => {
    const { fetchImpl } = node(balances('0', '0'));
    const holdings = await adapter(fetchImpl).getBalances(ADDR_ONE, NEO3_TESTNET);
    expect(holdings.map((h) => h.amount)).toEqual(['0', '0']);
  });

  it('rejects an endpoint on the wrong network', async () => {
    const { fetchImpl } = node(balances('1', '1'), NEO3_MAGIC[NEO3_MAINNET]); // mainnet magic on testnet query
    await expect(adapter(fetchImpl).getBalances(ADDR_ONE, NEO3_TESTNET)).rejects.toThrow(/network/);
  });

  it('rejects invalid addresses', async () => {
    const { fetchImpl } = node(balances('0', '0'));
    await expect(adapter(fetchImpl).getBalances('nonsense', NEO3_TESTNET)).rejects.toThrow(
      /invalid neo address/,
    );
  });
});

describe('neo status', () => {
  const HASH = `0x${'ab'.repeat(32)}`;

  it('confirms a HALTed transaction with its block', async () => {
    const { fetchImpl } = node({
      gettransactionheight: () => 20244251,
      getrawtransaction: () => ({ vmstate: 'HALT', blocktime: 1760000000000 }),
    });
    const status = await adapter(fetchImpl).status(HASH, NEO3_TESTNET);
    expect(status).toEqual({
      state: 'confirmed',
      blockNumber: 20244251,
      timestampMs: 1760000000000,
    });
  });

  it('reports a FAULTed transaction as failed', async () => {
    const { fetchImpl } = node({
      gettransactionheight: () => 20244251,
      getrawtransaction: () => ({ vmstate: 'FAULT' }),
    });
    expect(await adapter(fetchImpl).status(HASH, NEO3_TESTNET)).toMatchObject({ state: 'failed' });
  });

  it('sees mempool transactions as pending and absent ones as unknown', async () => {
    const pending = node({
      gettransactionheight: () => new Error('Unknown transaction'),
      getrawmempool: () => [HASH],
    });
    expect(await adapter(pending.fetchImpl).status(HASH, NEO3_TESTNET)).toEqual({
      state: 'pending',
    });
    const absent = node({
      gettransactionheight: () => new Error('Unknown transaction'),
      getrawmempool: () => [],
    });
    expect(await adapter(absent.fetchImpl).status(HASH, NEO3_TESTNET)).toEqual({
      state: 'unknown',
    });
  });

  it('rejects malformed hashes', async () => {
    const { fetchImpl } = node({});
    await expect(adapter(fetchImpl).status('0x1234', NEO3_TESTNET)).rejects.toThrow(/Invalid/);
  });
});

describe('neo history', () => {
  it('reports the indexer gap instead of failing', async () => {
    const { fetchImpl } = node({});
    const page = await adapter(fetchImpl).getHistory(ADDR_ONE, NEO3_TESTNET);
    expect(page.items).toEqual([]);
    expect(page.coverage).toMatch(/indexer/);
  });
});
