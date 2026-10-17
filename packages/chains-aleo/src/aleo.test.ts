import { MemoryRpcPool, UnsupportedKeyError, type ChainInfo } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  ALEO_CHAINS,
  ALEO_GENESIS,
  ALEO_MAINNET,
  ALEO_TESTNET,
  AleoAdapter,
  aleoAddressBytes,
  aleoAddressFromPayload,
  createAleoAdapter,
  isValidAleoAddress,
} from './aleo.js';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));
const bytesToHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

// `@provablehq/sdk` vectors (`.nur/aleo-oracle/vectors.mjs`); the Rust core
// (`aleo.rs`) pins the same bytes.
const ADDR_ZEROS = 'aleo136hx49mdevlqlnrlkhr2alxwn45qtpxv64jwrzk4rv39sclw6yxsms49ms';
const PAYLOAD_ZEROS = '8eae6a976dcb3e0fcc7fb5c6aefcce9d680584ccd564e18ad51b225863eed10d';
const ADDR_ONES = 'aleo1fagxe9lxaxektcnqfz4vpp0f9w7muxvwmrprepus8tve4h9fyyzq80pwu5';
const PAYLOAD_ONES = '4f506c97e6e9b365e26048aac085e92bbdbe198ed8c23c87903ad99adca92104';
const ADDR_SEQ = 'aleo1nxl6ymg85vyh3z5y486rp82cgkeyvun8qwqxdncl8489s9ht55qqqc6fll';
const ADDR_SEVENS = 'aleo1vlklqexj7vrs3vrw77agv5cxucqje6yuuu6lyvgteww3utzlnvrszhlqty';
const ZERO_ADDRESS = 'aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc';
const TXID = 'at1zkpde5rsukkekjd44vymy0m6t9jnw9zl4pzkczjzlm2m2m56uyxqdwx3yq';

const RPC_A = 'https://rpc-a.test';
const RPC_B = 'https://rpc-b.test';

const CHAINS: ChainInfo[] = [{ ...ALEO_CHAINS[0]!, defaultRpcs: [RPC_A, RPC_B] }];

type Route = (url: URL) => Response;

function node(net: string, routes: Record<string, Route>, genesis = ALEO_GENESIS[ALEO_MAINNET]!) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    calls.push(url.pathname);
    if (url.pathname === `/v1/${net}/block/0`) return Response.json({ block_hash: genesis });
    if (url.pathname === `/v1/${net}/latest/height`) return Response.json(20_554_425);
    const route = routes[url.pathname];
    if (!route) return Response.json({ statusCode: 404, message: 'Not Found' }, { status: 404 });
    return route(url);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const adapter = (fetchImpl: typeof fetch) =>
  new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });

class TestAdapter extends AleoAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

describe('aleo addresses', () => {
  it('matches the @provablehq/sdk vectors byte for byte', () => {
    expect(aleoAddressFromPayload(hexToBytes(PAYLOAD_ZEROS))).toBe(ADDR_ZEROS);
    expect(aleoAddressFromPayload(hexToBytes(PAYLOAD_ONES))).toBe(ADDR_ONES);
    expect(aleoAddressFromPayload(new Uint8Array(32))).toBe(ZERO_ADDRESS);
  });
  it('round-trips and validates by checksum', () => {
    expect(bytesToHex(aleoAddressBytes(ADDR_ZEROS)!)).toBe(PAYLOAD_ZEROS);
    expect(isValidAleoAddress(ADDR_SEQ)).toBe(true);
    expect(isValidAleoAddress(ADDR_SEVENS)).toBe(true);
    expect(isValidAleoAddress(ZERO_ADDRESS)).toBe(true);
  });
  it('rejects malformed and non-canonical spellings', () => {
    expect(isValidAleoAddress(ADDR_ZEROS.slice(0, -1))).toBe(false);
    expect(isValidAleoAddress(ADDR_ZEROS.toUpperCase())).toBe(false);
    expect(isValidAleoAddress(`${ADDR_ZEROS.slice(0, 10)}x${ADDR_ZEROS.slice(11)}`)).toBe(false);
    // bech32 (not bech32m) spelling of a payload must fail
    expect(isValidAleoAddress('aleo1q' + ADDR_ZEROS.slice(6, -1) + 'q')).toBe(false);
    expect(() => aleoAddressFromPayload(new Uint8Array(32).fill(0xff))).toThrow();
  });
  it('cannot derive from any key the core holds', () => {
    const a = adapter(node('mainnet', {}).fetchImpl);
    expect(() => a.deriveAddress({ curve: 'ed25519', hex: '11'.repeat(32) }, ALEO_MAINNET)).toThrow(
      UnsupportedKeyError,
    );
  });
});

describe('aleo balances', () => {
  it('reads the public credits.aleo mapping, cross-checked across endpoints', async () => {
    const routes = {
      [`/v2/mainnet/program/credits.aleo/mapping/account/${ADDR_ZEROS}`]: () =>
        Response.json('1234567u64'),
    };
    const { fetchImpl } = node('mainnet', routes);
    const holdings = await adapter(fetchImpl).getBalances(ADDR_ZEROS, ALEO_MAINNET);
    expect(holdings[0]!.amount).toBe('1234567');
    expect(holdings[0]!.assetRef).toBe(`${ALEO_MAINNET}:native`);
  });
  it('reports zero for an unfunded address (null mapping)', async () => {
    const routes = {
      [`/v2/mainnet/program/credits.aleo/mapping/account/${ADDR_ONES}`]: () => Response.json(null),
    };
    const holdings = await adapter(node('mainnet', routes).fetchImpl).getBalances(
      ADDR_ONES,
      ALEO_MAINNET,
    );
    expect(holdings[0]!.amount).toBe('0');
  });
  it('rejects an endpoint on the wrong network', async () => {
    const routes = {
      [`/v2/mainnet/program/credits.aleo/mapping/account/${ADDR_ZEROS}`]: () =>
        Response.json('1u64'),
    };
    const { fetchImpl } = node('mainnet', routes, ALEO_GENESIS[ALEO_TESTNET]!);
    await expect(adapter(fetchImpl).getBalances(ADDR_ZEROS, ALEO_MAINNET)).rejects.toThrow();
  });
  it('rejects invalid addresses', async () => {
    await expect(
      adapter(node('mainnet', {}).fetchImpl).getBalances(ADDR_ZEROS.toUpperCase(), ALEO_MAINNET),
    ).rejects.toThrow();
  });
});

describe('aleo status', () => {
  it('confirms an executed transaction', async () => {
    const routes = {
      [`/v1/mainnet/transaction/${TXID}`]: () =>
        Response.json({ type: 'execute', execution: { transitions: [] } }),
      [`/v1/mainnet/find/blockHash/${TXID}`]: () =>
        Response.json('ab15vur27e0x4ladzxxqmudd6mpcmujdd9fhw24pg63k85atyxmpypsavragd'),
      '/v1/mainnet/height/ab15vur27e0x4ladzxxqmudd6mpcmujdd9fhw24pg63k85atyxmpypsavragd': () =>
        Response.json(22_877_372),
    };
    const s = await adapter(node('mainnet', routes).fetchImpl).status(TXID, ALEO_MAINNET);
    expect(s).toEqual({ state: 'confirmed', blockNumber: 22_877_372 });
  });
  it('flags a fee-only transaction as failed', async () => {
    const routes = {
      [`/v1/mainnet/transaction/${TXID}`]: () => Response.json({ type: 'rejected', fee: {} }),
    };
    const s = await adapter(node('mainnet', routes).fetchImpl).status(TXID, ALEO_MAINNET);
    expect(s.state).toBe('failed');
  });
  it('reports absent ids as unknown and rejects malformed ids', async () => {
    const a = adapter(node('mainnet', {}).fetchImpl);
    expect((await a.status(TXID, ALEO_MAINNET)).state).toBe('unknown');
    await expect(a.status('0x' + 'ab'.repeat(32), ALEO_MAINNET)).rejects.toThrow();
  });
});

describe('aleo misc', () => {
  it('reports the history gap instead of failing', async () => {
    const page = await adapter(node('mainnet', {}).fetchImpl).getHistory(ADDR_ZEROS, ALEO_MAINNET);
    expect(page.items).toEqual([]);
    expect(page.coverage).toMatch(/history/);
  });
  it('exposes the chain ids, genesis hashes and factory', () => {
    expect(ALEO_MAINNET).toBe('aleo:mainnet');
    expect(ALEO_TESTNET).toBe('aleo:testnet');
    expect(ALEO_GENESIS[ALEO_MAINNET]).toMatch(/^ab1/);
    expect(createAleoAdapter({ rpc: new MemoryRpcPool(CHAINS) }).chains()[0]!.chainId).toBe(
      ALEO_MAINNET,
    );
  });
  it('reads the latest height', async () => {
    const height = await adapter(node('mainnet', {}).fetchImpl).latestHeight(ALEO_MAINNET);
    expect(height).toBe(20_554_425);
  });
});
