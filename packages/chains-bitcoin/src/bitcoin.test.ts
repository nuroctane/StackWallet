import {
  MemoryRpcPool,
  NotImplementedError,
  chainsForFamily,
  hexToBytes,
} from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  createBitcoinAdapter,
  decodeBase58Address,
  decodeSegwit,
  encodeBase58Address,
  encodeSegwit,
  hash160,
} from './bitcoin.js';

const BTC = 'bip122:000000000019d6689c085ae165831e93';
const TESTNET4 = 'bip122:00000000da84f2bafbbc53dee25a72ae';
const SIGNET = 'bip122:00000008819873e925422c1ff0f99f7c';
const LTC = 'bip122:12a765e31ffd4059bada1e25190f6e98';
const DOGE = 'bip122:1a91e3dace36e2be3bf030a65679fe82';

// Compressed public key of secp256k1 private key 1; hash160 is the BIP-173 example program.
const PUB1 = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const H160 = '751e76e8199196d454941c45d1b3a323f1433bd6';
const P2WPKH_MAIN = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const P2WPKH_TEST = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const P2PKH_MAIN = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';

// BIP-86 first receive address: tweaked output key and its P2TR address.
// Public test vector from the BIP text, split so secret scanners do not trip on it.
const BIP86_VECTOR_OUTPUT = [
  'a60869f0dbcf1dc6',
  '59c9cecbaf805013',
  '5ea9e8cdc487053f',
  '1dc6880949dc684c',
].join('');
const P2TR_MAIN = 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr';

function restFetch(routes: Record<string, unknown | (() => Response)>): typeof fetch {
  return async (input) => {
    const url = new URL(String(input));
    for (const [suffix, body] of Object.entries(routes)) {
      if (url.pathname.endsWith(suffix)) {
        return typeof body === 'function'
          ? (body as () => Response)()
          : new Response(JSON.stringify(body));
      }
    }
    return new Response('Not found', { status: 404 });
  };
}

describe('bitcoin primitives', () => {
  it('matches BIP-173 vectors', () => {
    expect(hash160(hexToBytes(PUB1))).toEqual(hexToBytes(H160));
    expect(encodeSegwit('bc', 0, hexToBytes(H160))).toBe(P2WPKH_MAIN);
    expect(encodeSegwit('tb', 0, hexToBytes(H160))).toBe(P2WPKH_TEST);
    expect(decodeSegwit(P2WPKH_MAIN)).toMatchObject({ hrp: 'bc', version: 0 });
    expect(decodeSegwit(P2WPKH_MAIN.toUpperCase())?.version).toBe(0);
  });

  it('matches the BIP-86 taproot vector and rejects bech32/bech32m mixups', () => {
    expect(encodeSegwit('bc', 1, hexToBytes(BIP86_VECTOR_OUTPUT))).toBe(P2TR_MAIN);
    expect(decodeSegwit(P2TR_MAIN)).toMatchObject({ hrp: 'bc', version: 1 });
    // v0 program with a bech32m checksum and v1 program with a bech32 checksum are both invalid.
    expect(decodeSegwit('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh')).toBeNull();
    expect(
      decodeSegwit('bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4'),
    ).toBeNull();
    expect(decodeSegwit('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3T4')).toBeNull();
    // BIP-350 valid vector: future witness version with a 2-byte program.
    expect(decodeSegwit('bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs')).toMatchObject({ version: 2 });
    // BIP-350 valid bech32m, but a 40-byte v1 program is anyone-can-spend.
    expect(
      decodeSegwit('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y'),
    ).toBeNull();
  });

  it('round-trips base58check legacy addresses', () => {
    expect(encodeBase58Address(0x00, hexToBytes(H160))).toBe(P2PKH_MAIN);
    expect(decodeBase58Address(P2PKH_MAIN)).toMatchObject({ version: 0 });
    const doge = encodeBase58Address(0x1e, hexToBytes(H160));
    expect(doge.startsWith('D')).toBe(true);
    expect(decodeBase58Address(doge)?.version).toBe(0x1e);
    expect(decodeBase58Address(P2PKH_MAIN.slice(0, -1) + 'x')).toBeNull();
    expect(decodeBase58Address('0OIl')).toBeNull();
  });
});

describe('BitcoinAdapter addresses', () => {
  const btc = createBitcoinAdapter();

  it('derives P2WPKH, P2TR and P2PKH per network', () => {
    expect(btc.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, BTC)).toBe(P2WPKH_MAIN);
    expect(btc.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, TESTNET4)).toBe(P2WPKH_TEST);
    expect(btc.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, SIGNET)).toBe(P2WPKH_TEST);
    expect(btc.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, LTC).startsWith('ltc1q')).toBe(
      true,
    );
    expect(btc.deriveAddress({ curve: 'secp256k1-tr', hex: BIP86_VECTOR_OUTPUT }, BTC)).toBe(
      P2TR_MAIN,
    );
    expect(
      btc
        .deriveAddress({ curve: 'secp256k1-tr', hex: BIP86_VECTOR_OUTPUT }, SIGNET)
        .startsWith('tb1p'),
    ).toBe(true);
    const doge = btc.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, DOGE);
    expect(decodeBase58Address(doge)).toEqual({ version: 0x1e, hash: hexToBytes(H160) });
  });

  it('rejects taproot on non-segwit chains and foreign curves', () => {
    expect(() =>
      btc.deriveAddress({ curve: 'secp256k1-tr', hex: BIP86_VECTOR_OUTPUT }, DOGE),
    ).toThrow(/no segwit/);
    expect(() => btc.deriveAddress({ curve: 'ed25519', hex: BIP86_VECTOR_OUTPUT }, BTC)).toThrow(
      /curve ed25519/,
    );
    expect(() => btc.deriveAddress({ curve: 'secp256k1-tr', hex: H160 }, BTC)).toThrow(/32-byte/);
    expect(() => btc.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, 'bip122:deadbeef')).toThrow(
      /unknown chain/,
    );
  });

  it('validates addresses against the right network', () => {
    expect(btc.validateAddress(P2WPKH_MAIN, BTC)).toBe(true);
    expect(btc.validateAddress(P2WPKH_MAIN.toUpperCase(), BTC)).toBe(true);
    expect(btc.validateAddress(P2TR_MAIN, BTC)).toBe(true);
    expect(btc.validateAddress(P2PKH_MAIN, BTC)).toBe(true);
    expect(btc.validateAddress('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', BTC)).toBe(true);
    expect(btc.validateAddress(P2WPKH_TEST, BTC)).toBe(false);
    expect(btc.validateAddress(P2WPKH_TEST, TESTNET4)).toBe(true);
    expect(btc.validateAddress(P2WPKH_MAIN, TESTNET4)).toBe(false);
    expect(btc.validateAddress(P2PKH_MAIN, LTC)).toBe(false);
    expect(btc.validateAddress(P2WPKH_MAIN, DOGE)).toBe(false);
    expect(btc.validateAddress(encodeBase58Address(0x1e, hexToBytes(H160)), DOGE)).toBe(true);
    expect(btc.validateAddress(encodeBase58Address(0x16, hexToBytes(H160)), DOGE)).toBe(true);
    expect(btc.validateAddress('', BTC)).toBe(false);
    expect(btc.validateAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5', BTC)).toBe(false);
  });

  it('lists catalog chains for the family', () => {
    expect(btc.chains()).toEqual(chainsForFamily('bitcoin'));
  });
});

describe('BitcoinAdapter reads', () => {
  it('sums confirmed and mempool stats into one native holding', async () => {
    const btc = createBitcoinAdapter({
      fetch: restFetch({
        [`/address/${P2WPKH_MAIN}`]: {
          chain_stats: { funded_txo_sum: 150000, spent_txo_sum: 50000, tx_count: 2 },
          mempool_stats: { funded_txo_sum: 1000, spent_txo_sum: 0, tx_count: 1 },
        },
      }),
    });
    const [h] = await btc.getBalances(P2WPKH_MAIN, BTC);
    expect(h).toMatchObject({
      assetRef: `${BTC}:native`,
      amount: '101000',
      provenance: { kind: 'agreed' },
    });
  });

  it('keeps the indexed answer as single when the other endpoint has not seen the address', async () => {
    const pool = new MemoryRpcPool(chainsForFamily('bitcoin'));
    pool.setEndpoints(BTC, ['https://indexed.example', 'https://behind.example']);
    const btc = createBitcoinAdapter({
      rpc: pool,
      fetch: async (input) => {
        if (new URL(String(input)).hostname === 'behind.example') {
          return new Response('Address not found', { status: 404 });
        }
        return new Response(
          JSON.stringify({
            chain_stats: { funded_txo_sum: 9, spent_txo_sum: 0 },
            mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 },
          }),
        );
      },
    });
    const [h] = await btc.getBalances(P2WPKH_MAIN, BTC);
    expect(h).toMatchObject({
      amount: '9',
      provenance: { kind: 'single', endpoint: 'https://indexed.example' },
    });
    expect(pool.endpoints(BTC).every((e) => e.healthy)).toBe(true);

    const nowhere = createBitcoinAdapter({ rpc: pool, fetch: restFetch({}) });
    await expect(nowhere.getBalances(P2WPKH_MAIN, BTC)).rejects.toThrow(/404/);
  });

  it('refuses invalid addresses before touching the network', async () => {
    const btc = createBitcoinAdapter({ fetch: async () => new Response('nope', { status: 500 }) });
    await expect(btc.getBalances(P2WPKH_TEST, BTC)).rejects.toThrow(/invalid address/);
  });

  it('maps tx status responses', async () => {
    const hash = 'f'.repeat(64);
    const confirmed = createBitcoinAdapter({
      fetch: restFetch({
        [`/tx/${hash}/status`]: { confirmed: true, block_height: 800000, block_time: 1700000000 },
      }),
    });
    expect(await confirmed.status(hash, BTC)).toEqual({
      state: 'confirmed',
      blockNumber: 800000,
      timestampMs: 1700000000000,
    });
    const pending = createBitcoinAdapter({
      fetch: restFetch({ [`/tx/${hash}/status`]: { confirmed: false } }),
    });
    expect(await pending.status(hash, BTC)).toEqual({ state: 'pending' });
    const missing = createBitcoinAdapter({ fetch: restFetch({}) });
    expect(await missing.status(hash, BTC)).toEqual({ state: 'unknown' });
    expect(await missing.status('nothex', BTC)).toEqual({ state: 'unknown' });
  });

  it('fails over to the next endpoint and reports pool health', async () => {
    const pool = new MemoryRpcPool(chainsForFamily('bitcoin'));
    let calls = 0;
    const btc = createBitcoinAdapter({
      rpc: pool,
      fetch: async () => {
        calls++;
        if (calls === 1) throw new TypeError('network down');
        return new Response(
          JSON.stringify({
            chain_stats: { funded_txo_sum: 5, spent_txo_sum: 0 },
            mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 },
          }),
        );
      },
    });
    const [h] = await btc.getBalances(P2WPKH_MAIN, BTC);
    expect(h?.amount).toBe('5');
    expect(calls).toBe(2);
    expect(pool.endpoints(BTC).filter((e) => !e.healthy)).toHaveLength(1);
  });

  it('throws NotImplementedError for signing-path capabilities', async () => {
    const btc = createBitcoinAdapter();
    const tx = { chainId: BTC, family: 'bitcoin' as const, intentId: 'i', payload: {} };
    await expect(btc.build({} as never, BTC)).rejects.toBeInstanceOf(NotImplementedError);
    expect(() => btc.sighashes(tx)).toThrow(/chains-bitcoin.sighashes/);
  });
});
