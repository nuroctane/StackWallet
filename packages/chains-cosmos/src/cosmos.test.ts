import { bech32 } from '@scure/base';
import {
  MemoryRpcPool,
  NotImplementedError,
  chainsForFamily,
  hexToBytes,
} from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  assetRefForDenom,
  cosmosAccountBytes,
  createCosmosAdapter,
  encodeCosmosAddress,
  isValidCosmosAddress,
} from './cosmos.js';

const HUB = 'cosmos:cosmoshub-4';
const OSMO = 'cosmos:osmosis-1';
const INJ = 'cosmos:injective-1';
const DYDX = 'cosmos:dydx-mainnet-1';

// secp256k1 private key 1: compressed key, its hash160, and the keccak-derived EVM-style account id.
const PUB1 = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const H160 = '751e76e8199196d454941c45d1b3a323f1433bd6';
const ETH20 = '7e5f4552091a69125d5dfcb7b8c2659029395bdf';

const expectBech32 = (prefix: string, hex: string) =>
  bech32.encode(prefix, bech32.toWords(hexToBytes(hex)));

function restFetch(
  handler: (url: URL) => unknown | Response,
  network = 'cosmoshub-4',
): typeof fetch {
  return async (input) => {
    const url = new URL(String(input));
    const out = url.pathname.endsWith('/node_info')
      ? { default_node_info: { network } }
      : handler(url);
    return out instanceof Response ? out : new Response(JSON.stringify(out));
  };
}

describe('cosmos primitives', () => {
  it('derives account bytes under both address algorithms', () => {
    expect(cosmosAccountBytes(hexToBytes(PUB1), 'secp256k1')).toEqual(hexToBytes(H160));
    expect(cosmosAccountBytes(hexToBytes(PUB1), 'ethsecp256k1')).toEqual(hexToBytes(ETH20));
  });

  it('maps denoms to asset refs', () => {
    expect(assetRefForDenom(HUB, 'uatom', 'uatom')).toBe(`${HUB}:native`);
    expect(
      assetRefForDenom(
        OSMO,
        'uosmo',
        'ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2',
      ),
    ).toBe(`${OSMO}:ibc:27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2`);
    expect(assetRefForDenom(OSMO, 'uosmo', 'factory/osmo1abc/utoken')).toBe(
      `${OSMO}:factory:osmo1abc/utoken`,
    );
    expect(assetRefForDenom(OSMO, 'uosmo', 'uion')).toBe(`${OSMO}:native:uion`);
  });
});

describe('CosmosAdapter addresses', () => {
  const cosmos = createCosmosAdapter();

  it('derives bech32 addresses with the chain prefix', () => {
    expect(cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, HUB)).toBe(
      expectBech32('cosmos', H160),
    );
    expect(cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, OSMO)).toBe(
      expectBech32('osmo', H160),
    );
    expect(cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, DYDX)).toBe(
      expectBech32('dydx', H160),
    );
    expect(cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, INJ)).toBe(
      expectBech32('inj', ETH20),
    );
    expect(cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, HUB).startsWith('cosmos1')).toBe(
      true,
    );
  });

  it('rejects other curves and unknown chains', () => {
    expect(() => cosmos.deriveAddress({ curve: 'ed25519', hex: PUB1 }, HUB)).toThrow(
      /curve ed25519/,
    );
    expect(() =>
      cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, 'cosmos:nowhere-1'),
    ).toThrow(/unknown chain/);
  });

  it('validates prefix and payload length', () => {
    const hub = cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, HUB);
    const osmo = cosmos.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, OSMO);
    expect(cosmos.validateAddress(hub, HUB)).toBe(true);
    expect(cosmos.validateAddress(osmo, HUB)).toBe(false);
    expect(cosmos.validateAddress(osmo, OSMO)).toBe(true);
    expect(cosmos.validateAddress(hub.slice(0, -1) + (hub.endsWith('q') ? 'p' : 'q'), HUB)).toBe(
      false,
    );
    expect(cosmos.validateAddress(hub.toUpperCase(), HUB)).toBe(true);
    expect(cosmos.validateAddress(hub.slice(0, 10) + hub.slice(10).toUpperCase(), HUB)).toBe(false);
    expect(isValidCosmosAddress(encodeCosmosAddress('cosmos', new Uint8Array(32)), 'cosmos')).toBe(
      true,
    );
    expect(isValidCosmosAddress(encodeCosmosAddress('cosmos', new Uint8Array(21)), 'cosmos')).toBe(
      false,
    );
    expect(isValidCosmosAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', 'cosmos')).toBe(
      false,
    );
    expect(isValidCosmosAddress('', 'cosmos')).toBe(false);
    expect(cosmos.chains()).toEqual(chainsForFamily('cosmos'));
  });
});

describe('CosmosAdapter reads', () => {
  const hubAddr = expectBech32('cosmos', H160);
  it('rejects a foreign network before reading bank balances', async () => {
    const paths: string[] = [];
    const cosmos = createCosmosAdapter({
      fetch: async (input) => {
        paths.push(new URL(String(input)).pathname);
        return new Response(JSON.stringify({ default_node_info: { network: 'osmosis-1' } }));
      },
    });
    await expect(cosmos.getBalances(hubAddr, HUB)).rejects.toThrow(/network/);
    expect(paths.every((path) => path.endsWith('/node_info'))).toBe(true);
  });

  it('reads bank balances and maps denoms', async () => {
    const cosmos = createCosmosAdapter({
      fetch: restFetch((url) => {
        expect(url.pathname).toBe(`/cosmos/bank/v1beta1/balances/${hubAddr}`);
        return {
          balances: [
            { denom: 'uatom', amount: '1500000' },
            { denom: 'ibc/ABC123', amount: '42' },
          ],
          pagination: { next_key: null, total: '2' },
        };
      }),
    });
    const holdings = await cosmos.getBalances(hubAddr, HUB);
    expect(holdings.map((h) => [h.assetRef, h.amount])).toEqual([
      [`${HUB}:native`, '1500000'],
      [`${HUB}:ibc:ABC123`, '42'],
    ]);
  });

  it('narrows a disagreement to the denoms that actually differ', async () => {
    const pool = new MemoryRpcPool(chainsForFamily('cosmos'));
    let calls = 0;
    const cosmos = createCosmosAdapter({
      rpc: pool,
      fetch: restFetch(() => ({
        balances:
          ++calls === 1
            ? [
                { denom: 'uatom', amount: '10' },
                { denom: 'ibc/ABC', amount: '1' },
              ]
            : [
                { denom: 'uatom', amount: '10' },
                { denom: 'ibc/ABC', amount: '2' },
              ],
      })),
    });
    const holdings = await cosmos.getBalances(hubAddr, HUB);
    expect(holdings.map((h) => [h.assetRef, h.amount, h.provenance?.kind])).toEqual([
      [`${HUB}:native`, '10', 'agreed'],
      [`${HUB}:ibc:ABC`, expect.stringMatching(/^[12]$/), 'disagreed'],
    ]);
    const ibc = holdings[1]?.provenance;
    if (ibc?.kind === 'disagreed') {
      expect(new Set([holdings[1]?.amount, ibc.other])).toEqual(new Set(['1', '2']));
    }
    expect(pool.endpoints(HUB).every((e) => e.healthy)).toBe(true);
  });

  it('keeps the indexed answer as single when the other LCD rejects the address', async () => {
    const pool = new MemoryRpcPool(chainsForFamily('cosmos'));
    pool.setEndpoints(HUB, ['https://indexed.example', 'https://behind.example']);
    const cosmos = createCosmosAdapter({
      rpc: pool,
      fetch: restFetch((url) =>
        url.hostname === 'behind.example'
          ? new Response(JSON.stringify({ code: 3, message: 'decoding bech32 failed' }), {
              status: 400,
            })
          : { balances: [{ denom: 'uatom', amount: '10' }] },
      ),
    });
    const holdings = await cosmos.getBalances(hubAddr, HUB);
    expect(holdings).toHaveLength(1);
    expect(holdings[0]).toMatchObject({
      assetRef: `${HUB}:native`,
      amount: '10',
      provenance: { kind: 'single', endpoint: 'https://indexed.example' },
    });
    expect(pool.endpoints(HUB).every((e) => e.healthy)).toBe(true);

    const nowhere = createCosmosAdapter({
      rpc: pool,
      fetch: restFetch(() => new Response('{}', { status: 404 })),
    });
    await expect(nowhere.getBalances(hubAddr, HUB)).rejects.toThrow(/rejected/);
  });

  it('adds a zero native holding when the account holds only other denoms', async () => {
    const cosmos = createCosmosAdapter({
      fetch: restFetch(() => ({ balances: [{ denom: 'uion', amount: '7' }] }), 'osmosis-1'),
    });
    const holdings = await cosmos.getBalances(expectBech32('osmo', H160), OSMO);
    expect(holdings[0]).toMatchObject({ assetRef: `${OSMO}:native`, amount: '0' });
    expect(holdings[1]).toMatchObject({ assetRef: `${OSMO}:native:uion`, amount: '7' });
  });

  it('rejects invalid addresses and malformed bodies', async () => {
    const pool = new MemoryRpcPool(chainsForFamily('cosmos'));
    const cosmos = createCosmosAdapter({
      rpc: pool,
      fetch: restFetch(() => ({ balances: [{ denom: 'uatom', amount: '1.5' }] })),
    });
    await expect(cosmos.getBalances(expectBech32('osmo', H160), HUB)).rejects.toThrow(
      /invalid address/,
    );
    await expect(cosmos.getBalances(hubAddr, HUB)).rejects.toThrow(/rpc endpoint/);
    expect(pool.endpoints(HUB).every((e) => !e.healthy)).toBe(true);
  });

  it('maps tx responses to status', async () => {
    const hash = 'ab'.repeat(32);
    const ok = createCosmosAdapter({
      fetch: restFetch((url) => {
        expect(url.pathname.endsWith(hash.toUpperCase())).toBe(true);
        return {
          tx_response: {
            height: '12345',
            code: 0,
            timestamp: '2024-01-01T00:00:00Z',
            txhash: hash,
          },
        };
      }),
    });
    expect(await ok.status(hash, HUB)).toEqual({
      state: 'confirmed',
      blockNumber: 12345,
      timestampMs: Date.parse('2024-01-01T00:00:00Z'),
    });

    const failed = createCosmosAdapter({
      fetch: restFetch(() => ({
        tx_response: { height: '12345', code: 5, raw_log: 'insufficient funds' },
      })),
    });
    expect(await failed.status(hash, HUB)).toEqual({
      state: 'failed',
      reason: 'insufficient funds',
    });

    const missing = createCosmosAdapter({
      fetch: restFetch(
        () => new Response(JSON.stringify({ code: 3, message: 'tx not found' }), { status: 404 }),
      ),
    });
    expect(await missing.status(hash, HUB)).toEqual({ state: 'unknown' });
    expect(await missing.status('zz', HUB)).toEqual({ state: 'unknown' });
  });

  it('throws NotImplementedError for signing-path capabilities', async () => {
    const cosmos = createCosmosAdapter();
    const tx = { chainId: HUB, family: 'cosmos' as const, intentId: 'i', payload: {} };
    await expect(cosmos.simulate(tx)).rejects.toBeInstanceOf(NotImplementedError);
    expect(() => cosmos.sighashes(tx)).toThrow(
      /chains-cosmos.sighashes is not implemented \(phase 4\)/,
    );
  });
});
