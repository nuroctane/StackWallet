import { base58 } from '@scure/base';
import { MemoryRpcPool } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  ERGO_MAINNET,
  ERGO_TESTNET,
  ErgoAdapter,
  FEE_CONTRACT,
  blake2b256,
  ergoAddressBytes,
  ergoAddressFromPublicKey,
  ergoP2pkTree,
  isValidErgoAddress,
} from './ergo.js';
import {
  broadcastErgo,
  ergoApprovalValid,
  ergoTransferStatus,
  ergoTxId,
  prepareErgo,
  serializeUnsignedErgoTx,
  type ErgoTx,
} from './send.js';

/** fleet-sdk vectors for secret 0x07…07 (`oracle.mjs`). */
const PUBKEY = '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const ADDR_TESTNET = '3WwmRJYcKmDVN3Uqdbh52cn8BmmWfBUVQPxtrJidXb3ofAZmnNEG';
const ADDR_MAINNET = '9fgGinDXJZHmmGYnPNnHqGLCpZ5JV8roKzou3B7fvzR9sQRNtFZ';
const ADDR2_TESTNET = '3WzSsD7WkLKAfEMPkP3Mg4yjKCorMPgNjZ649YSyvNqPFzNGACLP';
const GENESIS_TESTNET = '5b1827ca092b599eafbaf339d2acf2445bc5216ec2e022d9c001a6fff660cad9';
const GENESIS_MAINNET = 'b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b';
const BOX1 = 'ab'.repeat(32);
const BOX2 = 'cd'.repeat(32);

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

const tx: ErgoTx = {
  chainId: ERGO_TESTNET,
  from: ADDR_TESTNET,
  to: ADDR2_TESTNET,
  nanoerg: '1000000',
  inputs: [BOX1],
  change: '5000000',
  fee: '1000000',
  height: 500_000,
};
/** Produced by the Rust core's encoder (`ergo.rs` tests) and fleet-sdk. */
const BYTES_VECTOR =
  '01abababababababababababababababababababababababababababababababab0000000003c0843d0008cd03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661ba0c21e0000c096b1020008cd02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa0c21e0000c0843d' +
  FEE_CONTRACT +
  'a0c21e0000';
const TXID_VECTOR = '5176877f5d692cf122854804c5cec9700f99f414c48e611d6bcba3ba220455b4';

const EXPLORER = 'https://explorer.test';
const NODE = 'http://node.test';

type Routes = Record<string, (body: unknown, url: URL) => unknown>;
function mock(routes: Routes) {
  const posts: { path: string; body: unknown }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const route =
      routes[url.host + url.pathname + url.search] ??
      routes[url.host + url.pathname] ??
      routes[url.pathname + url.search] ??
      routes[url.pathname];
    if (!route) return new Response('{"error":404}', { status: 404 });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const out = route(body, url);
    if (out instanceof Response) return out;
    posts.push({ path: url.pathname, body });
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, posts };
}

function adapter(fetchImpl: typeof fetch) {
  const pool = new MemoryRpcPool([
    {
      chainId: ERGO_TESTNET,
      family: 'ergo',
      name: 'Ergo Testnet',
      nativeAsset: { ref: `${ERGO_TESTNET}:native`, symbol: 'ERG', decimals: 9 },
      testnet: true,
      defaultRpcs: [EXPLORER, NODE],
    },
  ]);
  return new ErgoAdapter({ fetch: fetchImpl, rpc: pool });
}

const EXPLORER_HOST = new URL(EXPLORER).host;
const NODE_HOST = new URL(NODE).host;
/** Routes both endpoint kinds through their identification probes. */
function baseRoutes(overrides: Routes = {}): Routes {
  return {
    [`${EXPLORER_HOST}/api/v1/blocks`]: () => ({ items: [{ id: GENESIS_TESTNET }] }),
    [`${EXPLORER_HOST}/api/v1/networkState`]: () => ({ height: 500_000 }),
    [`${NODE_HOST}/info`]: () => ({ network: 'testnet', fullHeight: 500_000 }),
    ...overrides,
  };
}

const intent = (amount = '1000000') => ({
  id: 't',
  walletId: 'w',
  accountId: 'a',
  chainId: ERGO_TESTNET,
  kind: 'transfer' as const,
  to: ADDR2_TESTNET,
  asset: `${ERGO_TESTNET}:native`,
  amount,
  proposer: { kind: 'human' as const, deviceId: 'd' },
  untrustedDestinations: [],
  createdAtMs: 0,
});

describe('ergo addresses', () => {
  it('derives the P2PK addresses of secret 0x07 like fleet-sdk', () => {
    expect(ergoAddressFromPublicKey(hexToBytes(PUBKEY), true)).toBe(ADDR_TESTNET);
    expect(ergoAddressFromPublicKey(hexToBytes(PUBKEY), false)).toBe(ADDR_MAINNET);
    const a = adapter(mock({}).fetchImpl);
    expect(a.deriveAddress({ curve: 'secp256k1', hex: PUBKEY }, ERGO_TESTNET)).toBe(ADDR_TESTNET);
    expect(a.deriveAddress({ curve: 'secp256k1', hex: PUBKEY }, ERGO_MAINNET)).toBe(ADDR_MAINNET);
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, ERGO_TESTNET),
    ).toThrow();
  });

  it('refuses bad checksums, foreign heads and other formats', () => {
    expect(isValidErgoAddress(ADDR_TESTNET)).toBe(true);
    expect(isValidErgoAddress(ADDR_TESTNET.slice(0, -1) + 'H')).toBe(false);
    expect(isValidErgoAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false);
    // A P2SH head byte (0x13 testnet) with a valid checksum is still not P2PK.
    const payload = ergoAddressBytes(ADDR_TESTNET)!;
    const p2sh = new Uint8Array(payload);
    p2sh[0] = 0x13;
    const full = new Uint8Array(38);
    full.set(p2sh);
    full.set(blake2b256(p2sh).subarray(0, 4), 34);
    expect(isValidErgoAddress(base58.encode(full))).toBe(false);
    // Network prefixes are enforced per chain.
    const a = adapter(mock({}).fetchImpl);
    expect(a.validateAddress(ADDR_TESTNET, ERGO_TESTNET)).toBe(true);
    expect(a.validateAddress(ADDR_MAINNET, ERGO_TESTNET)).toBe(false);
    expect(a.validateAddress(ADDR_MAINNET, ERGO_MAINNET)).toBe(true);
  });
});

describe('ergo transfers', () => {
  it('encodes the same unsigned bytes as the core', () => {
    expect(bytesToHexOf(serializeUnsignedErgoTx(tx))).toBe(BYTES_VECTOR);
    expect(ergoTxId(tx)).toBe(TXID_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => serializeUnsignedErgoTx({ ...tx, nanoerg: '0' })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, nanoerg: '01' })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, change: '999999' })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, fee: '10000001' })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, inputs: [BOX1, BOX1] })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, inputs: [] })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, height: 0 })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, to: ADDR_MAINNET })).toThrow();
    expect(() => serializeUnsignedErgoTx({ ...tx, chainId: ERGO_MAINNET as never })).toThrow();
  });

  it('prepares a testnet transfer from clean P2PK boxes', async () => {
    const box = (boxId: string, value: number, extra: Record<string, unknown> = {}) => ({
      boxId,
      value,
      ergoTree: ergoP2pkTree(hexToBytes(PUBKEY)),
      creationHeight: 499_000,
      address: ADDR_TESTNET,
      assets: [],
      additionalRegisters: {},
      spentTransactionId: null,
      ...extra,
    });
    const { fetchImpl } = mock(
      baseRoutes({
        [`/api/v1/boxes/unspent/byAddress/${ADDR_TESTNET}`]: () => ({
          items: [
            box(BOX2, 9_000_000),
            box(BOX1, 4_000_000),
            box('ef'.repeat(32), 50_000_000, { assets: [{ tokenId: 'aa'.repeat(32), amount: 1 }] }),
          ],
          total: 3,
        }),
      }),
    );
    const { unsigned, simulation } = await prepareErgo(adapter(fetchImpl), intent(), ADDR_TESTNET);
    // Ascending pick: the 4 ERG box alone covers amount + fee + min change.
    expect(unsigned.inputs).toEqual([BOX1]);
    expect(unsigned.change).toBe('2000000');
    expect(unsigned.fee).toBe('1000000');
    expect(unsigned.height).toBe(500_000);
    expect(simulation.ok).toBe(true);
    expect(simulation.warnings.some((w) => w.kind === 'other')).toBe(true);
  });

  it('reports when boxes cannot cover amount, fee and minimum change', async () => {
    const { fetchImpl } = mock(
      baseRoutes({
        [`/api/v1/boxes/unspent/byAddress/${ADDR_TESTNET}`]: () => ({
          items: [
            {
              boxId: BOX1,
              value: 2_500_000,
              ergoTree: ergoP2pkTree(hexToBytes(PUBKEY)),
              creationHeight: 499_000,
              assets: [],
              additionalRegisters: {},
              spentTransactionId: null,
            },
          ],
          total: 1,
        }),
      }),
    );
    const { simulation } = await prepareErgo(adapter(fetchImpl), intent(), ADDR_TESTNET);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/does not cover/);
  });

  it('keeps approval valid only while all inputs are unspent', async () => {
    let spent = false;
    const { fetchImpl } = mock(
      baseRoutes({
        [`/utxo/byId/${BOX1}`]: () =>
          spent ? new Response('{"error":404}', { status: 404 }) : { boxId: BOX1 },
      }),
    );
    const a = adapter(fetchImpl);
    await expect(ergoApprovalValid(a, tx)).resolves.toBe(true);
    spent = true;
    await expect(ergoApprovalValid(a, tx)).resolves.toBe(false);
  });

  it('broadcasts only the ledger transfer with one proof per input', async () => {
    const { fetchImpl, posts } = mock(
      baseRoutes({
        '/transactions': () => JSON.stringify(TXID_VECTOR),
      }),
    );
    const wire = JSON.stringify({
      id: TXID_VECTOR,
      inputs: [{ boxId: BOX1, spendingProof: { proofBytes: 'ab'.repeat(56), extension: {} } }],
      dataInputs: [],
      outputs: [
        {
          value: 1_000_000,
          ergoTree: ergoP2pkTree(ergoAddressBytes(ADDR2_TESTNET)!.subarray(1)),
          creationHeight: 500_000,
          assets: [],
          additionalRegisters: {},
        },
        {
          value: 5_000_000,
          ergoTree: ergoP2pkTree(ergoAddressBytes(ADDR_TESTNET)!.subarray(1)),
          creationHeight: 500_000,
          assets: [],
          additionalRegisters: {},
        },
        {
          value: 1_000_000,
          ergoTree: FEE_CONTRACT,
          creationHeight: 500_000,
          assets: [],
          additionalRegisters: {},
        },
      ],
    });
    await expect(broadcastErgo(adapter(fetchImpl), tx, wire)).resolves.toBe(TXID_VECTOR);
    expect(posts.some((p) => p.path === '/transactions')).toBe(true);
    await expect(
      broadcastErgo(adapter(fetchImpl), { ...tx, nanoerg: '1000001' }, wire),
    ).rejects.toThrow();
    const tampered = JSON.parse(wire);
    tampered.outputs[2].value = 999_999;
    await expect(broadcastErgo(adapter(fetchImpl), tx, JSON.stringify(tampered))).rejects.toThrow();
  });

  it('reads status from explorer and mempool', async () => {
    let mode: 'confirmed' | 'mempool' | 'unknown' = 'confirmed';
    const { fetchImpl } = mock(
      baseRoutes({
        [`/api/v1/transactions/${TXID_VECTOR}`]: () =>
          mode === 'confirmed'
            ? {
                id: TXID_VECTOR,
                inclusionHeight: 500_000,
                timestamp: 1_700_000_000_000,
                inputs: [],
                outputs: [],
              }
            : new Response('{"error":404}', { status: 404 }),
        [`/transactions/unconfirmed/byTransactionId/${TXID_VECTOR}`]: () =>
          mode === 'mempool' ? { id: TXID_VECTOR } : new Response('{"error":404}', { status: 404 }),
      }),
    );
    const a = adapter(fetchImpl);
    await expect(ergoTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 500_000,
      timestampMs: 1_700_000_000_000,
    });
    mode = 'mempool';
    await expect(ergoTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({ state: 'pending' });
    mode = 'unknown';
    await expect(ergoTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({ state: 'unknown' });
  });

  it('reads ERG and token balances from the explorer', async () => {
    const { fetchImpl } = mock(
      baseRoutes({
        [`/api/v1/addresses/${ADDR_TESTNET}/balance/confirmed`]: () => ({
          nanoErgs: 4_500_000_000,
          tokens: [{ tokenId: 'aa'.repeat(32), amount: 7 }],
        }),
      }),
    );
    const holdings = await adapter(fetchImpl).getBalances(ADDR_TESTNET, ERGO_TESTNET);
    expect(holdings[0]).toMatchObject({ assetRef: `${ERGO_TESTNET}:native`, amount: '4500000000' });
    expect(holdings[1]).toMatchObject({
      assetRef: `${ERGO_TESTNET}:token:${'aa'.repeat(32)}`,
      amount: '7',
    });
  });

  it('refuses an explorer that serves another Ergo network', async () => {
    const { fetchImpl } = mock({
      '/api/v1/blocks': () => ({ items: [{ id: GENESIS_MAINNET }] }),
      '/info': () => new Response('{"error":404}', { status: 404 }),
    });
    const pool = new MemoryRpcPool([
      {
        chainId: ERGO_TESTNET,
        family: 'ergo',
        name: 'Ergo Testnet',
        nativeAsset: { ref: `${ERGO_TESTNET}:native`, symbol: 'ERG', decimals: 9 },
        testnet: true,
        defaultRpcs: [EXPLORER],
      },
    ]);
    await expect(
      new ErgoAdapter({ fetch: fetchImpl, rpc: pool }).getBalances(ADDR_TESTNET, ERGO_TESTNET),
    ).rejects.toThrow();
  });
});

function bytesToHexOf(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}
