import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MemoryRpcPool } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  BroadcastRejected,
  broadcastVechain,
  encodeVechainTx,
  gasPriceCoefFor,
  legacyGasPrice,
  prepareVechain,
  vechainApprovalValid,
  vechainSigningHash,
  vechainTransferStatus,
  vechainTxId,
  type VechainTx,
} from './send.js';
import {
  VECHAIN_CHAINS,
  VECHAIN_GENESIS,
  VECHAIN_MAINNET,
  VECHAIN_TESTNET,
  VTHO_ADDRESS,
  VechainAdapter,
  isValidVechainAddress,
  vechainAddressFromPublicKey,
  vthoAssetRef,
} from './vechain.js';

const KEY_ONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
/** `Address.ofPublicKey(Secp256k1.derivePublicKey(fill(7)))` in `@vechain/sdk-core` 2.1.0. */
const SENDER = '0x4a62316623ad457f02cdc5d997ded67a383ec569';
const RECIPIENT = '0x7495dee08f1340fa1fbda59c979f799d7d676fce';
const TESTNET_URL = 'https://testnet.vechain.org';
const SECOND_URL = 'https://testnet.vecha.in';

const tx: VechainTx = {
  chainId: VECHAIN_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  vetWei: '1500000000000000000',
  blockRef: '018ff53eb317837f',
  expiration: 720,
  gasPriceCoef: 0,
  gas: 21_000,
  nonce: '0102030405060708',
};
const small: VechainTx = {
  ...tx,
  vetWei: '1',
  blockRef: '0000000000000001',
  expiration: 32,
  gasPriceCoef: 128,
  gas: 100_000,
  nonce: '0000000000000000',
};
/** `.nur/vechain-sdk/vector.mjs` (`@vechain/sdk-core` 2.1.0), pinned by `vechain.rs` too. */
const UNSIGNED_VECTOR =
  'f83d2788018ff53eb317837f8202d0e0df947495dee08f1340fa1fbda59c979f799d7d676fce8814d1120d7b160000808082520880880102030405060708c0';
const SIGNING_HASH_VECTOR = '86d522d04b48ddd6d79fd170cc46b5c9e9513cf94eb0700be6b3968bd6bc846f';
const SIGNED_VECTOR =
  '0xf8802788018ff53eb317837f8202d0e0df947495dee08f1340fa1fbda59c979f799d7d676fce8814d1120d7b160000808082520880880102030405060708c0b841b1466082962703304d29f71f6d2dd5e64b2676d36cce6c6b07e5d2e3fc8d3f3e02bc16be132cd0c79badc471fa7b13fe412da119aa730a7ff2999c19cfcbd2f700';
const TXID_VECTOR = '0xabe7e51af617e1f9dacd359702aabf1085afbb9badaaf6a02678efb62a983915';
const UNSIGNED_SMALL_VECTOR =
  'e5270120d8d7947495dee08f1340fa1fbda59c979f799d7d676fce01808180830186a08080c0';
const TXID_SMALL_VECTOR = '0x9e4c9f069b5abe57ac4f5c60cf67a7ef957338d2d5d4f2a920406d7ac840b04f';

type Route = (body: Record<string, unknown> | undefined, url: URL) => unknown;
function node(routes: Record<string, Route>, genesis: Record<string, string> = {}) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    calls.push(`${method} ${url.host}${url.pathname}`);
    if (url.pathname === '/blocks/0')
      return Response.json({
        number: 0,
        id: genesis[url.origin] ?? VECHAIN_GENESIS[VECHAIN_TESTNET],
        timestamp: 1530014400,
      });
    const route = routes[`${method} ${url.pathname}`];
    if (!route) return new Response('not found', { status: 404 });
    const body = init?.body
      ? (JSON.parse(String(init.body)) as Record<string, unknown>)
      : undefined;
    const out = route(body, url);
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch, testnetRpcs = [TESTNET_URL]) {
  const chains = VECHAIN_CHAINS.map((c) =>
    c.chainId === VECHAIN_TESTNET ? { ...c, defaultRpcs: testnetRpcs } : c,
  );
  return new VechainAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) });
}

const block = (number: number, baseFee = '0x9184e72a000') => ({
  number,
  id: `0x${number.toString(16).padStart(8, '0')}${'ab'.repeat(28)}`,
  timestamp: 1_792_155_010,
  baseFeePerGas: baseFee,
});

describe('vechain addresses', () => {
  it('derives the keccak address in lowercase', () => {
    expect(vechainAddressFromPublicKey(Buffer.from(KEY_ONE, 'hex'))).toBe(
      '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf',
    );
    const seven = secp256k1.getPublicKey(new Uint8Array(32).fill(7), true);
    const a = new VechainAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: bytesToHex(seven) }, VECHAIN_TESTNET)).toBe(
      SENDER,
    );
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, VECHAIN_TESTNET),
    ).toThrow();
  });

  it('accepts lowercase or valid EIP-55 and refuses the rest', () => {
    expect(isValidVechainAddress('0x7e5f4552091a69125d5dfcb7b8c2659029395bdf')).toBe(true);
    expect(isValidVechainAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(true);
    expect(isValidVechainAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395BDF')).toBe(false);
    expect(isValidVechainAddress('7e5f4552091a69125d5dfcb7b8c2659029395bdf')).toBe(false);
    expect(isValidVechainAddress(`0x${'00'.repeat(20)}`)).toBe(false);
    expect(isValidVechainAddress('TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC')).toBe(false);
  });
});

describe('vechain transfers', () => {
  it('encodes the same bytes as the SDK and the core', () => {
    expect(bytesToHex(encodeVechainTx(tx))).toBe(UNSIGNED_VECTOR);
    expect(bytesToHex(vechainSigningHash(tx))).toBe(SIGNING_HASH_VECTOR);
    expect(vechainTxId(tx)).toBe(TXID_VECTOR);
    expect(bytesToHex(encodeVechainTx(small))).toBe(UNSIGNED_SMALL_VECTOR);
    expect(vechainTxId(small)).toBe(TXID_SMALL_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => encodeVechainTx({ ...tx, vetWei: '0' })).toThrow();
    expect(() => encodeVechainTx({ ...tx, vetWei: '01' })).toThrow();
    expect(() => encodeVechainTx({ ...tx, vetWei: (1n << 128n).toString() })).toThrow();
    expect(() => encodeVechainTx({ ...tx, to: tx.from })).toThrow();
    expect(() =>
      encodeVechainTx({ ...tx, to: RECIPIENT.toUpperCase().replace('0X', '0x') }),
    ).toThrow();
    expect(() => encodeVechainTx({ ...tx, gas: 20_999 })).toThrow();
    expect(() => encodeVechainTx({ ...tx, gas: 100_001 })).toThrow();
    expect(() => encodeVechainTx({ ...tx, expiration: 721 })).toThrow();
    expect(() => encodeVechainTx({ ...tx, gasPriceCoef: 256 })).toThrow();
    expect(() => encodeVechainTx({ ...tx, blockRef: '018FF53EB317837F' })).toThrow();
    expect(() => encodeVechainTx({ ...tx, data: '00' } as VechainTx)).toThrow();
    expect(() =>
      encodeVechainTx({ ...tx, chainId: VECHAIN_MAINNET as typeof VECHAIN_TESTNET }),
    ).toThrow();
  });

  it('picks the smallest legacy coefficient that covers the base fee and tip', () => {
    const base = 10_000_000_000_000n;
    expect(gasPriceCoefFor(base, base)).toBe(0);
    expect(gasPriceCoefFor(base, base + 500_000_000_000n)).toBe(13);
    expect(legacyGasPrice(base, 13)).toBeGreaterThanOrEqual(base + 500_000_000_000n);
    expect(gasPriceCoefFor(base, base * 2n)).toBe(255);
    expect(gasPriceCoefFor(base, base * 2n + 1n)).toBeUndefined();
  });

  it('prepares a testnet transfer with the VTHO fee', async () => {
    const calls: Record<string, unknown>[] = [];
    const { fetchImpl } = node({
      'GET /blocks/best': () => block(26_211_646),
      'GET /fees/priority': () => ({ maxPriorityFeePerGas: '0x746a528800' }),
      [`GET /accounts/${SENDER}`]: () => ({
        balance: '0x1bc16d674ec80000',
        // 0.3 VTHO; the tipped fee is about 0.2207 VTHO.
        energy: `0x${(3n * 10n ** 17n).toString(16)}`,
        hasCode: false,
      }),
      [`GET /accounts/${RECIPIENT}`]: () => ({ balance: '0x0', energy: '0x0', hasCode: false }),
      'POST /accounts/*': (body) => {
        calls.push(body!);
        const clause = (body!.clauses as { to: string }[])[0]!;
        return clause.to === RECIPIENT
          ? [{ data: '0x', gasUsed: 0, reverted: false, vmError: '' }]
          : [
              {
                data: `0x${'9184e72a000'.padStart(64, '0')}`,
                gasUsed: 591,
                reverted: false,
                vmError: '',
              },
            ];
      },
    });
    const intent = {
      id: 't',
      walletId: 'w',
      accountId: 'a',
      chainId: VECHAIN_TESTNET,
      kind: 'transfer' as const,
      // EIP-55 spelling from `Address.of(...)` in `@vechain/sdk-core` 2.1.0.
      to: '0x7495dEe08f1340Fa1FBDA59C979F799d7D676FcE',
      asset: `${VECHAIN_TESTNET}:native`,
      amount: tx.vetWei,
      proposer: { kind: 'human' as const, deviceId: 'd' },
      untrustedDestinations: [],
      createdAtMs: 0,
    };
    const { unsigned, simulation } = await prepareVechain(
      adapter(fetchImpl),
      intent as never,
      SENDER,
      {
        nonce: tx.nonce,
      },
    );
    expect(unsigned).toEqual({
      ...tx,
      blockRef: '018ff53eabababab',
      expiration: 180,
      gasPriceCoef: 13,
    });
    expect(calls.find((c) => c.caller === SENDER)).toMatchObject({
      clauses: [{ to: RECIPIENT, value: '0x14d1120d7b160000', data: '0x' }],
    });
    const fee = 21_000n * legacyGasPrice(10_000_000_000_000n, 13);
    expect(simulation.fee).toEqual({
      assetRef: vthoAssetRef(VECHAIN_TESTNET),
      amount: fee.toString(),
    });
    expect(simulation.ok).toBe(true);
  });

  it('flags a sender without VTHO', async () => {
    const { fetchImpl } = node({
      'GET /blocks/best': () => block(26_211_646),
      'GET /fees/priority': () => new Response('nope', { status: 500 }),
      [`GET /accounts/${SENDER}`]: () => ({
        balance: '0x1bc16d674ec80000',
        energy: '0x0',
        hasCode: false,
      }),
      [`GET /accounts/${RECIPIENT}`]: () => ({ balance: '0x0', energy: '0x0', hasCode: true }),
      'POST /accounts/*': (body) =>
        (body!.clauses as { to: string }[])[0]!.to === RECIPIENT
          ? [{ data: '0x', gasUsed: 2_000, reverted: false, vmError: '' }]
          : [
              {
                data: `0x${'9184e72a000'.padStart(64, '0')}`,
                gasUsed: 591,
                reverted: false,
                vmError: '',
              },
            ],
    });
    const intent = {
      chainId: VECHAIN_TESTNET,
      kind: 'transfer',
      to: RECIPIENT,
      asset: `${VECHAIN_TESTNET}:native`,
      amount: '1',
    };
    const { unsigned, simulation } = await prepareVechain(
      adapter(fetchImpl),
      intent as never,
      SENDER,
    );
    expect(unsigned.gas).toBe(23_000);
    expect(unsigned.gasPriceCoef).toBe(0);
    expect(unsigned.nonce).toMatch(/^[0-9a-f]{16}$/);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/VTHO/);
    expect(simulation.warnings).toEqual([{ kind: 'destinationIsContract', address: RECIPIENT }]);
  });

  it('refuses mainnet sends and endpoints that serve another network', async () => {
    const { fetchImpl } = node(
      { [`GET /accounts/${SENDER}`]: () => ({ balance: '0x1', energy: '0x1', hasCode: false }) },
      { [TESTNET_URL]: VECHAIN_GENESIS[VECHAIN_MAINNET]! },
    );
    await expect(adapter(fetchImpl).getBalances(SENDER, VECHAIN_TESTNET)).rejects.toThrow();
    const intent = {
      chainId: VECHAIN_MAINNET,
      kind: 'transfer',
      to: RECIPIENT,
      asset: `${VECHAIN_MAINNET}:native`,
      amount: '1',
    };
    await expect(prepareVechain(adapter(fetchImpl), intent as never, SENDER)).rejects.toThrow();
  });

  it('broadcasts only the ledger transfer signed by its sender', async () => {
    const seen: unknown[] = [];
    let reply: () => unknown = () => ({ id: TXID_VECTOR });
    const { fetchImpl } = node({
      'POST /transactions': (b) => {
        seen.push(b!.raw);
        return reply();
      },
    });
    const a = adapter(fetchImpl);
    await expect(broadcastVechain(a, tx, SIGNED_VECTOR)).resolves.toBe(TXID_VECTOR);
    expect(seen).toEqual([SIGNED_VECTOR]);
    await expect(
      broadcastVechain(a, { ...tx, vetWei: '1500000000000000001' }, SIGNED_VECTOR),
    ).rejects.toThrow();
    await expect(broadcastVechain(a, tx, SIGNED_VECTOR + '00')).rejects.toThrow();
    const flipped = SIGNED_VECTOR.slice(0, -2) + '01';
    await expect(broadcastVechain(a, tx, flipped)).rejects.toThrow(/signed by its sender|recover/);
    expect(seen).toHaveLength(1);
    reply = () => new Response('tx rejected: insufficient energy', { status: 400 });
    await expect(broadcastVechain(a, tx, SIGNED_VECTOR)).rejects.toBeInstanceOf(BroadcastRejected);
    reply = () => new Response('tx rejected: known tx', { status: 400 });
    await expect(broadcastVechain(a, tx, SIGNED_VECTOR)).resolves.toBe(TXID_VECTOR);
    reply = () => ({ id: TXID_SMALL_VECTOR });
    await expect(broadcastVechain(a, tx, SIGNED_VECTOR)).rejects.toThrow(/different/);
  });

  it('reports pending, confirmed, failed and expired', async () => {
    let head = 26_000_000;
    let receipt: unknown = null;
    let pending: unknown = null;
    const t = {
      ...tx,
      blockRef: `${(26_000_000).toString(16).padStart(8, '0')}abababab`,
      expiration: 180,
    };
    const { fetchImpl } = node({
      'GET /blocks/best': () => block(head),
      [`GET /transactions/${TXID_VECTOR}/receipt`]: () => receipt,
      [`GET /transactions/${TXID_VECTOR}`]: (_b, url) => {
        expect(url.searchParams.get('pending')).toBe('true');
        return pending;
      },
    });
    const a = adapter(fetchImpl);
    await expect(vechainApprovalValid(a, t)).resolves.toBe(true);
    await expect(vechainTransferStatus(a, t, TXID_VECTOR)).resolves.toEqual({ state: 'unknown' });
    pending = { id: TXID_VECTOR, meta: null };
    await expect(vechainTransferStatus(a, t, TXID_VECTOR)).resolves.toEqual({ state: 'pending' });
    head = 26_000_175;
    await expect(vechainApprovalValid(a, t)).resolves.toBe(false);
    head = 26_000_181;
    await expect(vechainTransferStatus(a, t, TXID_VECTOR)).resolves.toEqual({ state: 'expired' });
    const meta = {
      blockID: `0x${'cd'.repeat(32)}`,
      blockNumber: 26_000_005,
      blockTimestamp: 1_792_155_010,
    };
    receipt = { reverted: false, gasUsed: 21_000, paid: '0x1', meta };
    await expect(vechainTransferStatus(a, t, TXID_VECTOR)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 26_000_005,
      timestampMs: 1_792_155_010_000,
    });
    receipt = { reverted: true, meta };
    await expect(a.status(TXID_VECTOR, VECHAIN_TESTNET)).resolves.toMatchObject({
      state: 'failed',
    });
  });
});

describe('vechain reads', () => {
  it('reads VET and VTHO from two agreeing endpoints', async () => {
    const { fetchImpl, calls } = node({
      [`GET /accounts/${SENDER}`]: () => ({
        balance: '0x1bc16d674ec80000',
        energy: '0x1cb334a6f947ce1',
        hasCode: false,
      }),
    });
    const holdings = await adapter(fetchImpl, [TESTNET_URL, SECOND_URL]).getBalances(
      '0x4a62316623ad457F02cDC5D997deD67a383EC569',
      VECHAIN_TESTNET,
    );
    expect(holdings[0]).toMatchObject({
      assetRef: `${VECHAIN_TESTNET}:native`,
      amount: '2000000000000000000',
      provenance: { kind: 'agreed' },
    });
    expect(holdings[1]).toMatchObject({
      assetRef: `${VECHAIN_TESTNET}:vip180:${VTHO_ADDRESS}`,
      amount: BigInt('0x1cb334a6f947ce1').toString(),
      metadata: { symbol: 'VTHO', decimals: 18 },
    });
    expect(calls.filter((c) => c.endsWith(`/accounts/${SENDER}`))).toHaveLength(2);
  });

  it('lists VET transfer logs with net deltas and paging', async () => {
    const log = (sender: string, recipient: string, amount: string, i: number) => ({
      sender,
      recipient,
      amount,
      meta: {
        blockID: `0x${'cd'.repeat(32)}`,
        blockNumber: 20_589_222 - i,
        blockTimestamp: 1_735_929_710,
        txID: `0x${i.toString(16).padStart(64, '0')}`,
        txOrigin: sender,
        clauseIndex: 0,
      },
    });
    let body: Record<string, unknown> | undefined;
    const { fetchImpl } = node({
      'POST /logs/transfer': (b) => {
        body = b;
        return [
          log(SENDER, RECIPIENT, '0x7e49b1e2ddc1f900', 1),
          log(RECIPIENT, SENDER, '0x989680', 2),
          ...Array.from({ length: 18 }, (_, i) => log(RECIPIENT, SENDER, '0x1', i + 3)),
        ];
      },
    });
    const page = await adapter(fetchImpl).getHistory(SENDER, VECHAIN_TESTNET, '20');
    expect(body).toMatchObject({
      options: { offset: 20, limit: 20 },
      criteriaSet: [{ sender: SENDER }, { recipient: SENDER }],
      order: 'desc',
    });
    expect(page.items[0]!.assetDeltas).toEqual([
      { assetRef: `${VECHAIN_TESTNET}:native`, amount: `-${BigInt('0x7e49b1e2ddc1f900')}` },
    ]);
    expect(page.items[1]!.assetDeltas[0]!.amount).toBe('10000000');
    expect(page.items[0]!.fee).toBeNull();
    expect(page.nextCursor).toBe('40');
    await expect(adapter(fetchImpl).getHistory(SENDER, VECHAIN_TESTNET, '-1')).rejects.toThrow();
  });
});
