import { ed25519 } from '@noble/curves/ed25519.js';
import { base58, base64 } from '@scure/base';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  SuiTx,
  broadcastSui,
  gasBudgetFor,
  prepareSui,
  selectGasCoins,
  suiApprovalValid,
  suiSigningDigest,
  suiTransferStatus,
  suiTxBcs,
  suiTxDigest,
} from './send.js';
import {
  IOTA_MAINNET,
  IOTA_TESTNET,
  SUI_CHAIN_IDENTIFIERS,
  SUI_DEVNET,
  SUI_MAINNET,
  SUI_TESTNET,
  SUI_USDC_TYPE,
  SuiAdapter,
  iotaAddressFromPublicKey,
  isSuiDigest,
  isValidSuiAddress,
  longCoinType,
  suiAddressFromPublicKey,
} from './sui.js';

const SEED = new Uint8Array(32).fill(7);
const PUB = ed25519.getPublicKey(SEED);
/** `Ed25519Keypair.fromSecretKey(new Uint8Array(32).fill(7))` in `@mysten/sui` 1.45.2. */
const SENDER = '0xa0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233da';
/** The same key in `@iota/iota-sdk` 1.17.0. */
const IOTA_SENDER = '0x8d2d1c260127c74476b27136c5e38c003b66b889f5c80032fb81ebc3f44f45a3';
const RECIPIENT = '0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133';
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const coinRef = (byte: number, version: number, digest: number) => ({
  objectId: `0x${hex(new Uint8Array(32).fill(byte))}`,
  version,
  digest: base58.encode(new Uint8Array(32).fill(digest)),
});

const tx: SuiTx = {
  chainId: SUI_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  mist: '1500000',
  gasPayment: [coinRef(0x11, 42, 0x22)],
  gasPrice: 1000,
  gasBudget: 5_000_000,
};
/** `@mysten/sui` 1.45.2 output for the same fields (`.nur/sui-sdk/vector.mjs`), pinned by `sui.rs` too. */
const BCS_ONE =
  '000002000860e31600000000000020a2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133020200010100000101020000010100a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233da0111111111111111111111111111111111111111111111111111111111111111112a00000000000000202222222222222222222222222222222222222222222222222222222222222222a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233dae803000000000000404b4c000000000000';
const DIGEST_ONE = '8LcP7xBrPoZQeKavX1L3aDsku2U7q7PyPcKge8YXNp31';
const SIGNATURE_ONE =
  'ALXGu6o7C+a0kizXho4bCriBBUHK4LqbJCs5JdcSsE5InySileG1HOe3QhhAPVwfIbDfVWx/gGeXXpfDaevz9ATqSmxj4pxSCr71UHsTLsX5lUd2rr6+e5JCHuppFEbSLA==';
const BCS_TWO =
  '000002000860e31600000000000020a2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133020200010100000101020000010100a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233da0211111111111111111111111111111111111111111111111111111111111111112a0000000000000020222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330700000000000000204444444444444444444444444444444444444444444444444444444444444444a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233dae803000000000000404b4c000000000000';
const DIGEST_TWO = 'EXLf3pP1MZM5m6RJxYfPghiS6CiuiCaEZ5Z2QQosiJrn';

const SUI_URL = 'https://graphql.testnet.sui.io/graphql';
const MAIN_URL = 'https://graphql.mainnet.sui.io/graphql';
const IOTA_URL = 'https://api.testnet.iota.cafe';

function chain(
  chainId: string,
  name: string,
  symbol: string,
  rpcs: string[],
  testnet: boolean,
): ChainInfo {
  return {
    chainId,
    family: 'sui',
    name,
    nativeAsset: { ref: `${chainId}:native`, symbol, decimals: 9 },
    testnet,
    defaultRpcs: rpcs,
  };
}
const CHAINS: ChainInfo[] = [
  chain(SUI_MAINNET, 'Sui', 'SUI', [MAIN_URL], false),
  chain(SUI_TESTNET, 'Sui Testnet', 'SUI', [SUI_URL], true),
  chain(SUI_DEVNET, 'Sui Devnet', 'SUI', ['https://graphql.devnet.sui.io/graphql'], true),
  chain(IOTA_MAINNET, 'IOTA', 'IOTA', ['https://api.mainnet.iota.cafe'], false),
  chain(IOTA_TESTNET, 'IOTA Testnet', 'IOTA', [IOTA_URL], true),
];

class TestAdapter extends SuiAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Gql = (query: string, variables: Record<string, unknown>) => unknown;
type Call = {
  url: string;
  query?: string;
  variables?: Record<string, unknown>;
  method?: string;
  params?: unknown[];
};

/** Routes GraphQL by the first matching substring of the query; JSON-RPC by method. */
function mock(
  routes: Record<string, Gql>,
  rpc: Record<string, (params: unknown[]) => { result?: unknown; error?: unknown }> = {},
  identifiers: Record<string, string> = {
    [SUI_URL]: SUI_CHAIN_IDENTIFIERS[SUI_TESTNET]!,
    [MAIN_URL]: SUI_CHAIN_IDENTIFIERS[SUI_MAINNET]!,
  },
) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = JSON.parse(String(init?.body));
    if (body.jsonrpc) {
      calls.push({ url, method: body.method, params: body.params });
      if (body.method === 'iota_getChainIdentifier')
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: url.includes('testnet') ? '2304aa97' : '6364aad5',
        });
      const out = rpc[body.method]?.(body.params);
      if (!out)
        return Response.json({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'no' } });
      return Response.json({ jsonrpc: '2.0', id: 1, ...out });
    }
    calls.push({ url, query: body.query, variables: body.variables });
    if (body.query === '{ chainIdentifier }')
      return Response.json({ data: { chainIdentifier: identifiers[url] ?? 'devnetid' } });
    const key = Object.keys(routes).find((k) => body.query.includes(k));
    if (!key)
      return Response.json({ errors: [{ message: `unmocked ${body.query.slice(0, 40)}` }] });
    const out = routes[key]!(body.query, body.variables);
    return Response.json(out);
  }) as typeof fetch;
  return { adapter: new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) }), calls };
}

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: SUI_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${SUI_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  } as unknown as TxIntent;
}

/** What the core's `sign` returns: `0x` + bcs + flag + signature + public key. */
function signedWire(t: SuiTx, seed = SEED): string {
  const sig = ed25519.sign(suiSigningDigest(t), seed);
  return `0x${hex(suiTxBcs(t))}00${hex(sig)}${hex(ed25519.getPublicKey(seed))}`;
}

const effects = (over: Record<string, unknown> = {}) => ({
  digest: DIGEST_ONE,
  status: 'SUCCESS',
  timestamp: '2026-10-16T09:52:09.512Z',
  checkpoint: { sequenceNumber: 395513284 },
  executionError: null,
  gasEffects: {
    gasSummary: {
      computationCost: 1000000,
      storageCost: 1976000,
      storageRebate: 978120,
      nonRefundableStorageFee: 9880,
    },
  },
  balanceChanges: { nodes: [] },
  ...over,
});

describe('sui addresses', () => {
  it('derives the SDK addresses for Sui and IOTA', () => {
    expect(suiAddressFromPublicKey(PUB)).toBe(SENDER);
    expect(iotaAddressFromPublicKey(PUB)).toBe(IOTA_SENDER);
    const { adapter } = mock({});
    expect(adapter.deriveAddress({ curve: 'ed25519', hex: hex(PUB) }, SUI_TESTNET)).toBe(SENDER);
    expect(adapter.deriveAddress({ curve: 'ed25519', hex: hex(PUB) }, IOTA_MAINNET)).toBe(
      IOTA_SENDER,
    );
    expect(() =>
      adapter.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, SUI_TESTNET),
    ).toThrow();
  });
  it('accepts only full-length hex addresses', () => {
    expect(isValidSuiAddress(RECIPIENT)).toBe(true);
    expect(isValidSuiAddress(RECIPIENT.toUpperCase().replace('0X', '0x'))).toBe(true);
    expect(isValidSuiAddress('0x2')).toBe(false);
    expect(isValidSuiAddress(RECIPIENT.slice(2))).toBe(false);
    expect(isValidSuiAddress(RECIPIENT + '00')).toBe(false);
    expect(isValidSuiAddress(RECIPIENT.replace('a', 'g'))).toBe(false);
    expect(isSuiDigest(DIGEST_ONE)).toBe(true);
    expect(isSuiDigest('0OIl')).toBe(false);
    expect(longCoinType('0x2::sui::SUI')).toBe(`0x${'0'.repeat(63)}2::sui::SUI`);
  });
});

describe('sui transaction bytes', () => {
  it('matches the SDK BCS, digest and signature', () => {
    expect(hex(suiTxBcs(tx))).toBe(BCS_ONE);
    expect(suiTxDigest(tx)).toBe(DIGEST_ONE);
    const wire = signedWire(tx);
    expect(base64.encode(Buffer.from(wire.slice(2 + BCS_ONE.length), 'hex'))).toBe(SIGNATURE_ONE);
    const two = { ...tx, gasPayment: [coinRef(0x11, 42, 0x22), coinRef(0x33, 7, 0x44)] };
    expect(hex(suiTxBcs(two))).toBe(BCS_TWO);
    expect(suiTxDigest(two)).toBe(DIGEST_TWO);
  });
  it('refuses hostile fields', () => {
    const bad: unknown[] = [
      { ...tx, chainId: SUI_MAINNET },
      { ...tx, mist: '0' },
      { ...tx, mist: '01' },
      { ...tx, mist: '18446744073709551616' },
      { ...tx, to: tx.from },
      { ...tx, to: RECIPIENT.toUpperCase().replace('0X', '0x') },
      { ...tx, gasPrice: 0 },
      { ...tx, gasPrice: 100_001 },
      { ...tx, gasBudget: 999_999 },
      { ...tx, gasBudget: 1_000_000_001 },
      { ...tx, gasPayment: [] },
      { ...tx, gasPayment: Array.from({ length: 17 }, (_, i) => coinRef(i + 1, 1, 1)) },
      { ...tx, gasPayment: [coinRef(0x11, 42, 0x22), coinRef(0x11, 43, 0x23)] },
      { ...tx, gasPayment: [{ ...coinRef(0x11, 42, 0x22), version: 0 }] },
      {
        ...tx,
        gasPayment: [{ ...coinRef(0x11, 42, 0x22), digest: base58.encode(new Uint8Array(31)) }],
      },
      { ...tx, sponsor: SENDER },
    ];
    for (const b of bad) expect(() => suiTxBcs(b as SuiTx), JSON.stringify(b)).toThrow();
  });
});

describe('sui reads', () => {
  it('reads mainnet SUI and USDC from one query after checking the chain id', async () => {
    const { adapter, calls } = mock({
      'native: balance': (_q, v) => {
        expect(v).toMatchObject({ a: SENDER, usdc: SUI_USDC_TYPE, withUsdc: true });
        return {
          data: {
            address: {
              native: { totalBalance: '6912554913750' },
              usdc: { totalBalance: '1500000' },
            },
          },
        };
      },
    });
    const holdings = await adapter.getBalances(
      SENDER.toUpperCase().replace('0X', '0x'),
      SUI_MAINNET,
    );
    expect(holdings.map((h) => [h.assetRef, h.amount])).toEqual([
      [`${SUI_MAINNET}:native`, '6912554913750'],
      [`${SUI_MAINNET}:coin:${SUI_USDC_TYPE}`, '1500000'],
    ]);
    expect(holdings[1]!.metadata).toEqual({ symbol: 'USDC', decimals: 6 });
    expect(calls[0]!.query).toBe('{ chainIdentifier }');
  });
  it('refuses an endpoint that serves another network', async () => {
    const { adapter } = mock(
      { 'native: balance': () => ({ data: { address: null } }) },
      {},
      { [SUI_URL]: SUI_CHAIN_IDENTIFIERS[SUI_MAINNET]! },
    );
    await expect(adapter.getBalances(SENDER, SUI_TESTNET)).rejects.toThrow();
    const devnet = mock(
      { 'native: balance': () => ({ data: { address: null } }) },
      {},
      { 'https://graphql.devnet.sui.io/graphql': SUI_CHAIN_IDENTIFIERS[SUI_TESTNET]! },
    );
    await expect(devnet.adapter.getBalances(SENDER, SUI_DEVNET)).rejects.toThrow();
  });
  it('reports zero for an address the chain has never seen', async () => {
    const { adapter } = mock({ 'native: balance': () => ({ data: { address: null } }) });
    const [h] = await adapter.getBalances(SENDER, SUI_TESTNET);
    expect(h!.amount).toBe('0');
  });
  it('maps status from effects', async () => {
    let answer: unknown = null;
    const { adapter } = mock({ 'transaction(digest': () => ({ data: { transaction: answer } }) });
    expect(await adapter.status(DIGEST_ONE, SUI_TESTNET)).toEqual({ state: 'unknown' });
    answer = { digest: DIGEST_ONE, effects: effects() };
    expect(await adapter.status(DIGEST_ONE, SUI_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 395513284,
      timestampMs: Date.parse('2026-10-16T09:52:09.512Z'),
    });
    answer = {
      digest: DIGEST_ONE,
      effects: effects({ status: 'FAILURE', executionError: { message: 'InsufficientGas' } }),
    };
    expect(await adapter.status(DIGEST_ONE, SUI_TESTNET)).toEqual({
      state: 'failed',
      reason: 'InsufficientGas',
    });
    await expect(adapter.status('nothex', SUI_TESTNET)).rejects.toThrow();
  });
  it('maps history with gas listed apart from the transfer', async () => {
    const SUI = `0x${'0'.repeat(63)}2::sui::SUI`;
    const { adapter, calls } = mock({
      'relation: AFFECTED': () => ({
        data: {
          address: {
            transactions: {
              pageInfo: { hasPreviousPage: true, startCursor: 'KAE6DAiK0My8ARDBy5y/Dw==' },
              nodes: [
                {
                  digest: DIGEST_TWO,
                  sender: { address: RECIPIENT },
                  gasInput: { gasSponsor: { address: RECIPIENT } },
                  effects: effects({
                    balanceChanges: {
                      nodes: [
                        { owner: { address: SENDER }, coinType: { repr: SUI }, amount: '2000' },
                        {
                          owner: { address: RECIPIENT },
                          coinType: { repr: SUI },
                          amount: '-1999999',
                        },
                      ],
                    },
                  }),
                },
                {
                  digest: DIGEST_ONE,
                  sender: { address: SENDER },
                  gasInput: { gasSponsor: { address: SENDER } },
                  effects: effects({
                    timestamp: '2026-10-16T10:00:00.000Z',
                    balanceChanges: {
                      nodes: [
                        { owner: { address: SENDER }, coinType: { repr: SUI }, amount: '-3497880' },
                        {
                          owner: { address: RECIPIENT },
                          coinType: { repr: SUI },
                          amount: '1500000',
                        },
                      ],
                    },
                  }),
                },
              ],
            },
          },
        },
      }),
    });
    const page = await adapter.getHistory(SENDER, SUI_TESTNET);
    expect(page.nextCursor).toBe('KAE6DAiK0My8ARDBy5y/Dw==');
    expect(page.items.map((i) => i.hash)).toEqual([DIGEST_ONE, DIGEST_TWO]);
    const [sent, received] = page.items;
    expect(sent).toMatchObject({
      from: SENDER,
      to: RECIPIENT,
      fee: '1997880',
      status: 'confirmed',
      assetDeltas: [{ assetRef: `${SUI_TESTNET}:native`, amount: '-1500000' }],
    });
    expect(received).toMatchObject({
      from: RECIPIENT,
      to: SENDER,
      fee: null,
      assetDeltas: [{ assetRef: `${SUI_TESTNET}:native`, amount: '2000' }],
    });
    await adapter.getHistory(SENDER, SUI_TESTNET, page.nextCursor);
    expect(calls.at(-1)!.variables).toMatchObject({ before: 'KAE6DAiK0My8ARDBy5y/Dw==' });
    await expect(adapter.getHistory(SENDER, SUI_TESTNET, 'bad cursor!')).rejects.toThrow();
  });
  it('reads IOTA over JSON-RPC', async () => {
    const block = {
      digest: DIGEST_ONE,
      transaction: {
        data: { sender: IOTA_SENDER, gasData: { owner: IOTA_SENDER, price: '1000' } },
      },
      effects: {
        status: { status: 'success' },
        gasUsed: { computationCost: '1000000', storageCost: '0', storageRebate: '0' },
      },
      balanceChanges: [
        { owner: { AddressOwner: IOTA_SENDER }, coinType: '0x2::iota::IOTA', amount: '-6000000' },
        { owner: { AddressOwner: RECIPIENT }, coinType: '0x2::iota::IOTA', amount: '5000000' },
      ],
      timestampMs: '1792144539320',
      checkpoint: '278289784',
    };
    const { adapter, calls } = mock(
      {},
      {
        iotax_getBalance: (p) => {
          expect(p).toEqual([IOTA_SENDER, '0x2::iota::IOTA']);
          return {
            result: { coinType: '0x2::iota::IOTA', coinObjectCount: 1, totalBalance: '1000000000' },
          };
        },
        iota_getTransactionBlock: (p) =>
          p[0] === DIGEST_ONE
            ? { result: block }
            : { error: { code: -32003, message: 'Could not find the referenced transaction' } },
        iotax_queryTransactionBlocks: (p) => {
          const filter = (p[0] as { filter: Record<string, string> }).filter;
          return filter.FromAddress
            ? { result: { data: [block], nextCursor: DIGEST_ONE, hasNextPage: true } }
            : { result: { data: [], nextCursor: null, hasNextPage: false } };
        },
      },
    );
    const [h] = await adapter.getBalances(IOTA_SENDER, IOTA_TESTNET);
    expect(h).toMatchObject({ assetRef: `${IOTA_TESTNET}:native`, amount: '1000000000' });
    expect(await adapter.status(DIGEST_ONE, IOTA_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 278289784,
      timestampMs: 1792144539320,
    });
    expect(await adapter.status(DIGEST_TWO, IOTA_TESTNET)).toEqual({ state: 'unknown' });
    const page = await adapter.getHistory(IOTA_SENDER, IOTA_TESTNET);
    expect(page.items).toHaveLength(1);
    expect(page.items[0]).toMatchObject({
      from: IOTA_SENDER,
      to: RECIPIENT,
      fee: '1000000',
      assetDeltas: [{ assetRef: `${IOTA_TESTNET}:native`, amount: '-5000000' }],
    });
    expect(page.nextCursor).toBe(`${DIGEST_ONE}.`);
    await adapter.getHistory(IOTA_SENDER, IOTA_TESTNET, page.nextCursor);
    const last = calls.filter((c) => c.method === 'iotax_queryTransactionBlocks').slice(-1);
    expect(last).toHaveLength(1);
    expect(last[0]!.params![1]).toBe(DIGEST_ONE);
    await expect(adapter.getHistory(IOTA_SENDER, IOTA_TESTNET, '.')).rejects.toThrow();
  });
});

describe('sui send', () => {
  const coin = (byte: number, version: number, balance: string) => ({
    address: coinRef(byte, version, byte + 1).objectId,
    version,
    digest: coinRef(byte, version, byte + 1).digest,
    contents: { json: { id: 'x', balance } },
  });

  it('selects the largest coins and budgets gas from a dry run', async () => {
    let dryRunBcs: string | undefined;
    const { adapter } = mock({
      'objects(first: 50': () => ({
        data: {
          address: {
            native: { totalBalance: '230000000' },
            objects: {
              nodes: [
                coin(0x11, 5, '10000000'),
                coin(0x33, 9, '200000000'),
                coin(0x55, 3, '20000000'),
              ],
            },
          },
          epoch: { referenceGasPrice: '1000' },
        },
      }),
      simulateTransaction: (_q, v) => {
        dryRunBcs = (v as { t: { bcs: { value: string } } }).t.bcs.value;
        return { data: { simulateTransaction: { effects: effects() } } };
      },
    });
    const { unsigned, simulation } = await prepareSui(
      adapter,
      intent(RECIPIENT, '150000000'),
      SENDER,
    );
    expect(unsigned.gasPayment.map((c) => c.objectId)).toEqual([coinRef(0x33, 9, 0).objectId]);
    // computation 1_000_000 + 1000 * 1000 overhead + storage 1_976_000 - rebate 978_120
    expect(unsigned.gasBudget).toBe(2_997_880);
    expect(unsigned).toMatchObject({
      gasPrice: 1000,
      mist: '150000000',
      from: SENDER,
      to: RECIPIENT,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('2997880');
    const draft = SuiTx.parse({ ...unsigned, gasBudget: 50_000_000 });
    expect(dryRunBcs).toBe(base64.encode(suiTxBcs(draft)));

    const two = selectGasCoins(
      [
        { objectId: 'a', version: 1, digest: 'd', balance: 5n },
        { objectId: 'b', version: 1, digest: 'd', balance: 7n },
      ],
      10n,
    );
    expect(two!.map((c) => c.objectId)).toEqual(['b', 'a']);
    expect(
      gasBudgetFor({ computationCost: 0, storageCost: 0, storageRebate: 9_000_000 }, 1000n),
    ).toBe(1_000_000n);
  });

  it('refuses mainnet, address-only balances and short balances', async () => {
    const nodes: unknown[] = [];
    const { adapter } = mock({
      'objects(first: 50': () => ({
        data: {
          address: { native: { totalBalance: '73272491689705' }, objects: { nodes } },
          epoch: { referenceGasPrice: '1000' },
        },
      }),
    });
    await expect(
      prepareSui(adapter, { ...intent(RECIPIENT, '1'), chainId: SUI_MAINNET } as TxIntent, SENDER),
    ).rejects.toThrow(/testnet/);
    await expect(prepareSui(adapter, intent(RECIPIENT, '1'), SENDER)).rejects.toThrow(
      /address balance/,
    );
    nodes.push(coin(0x11, 5, '1000000'));
    await expect(prepareSui(adapter, intent(RECIPIENT, '500000'), SENDER)).rejects.toThrow(/cover/);
  });

  it('keeps approval only while the gas coins and price are unchanged', async () => {
    let version = 42;
    let owner = SENDER;
    let rgp = '1000';
    const { adapter } = mock({
      multiGetObjects: () => ({
        data: {
          multiGetObjects: [
            {
              address: tx.gasPayment[0]!.objectId,
              version,
              digest: tx.gasPayment[0]!.digest,
              owner: { __typename: 'AddressOwner', address: { address: owner } },
            },
          ],
          epoch: { referenceGasPrice: rgp },
        },
      }),
    });
    expect(await suiApprovalValid(adapter, tx)).toBe(true);
    version = 43;
    expect(await suiApprovalValid(adapter, tx)).toBe(false);
    version = 42;
    owner = RECIPIENT;
    expect(await suiApprovalValid(adapter, tx)).toBe(false);
    owner = SENDER;
    rgp = '1001';
    expect(await suiApprovalValid(adapter, tx)).toBe(false);
  });

  it('broadcasts only the exact signed transfer', async () => {
    let reply: unknown = { data: { executeTransaction: { effects: effects() } } };
    const { adapter, calls } = mock({
      executeTransaction: () => reply,
      'transaction(digest': () => ({ data: { transaction: null } }),
    });
    const wire = signedWire(tx);
    expect(await broadcastSui(adapter, tx, wire)).toBe(DIGEST_ONE);
    const sent = calls.find((c) => c.query?.includes('executeTransaction'))!;
    expect(sent.variables).toEqual({
      b: base64.encode(Buffer.from(BCS_ONE, 'hex')),
      s: [SIGNATURE_ONE],
    });

    const other = { ...tx, mist: '1500001' };
    await expect(broadcastSui(adapter, other, wire)).rejects.toThrow(/not this SUI transfer/);
    await expect(broadcastSui(adapter, tx, wire + '00')).rejects.toThrow(/not this SUI transfer/);
    const forged = wire.slice(0, -64 - 2) + 'ff' + wire.slice(-64);
    await expect(broadcastSui(adapter, tx, forged)).rejects.toThrow(/verify/);
    const wrongKey = signedWire(tx, new Uint8Array(32).fill(8));
    await expect(broadcastSui(adapter, tx, wrongKey)).rejects.toThrow(/sender key/);
    await expect(
      broadcastSui(adapter, { ...tx, chainId: SUI_MAINNET } as unknown as SuiTx, wire),
    ).rejects.toThrow();

    reply = {
      data: null,
      errors: [{ message: 'Invalid user signature', extensions: { code: 'BAD_USER_INPUT' } }],
    };
    await expect(broadcastSui(adapter, tx, wire)).rejects.toThrow(
      /Broadcast rejected: Invalid user signature/,
    );
    reply = { data: { executeTransaction: { effects: effects({ digest: DIGEST_TWO }) } } };
    await expect(broadcastSui(adapter, tx, wire)).rejects.toThrow(/different/);
  });

  it('reports expired once a gas coin moved and the digest never landed', async () => {
    let known: unknown = null;
    let version = 42;
    const { adapter } = mock({
      'transaction(digest': () => ({ data: { transaction: known } }),
      multiGetObjects: () => ({
        data: {
          multiGetObjects: [
            {
              address: tx.gasPayment[0]!.objectId,
              version,
              digest: tx.gasPayment[0]!.digest,
              owner: { __typename: 'AddressOwner', address: { address: SENDER } },
            },
          ],
          epoch: { referenceGasPrice: '1000' },
        },
      }),
    });
    expect(await suiTransferStatus(adapter, tx, DIGEST_ONE)).toEqual({ state: 'unknown' });
    version = 43;
    expect(await suiTransferStatus(adapter, tx, DIGEST_ONE)).toEqual({ state: 'expired' });
    known = { digest: DIGEST_ONE, effects: effects() };
    expect((await suiTransferStatus(adapter, tx, DIGEST_ONE)).state).toBe('confirmed');
  });
});
