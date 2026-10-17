import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  AntelopeAdapter,
  ANTELOPE_TESTNET,
  VAULTA_MAINNET,
  WAX_TESTNET,
  antelopeErrorOf,
  antelopePublicKey,
  decodeAntelopeSignature,
  encodeAntelopeSignature,
  formatAsset,
  isCanonicalSignature,
  isValidAntelopeAccount,
  isValidAntelopePublicKey,
  nameValue,
  normalizeAntelopeKey,
  parseAsset,
  type AntelopeAdapterOptions,
} from './antelope.js';
import {
  AntelopeTx,
  antelopeActionData,
  antelopeApprovalValid,
  antelopePacked,
  antelopeSigningDigest,
  antelopeTransferStatus,
  antelopeTxId,
  broadcastAntelope,
  memoError,
  prepareAntelope,
  tapos,
} from './send.js';

/** The eosio development key `5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3`. */
const DEV_SECRET = hexToBytes(
  ['d2653ff7cbb2d8ff129a', 'c27ef5781ce68b2558c4', '1a74af1f2ddca635cbee', 'f07d'].join(''),
);
const DEV_LEGACY = ['EO', 'S6MRyAjQq8ud7hVNYcfn', 'VPJqcVpscN5So8BhtHuG', 'YqET5GDW5CV'].join('');
const DEV_PUBLIC = ['PU', 'B_K1_6MRyAjQq8ud7hVN', 'YcfnVPJqcVpscN5So8Bh', 'tHuGYqET5BoDq63'].join(
  '',
);
const ONE_PUBLIC = ['PU', 'B_K1_5p78kHbL33Rn3JW', 'kTWRE2B9uz6gy4r1KbfA', 'KLNQGE3ovLY8E9M'].join(
  '',
);
const WAX_TESTNET_ID = [
  'f16b1833c747c43682f4',
  '386fca9cbb327929334a',
  '762755ebec17f6f23c9b',
  '8a12',
].join('');

const tx: AntelopeTx = {
  chainId: ANTELOPE_TESTNET,
  from: 'stackwallet1',
  permission: 'active',
  to: 'swrecipient2',
  antelopeUnits: '123456789',
  symbol: 'WAX',
  precision: 8,
  tokenContract: 'eosio.token',
  memo: '',
  expiration: 1_792_152_000,
  refBlockNum: 0x1234,
  refBlockPrefix: 0xdeadbeef,
  builtAtSecs: 1_792_151_700,
  publicKey: DEV_PUBLIC,
};
/** `@wharfkit/antelope` output for the same fields; pinned by the core (`antelope.rs`). */
const ACTION_DATA = [
  '10b28ad170884cc620f2',
  '54ae3aa42ec715cd5b07',
  '00000000085741580000',
  '000000',
].join('');
const PACKED =
  'c011d26a3412efbeadde000000000100a6823403ea3055000000572d3ccdcd0110b28ad170884cc600000000a8ed32322110b28ad170884cc620f254ae3aa42ec715cd5b070000000008574158000000000000';
const DIGEST = [
  '7745d93072e34b64d3fa',
  '22f9745f827f48a038aa',
  'a3c06086ab1d20482fae',
  'e2d0',
].join('');
const TXID = ['e7ccc4604379fa1f6cdf', '092539ca64ccf3b661cd', '7cf2c919687fbbf5a349', '46c7'].join(
  '',
);
const SIG =
  'SIG_K1_KVCinNw3R6tf3G6YPVa9NiaXGZQinm44vJ1PUsmADzpdfH334wau5JKfKBPd8nabSQKvmikimcS5R3LSvWCZZUaB3rAdXU';
const MEMO_PACKED =
  'c011d26a3412efbeadde000000000100a6823403ea3055000000572d3ccdcd0110b28ad170884cc600000000a8ed32322b10b28ad170884cc620f254ae3aa42ec715cd5b070000000008574158000000000a696e766f69636520343200';
const MEMO_TXID = [
  'de2ea33d4fe18d369b94',
  '7eea74e2d6f6f5df520f',
  'ce08af4eb87335b5981b',
  'c92a',
].join('');

/** RFC 6979 with the attempt counter as extra data until eosio-canonical, as `antelope.rs` signs. */
function signLikeCore(digest: Uint8Array, secret: Uint8Array): string {
  for (let attempt = 1; attempt < 64; attempt++) {
    const bytes = secp256k1.sign(digest, secret, {
      prehash: false,
      extraEntropy: Uint8Array.of(attempt),
      format: 'recovered',
    });
    const sig = secp256k1.Signature.fromBytes(bytes, 'recovered');
    const rs = sig.toBytes('compact');
    if (!isCanonicalSignature(rs)) continue;
    const compact = new Uint8Array(65);
    compact[0] = 31 + sig.recovery!;
    compact.set(rs, 1);
    return encodeAntelopeSignature(compact);
  }
  throw new Error('no canonical signature');
}

const wire = (sig = SIG, packed = PACKED) =>
  JSON.stringify({
    signatures: [sig],
    compression: 0,
    packed_context_free_data: '',
    packed_trx: packed,
  });

const chain = (chainId: string, symbol: string, decimals: number, rpcs: string[]): ChainInfo => ({
  chainId,
  family: 'antelope',
  name: chainId,
  nativeAsset: { ref: `${chainId}:native`, symbol, decimals },
  testnet: chainId !== VAULTA_MAINNET,
  defaultRpcs: rpcs,
});
const RPC_A = 'https://testnet.waxsweden.org';
const RPC_B = 'https://waxtestnet.greymass.com';
const CHAINS: ChainInfo[] = [
  chain(WAX_TESTNET, 'WAX', 8, [RPC_A, RPC_B]),
  chain(VAULTA_MAINNET, 'EOS', 4, ['https://eos.greymass.com']),
];

class TestAdapter extends AntelopeAdapter {
  constructor(opts: AntelopeAdapterOptions = {}) {
    super({ rpc: new MemoryRpcPool(CHAINS), ...opts });
  }

  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Reply = { status?: number; body: unknown };
type Handler = (url: string, body: Record<string, unknown> | undefined) => Reply | undefined;

function fakeFetch(handler: Handler, calls: string[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    const body =
      typeof init?.body === 'string'
        ? (JSON.parse(init.body) as Record<string, unknown>)
        : undefined;
    const reply = handler(url, body);
    if (!reply)
      return new Response('{"code":404,"error":{"name":"exception","what":"unspecified"}}', {
        status: 404,
      });
    return new Response(JSON.stringify(reply.body), { status: reply.status ?? 200 });
  }) as typeof fetch;
}

const INFO = {
  chain_id: WAX_TESTNET_ID,
  head_block_num: 432_433_463,
  head_block_time: '2026-10-16T11:22:37.500',
  last_irreversible_block_num: 432_433_364,
  last_irreversible_block_id: [
    '19c668d495f5268aa158',
    'aa1c5f3e44442e9d84d7',
    'ee3de971ffedf1a572c7',
    'fe62',
  ].join(''),
};
const account = (name: string, key: string, cpu = 38_408, net = 106_837) => ({
  account_name: name,
  head_block_time: INFO.head_block_time,
  cpu_limit: { used: 0, available: cpu, max: 38_408 },
  net_limit: { used: 0, available: net, max: 106_837 },
  ram_quota: 9592,
  ram_usage: 2996,
  permissions: [
    {
      perm_name: 'active',
      parent: 'owner',
      required_auth: { threshold: 1, keys: [{ key, weight: 1 }], accounts: [], waits: [] },
      linked_actions: [],
    },
    {
      perm_name: 'owner',
      parent: '',
      required_auth: {
        threshold: 1,
        keys: [
          {
            key: ['EO', 'S5w2pDou4unGd1qaksrE', '2nug6ZTbzWtLE36n8ha1', '8qp7EGs62BW'].join(''),
            weight: 1,
          },
        ],
        accounts: [],
        waits: [],
      },
    },
  ],
});
const notFound = {
  status: 500,
  body: { code: 500, error: { name: 'account_query_exception', what: 'Account Query Exception' } },
};

function chainNode(
  over: Partial<Record<string, (b: Record<string, unknown> | undefined) => Reply>> = {},
): Handler {
  return (url, body) => {
    const path = new URL(url).pathname;
    const custom = over[path];
    if (custom) return custom(body);
    switch (path) {
      case '/v1/chain/get_info':
        return { body: INFO };
      case '/v1/chain/get_account':
        if (body?.account_name === 'stackwallet1')
          return { body: account('stackwallet1', DEV_LEGACY) };
        if (body?.account_name === 'swrecipient2')
          return { body: account('swrecipient2', ONE_PUBLIC) };
        return notFound;
      case '/v1/chain/get_currency_balance':
        return { body: body?.account === 'stackwallet1' ? ['500.00000000 WAX'] : [] };
      default:
        return undefined;
    }
  };
}

const intent = (over: Partial<{ to: string; amount: string }> = {}): TxIntent =>
  ({
    id: 'i',
    walletId: 'w',
    accountId: 'a',
    chainId: ANTELOPE_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to: over.to ?? 'swrecipient2',
    asset: `${ANTELOPE_TESTNET}:native`,
    amount: over.amount ?? '123456789',
    untrustedDestinations: [],
    createdAtMs: 0,
  }) as unknown as TxIntent;

describe('keys and names', () => {
  it('matches the wharfkit key vectors', () => {
    expect(antelopePublicKey(secp256k1.getPublicKey(DEV_SECRET, true))).toBe(DEV_PUBLIC);
    expect(antelopePublicKey(secp256k1.getPublicKey(DEV_SECRET, false))).toBe(DEV_PUBLIC);
    expect(antelopePublicKey(secp256k1.getPublicKey(hexToBytes('00'.repeat(31) + '01')))).toBe(
      ONE_PUBLIC,
    );
    expect(normalizeAntelopeKey(DEV_LEGACY)).toBe(DEV_PUBLIC);
    expect(isValidAntelopePublicKey(DEV_PUBLIC)).toBe(true);
    expect(isValidAntelopePublicKey(DEV_LEGACY)).toBe(false);
    expect(normalizeAntelopeKey(DEV_PUBLIC.slice(0, -1) + '4')).toBeUndefined();
    expect(normalizeAntelopeKey(DEV_LEGACY.slice(0, -1) + 'W')).toBeUndefined();
    expect(normalizeAntelopeKey(DEV_PUBLIC.replace('K1', 'R1'))).toBeUndefined();
    const adapter = new TestAdapter();
    expect(
      adapter.deriveAddress(
        { curve: 'secp256k1', hex: bytesToHex(secp256k1.getPublicKey(DEV_SECRET, true)) },
        WAX_TESTNET,
      ),
    ).toBe(DEV_PUBLIC);
    expect(adapter.validateAddress('swrecipient2', WAX_TESTNET)).toBe(true);
    expect(adapter.validateAddress(DEV_PUBLIC, WAX_TESTNET)).toBe(true);
    expect(adapter.validateAddress('Swrecipient2', WAX_TESTNET)).toBe(false);
  });

  it('encodes names like the core', () => {
    const vectors: [string, bigint][] = [
      ['eosio.token', 6138663591592764928n],
      ['transfer', 14829575313431724032n],
      ['active', 3617214756542218240n],
      ['stackwallet1', 14288945735872983568n],
      ['a', 3458764513820540928n],
      ['zzzzzzzzzzzz', 18446744073709551600n],
      ['1.2.3.4.5', 577588303627812864n],
    ];
    for (const [n, v] of vectors) expect(nameValue(n)).toBe(v);
    for (const bad of ['', 'Alice', 'alice.', 'abcdefghijklm', 'a6', 'a b', 'a-b'])
      expect(isValidAntelopeAccount(bad)).toBe(false);
  });

  it('parses assets only in the expected symbol and precision', () => {
    const wax = { contract: 'eosio.token', symbol: 'WAX', precision: 8 };
    expect(parseAsset('500.00000000 WAX', wax)).toBe(50_000_000_000n);
    expect(parseAsset('500.0000 WAX', wax)).toBeUndefined();
    expect(parseAsset('500.00000000 EOS', wax)).toBeUndefined();
    expect(formatAsset(123456789n, wax)).toBe('1.23456789 WAX');
    expect(formatAsset(5n, { ...wax, symbol: 'EOS', precision: 4 })).toBe('0.0005 EOS');
  });

  it('reads node verdicts from truncated error bodies', () => {
    const body =
      '{"code":500,"message":"Internal Service Error","error":{"code":3080004,"name":"tx_cpu_usage_exceeded","what":"Transaction exceeded the current CPU usage limit imposed on the transaction","details":[{"message":"billed CPU time (412 us) is greater than the maximum';
    expect(antelopeErrorOf(body)?.name).toBe('tx_cpu_usage_exceeded');
    expect(antelopeErrorOf('<html>')).toBeUndefined();
  });
});

describe('encoding', () => {
  it('pins the wharfkit packed transaction, digest and id', () => {
    expect(bytesToHex(antelopeActionData(tx))).toBe(ACTION_DATA);
    expect(bytesToHex(antelopePacked(tx))).toBe(PACKED);
    expect(bytesToHex(antelopeSigningDigest(tx))).toBe(DIGEST);
    expect(antelopeTxId(tx)).toBe(TXID);
    const memo = { ...tx, memo: 'invoice 42' };
    expect(bytesToHex(antelopePacked(memo))).toBe(MEMO_PACKED);
    expect(antelopeTxId(memo)).toBe(MEMO_TXID);
  });

  it('recovers the sender from the wharfkit signature', () => {
    const raw = decodeAntelopeSignature(SIG)!;
    expect(raw[0]).toBe(32);
    expect(isCanonicalSignature(raw.subarray(1))).toBe(true);
    expect(encodeAntelopeSignature(raw)).toBe(SIG);
    const point = secp256k1.Signature.fromBytes(raw.subarray(1), 'compact')
      .addRecoveryBit(raw[0]! - 31)
      .recoverPublicKey(hexToBytes(DIGEST))
      .toBytes(true);
    expect(antelopePublicKey(point)).toBe(DEV_PUBLIC);
    expect(decodeAntelopeSignature(SIG.slice(0, -1) + 'V')).toBeUndefined();
  });

  it('reproduces the core and wharfkit signature with noble', () => {
    expect(signLikeCore(hexToBytes(DIGEST), DEV_SECRET)).toBe(SIG);
  });

  it('refuses fields the core refuses', () => {
    expect(() => antelopePacked({ ...tx, to: tx.from })).toThrow();
    expect(() => antelopePacked({ ...tx, antelopeUnits: '0' })).toThrow();
    expect(() => antelopePacked({ ...tx, antelopeUnits: '4611686018427387904' })).toThrow();
    expect(() => antelopePacked({ ...tx, antelopeUnits: '4611686018427387903' })).not.toThrow();
    expect(() => antelopePacked({ ...tx, memo: 'x'.repeat(257) })).toThrow();
    expect(() => antelopePacked({ ...tx, memo: 'é'.repeat(129) })).toThrow();
    expect(() => antelopePacked({ ...tx, memo: 'a\nb' })).toThrow();
    expect(() => antelopePacked({ ...tx, memo: '\u202e' })).toThrow();
    expect(() => antelopePacked({ ...tx, expiration: tx.builtAtSecs })).toThrow();
    expect(() => antelopePacked({ ...tx, expiration: tx.builtAtSecs + 3601 })).toThrow();
    expect(() => antelopePacked({ ...tx, publicKey: DEV_LEGACY })).toThrow();
    expect(() => antelopePacked({ ...tx, symbol: 'EOS' } as unknown as AntelopeTx)).toThrow();
    expect(() =>
      antelopePacked({ ...tx, chainId: VAULTA_MAINNET } as unknown as AntelopeTx),
    ).toThrow();
    expect(() => antelopePacked({ ...tx, extra: 1 } as unknown as AntelopeTx)).toThrow();
    expect(memoError('café ✓')).toBeUndefined();
  });

  it('derives TaPoS from a block id', () => {
    expect(tapos(432_433_364, INFO.last_irreversible_block_id)).toEqual({
      refBlockNum: 26836,
      refBlockPrefix: 0x1caa58a1,
    });
  });
});

describe('prepare', () => {
  it('builds the transfer from chain state', async () => {
    const adapter = new TestAdapter({ fetch: fakeFetch(chainNode()) });
    const { unsigned, simulation } = await prepareAntelope(
      adapter,
      intent(),
      'stackwallet1',
      DEV_PUBLIC,
      {
        memo: 'hi',
      },
    );
    expect(unsigned).toEqual({
      ...tx,
      memo: 'hi',
      expiration: 1_792_149_757 + 1800,
      builtAtSecs: 1_792_149_757,
      refBlockNum: 26836,
      refBlockPrefix: 0x1caa58a1,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('0');
    expect(simulation.warnings.some((w) => w.kind === 'other' && w.message.includes('Memo'))).toBe(
      true,
    );
  });

  it('flags missing CPU or NET and explains PowerUp', async () => {
    const adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v1/chain/get_account': (b) =>
            b?.account_name === 'stackwallet1'
              ? { body: account('stackwallet1', DEV_LEGACY, 120, 5000) }
              : { body: account('swrecipient2', ONE_PUBLIC) },
        }),
      ),
    });
    const { simulation } = await prepareAntelope(adapter, intent(), 'stackwallet1', DEV_PUBLIC);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/120 µs of CPU.*PowerUp/);
  });

  it('refuses a missing recipient, a foreign key and an over-balance send', async () => {
    const adapter = new TestAdapter({ fetch: fakeFetch(chainNode()) });
    await expect(
      prepareAntelope(adapter, intent({ to: 'nosuchacct11' }), 'stackwallet1', DEV_PUBLIC),
    ).rejects.toThrow(/does not exist/);
    await expect(prepareAntelope(adapter, intent(), 'stackwallet1', ONE_PUBLIC)).rejects.toThrow(
      /does not control/,
    );
    const { simulation } = await prepareAntelope(
      adapter,
      intent({ amount: '50000000001' }),
      'stackwallet1',
      DEV_PUBLIC,
    );
    expect(simulation.ok).toBe(false);
    await expect(
      prepareAntelope(
        adapter,
        { ...intent(), chainId: VAULTA_MAINNET } as TxIntent,
        'stackwallet1',
        DEV_PUBLIC,
      ),
    ).rejects.toThrow(/WAX testnet/);
  });

  it('refuses an endpoint on another chain', async () => {
    const adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v1/chain/get_info': () => ({ body: { ...INFO, chain_id: '00'.repeat(32) } }),
        }),
      ),
    });
    await expect(prepareAntelope(adapter, intent(), 'stackwallet1', DEV_PUBLIC)).rejects.toThrow();
  });

  it('approval tracks expiry and the key link', async () => {
    const live = { ...tx, expiration: 1_792_149_757 + 600 };
    let adapter = new TestAdapter({ fetch: fakeFetch(chainNode()) });
    expect(await antelopeApprovalValid(adapter, live)).toBe(true);
    expect(await antelopeApprovalValid(adapter, { ...live, expiration: 1_792_149_757 + 30 })).toBe(
      false,
    );
    adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v1/chain/get_account': () => ({ body: account('stackwallet1', ONE_PUBLIC) }),
        }),
      ),
    });
    expect(await antelopeApprovalValid(adapter, live)).toBe(false);
  });
});

describe('broadcast and status', () => {
  it('pushes only the expected signed body', async () => {
    const pushed: unknown[] = [];
    const adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v1/chain/push_transaction': (b) => {
            pushed.push(b);
            return {
              body: { transaction_id: TXID, processed: { receipt: { status: 'executed' } } },
            };
          },
        }),
      ),
    });
    expect(await broadcastAntelope(adapter, tx, wire())).toBe(TXID);
    expect(pushed).toEqual([JSON.parse(wire())]);
    await expect(broadcastAntelope(adapter, tx, wire(SIG, MEMO_PACKED))).rejects.toThrow(
      /not this/,
    );
    await expect(broadcastAntelope(adapter, { ...tx, memo: 'x' }, wire())).rejects.toThrow(
      /not this/,
    );
    await expect(
      broadcastAntelope(adapter, { ...tx, publicKey: ONE_PUBLIC }, wire()),
    ).rejects.toThrow();
    const raw = decodeAntelopeSignature(SIG)!;
    const flipped = Uint8Array.from(raw);
    flipped[0] = 31;
    await expect(
      broadcastAntelope(adapter, tx, wire(encodeAntelopeSignature(flipped))),
    ).rejects.toThrow(/verify/);
    await expect(
      broadcastAntelope(adapter, tx, wire().replace('"compression":0', '"compression":1')),
    ).rejects.toThrow();
    expect(pushed).toHaveLength(1);
  });

  it('reports node verdicts and accepts a duplicate that is known', async () => {
    const verdict = (name: string) => () => ({
      status: 500,
      body: {
        code: 500,
        message: 'Internal Service Error',
        error: { name, what: name, details: [{ message: `${name} detail` }] },
      },
    });
    let adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({ '/v1/chain/push_transaction': verdict('tx_net_usage_exceeded') }),
      ),
    });
    await expect(broadcastAntelope(adapter, tx, wire())).rejects.toThrow(/tx_net_usage_exceeded/);
    adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v1/chain/push_transaction': verdict('tx_duplicate'),
          '/v1/chain/get_transaction_status': () => ({
            body: { state: 'IN_BLOCK', block_number: 5 },
          }),
        }),
      ),
    });
    expect(await broadcastAntelope(adapter, tx, wire())).toBe(TXID);
  });

  it('reads status from the finality API, then Hyperion', async () => {
    let adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v1/chain/get_transaction_status': () => ({
            body: {
              state: 'IRREVERSIBLE',
              block_number: 432433364,
              block_timestamp: '2026-10-16T11:21:48.000',
            },
          }),
        }),
      ),
    });
    expect(await adapter.status(TXID, WAX_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 432433364,
      timestampMs: Date.parse('2026-10-16T11:21:48.000Z'),
    });
    const health = {
      health: [{ service: 'NodeosRPC', service_data: { chain_id: WAX_TESTNET_ID } }],
    };
    adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v2/health': () => ({ body: health }),
          '/v2/history/get_transaction': () => ({
            body: {
              executed: true,
              trx_id: TXID,
              lib: 432433400,
              actions: [{ block_num: 432433364, '@timestamp': '2026-10-16T11:21:48.000' }],
            },
          }),
        }),
      ),
    });
    expect((await adapter.status(TXID, WAX_TESTNET)).state).toBe('confirmed');
    adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v2/health': () => ({ body: health }),
          '/v2/history/get_transaction': () => ({ body: { executed: false, trx_id: TXID } }),
        }),
      ),
    });
    expect(await adapter.status(TXID, WAX_TESTNET)).toEqual({ state: 'unknown' });
    expect(
      await antelopeTransferStatus(adapter, { ...tx, expiration: 1_792_149_000 }, TXID),
    ).toEqual({
      state: 'expired',
    });
    expect(
      await antelopeTransferStatus(adapter, { ...tx, expiration: 1_792_150_000 }, TXID),
    ).toEqual({
      state: 'unknown',
    });
    const wrongChain = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v2/health': () => ({
            body: {
              health: [{ service: 'NodeosRPC', service_data: { chain_id: '11'.repeat(32) } }],
            },
          }),
          '/v2/history/get_transaction': () => ({
            body: { executed: true, trx_id: TXID, actions: [{ block_num: 1 }] },
          }),
        }),
      ),
    });
    expect(await wrongChain.status(TXID, WAX_TESTNET)).toEqual({ state: 'unknown' });
  });
});

describe('reads', () => {
  it('discovers accounts for a key and cross-checks balances', async () => {
    const calls: string[] = [];
    const adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v1/chain/get_accounts_by_authorizers': () => ({
            body: {
              accounts: [
                {
                  account_name: 'stackwallet1',
                  permission_name: 'owner',
                  authorizing_key: DEV_LEGACY,
                  weight: 1,
                  threshold: 1,
                },
                {
                  account_name: 'stackwallet1',
                  permission_name: 'active',
                  authorizing_key: DEV_LEGACY,
                  weight: 1,
                  threshold: 1,
                },
                {
                  account_name: 'weakaccount1',
                  permission_name: 'active',
                  authorizing_key: DEV_LEGACY,
                  weight: 1,
                  threshold: 2,
                },
                {
                  account_name: 'otheraccount',
                  permission_name: 'active',
                  authorizing_key: ONE_PUBLIC,
                  weight: 1,
                  threshold: 1,
                },
              ],
            },
          }),
        }),
        calls,
      ),
    });
    expect(await adapter.accountsForKey(DEV_LEGACY, WAX_TESTNET)).toEqual([
      { account: 'stackwallet1', permission: 'active' },
      { account: 'stackwallet1', permission: 'owner' },
    ]);
    const [holding] = await adapter.getBalances(DEV_PUBLIC, WAX_TESTNET);
    expect(holding!.amount).toBe('50000000000');
    expect(holding!.provenance?.kind).toBe('agreed');
    expect(holding!.notice).toMatch(/stackwallet1/);
    const [byName] = await adapter.getBalances('stackwallet1', WAX_TESTNET);
    expect(byName!.notice).toBeUndefined();
    expect(calls.every((u) => u.startsWith(RPC_A) || u.startsWith(RPC_B))).toBe(true);
  });

  it('reports a key without an account', async () => {
    const adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({ '/v1/chain/get_accounts_by_authorizers': () => ({ body: { accounts: [] } }) }),
      ),
    });
    const [holding] = await adapter.getBalances(ONE_PUBLIC, WAX_TESTNET);
    expect(holding!.amount).toBe('0');
    expect(holding!.notice).toMatch(/created on chain/);
  });

  it('maps Hyperion actions into history', async () => {
    const health = {
      health: [{ service: 'NodeosRPC', service_data: { chain_id: WAX_TESTNET_ID } }],
    };
    const actions = [
      {
        '@timestamp': '2026-10-16T11:21:48.000',
        block_num: 432433364,
        trx_id: [
          'ca2ce3ec7c6864a9d90d',
          '606df6969b71624f6cdd',
          '3de5038367b404b03601',
          '5b48',
        ].join(''),
        global_sequence: 863937283,
        act: {
          account: 'eosio.token',
          name: 'transfer',
          authorization: [{ actor: 'faucet.wax', permission: 'operation' }],
          data: { from: 'faucet.wax', to: 'stackwallet1', quantity: '500.00000000 WAX', memo: '' },
        },
      },
      {
        '@timestamp': '2026-10-16T11:21:43.500',
        block_num: 432433353,
        trx_id: '11'.repeat(32),
        act: {
          account: 'eosio',
          name: 'newaccount',
          authorization: [{ actor: 'faucet.wax', permission: 'active' }],
          data: {},
        },
      },
      {
        '@timestamp': '2026-10-16T11:21:43.500',
        block_num: 432433353,
        trx_id: '22'.repeat(32),
        act: {
          account: 'fake.token',
          name: 'transfer',
          data: { from: 'x', to: 'stackwallet1', quantity: '9.00000000 WAX' },
        },
      },
    ];
    const adapter = new TestAdapter({
      fetch: fakeFetch(
        chainNode({
          '/v2/health': () => ({ body: health }),
          '/v2/history/get_actions': () => ({ body: { actions } }),
        }),
      ),
    });
    const page = await adapter.getHistory('stackwallet1', WAX_TESTNET);
    expect(page.items).toHaveLength(3);
    expect(page.items[0]).toMatchObject({
      from: 'faucet.wax',
      to: 'stackwallet1',
      fee: '0',
      assetDeltas: [{ assetRef: `${WAX_TESTNET}:native`, amount: '50000000000' }],
    });
    expect(page.items[1]).toMatchObject({ description: 'eosio::newaccount', assetDeltas: [] });
    expect(page.items[2]).toMatchObject({ description: 'fake.token::transfer', assetDeltas: [] });
    expect(page.nextCursor).toBeUndefined();
    await expect(adapter.getHistory('stackwallet1', WAX_TESTNET, '0')).rejects.toThrow();
  });
});
