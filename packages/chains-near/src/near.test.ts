import { ed25519 } from '@noble/curves/ed25519.js';
import { base58, base64 } from '@scure/base';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  GENESIS_HASHES,
  NEAR_MAINNET,
  NEAR_TESTNET,
  NearAdapter,
  failureReason,
  implicitPublicKey,
  isImplicitAccount,
  isValidNearAccountId,
  nearAddressFromPublicKey,
  tokenRef,
} from './near.js';
import {
  MIN_NEW_IMPLICIT_YOCTO,
  NearTx,
  broadcastNear,
  nearApprovalValid,
  nearTransferStatus,
  nearTxBorsh,
  nearTxHash,
  prepareNear,
  transferFee,
} from './send.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const SEED = new Uint8Array(32).fill(7);
/** Implicit account of seed `[7; 32]`, from `@near-js/crypto` KeyPair. */
const SENDER = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c';
const RFC_SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const RFC_ACCOUNT = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const BLOCK_HASH = '4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw';
const USDC = '17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1';

const tx: NearTx = {
  chainId: NEAR_TESTNET,
  from: SENDER,
  to: 'receiver.testnet',
  yocto: '1500000000000000000000000',
  nonce: '123456789012345',
  blockHash: BLOCK_HASH,
  blockHeight: 273_319_917,
};
/** Produced by `@near-js/transactions` for the same fields and pinned by the core (`near.rs`). */
const TX_VECTOR =
  '400000006561346136633633653239633532306162656635353037623133326563356639393534373736616562656265376239323432316565613639313434366432326300ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c79df0d86487000001000000072656365697665722e746573746e65740102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200100000003000080716433b629a33d010000000000';
const HASH_VECTOR = '7Cxca3BzhUVDPn3Mh6Y266hGuHmHoUkkEfF5TGe8HQtv';
const SIGNED_VECTOR =
  '400000006561346136633633653239633532306162656635353037623133326563356639393534373736616562656265376239323432316565613639313434366432326300ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c79df0d86487000001000000072656365697665722e746573746e65740102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200100000003000080716433b629a33d010000000000001bfe0065918525840da2baf3a9be68d89b55ec2936a4df2aa83e8173b692fecf409820d8ed0303ff16fc40fd6d65b8ee3beee0bcbcac98af5d6de00d1bc14407';
const SIGNED_BASE64 =
  'QAAAAGVhNGE2YzYzZTI5YzUyMGFiZWY1NTA3YjEzMmVjNWY5OTU0Nzc2YWViZWJlN2I5MjQyMWVlYTY5MTQ0NmQyMmMA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0ix53w2GSHAAABAAAAByZWNlaXZlci50ZXN0bmV0AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyABAAAAAwAAgHFkM7Ypoz0BAAAAAAAAG/4AZZGFJYQNorrzqb5o2JtV7Ck2pN8qqD6Bc7aS/s9AmCDY7QMD/xb8QP1tZbjuO+7gvLysmK9dbeANG8FEBw==';

const CHAINS: ChainInfo[] = [
  {
    chainId: NEAR_MAINNET,
    family: 'near',
    name: 'NEAR',
    nativeAsset: { ref: `${NEAR_MAINNET}:native`, symbol: 'NEAR', decimals: 24 },
    testnet: false,
    defaultRpcs: ['https://free.rpc.fastnear.com', 'https://rpc.mainnet.near.org'],
  },
  {
    chainId: NEAR_TESTNET,
    family: 'near',
    name: 'NEAR Testnet',
    nativeAsset: { ref: `${NEAR_TESTNET}:native`, symbol: 'NEAR', decimals: 24 },
    testnet: true,
    defaultRpcs: ['https://test.rpc.fastnear.com'],
  },
];

class TestAdapter extends NearAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Rpc = (params: Record<string, unknown>) => { result?: unknown; error?: unknown } | undefined;
type Rest = (body: Record<string, unknown>) => unknown;

function handlerError(name: string, data: unknown = 'error') {
  return {
    error: {
      name: 'HANDLER_ERROR',
      cause: { name, info: {} },
      code: -32000,
      message: 'Server error',
      data,
    },
  };
}

function node(
  methods: Record<string, Rpc>,
  opts: { genesis?: string | undefined; rest?: Record<string, Rest> } = {},
) {
  const calls: { url: string; method?: string; body: Record<string, unknown> }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    const rest = opts.rest?.[`${url.host}${url.pathname}`];
    if (rest) {
      calls.push({ url: url.toString(), body });
      return Response.json(rest(body));
    }
    const method = String(body.method);
    calls.push({ url: url.toString(), method, body });
    if (method === 'status')
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: {
          chain_id: url.host.includes('test') ? 'testnet' : 'mainnet',
          genesis_hash:
            opts.genesis ?? GENESIS_HASHES[url.host.includes('test') ? NEAR_TESTNET : NEAR_MAINNET],
        },
      });
    const out = methods[method]?.(body.params as Record<string, unknown>);
    if (!out)
      return Response.json({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'no' } });
    return Response.json({ jsonrpc: '2.0', id: 1, ...out });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });
}

const account = (amount: string, storage = 182, locked = '0') => ({
  result: {
    amount,
    locked,
    storage_usage: storage,
    block_height: 100,
    code_hash: '11111111111111111111111111111111',
  },
});
const header = (height: number, hash: string, gas = '100000000') => ({
  result: { header: { height, hash, timestamp_nanosec: '1792144697254299966', gas_price: gas } },
});
const FINAL_HASH = base58.encode(new Uint8Array(32).fill(5));

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: NEAR_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${NEAR_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  } as unknown as TxIntent;
}

function query(
  accounts: Record<string, unknown>,
  nonce = 7,
  permission: unknown = 'FullAccess',
): Rpc {
  return (p) => {
    if (p.request_type === 'view_account') {
      const a = accounts[String(p.account_id)];
      return a ? (a as { result: unknown }) : handlerError('UNKNOWN_ACCOUNT');
    }
    if (p.request_type === 'view_access_key') {
      if (p.public_key !== implicitPublicKey(String(p.account_id)))
        return { result: { error: 'access key does not exist while viewing', logs: [] } };
      return { result: { nonce, permission, block_height: 100 } };
    }
    return undefined;
  };
}

describe('NEAR addresses', () => {
  it('derives implicit accounts like the SDK', () => {
    expect(nearAddressFromPublicKey(ed25519.getPublicKey(SEED))).toBe(SENDER);
    const rfc = Uint8Array.from(Buffer.from(RFC_SEED, 'hex'));
    expect(nearAddressFromPublicKey(ed25519.getPublicKey(rfc))).toBe(RFC_ACCOUNT);
    const a = adapter(node({}).fetchImpl);
    expect(
      a.deriveAddress({ curve: 'ed25519', hex: hex(ed25519.getPublicKey(SEED)) }, NEAR_TESTNET),
    ).toBe(SENDER);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, NEAR_TESTNET),
    ).toThrow();
    expect(implicitPublicKey(SENDER)).toBe('ed25519:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB');
  });

  it('validates account ids', () => {
    for (const ok of [
      'ab',
      'alice.testnet',
      'a-b_c.near',
      'app.alice.testnet',
      RFC_ACCOUNT,
      'a'.repeat(64),
    ])
      expect(isValidNearAccountId(ok)).toBe(true);
    for (const bad of [
      'a',
      'a'.repeat(65),
      'Alice.testnet',
      'alice..testnet',
      '.alice',
      'alice.',
      '-alice',
      'al--ice',
      'al-_ice',
      'alice@testnet',
    ])
      expect(isValidNearAccountId(bad)).toBe(false);
    expect(isImplicitAccount(SENDER)).toBe(true);
    expect(isImplicitAccount('alice.testnet')).toBe(false);
    expect(isImplicitAccount(SENDER.toUpperCase())).toBe(false);
  });
});

describe('NEAR encoding', () => {
  it('matches the SDK and core vectors', () => {
    expect(hex(nearTxBorsh(tx))).toBe(TX_VECTOR);
    expect(nearTxHash(tx)).toBe(HASH_VECTOR);
    const sig = ed25519.sign(base58.decode(HASH_VECTOR), SEED);
    expect(TX_VECTOR + '00' + hex(sig)).toBe(SIGNED_VECTOR);
    expect(base64.encode(Uint8Array.from(Buffer.from(SIGNED_VECTOR, 'hex')))).toBe(SIGNED_BASE64);
  });

  it('refuses hostile fields', () => {
    const bad: Partial<NearTx>[] = [
      { yocto: '0' },
      { yocto: '01' },
      { yocto: (10n ** 34n + 1n).toString() },
      { nonce: '0' },
      { nonce: (1n << 64n).toString() },
      { to: SENDER },
      { to: 'Bad..id' },
      { from: 'alice.testnet' },
      { blockHash: `1${BLOCK_HASH}` },
      { chainId: NEAR_MAINNET as typeof NEAR_TESTNET },
    ];
    for (const b of bad) expect(() => nearTxBorsh({ ...tx, ...b }), JSON.stringify(b)).toThrow();
    expect(() => NearTx.parse({ ...tx, memo: 'x' })).toThrow();
  });

  it('names failure variants', () => {
    expect(
      failureReason({
        ActionError: { index: 0, kind: { AccountDoesNotExist: { account_id: 'x' } } },
      }),
    ).toBe('ActionError AccountDoesNotExist');
    expect(failureReason({ TxExecutionError: { InvalidTxError: 'Expired' } })).toBe(
      'TxExecutionError InvalidTxError Expired',
    );
    expect(
      failureReason({
        TxExecutionError: { InvalidTxError: { InvalidNonce: { tx_nonce: 1, ak_nonce: 2 } } },
      }),
    ).toBe('TxExecutionError InvalidTxError InvalidNonce');
  });
});

describe('NEAR reads', () => {
  it('refuses an endpoint on another network', async () => {
    const { fetchImpl } = node(
      { query: query({ [SENDER]: account('5') }) },
      { genesis: GENESIS_HASHES[NEAR_MAINNET] },
    );
    await expect(adapter(fetchImpl).getBalances(SENDER, NEAR_TESTNET)).rejects.toThrow();
  });

  it('reads balances, treating an unknown account as zero', async () => {
    const { fetchImpl } = node({
      query: query({ [SENDER]: account('2500000000000000000000000') }),
    });
    const a = adapter(fetchImpl);
    const [held] = await a.getBalances(SENDER, NEAR_TESTNET);
    expect(held!.amount).toBe('2500000000000000000000000');
    const [none] = await a.getBalances(RFC_ACCOUNT, NEAR_TESTNET);
    expect(none!.amount).toBe('0');
  });

  it('reads mainnet USDC through ft_balance_of on two endpoints', async () => {
    const encoded = [...new TextEncoder().encode('"1234567"')];
    const { fetchImpl, calls } = node({
      query: (p) => {
        if (p.request_type === 'call_function') {
          expect(p.account_id).toBe(USDC);
          expect(JSON.parse(atob(String(p.args_base64)))).toEqual({ account_id: 'alice.near' });
          return { result: { result: encoded, logs: [] } };
        }
        return account('10');
      },
    });
    const holdings = await adapter(fetchImpl).getBalances('alice.near', NEAR_MAINNET);
    expect(holdings.map((h) => h.amount)).toEqual(['10', '1234567']);
    expect(holdings[1]!.assetRef).toBe(tokenRef(NEAR_MAINNET, USDC));
    expect(holdings[0]!.provenance?.kind).toBe('agreed');
    expect(new Set(calls.map((c) => new URL(c.url).host)).size).toBe(2);
  });

  it('maps indexed history with exact deposits and a resume cursor', async () => {
    const h1 = base58.encode(new Uint8Array(32).fill(1));
    const h2 = base58.encode(new Uint8Array(32).fill(2));
    const { fetchImpl, calls } = node(
      {},
      {
        rest: {
          'tx.test.fastnear.com/v0/account': (body) => {
            expect(body).toEqual({ account_id: SENDER, limit: 20, resume_token: '42' });
            return {
              account_txs: [
                {
                  transaction_hash: h1,
                  tx_block_height: 10,
                  tx_block_timestamp: '1792143011581168775',
                  is_success: true,
                },
                {
                  transaction_hash: h2,
                  tx_block_height: 9,
                  tx_block_timestamp: '1792143011000000000',
                  is_success: false,
                },
              ],
              resume_token: '41',
              txs_count: 2,
            };
          },
          'tx.test.fastnear.com/v0/transactions': () => ({
            transactions: [
              {
                transaction: {
                  hash: h1,
                  signer_id: 'faucet.testnet',
                  receiver_id: SENDER,
                  actions: [{ Transfer: { deposit: '1234567890123456789012345' } }],
                },
                execution_outcome: { block_height: 10, outcome: { tokens_burnt: '100' } },
                receipts: [{ execution_outcome: { outcome: { tokens_burnt: '20' } } }],
              },
              {
                transaction: {
                  hash: h2,
                  signer_id: SENDER,
                  receiver_id: 'app.testnet',
                  actions: ['CreateAccount', { FunctionCall: { method_name: 'x', deposit: '5' } }],
                },
              },
            ],
          }),
        },
      },
    );
    const page = await adapter(fetchImpl).getHistory(SENDER, NEAR_TESTNET, '42');
    expect(page.items[0]).toMatchObject({
      hash: h1,
      from: 'faucet.testnet',
      to: SENDER,
      status: 'confirmed',
      fee: '120',
      timestampMs: 1792143011581,
      assetDeltas: [{ assetRef: `${NEAR_TESTNET}:native`, amount: '1234567890123456789012345' }],
    });
    expect(page.items[0]!.description).toBeUndefined();
    expect(page.items[1]).toMatchObject({
      status: 'failed',
      description: 'CreateAccount, FunctionCall',
      fee: null,
      assetDeltas: [{ amount: '0' }],
    });
    expect(page.nextCursor).toBeUndefined();
    expect(calls).toHaveLength(2);
    await expect(adapter(fetchImpl).getHistory(SENDER, NEAR_TESTNET, 'x')).rejects.toThrow();
  });

  it('reports tx status from RPC', async () => {
    const outcomeBlock = base58.encode(new Uint8Array(32).fill(3));
    let level = 'INCLUDED';
    let status: unknown = { SuccessValue: '' };
    const { fetchImpl } = node({
      tx: (p) => {
        if (p.tx_hash !== HASH_VECTOR) return handlerError('UNKNOWN_TRANSACTION');
        expect(p.sender_account_id).toBe(SENDER);
        return {
          result: {
            final_execution_status: level,
            status,
            transaction_outcome: { block_hash: outcomeBlock },
          },
        };
      },
      block: (p) => (p.block_id === outcomeBlock ? header(500, outcomeBlock) : undefined),
    });
    const a = adapter(fetchImpl);
    expect(await a.txStatus(HASH_VECTOR, SENDER, NEAR_TESTNET)).toEqual({ state: 'pending' });
    level = 'FINAL';
    expect(await a.txStatus(HASH_VECTOR, SENDER, NEAR_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 500,
      timestampMs: 1792144697254,
    });
    status = {
      Failure: { ActionError: { index: 0, kind: { AccountDoesNotExist: { account_id: 'x' } } } },
    };
    expect(await a.txStatus(HASH_VECTOR, SENDER, NEAR_TESTNET)).toEqual({
      state: 'failed',
      reason: 'ActionError AccountDoesNotExist',
    });
    expect(await a.txStatus(FINAL_HASH, SENDER, NEAR_TESTNET)).toEqual({ state: 'unknown' });
  });
});

describe('NEAR send', () => {
  it('prepares a transfer from chain state', async () => {
    const { fetchImpl } = node({
      query: query({
        [SENDER]: account('3000000000000000000000000'),
        'receiver.testnet': account('1'),
      }),
      block: () => header(273_400_000, FINAL_HASH),
    });
    const { unsigned, simulation } = await prepareNear(
      adapter(fetchImpl),
      intent('receiver.testnet', '1500000000000000000000000'),
      SENDER,
    );
    expect(unsigned).toEqual({
      chainId: NEAR_TESTNET,
      from: SENDER,
      to: 'receiver.testnet',
      yocto: '1500000000000000000000000',
      nonce: '8',
      blockHash: FINAL_HASH,
      blockHeight: 273_400_000,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe(transferFee(100_000_000n, false).toString());
    expect(simulation.warnings).toEqual([]);
  });

  it('handles absent recipients, storage reserve and key permissions', async () => {
    const accounts = { [SENDER]: account('2000000000000000000000') };
    const { fetchImpl } = node({
      query: query(accounts),
      block: () => header(273_400_000, FINAL_HASH),
    });
    const a = adapter(fetchImpl);
    await expect(prepareNear(a, intent('nobody.testnet', '1000'), SENDER)).rejects.toThrow(
      /does not exist/,
    );
    await expect(prepareNear(a, intent(RFC_ACCOUNT, '1000'), SENDER)).rejects.toThrow(/0.00182/);
    const created = await prepareNear(
      a,
      intent(RFC_ACCOUNT, MIN_NEW_IMPLICIT_YOCTO.toString()),
      SENDER,
    );
    expect(created.simulation.warnings).toHaveLength(1);
    // 0.002 NEAR minus 182 bytes of storage cannot cover 0.00182 NEAR plus fees.
    expect(created.simulation.ok).toBe(false);
    await expect(prepareNear(a, intent('x.testnet', '1'), RFC_ACCOUNT)).rejects.toThrow(/fund it/);
    await expect(
      prepareNear(a, { ...intent('x.testnet', '1'), chainId: NEAR_MAINNET } as TxIntent, SENDER),
    ).rejects.toThrow();
    const limited = node({
      query: query({ [SENDER]: account('5'), 'x.testnet': account('1') }, 7, { FunctionCall: {} }),
      block: () => header(273_400_000, FINAL_HASH),
    });
    await expect(
      prepareNear(adapter(limited.fetchImpl), intent('x.testnet', '1'), SENDER),
    ).rejects.toThrow(/cannot sign/);
  });

  it('checks approval against nonce and block validity', async () => {
    let nonce = 123456789012344;
    let head = tx.blockHeight + 100;
    const { fetchImpl } = node({
      query: (p) => query({}, nonce)(p),
      block: (p) =>
        p.block_id === BLOCK_HASH
          ? header(tx.blockHeight, BLOCK_HASH)
          : p.finality === 'final'
            ? header(head, FINAL_HASH)
            : handlerError('UNKNOWN_BLOCK'),
    });
    const a = adapter(fetchImpl);
    expect(await nearApprovalValid(a, tx)).toBe(true);
    expect(await nearApprovalValid(a, { ...tx, blockHeight: tx.blockHeight + 1 })).toBe(false);
    head = tx.blockHeight + 86_400 - 3_000;
    expect(await nearApprovalValid(a, tx)).toBe(false);
    head = tx.blockHeight + 100;
    nonce = 123456789012345;
    expect(await nearApprovalValid(a, tx)).toBe(false);
  });

  it('broadcasts only the exact signed transaction', async () => {
    let answer: { result?: unknown; error?: unknown } = {
      result: { final_execution_status: 'INCLUDED' },
    };
    const sent: string[] = [];
    const { fetchImpl } = node({
      send_tx: (p) => {
        sent.push(String(p.signed_tx_base64));
        return answer;
      },
      tx: () => handlerError('UNKNOWN_TRANSACTION'),
    });
    const a = adapter(fetchImpl);
    expect(await broadcastNear(a, tx, `0x${SIGNED_VECTOR}`)).toBe(HASH_VECTOR);
    expect(sent).toEqual([SIGNED_BASE64]);
    const sig = SIGNED_VECTOR.slice(-128);
    const flipped = (sig[0] === '0' ? '1' : '0') + sig.slice(1);
    await expect(broadcastNear(a, tx, TX_VECTOR + '00' + flipped)).rejects.toThrow(/verify/);
    await expect(broadcastNear(a, { ...tx, yocto: '1' }, SIGNED_VECTOR)).rejects.toThrow(
      /not this NEAR transfer/,
    );
    await expect(broadcastNear(a, tx, SIGNED_VECTOR + '00')).rejects.toThrow();
    answer = handlerError('TIMEOUT_ERROR');
    expect(await broadcastNear(a, tx, SIGNED_VECTOR)).toBe(HASH_VECTOR);
    answer = handlerError('INVALID_TRANSACTION', {
      TxExecutionError: { InvalidTxError: { InvalidNonce: { tx_nonce: 1, ak_nonce: 2 } } },
    });
    await expect(broadcastNear(a, tx, SIGNED_VECTOR)).rejects.toThrow(/InvalidNonce/);
    expect(sent).toHaveLength(3);
  });

  it('reports expiry only when the hash is unknown everywhere', async () => {
    let head = tx.blockHeight + 10;
    let indexed: unknown[] = [];
    const { fetchImpl } = node(
      {
        tx: () => handlerError('UNKNOWN_TRANSACTION'),
        query: query({}, 5),
        block: () => header(head, FINAL_HASH),
      },
      { rest: { 'tx.test.fastnear.com/v0/transactions': () => ({ transactions: indexed }) } },
    );
    const a = adapter(fetchImpl);
    expect(await nearTransferStatus(a, tx, HASH_VECTOR)).toEqual({ state: 'unknown' });
    head = tx.blockHeight + 86_401;
    expect(await nearTransferStatus(a, tx, HASH_VECTOR)).toEqual({ state: 'expired' });
    indexed = [
      {
        transaction: {
          hash: HASH_VECTOR,
          signer_id: SENDER,
          receiver_id: 'receiver.testnet',
          actions: [],
        },
        execution_outcome: {
          block_height: 273_319_920,
          block_timestamp: 1792143011581169000,
          outcome: { tokens_burnt: '1' },
        },
        receipts: [
          { execution_outcome: { outcome: { tokens_burnt: '0', status: { SuccessValue: '' } } } },
        ],
      },
    ];
    expect(await nearTransferStatus(a, tx, HASH_VECTOR)).toMatchObject({
      state: 'confirmed',
      blockNumber: 273_319_920,
    });
  });
});
