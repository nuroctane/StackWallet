import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  MAX_FEE,
  StacksTx,
  broadcastStacks,
  prepareStacks,
  stacksApprovalValid,
  stacksSighash,
  stacksTransferStatus,
  stacksTxId,
  stacksUnsignedBytes,
} from './send.js';
import {
  STACKS_MAINNET,
  STACKS_TESTNET,
  StacksAdapter,
  encodeStacksAddress,
  isValidStacksAddress,
  stacksAddressFromPublicKey,
} from './stacks.js';

/** Compressed public key of private key 1. */
const KEY_ONE = [
  '0279be667ef9dcbbac55',
  'a06295ce870b07029bfc',
  'db2dce28d959f2815b16',
  'f81798',
].join('');
const KEY_ONE_TESTNET = ['ST1THWXQ8368SDN2MJGE', '4BMDKMCHZ2GSVTSQDA7Q', 'F'].join('');
const KEY_ONE_MAINNET = ['SP1THWXQ8368SDN2MJGE', '4BMDKMCHZ2GSVTS1X0BP', 'M'].join('');
const RECIPIENT = ['ST2CY5V39NHDPWSXMW9Q', 'DT3HC3GD6Q6XX4CFRK9A', 'G'].join('');
const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

const tx: StacksTx = {
  chainId: STACKS_TESTNET,
  from: KEY_ONE_TESTNET,
  to: RECIPIENT,
  microstx: '1500000',
  fee: 180,
  nonce: 7,
};
/** `@stacks/transactions` output for these fields; the core (`stacks.rs`) pins the same hex. */
const UNSIGNED_VECTOR =
  '80800000000400751e76e8199196d454941c45d1b3a323f1433bd6000000000000000700000000000000b400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000000051a99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd23000000000016e36000000000000000000000000000000000000000000000000000000000000000000000';
const SIGNED_VECTOR =
  '80800000000400751e76e8199196d454941c45d1b3a323f1433bd6000000000000000700000000000000b40000cdd4dfa8b6c82ef87bebf85581c142d592374b7f7051ddbc23509dbec52a1f500ad387b563c2b7df70d2c7dc77a94b237aa872f2362f6bd3fb965dc5f6facfea03020000000000051a99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd23000000000016e36000000000000000000000000000000000000000000000000000000000000000000000';
const TXID_VECTOR = [
  '0xb1f0e6c2f0e261b47d',
  'c201e563f8e75def59f5',
  '8b98aafc7ba602f57589',
  'abcdc9',
].join('');

const CHAINS: ChainInfo[] = [
  {
    chainId: STACKS_MAINNET,
    family: 'stacks',
    name: 'Stacks',
    nativeAsset: { ref: `${STACKS_MAINNET}:native`, symbol: 'STX', decimals: 6 },
    testnet: false,
    defaultRpcs: ['https://api.hiro.so'],
  },
  {
    chainId: STACKS_TESTNET,
    family: 'stacks',
    name: 'Stacks Testnet',
    nativeAsset: { ref: `${STACKS_TESTNET}:native`, symbol: 'STX', decimals: 6 },
    testnet: true,
    defaultRpcs: ['https://api.testnet.hiro.so'],
  },
];

class TestAdapter extends StacksAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Route = (url: URL, body: unknown) => { status?: number; body: unknown } | undefined;

function node(routes: Record<string, Route>, networkId = 2147483648) {
  const calls: { path: string; body: unknown }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const body = init?.body ? (JSON.parse(String(init.body)) as unknown) : undefined;
    calls.push({ path: url.pathname, body });
    if (url.pathname === '/v2/info') return Response.json({ network_id: networkId });
    const out = routes[url.pathname]?.(url, body);
    if (!out) return Response.json({ statusCode: 404, error: 'Not Found' }, { status: 404 });
    return Response.json(out.body, { status: out.status ?? 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const adapter = (fetchImpl: typeof fetch) =>
  new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });

const nonces = (next: number, executed: number | null = next - 1) => ({
  body: {
    last_executed_tx_nonce: executed,
    last_mempool_tx_nonce: null,
    possible_next_nonce: next,
    detected_missing_nonces: [],
    detected_mempool_nonces: [],
  },
});

const intent = {
  id: 't',
  walletId: 'w',
  accountId: 'a',
  chainId: STACKS_TESTNET,
  kind: 'transfer',
  to: RECIPIENT,
  asset: `${STACKS_TESTNET}:native`,
  amount: '1500000',
  proposer: { kind: 'human', deviceId: 'd' },
  untrustedDestinations: [],
  createdAtMs: 0,
} as unknown as TxIntent;

describe('stacks addresses', () => {
  it('derives the SDK addresses of private key 1', () => {
    expect(stacksAddressFromPublicKey(hexToBytes(KEY_ONE))).toBe(KEY_ONE_TESTNET);
    expect(stacksAddressFromPublicKey(hexToBytes(KEY_ONE), STACKS_MAINNET)).toBe(KEY_ONE_MAINNET);
    const a = new TestAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: KEY_ONE }, STACKS_TESTNET)).toBe(
      KEY_ONE_TESTNET,
    );
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, STACKS_TESTNET),
    ).toThrow();
  });

  it('matches the c32check reference vector', () => {
    expect(
      encodeStacksAddress(
        22,
        hexToBytes(['a46ff88886c2ef9762d9', '70b4d2c63678835bd39d'].join('')),
      ),
    ).toBe(['SP2J6ZY48GV1EZ5V2V5R', 'B9MP66SW86PYKKNRV9EJ', '7'].join(''));
    const low = new Uint8Array(20);
    low[19] = 1;
    const addr = encodeStacksAddress(26, low);
    expect(addr.startsWith('ST0')).toBe(true);
    expect(isValidStacksAddress(addr, STACKS_TESTNET)).toBe(true);
  });

  it('refuses bad checksums, other networks, contracts and the zero address', () => {
    const a = new TestAdapter();
    expect(a.validateAddress(RECIPIENT, STACKS_TESTNET)).toBe(true);
    expect(a.validateAddress(KEY_ONE_MAINNET, STACKS_TESTNET)).toBe(false);
    expect(a.validateAddress(KEY_ONE_MAINNET, STACKS_MAINNET)).toBe(true);
    expect(isValidStacksAddress(RECIPIENT.slice(0, -1) + 'H')).toBe(false);
    expect(isValidStacksAddress(RECIPIENT.toLowerCase())).toBe(false);
    expect(isValidStacksAddress(`${RECIPIENT}.pox-4`)).toBe(false);
    expect(isValidStacksAddress(`ST0${RECIPIENT.slice(2)}`)).toBe(false);
    expect(isValidStacksAddress(encodeStacksAddress(26, new Uint8Array(20)))).toBe(false);
  });
});

describe('stacks transfers', () => {
  it('encodes the same bytes as the SDK and the core', () => {
    expect(hex(stacksUnsignedBytes(tx))).toBe(UNSIGNED_VECTOR);
    expect(stacksTxId(hexToBytes(SIGNED_VECTOR))).toBe(TXID_VECTOR);
    expect(stacksSighash(tx)).toMatch(/^[0-9a-f]{64}$/);
    expect(stacksSighash({ ...tx, fee: 181 })).not.toBe(stacksSighash(tx));
  });

  it('refuses hostile fields', () => {
    expect(() => stacksUnsignedBytes({ ...tx, microstx: '0' })).toThrow();
    expect(() => stacksUnsignedBytes({ ...tx, microstx: '01' })).toThrow();
    expect(() => stacksUnsignedBytes({ ...tx, microstx: '18446744073709551616' })).toThrow();
    expect(() => stacksUnsignedBytes({ ...tx, fee: 0 })).toThrow();
    expect(() => stacksUnsignedBytes({ ...tx, fee: MAX_FEE + 1 })).toThrow();
    expect(() => stacksUnsignedBytes({ ...tx, to: tx.from })).toThrow();
    expect(() => stacksUnsignedBytes({ ...tx, to: KEY_ONE_MAINNET })).toThrow();
    expect(() =>
      stacksUnsignedBytes({ ...tx, chainId: STACKS_MAINNET as typeof STACKS_TESTNET }),
    ).toThrow();
    expect(() => StacksTx.parse({ ...tx, memo: 'x' })).toThrow();
  });

  it('prepares a testnet transfer with the next nonce and the estimated fee', async () => {
    const { fetchImpl, calls } = node({
      [`/extended/v1/address/${KEY_ONE_TESTNET}/nonces`]: () => nonces(7),
      [`/extended/v1/address/${KEY_ONE_TESTNET}/stx`]: () => ({
        body: { balance: '2000000', locked: '100000' },
      }),
      '/v2/fees/transaction': () => ({
        body: { estimations: [{ fee: 200 }, { fee: 322 }, { fee: 900 }] },
      }),
    });
    const { unsigned, simulation } = await prepareStacks(
      adapter(fetchImpl),
      intent,
      KEY_ONE_TESTNET,
    );
    expect(unsigned).toEqual({ ...tx, fee: 322 });
    expect(simulation).toMatchObject({ ok: true, fee: { amount: '322' } });
    const feeCall = calls.find((c) => c.path === '/v2/fees/transaction')!;
    expect(feeCall.body).toEqual({
      transaction_payload: UNSIGNED_VECTOR.slice(-130),
      estimated_len: 180,
    });
  });

  it('falls back to the per-byte rate, keeps the 1/byte floor and counts locked STX', async () => {
    const { fetchImpl } = node({
      [`/extended/v1/address/${KEY_ONE_TESTNET}/nonces`]: () => nonces(0, null),
      [`/extended/v1/address/${KEY_ONE_TESTNET}/stx`]: () => ({
        body: { balance: '1500100', locked: '1000' },
      }),
      '/v2/fees/transaction': () => ({ status: 400, body: { error: 'NoEstimateAvailable' } }),
      '/v2/fees/transfer': () => ({ body: 0 }),
    });
    const { unsigned, simulation } = await prepareStacks(
      adapter(fetchImpl),
      intent,
      KEY_ONE_TESTNET,
    );
    expect(unsigned.fee).toBe(180);
    expect(unsigned.nonce).toBe(0);
    expect(simulation.ok).toBe(false);
  });

  it('refuses an endpoint that serves another Stacks network', async () => {
    const { fetchImpl } = node(
      {
        [`/extended/v1/address/${RECIPIENT}/stx`]: () => ({ body: { balance: '1', locked: '0' } }),
      },
      1,
    );
    await expect(adapter(fetchImpl).getBalances(RECIPIENT, STACKS_TESTNET)).rejects.toThrow();
  });

  it('reads balances with a stacking notice', async () => {
    const { fetchImpl } = node(
      {
        [`/extended/v1/address/${KEY_ONE_MAINNET}/stx`]: () => ({
          body: { balance: '95000000000000001', locked: '5', estimated_balance: '1' },
        }),
      },
      1,
    );
    const [h] = await adapter(fetchImpl).getBalances(KEY_ONE_MAINNET, STACKS_MAINNET);
    expect(h).toMatchObject({ assetRef: `${STACKS_MAINNET}:native`, amount: '95000000000000001' });
    expect(h!.notice).toMatch(/locked/);
  });

  it('broadcasts only the ledger transfer with one signature', async () => {
    const seen: unknown[] = [];
    const { fetchImpl } = node({
      '/v2/transactions': (_u, body) => {
        seen.push(body);
        return { body: TXID_VECTOR.slice(2) };
      },
    });
    const a = adapter(fetchImpl);
    await expect(broadcastStacks(a, tx, `0x${SIGNED_VECTOR}`)).resolves.toBe(TXID_VECTOR);
    expect(seen).toEqual([{ tx: SIGNED_VECTOR }]);
    await expect(
      broadcastStacks(a, { ...tx, microstx: '1500001' }, SIGNED_VECTOR),
    ).rejects.toThrow();
    await expect(broadcastStacks(a, tx, SIGNED_VECTOR + '00')).rejects.toThrow();
    const badRecovery = SIGNED_VECTOR.slice(0, 88) + '04' + SIGNED_VECTOR.slice(90);
    await expect(broadcastStacks(a, tx, badRecovery)).rejects.toThrow();
    expect(seen).toHaveLength(1);
  });

  it('surfaces a rejection reason and treats a known txid as a retry', async () => {
    let known = false;
    const { fetchImpl } = node({
      '/v2/transactions': () => ({
        status: 400,
        body: {
          error: 'transaction rejected',
          reason: 'NotEnoughFunds',
          txid: TXID_VECTOR.slice(2),
        },
      }),
      [`/extended/v1/tx/${TXID_VECTOR}`]: () =>
        known
          ? {
              body: {
                tx_id: TXID_VECTOR,
                tx_type: 'token_transfer',
                tx_status: 'pending',
                sender_address: KEY_ONE_TESTNET,
              },
            }
          : undefined,
    });
    const a = adapter(fetchImpl);
    await expect(broadcastStacks(a, tx, SIGNED_VECTOR)).rejects.toThrow(/NotEnoughFunds/);
    known = true;
    await expect(broadcastStacks(a, tx, SIGNED_VECTOR)).resolves.toBe(TXID_VECTOR);
  });

  it('maps statuses and reports expiry only after the nonce is consumed', async () => {
    let executed = 6;
    const statuses: Record<string, unknown> = {
      [`0x${'aa'.repeat(32)}`]: {
        tx_status: 'success',
        block_height: 12,
        block_time: 1_760_000_000,
      },
      [`0x${'bb'.repeat(32)}`]: { tx_status: 'abort_by_response' },
      [`0x${'cc'.repeat(32)}`]: {
        tx_status: 'dropped_replace_by_fee',
        replaced_by_tx_id: `0x${'dd'.repeat(32)}`,
      },
    };
    const { fetchImpl } = node({
      [`/extended/v1/address/${KEY_ONE_TESTNET}/nonces`]: () => nonces(executed + 1, executed),
      ...Object.fromEntries(
        Object.entries(statuses).map(([id, s]) => [
          `/extended/v1/tx/${id}`,
          () => ({
            body: {
              tx_id: id,
              tx_type: 'token_transfer',
              sender_address: KEY_ONE_TESTNET,
              ...(s as object),
            },
          }),
        ]),
      ),
    });
    const a = adapter(fetchImpl);
    await expect(a.status(`0x${'aa'.repeat(32)}`, STACKS_TESTNET)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 12,
      timestampMs: 1_760_000_000_000,
    });
    await expect(a.status('bb'.repeat(32), STACKS_TESTNET)).resolves.toMatchObject({
      state: 'failed',
    });
    await expect(a.status(`0x${'cc'.repeat(32)}`, STACKS_TESTNET)).resolves.toEqual({
      state: 'replaced',
      byHash: `0x${'dd'.repeat(32)}`,
    });
    await expect(stacksTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({ state: 'unknown' });
    await expect(stacksApprovalValid(a, tx)).resolves.toBe(true);
    executed = 7;
    await expect(stacksTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({ state: 'expired' });
    await expect(stacksApprovalValid(a, tx)).resolves.toBe(false);
  });

  it('reads history with STX deltas and offset cursors', async () => {
    const { fetchImpl } = node({
      [`/extended/v1/address/${KEY_ONE_TESTNET}/transactions`]: (url) => ({
        body: {
          limit: 20,
          offset: Number(url.searchParams.get('offset')),
          total: 21,
          results: [
            {
              tx_id: TXID_VECTOR,
              tx_type: 'token_transfer',
              tx_status: 'success',
              sender_address: KEY_ONE_TESTNET,
              fee_rate: '180',
              block_height: 5,
              block_time: 1_760_000_000,
              token_transfer: { recipient_address: RECIPIENT, amount: '1500000', memo: '0x00' },
            },
            {
              tx_id: `0x${'ee'.repeat(32)}`,
              tx_type: 'contract_call',
              tx_status: 'abort_by_response',
              sender_address: RECIPIENT,
              fee_rate: '3000',
            },
          ],
        },
      }),
    });
    const page = await adapter(fetchImpl).getHistory(KEY_ONE_TESTNET, STACKS_TESTNET);
    expect(page.nextCursor).toBe('2');
    expect(page.items[0]).toMatchObject({
      hash: TXID_VECTOR,
      to: RECIPIENT,
      fee: '180',
      status: 'confirmed',
      assetDeltas: [{ assetRef: `${STACKS_TESTNET}:native`, amount: '-1500000' }],
    });
    expect(page.items[1]).toMatchObject({
      status: 'failed',
      fee: '0',
      description: 'contract_call',
    });
  });
});
