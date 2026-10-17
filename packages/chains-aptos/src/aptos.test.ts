import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  APTOS_MAINNET,
  APTOS_TESTNET,
  AptosAdapter,
  MOVEMENT_MAINNET,
  SUPRA_MAINNET,
  aptosAddressFromPublicKey,
  faAssetRef,
  isValidAptosAddress,
  normalizeAptosAddress,
} from './aptos.js';
import {
  AptosTx,
  aptosApprovalValid,
  aptosRawTransaction,
  aptosSignedTxHash,
  aptosSigningMessage,
  aptosTransferStatus,
  broadcastAptos,
  maxGasFor,
  prepareAptos,
} from './send.js';

const SEED = new Uint8Array(32).fill(7);
const SENDER = '0xcc405722b15c00a19d37e51d9a756de1e61b780ad0935f3363bc7fce64edbdad';
const RECIPIENT = '0x978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa';
const USDC = '0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b';

const tx: AptosTx = {
  chainId: APTOS_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  octas: '150000000',
  sequenceNumber: '7',
  maxGasAmount: 2000,
  gasUnitPrice: 100,
  expirationTimestampSecs: 1_760_000_600,
};
/** Produced by `@aptos-labs/ts-sdk` 7.5.0 for the same fields and pinned by the core (`aptos.rs`). */
const RAW_VECTOR =
  'cc405722b15c00a19d37e51d9a756de1e61b780ad0935f3363bc7fce64edbdad07000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa0880d1f00800000000d0070000000000006400000000000000587ae7680000000002';
const SIGNED_VECTOR =
  'cc405722b15c00a19d37e51d9a756de1e61b780ad0935f3363bc7fce64edbdad07000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa0880d1f00800000000d0070000000000006400000000000000587ae76800000000020020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c40d470aff68b8e1aa3d7210140520d9ab949df0d310c5a5e14f8865cc39bb7ed742ad0be147e2c1f9aadacf4efa0c0ccccbbed6e20ecc8a000ed28546177e39500';
const HASH_VECTOR = '0xdb94298325234b017360f255cc13ebab45dba88a371c5e401df7d640c29952c9';

const chain = (chainId: string, name: string, symbol: string, testnet: boolean, rpc: string) =>
  ({
    chainId,
    family: 'aptos',
    name,
    nativeAsset: { ref: `${chainId}:native`, symbol, decimals: 8 },
    testnet,
    defaultRpcs: [rpc],
  }) as ChainInfo;
const MAINNET_RPC = 'https://api.mainnet.aptoslabs.com/v1';
const TESTNET_RPC = 'https://api.testnet.aptoslabs.com/v1';
const CHAINS: ChainInfo[] = [
  chain(APTOS_MAINNET, 'Aptos', 'APT', false, MAINNET_RPC),
  chain(APTOS_TESTNET, 'Aptos Testnet', 'APT', true, TESTNET_RPC),
  chain(MOVEMENT_MAINNET, 'Movement', 'MOVE', false, 'https://mainnet.movementnetwork.xyz/v1'),
  chain(SUPRA_MAINNET, 'Supra', 'SUPRA', false, 'https://rpc-mainnet.supra.com/rpc/v1'),
];

class TestAdapter extends AptosAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Reply = { status?: number; body: unknown } | undefined;
type Route = (url: URL, body: unknown, init?: RequestInit) => Reply;

const ledger = (chainId: number, secs = 1_760_000_000) => ({
  chain_id: chainId,
  ledger_version: '91673188',
  ledger_timestamp: `${secs}000000`,
  block_height: '7047485',
});

function node(routes: Record<string, Route>, root: unknown = ledger(2)) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push({ url: url.toString(), ...(init ? { init } : {}) });
    const path = url.pathname.replace(/^\/(rpc\/)?v1/, '');
    if (path === '' || path === '/') return Response.json(root);
    const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : init?.body;
    const out = routes[path]?.(url, body, init);
    if (!out)
      return Response.json(
        { message: 'not found', error_code: 'not_found', vm_error_code: null },
        { status: 404 },
      );
    return Response.json(out.body, { status: out.status ?? 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });
}

type ViewBody = { function: string; type_arguments: string[]; arguments: string[] };
const balances =
  (by: Record<string, string>, wrap = false): Route =>
  (_url, body) => {
    const b = body as ViewBody;
    const key = `${b.function}<${b.type_arguments.join(',')}>(${b.arguments.join(',')})`;
    const value = by[key] ?? by[b.arguments[0]!] ?? '0';
    return { body: wrap ? { result: [value] } : [value] };
  };
const account =
  (seq: string): Route =>
  () => ({
    body: { sequence_number: seq, authentication_key: SENDER },
  });

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: APTOS_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${APTOS_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  } as unknown as TxIntent;
}

const signedHex = (t: AptosTx) => {
  const sig = ed25519.sign(aptosSigningMessage(t), SEED);
  const pub = ed25519.getPublicKey(SEED);
  return `0x${bytesToHex(aptosRawTransaction(t))}0020${bytesToHex(pub)}40${bytesToHex(sig)}`;
};

describe('aptos addresses', () => {
  it('derives the SDK addresses', () => {
    const pub = ed25519.getPublicKey(SEED);
    expect(aptosAddressFromPublicKey(pub)).toBe(SENDER);
    // ts-sdk unit-test key 0xc5338cd2…efa5.
    const doc = Buffer.from(
      'de19e5d1880cac87d57484ce9ed2e84cf0f9599f12e7cc3a52e4e7657a763f2c',
      'hex',
    );
    expect(aptosAddressFromPublicKey(doc)).toBe(RECIPIENT);
    // ts-sdk `Account.fromDerivationPath` m/44'/637'/0'/0'/0' of "abandon … about".
    const petra = ed25519.getPublicKey(
      Buffer.from('cc92c0eaf80206d817f150e21917f797e49cf644a33ac514de3c316baa2f1bf5', 'hex'),
    );
    expect(aptosAddressFromPublicKey(petra)).toBe(
      '0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf',
    );
    const a = new TestAdapter();
    expect(a.deriveAddress({ curve: 'ed25519', hex: bytesToHex(pub) }, APTOS_TESTNET)).toBe(SENDER);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, APTOS_TESTNET),
    ).toThrow();
    expect(() => aptosAddressFromPublicKey(pub.subarray(0, 31))).toThrow();
  });

  it('accepts only canonical long-form user addresses', () => {
    expect(isValidAptosAddress(RECIPIENT)).toBe(true);
    expect(isValidAptosAddress(RECIPIENT.toUpperCase().replace('0X', '0x'))).toBe(false);
    expect(isValidAptosAddress(RECIPIENT.slice(2))).toBe(false);
    expect(isValidAptosAddress('0x1')).toBe(false);
    expect(isValidAptosAddress(`0x${'0'.repeat(63)}a`)).toBe(false);
    expect(isValidAptosAddress(`0x${'0'.repeat(62)}10`)).toBe(true);
    expect(isValidAptosAddress('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')).toBe(false);
    expect(normalizeAptosAddress(` ${RECIPIENT.toUpperCase().replace('0X', '0x')} `)).toBe(
      RECIPIENT,
    );
    expect(normalizeAptosAddress('0xA8F')).toBe(`0x${'0'.repeat(61)}a8f`);
    expect(normalizeAptosAddress('0x1')).toBeUndefined();
    expect(normalizeAptosAddress(`0x${'1'.repeat(65)}`)).toBeUndefined();
  });
});

describe('aptos transfers', () => {
  it('encodes and signs the same bytes as the SDK and the core', () => {
    expect(bytesToHex(aptosRawTransaction(tx))).toBe(RAW_VECTOR);
    const signed = signedHex(tx);
    expect(signed).toBe(`0x${SIGNED_VECTOR}`);
    expect(aptosSignedTxHash(Buffer.from(SIGNED_VECTOR, 'hex'))).toBe(HASH_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => aptosRawTransaction({ ...tx, octas: '0' })).toThrow();
    expect(() => aptosRawTransaction({ ...tx, octas: '0150000000' })).toThrow();
    expect(() => aptosRawTransaction({ ...tx, octas: '18446744073709551616' })).toThrow();
    expect(() => aptosRawTransaction({ ...tx, sequenceNumber: '07' })).toThrow();
    expect(() => aptosRawTransaction({ ...tx, to: tx.from })).toThrow();
    expect(() => aptosRawTransaction({ ...tx, to: '0x1' })).toThrow();
    expect(() => aptosRawTransaction({ ...tx, maxGasAmount: 0 })).toThrow();
    expect(() => aptosRawTransaction({ ...tx, maxGasAmount: 20_001 })).toThrow();
    expect(() =>
      aptosRawTransaction({ ...tx, maxGasAmount: 20_000, gasUnitPrice: 10_000 }),
    ).toThrow();
    expect(() =>
      aptosRawTransaction({ ...tx, expirationTimestampSecs: 1_760_000_600_000 }),
    ).toThrow();
    expect(() =>
      aptosRawTransaction({ ...tx, chainId: APTOS_MAINNET as typeof APTOS_TESTNET }),
    ).toThrow();
    expect(() => AptosTx.parse({ ...tx, payload: '00' })).toThrow();
    expect(aptosRawTransaction({ ...tx, sequenceNumber: '0' }).length).toBe(RAW_VECTOR.length / 2);
  });

  it('budgets gas for new state slots', () => {
    expect(maxGasFor(100, 0)).toBe(2_000);
    expect(maxGasFor(100, 1)).toBe(7_000);
    expect(maxGasFor(100, 2)).toBe(12_000);
    expect(maxGasFor(150, 2)).toBe(8_667);
    expect(maxGasFor(1, 2)).toBe(20_000);
  });

  it('prepares a transfer from a new sender to a new recipient', async () => {
    const { fetchImpl, calls } = node({
      [`/accounts/${SENDER}`]: account('0'),
      '/estimate_gas_price': () => ({
        body: { deprioritized_gas_estimate: 100, gas_estimate: 100, prioritized_gas_estimate: 150 },
      }),
      '/view': balances({ [SENDER]: '200000000' }),
    });
    const { unsigned, simulation } = await prepareAptos(
      adapter(fetchImpl),
      intent(RECIPIENT, '150000000'),
      SENDER,
      1_760_000_000_500,
    );
    expect(unsigned).toEqual({
      chainId: APTOS_TESTNET,
      from: SENDER,
      to: RECIPIENT,
      octas: '150000000',
      sequenceNumber: '0',
      maxGasAmount: 12_000,
      gasUnitPrice: 100,
      expirationTimestampSecs: 1_760_001_800,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee).toEqual({ assetRef: `${APTOS_TESTNET}:native`, amount: '1200000' });
    expect(simulation.warnings).toHaveLength(2);
    const view = calls.find((c) => c.url.endsWith('/view'))!;
    expect(JSON.parse(view.init!.body as string)).toMatchObject({
      function: '0x1::coin::balance',
      type_arguments: ['0x1::aptos_coin::AptosCoin'],
    });
  });

  it('flags a balance that cannot reserve the fee bound', async () => {
    const { fetchImpl } = node({
      [`/accounts/${SENDER}`]: account('7'),
      '/estimate_gas_price': () => ({ body: { gas_estimate: 100 } }),
      '/view': balances({ [SENDER]: '150100000', [RECIPIENT]: '5' }),
    });
    const { unsigned, simulation } = await prepareAptos(
      adapter(fetchImpl),
      intent(RECIPIENT, '150000000'),
      SENDER,
      1_760_000_000_500,
    );
    expect(unsigned.maxGasAmount).toBe(2_000);
    expect(unsigned.sequenceNumber).toBe('7');
    expect(simulation.ok).toBe(false);
    expect(simulation.warnings).toHaveLength(1);
  });

  it('refuses mainnet, tokens, a wrong network and a clock behind the ledger', async () => {
    const routes = {
      [`/accounts/${SENDER}`]: account('7'),
      '/estimate_gas_price': () => ({ body: { gas_estimate: 100 } }),
      '/view': balances({}),
    };
    const a = adapter(node(routes).fetchImpl);
    await expect(
      prepareAptos(a, { ...intent(RECIPIENT, '1'), chainId: APTOS_MAINNET } as TxIntent, SENDER),
    ).rejects.toThrow(/testnet/);
    await expect(
      prepareAptos(
        a,
        { ...intent(RECIPIENT, '1'), asset: `${APTOS_TESTNET}:fa:0xa` } as TxIntent,
        SENDER,
      ),
    ).rejects.toThrow(/native/);
    await expect(prepareAptos(a, intent(SENDER, '1'), SENDER)).rejects.toThrow();
    const wrong = adapter(node(routes, ledger(1)).fetchImpl);
    await expect(prepareAptos(wrong, intent(RECIPIENT, '1'), SENDER)).rejects.toThrow();
    const ahead = adapter(node(routes, ledger(2, 1_760_010_000)).fetchImpl);
    await expect(
      prepareAptos(ahead, intent(RECIPIENT, '1'), SENDER, 1_760_000_000_000),
    ).rejects.toThrow(/clock/);
  });

  it('keeps approval only while the sequence and expiry hold', async () => {
    const at = (seq: string, secs = 1_760_000_000) =>
      adapter(node({ [`/accounts/${SENDER}`]: account(seq) }, ledger(2, secs)).fetchImpl);
    expect(await aptosApprovalValid(at('7'), tx, 1_760_000_000_000)).toBe(true);
    expect(await aptosApprovalValid(at('8'), tx, 1_760_000_000_000)).toBe(false);
    expect(await aptosApprovalValid(at('7', 1_760_000_550), tx, 1_760_000_000_000)).toBe(false);
    expect(await aptosApprovalValid(at('7'), tx, 1_760_000_550_000)).toBe(false);
  });

  it('broadcasts exactly the signed transfer', async () => {
    const { fetchImpl, calls } = node({
      '/transactions': (_u, body, init) => {
        expect(new Headers(init?.headers).get('content-type')).toBe(
          'application/x.aptos.signed_transaction+bcs',
        );
        expect(bytesToHex(body as Uint8Array)).toBe(SIGNED_VECTOR);
        return { status: 202, body: { type: 'pending_transaction', hash: HASH_VECTOR } };
      },
    });
    expect(await broadcastAptos(adapter(fetchImpl), tx, signedHex(tx))).toBe(HASH_VECTOR);
    expect(calls.some((c) => c.init?.method === 'POST')).toBe(true);
  });

  it('refuses tampered, foreign or mis-signed bytes before broadcasting', async () => {
    const { fetchImpl, calls } = node({});
    const a = adapter(fetchImpl);
    const good = signedHex(tx);
    const flip = (hex: string, at: number) =>
      hex.slice(0, at) + (hex[at] === '0' ? '1' : '0') + hex.slice(at + 1);
    await expect(broadcastAptos(a, tx, flip(good, 80))).rejects.toThrow(/not this APT/);
    await expect(broadcastAptos(a, tx, flip(good, good.length - 4))).rejects.toThrow(/verify/);
    await expect(broadcastAptos(a, tx, good + '00')).rejects.toThrow(/not this APT/);
    const other = new Uint8Array(32).fill(9);
    const foreign = `0x${bytesToHex(aptosRawTransaction(tx))}0020${bytesToHex(ed25519.getPublicKey(other))}40${bytesToHex(ed25519.sign(aptosSigningMessage(tx), other))}`;
    await expect(broadcastAptos(a, tx, foreign)).rejects.toThrow(/sender/);
    await expect(
      broadcastAptos(a, { ...tx, chainId: APTOS_MAINNET as typeof APTOS_TESTNET }, good),
    ).rejects.toThrow(/testnet/);
    expect(calls.some((c) => c.init?.method === 'POST')).toBe(false);
  });

  it('reports node rejections and accepts a retry that already landed', async () => {
    const rejected = node({
      '/transactions': () => ({
        status: 400,
        body: {
          message:
            'Invalid transaction: Type: Validation Code: INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE',
          error_code: 'vm_error',
          vm_error_code: 5,
        },
      }),
    });
    await expect(broadcastAptos(adapter(rejected.fetchImpl), tx, signedHex(tx))).rejects.toThrow(
      /INSUFFICIENT_BALANCE/,
    );
    const retried = node({
      '/transactions': () => ({
        status: 400,
        body: { message: 'Invalid transaction: Type: Validation Code: SEQUENCE_NUMBER_TOO_OLD' },
      }),
      [`/transactions/by_hash/${HASH_VECTOR}`]: () => ({ body: userTx(true) }),
    });
    expect(await broadcastAptos(adapter(retried.fetchImpl), tx, signedHex(tx))).toBe(HASH_VECTOR);
    const mismatch = node({
      '/transactions': () => ({ status: 202, body: { hash: `0x${'ab'.repeat(32)}` } }),
    });
    await expect(broadcastAptos(adapter(mismatch.fetchImpl), tx, signedHex(tx))).rejects.toThrow(
      /different/,
    );
  });

  it('tracks pending, confirmed, failed and expired transfers', async () => {
    const at = (reply: Reply, seq = '7', secs = 1_760_000_000) =>
      adapter(
        node(
          {
            [`/transactions/by_hash/${HASH_VECTOR}`]: () => reply,
            [`/accounts/${SENDER}`]: account(seq),
          },
          ledger(2, secs),
        ).fetchImpl,
      );
    expect(
      await aptosTransferStatus(
        at({ body: { type: 'pending_transaction', hash: HASH_VECTOR } }),
        tx,
        HASH_VECTOR,
      ),
    ).toEqual({ state: 'pending' });
    expect(await aptosTransferStatus(at({ body: userTx(true) }), tx, HASH_VECTOR)).toEqual({
      state: 'confirmed',
      blockNumber: 91673188,
      timestampMs: 1_760_000_100_123,
    });
    expect(await aptosTransferStatus(at({ body: userTx(false) }), tx, HASH_VECTOR)).toEqual({
      state: 'failed',
      reason: 'Move abort in 0x1::coin: EINSUFFICIENT_BALANCE(0x10006)',
    });
    expect(await aptosTransferStatus(at(undefined), tx, HASH_VECTOR)).toEqual({ state: 'unknown' });
    expect(await aptosTransferStatus(at(undefined, '8'), tx, HASH_VECTOR)).toEqual({
      state: 'expired',
    });
    expect(await aptosTransferStatus(at(undefined, '7', 1_760_000_601), tx, HASH_VECTOR)).toEqual({
      state: 'expired',
    });
  });
});

function userTx(success: boolean, extra: Record<string, unknown> = {}) {
  return {
    type: 'user_transaction',
    version: '91673188',
    hash: HASH_VECTOR,
    success,
    vm_status: success
      ? 'Executed successfully'
      : 'Move abort in 0x1::coin: EINSUFFICIENT_BALANCE(0x10006)',
    timestamp: '1760000100123456',
    sender: SENDER,
    sequence_number: '7',
    gas_used: '12',
    gas_unit_price: '100',
    max_gas_amount: '2000',
    payload: {
      type: 'entry_function_payload',
      function: '0x1::aptos_account::transfer',
      type_arguments: [],
      arguments: [RECIPIENT, '150000000'],
    },
    changes: [],
    ...extra,
  };
}

describe('aptos reads', () => {
  it('reads APT and USDC on mainnet with the chain id proven', async () => {
    const { fetchImpl } = node(
      {
        '/view': balances({
          [`0x1::coin::balance<0x1::aptos_coin::AptosCoin>(${SENDER})`]: '11120868786',
          [`0x1::primary_fungible_store::balance<0x1::fungible_asset::Metadata>(${SENDER},${USDC})`]:
            '6872573199',
        }),
      },
      ledger(1),
    );
    const holdings = await adapter(fetchImpl).getBalances(SENDER, APTOS_MAINNET);
    expect(holdings.map((h) => [h.assetRef, h.amount])).toEqual([
      [`${APTOS_MAINNET}:native`, '11120868786'],
      [faAssetRef(APTOS_MAINNET, USDC), '6872573199'],
    ]);
    expect(holdings[1]!.metadata).toEqual({ symbol: 'USDC', decimals: 6 });
    const testnet = await adapter(
      node({ '/view': balances({ [SENDER]: '5' }) }).fetchImpl,
    ).getBalances(SENDER, APTOS_TESTNET);
    expect(testnet.map((h) => h.amount)).toEqual(['5']);
    await expect(
      adapter(node({ '/view': balances({}) }, ledger(2)).fetchImpl).getBalances(
        SENDER,
        APTOS_MAINNET,
      ),
    ).rejects.toThrow();
    await expect(adapter(fetchImpl).getBalances('0x1', APTOS_MAINNET)).rejects.toThrow();
  });

  it('reads Movement as AptosCoin and Supra through its own dialect', async () => {
    const movement = node({ '/view': balances({ [SENDER]: '377410874' }) }, ledger(126));
    const [move] = await adapter(movement.fetchImpl).getBalances(SENDER, MOVEMENT_MAINNET);
    expect(move!.amount).toBe('377410874');
    const supra = node(
      {
        '/block': () => ({
          body: { height: 56249346, view: { epoch_id: { chain_id: 8, epoch: 8326 }, round: 1 } },
        }),
        '/view': (url, body) => {
          expect((body as ViewBody).type_arguments).toEqual(['0x1::supra_coin::SupraCoin']);
          return balances({ [SENDER]: '1910000103' }, true)(url, body);
        },
      },
      { message: 'no root' },
    );
    const a = adapter(supra.fetchImpl);
    const [sup] = await a.getBalances(SENDER, SUPRA_MAINNET);
    expect(sup!.amount).toBe('1910000103');
    expect((await a.getHistory(SENDER, SUPRA_MAINNET)).items).toEqual([]);
    await expect(a.status(HASH_VECTOR, SUPRA_MAINNET)).rejects.toThrow(/not supported/);
  });

  it('lists sent transactions newest first, paged by sequence number', async () => {
    const { fetchImpl, calls } = node(
      {
        [`/accounts/${SENDER}`]: account('25'),
        [`/accounts/${SENDER}/transactions`]: () => ({
          body: [
            userTx(true, { version: '10', sequence_number: '5' }),
            userTx(false, {
              version: '11',
              sequence_number: '6',
              hash: `0x${'cd'.repeat(32)}`,
              payload: {
                type: 'entry_function_payload',
                function: '0xd368::dex::place_order',
                type_arguments: [],
                arguments: ['1'],
              },
            }),
            { type: 'garbage' },
          ],
        }),
      },
      ledger(2),
    );
    const page = await adapter(fetchImpl).getHistory(SENDER, APTOS_TESTNET);
    const list = calls.find((c) => c.url.includes('/transactions?'))!;
    expect(new URL(list.url).searchParams.get('start')).toBe('5');
    expect(new URL(list.url).searchParams.get('limit')).toBe('20');
    expect(page.nextCursor).toBe('5');
    expect(page.items.map((i) => i.blockNumber)).toEqual([11, 10]);
    expect(page.items[1]).toMatchObject({
      hash: HASH_VECTOR,
      from: SENDER,
      to: RECIPIENT,
      status: 'confirmed',
      fee: '1200',
      timestampMs: 1_760_000_100_123,
      assetDeltas: [{ assetRef: `${APTOS_TESTNET}:native`, amount: '-150000000' }],
    });
    expect(page.items[0]).toMatchObject({
      status: 'failed',
      description: '0xd368::dex::place_order',
      assetDeltas: [],
    });
    const older = await adapter(fetchImpl).getHistory(SENDER, APTOS_TESTNET, '5');
    expect(older.nextCursor).toBeUndefined();
    await expect(adapter(fetchImpl).getHistory(SENDER, APTOS_TESTNET, '0')).rejects.toThrow();
  });
});
