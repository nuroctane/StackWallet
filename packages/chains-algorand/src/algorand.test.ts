import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  ALGORAND_MAINNET,
  ALGORAND_TESTNET,
  AlgorandAdapter,
  NETWORKS,
  USDC_ASA,
  VOI_MAINNET,
  algorandAddressBytes,
  algorandAddressFromPublicKey,
  asaAssetRef,
  caip2FromGenesisHash,
  isValidAlgorandAddress,
  simulateRequest,
} from './algorand.js';
import {
  AlgorandTx,
  algorandApprovalValid,
  algorandSigningMessage,
  algorandTransferStatus,
  algorandTxId,
  algorandTxnMsgpack,
  broadcastAlgorand,
  feeBid,
  prepareAlgorand,
} from './send.js';

const SEED = new Uint8Array(32).fill(7);
const SENDER = '5JFGYY7CTRJAVPXVKB5RGLWF7GKUO5VOX27HXESCD3VGSFCG2IWAKDM5YU';
const RECIPIENT = '7ULSIOC2UDDVWZH3PDGWAL5B3GI7327XNMJ4LDWXALVMQNPJ6YMB7QOADI';
const TESTNET = NETWORKS[ALGORAND_TESTNET]!;

const tx: AlgorandTx = {
  chainId: ALGORAND_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  microalgos: '1500000',
  fee: 1000,
  firstValid: 68_321_000,
  lastValid: 68_322_000,
  genesisID: 'testnet-v1.0',
  genesisHash: TESTNET.genesisHash,
};
/** Produced by algosdk 3.9.0 for the same fields and pinned by the core (`algorand.rs`). */
const SMALL_TXN =
  '89a3616d74ce0016e360a3666565cd03e8a26676ce04127ee8a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76ce041282d0a3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179';
const SMALL_TXID = 'J2ZUC43BOWQL7A2ZEWYF53UMG24HCN3P7UL5LF6M4VV5CPRMROHQ';
const SMALL_SIGNED =
  '82a3736967c440bac24643b1616dc4ee75f7c335ea7580ec7f53e909744c14d3b155db913d535e656ff523e253e7122fbdd5ba6bca100aec48b36db8146e0a029c6ab1ba67f909a374786e89a3616d74ce0016e360a3666565cd03e8a26676ce04127ee8a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76ce041282d0a3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179';
const BIG_TXN =
  '89a3616d74cf001ff973cafa8000a3666565ce0003d090a2667605a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76cd03eca3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179';
const BIG_TXID = 'GAHQSBQVFR27KVPZUJ722ZPEAJFVLOGRDUZBT3K5OTTWR6PPFSDA';
const TINY_TXN =
  '89a3616d7401a3666565cd03e8a266767fa367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76cc80a3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179';
const TINY_TXID = '72RT7KS25RZP4IYPXNASOZLFJAQOXPJ3DGOG64MCFZFJB5UEQV2Q';

const chain = (chainId: string, name: string, symbol: string, testnet: boolean, rpcs: string[]) =>
  ({
    chainId,
    family: 'algorand',
    name,
    nativeAsset: { ref: `${chainId}:native`, symbol, decimals: 6 },
    testnet,
    defaultRpcs: rpcs,
  }) as ChainInfo;
const MAIN_A = 'https://mainnet-api.algonode.cloud';
const MAIN_B = 'https://mainnet-api.4160.nodely.dev';
const TEST_A = 'https://testnet-api.algonode.cloud';
const TEST_IDX = 'https://testnet-idx.algonode.cloud';
const CHAINS: ChainInfo[] = [
  chain(ALGORAND_MAINNET, 'Algorand', 'ALGO', false, [MAIN_A, MAIN_B]),
  chain(ALGORAND_TESTNET, 'Algorand Testnet', 'ALGO', true, [TEST_A]),
  chain(VOI_MAINNET, 'Voi', 'VOI', false, ['https://mainnet-api.voi.nodely.dev']),
];
const INDEXERS = new MemoryRpcPool([chain(ALGORAND_TESTNET, 'idx', 'ALGO', true, [TEST_IDX])]);

class TestAdapter extends AlgorandAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Reply = { status?: number; body: unknown } | undefined;
type Route = (url: URL, init?: RequestInit) => Reply;

const params = (chainId: string, lastRound = 68_321_500, fee = 0) => ({
  'consensus-version': 'x',
  fee,
  'genesis-hash': NETWORKS[chainId]!.genesisHash,
  'genesis-id': NETWORKS[chainId]!.genesisId,
  'last-round': lastRound,
  'min-fee': 1000,
});
const account = (address: string, amount: number, extra: Record<string, unknown> = {}) => ({
  address,
  amount,
  'amount-without-pending-rewards': amount,
  'min-balance': 100_000,
  'pending-rewards': 0,
  round: 68_321_500,
  status: 'Offline',
  ...extra,
});

function node(routes: Record<string, Route>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push({ url: url.toString(), ...(init ? { init } : {}) });
    const key = `${init?.method ?? 'GET'} ${url.origin}${url.pathname}`;
    const route = Object.entries(routes).find(([k]) =>
      k.endsWith('*') ? key.startsWith(k.slice(0, -1)) : key === k,
    );
    const reply = route?.[1](url, init) ?? { status: 404, body: { message: 'not found' } };
    return new Response(JSON.stringify(reply.body), {
      status: reply.status ?? 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return {
    adapter: new TestAdapter({
      fetch: fetchImpl,
      rpc: new MemoryRpcPool(CHAINS),
      indexers: INDEXERS,
    }),
    calls,
  };
}

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: ALGORAND_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${ALGORAND_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  } as unknown as TxIntent;
}

const signed = (t: AlgorandTx) =>
  bytesToHex(
    Uint8Array.from([
      0x82,
      0xa3,
      ...new TextEncoder().encode('sig'),
      0xc4,
      0x40,
      ...ed25519.sign(algorandSigningMessage(t), SEED),
      0xa3,
      ...new TextEncoder().encode('txn'),
      ...algorandTxnMsgpack(t),
    ]),
  );

describe('algorand addresses', () => {
  it('matches the algosdk vectors', () => {
    expect(algorandAddressFromPublicKey(ed25519.getPublicKey(SEED))).toBe(SENDER);
    expect(algorandAddressFromPublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)))).toBe(
      RECIPIENT,
    );
    // SLIP-10 m/44'/283'/0'/0'/0' of "abandon … about" (pinned in the core too).
    const hd = hexToBytes('23f43fcebf400a06e4ead87d05a83ddb7b498ff1046b7ccec278a3080558a999');
    expect(algorandAddressFromPublicKey(hd)).toBe(
      'EP2D7TV7IAFANZHK3B6QLKB53N5UTD7RARVXZTWCPCRQQBKYVGM2XIMT2Q',
    );
    expect(algorandAddressFromPublicKey(new Uint8Array(32))).toBe(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ',
    );
    expect(bytesToHex(algorandAddressBytes(SENDER)!)).toBe(bytesToHex(ed25519.getPublicKey(SEED)));
  });

  it('refuses non-canonical addresses', () => {
    expect(isValidAlgorandAddress(SENDER)).toBe(true);
    expect(isValidAlgorandAddress(`${SENDER.slice(0, 57)}V`)).toBe(false);
    expect(isValidAlgorandAddress(`${SENDER.slice(0, 57)}Q`)).toBe(false);
    expect(isValidAlgorandAddress(SENDER.toLowerCase())).toBe(false);
    expect(isValidAlgorandAddress(SENDER.slice(0, 57))).toBe(false);
    expect(isValidAlgorandAddress('GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6')).toBe(
      false,
    );
  });

  it('derives an address only from Ed25519 keys', () => {
    const a = new TestAdapter();
    const hex = bytesToHex(ed25519.getPublicKey(SEED));
    expect(a.deriveAddress({ curve: 'ed25519', hex }, ALGORAND_TESTNET)).toBe(SENDER);
    expect(() => a.deriveAddress({ curve: 'secp256k1', hex }, ALGORAND_TESTNET)).toThrow();
    expect(a.validateAddress(RECIPIENT, VOI_MAINNET)).toBe(true);
  });

  it('names networks by CAIP-2 genesis prefix', () => {
    for (const [chainId, n] of Object.entries(NETWORKS))
      expect(caip2FromGenesisHash(n.genesisHash)).toBe(chainId);
    expect(VOI_MAINNET).toBe('algorand:r20fSQI8gWe_kFZziNonSPCXLwcQmH_n');
  });
});

describe('algorand encoding', () => {
  it('matches the algosdk and core vectors', () => {
    expect(bytesToHex(algorandTxnMsgpack(tx))).toBe(SMALL_TXN);
    expect(algorandTxId(tx)).toBe(SMALL_TXID);
    expect(signed(tx)).toBe(SMALL_SIGNED);
    const big = {
      ...tx,
      microalgos: '9000000000000000',
      fee: 250_000,
      firstValid: 5,
      lastValid: 1004,
    };
    expect(bytesToHex(algorandTxnMsgpack(big))).toBe(BIG_TXN);
    expect(algorandTxId(big)).toBe(BIG_TXID);
    const tiny = { ...tx, microalgos: '1', firstValid: 127, lastValid: 128 };
    expect(bytesToHex(algorandTxnMsgpack(tiny))).toBe(TINY_TXN);
    expect(algorandTxId(tiny)).toBe(TINY_TXID);
  });

  it('refuses hostile fields', () => {
    const bad: Partial<Record<keyof AlgorandTx, unknown>>[] = [
      { chainId: ALGORAND_MAINNET },
      { chainId: VOI_MAINNET },
      { genesisID: 'mainnet-v1.0' },
      { genesisHash: NETWORKS[ALGORAND_MAINNET]!.genesisHash },
      { microalgos: '0' },
      { microalgos: '01' },
      { microalgos: '10000000000000001' },
      { to: SENDER },
      { fee: 999 },
      { fee: 1_000_001 },
      { lastValid: tx.firstValid + 1001 },
      { lastValid: tx.firstValid - 1 },
      { firstValid: 0 },
    ];
    for (const b of bad) expect(() => algorandTxnMsgpack({ ...tx, ...b } as AlgorandTx)).toThrow();
    for (const field of ['note', 'closeRemainderTo', 'rekeyTo'])
      expect(AlgorandTx.safeParse({ ...tx, [field]: 'x' }).success).toBe(false);
  });

  it('bids the per-byte fee only above the minimum', () => {
    expect(feeBid({ fee: 0, 'min-fee': 1000 }, 160)).toBe(1000);
    expect(feeBid({ fee: 10, 'min-fee': 1000 }, 160)).toBe(2350);
    expect(() => feeBid({ fee: 1000, 'min-fee': 1000 }, 160)).toThrow();
  });

  it('wraps the simulate request around the txn', () => {
    const txn = algorandTxnMsgpack(tx);
    const req = simulateRequest(txn);
    expect(bytesToHex(req.subarray(req.length - txn.length))).toBe(SMALL_TXN);
    expect(req[0]).toBe(0x82);
  });
});

describe('algorand reads', () => {
  it('cross-checks ALGO and USDC across two algod operators', async () => {
    const holder = RECIPIENT;
    const routes: Record<string, Route> = {};
    for (const base of [MAIN_A, MAIN_B]) {
      routes[`GET ${base}/v2/transactions/params`] = () => ({ body: params(ALGORAND_MAINNET) });
      routes[`GET ${base}/v2/accounts/${holder}`] = () => ({ body: account(holder, 2_500_000) });
      routes[`GET ${base}/v2/accounts/${holder}/assets/${USDC_ASA}`] = () => ({
        body: { 'asset-holding': { amount: 1_370_151, 'asset-id': USDC_ASA, 'is-frozen': false } },
      });
    }
    const { adapter } = node(routes);
    const [native, usdc] = await adapter.getBalances(holder, ALGORAND_MAINNET);
    expect(native).toMatchObject({
      assetRef: `${ALGORAND_MAINNET}:native`,
      amount: '2500000',
      provenance: { kind: 'agreed' },
    });
    expect(usdc).toMatchObject({
      assetRef: asaAssetRef(ALGORAND_MAINNET, USDC_ASA),
      amount: '1370151',
      metadata: { symbol: 'USDC', decimals: 6 },
    });
  });

  it('refuses an endpoint on another network', async () => {
    const { adapter } = node({
      [`GET ${TEST_A}/v2/transactions/params`]: () => ({ body: params(ALGORAND_MAINNET) }),
      [`GET ${TEST_A}/v2/accounts/*`]: () => ({ body: account(SENDER, 1) }),
    });
    await expect(adapter.getBalances(SENDER, ALGORAND_TESTNET)).rejects.toThrow();
  });

  it('maps indexer history and refuses foreign genesis hashes', async () => {
    const page = (gh: string) => ({
      'current-round': 10,
      transactions: [
        {
          id: SMALL_TXID,
          'tx-type': 'pay',
          sender: SENDER,
          fee: 1000,
          'confirmed-round': 9,
          'round-time': 1_760_000_000,
          'genesis-hash': gh,
          'payment-transaction': { amount: 1_500_000, receiver: RECIPIENT, 'close-amount': 0 },
        },
        {
          id: TINY_TXID,
          'tx-type': 'axfer',
          sender: RECIPIENT,
          fee: 1000,
          'confirmed-round': 8,
          'genesis-hash': gh,
          'asset-transfer-transaction': { amount: 5, 'asset-id': 10458941, receiver: SENDER },
        },
      ],
    });
    let gh = TESTNET.genesisHash;
    const { adapter } = node({
      [`GET ${TEST_IDX}/v2/accounts/${SENDER}/transactions`]: () => ({ body: page(gh) }),
    });
    const res = await adapter.getHistory(SENDER, ALGORAND_TESTNET);
    expect(res.items[0]).toMatchObject({
      hash: SMALL_TXID,
      from: SENDER,
      to: RECIPIENT,
      blockNumber: 9,
      timestampMs: 1_760_000_000_000,
      fee: '1000',
      assetDeltas: [{ assetRef: `${ALGORAND_TESTNET}:native`, amount: '-1500000' }],
    });
    expect(res.items[1]).toMatchObject({
      description: 'axfer',
      assetDeltas: [{ assetRef: asaAssetRef(ALGORAND_TESTNET, 10458941), amount: '5' }],
    });
    gh = NETWORKS[ALGORAND_MAINNET]!.genesisHash;
    await expect(adapter.getHistory(SENDER, ALGORAND_TESTNET)).rejects.toThrow();
  });

  it('reads status from the pool, then the indexer', async () => {
    let pending: Reply = { body: { 'pool-error': '' } };
    const { adapter } = node({
      [`GET ${TEST_A}/v2/transactions/params`]: () => ({ body: params(ALGORAND_TESTNET) }),
      [`GET ${TEST_A}/v2/transactions/pending/${SMALL_TXID}`]: () => pending,
      [`GET ${TEST_IDX}/v2/transactions/${TINY_TXID}`]: () => ({
        body: {
          transaction: {
            id: TINY_TXID,
            'tx-type': 'pay',
            sender: SENDER,
            fee: 1000,
            'confirmed-round': 77,
            'round-time': 1_760_000_000,
            'genesis-hash': TESTNET.genesisHash,
          },
        },
      }),
    });
    expect(await adapter.status(SMALL_TXID, ALGORAND_TESTNET)).toEqual({ state: 'pending' });
    pending = { body: { 'pool-error': '', 'confirmed-round': 68_321_501 } };
    expect(await adapter.status(SMALL_TXID, ALGORAND_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 68_321_501,
    });
    pending = { body: { 'pool-error': 'overspend' } };
    expect(await adapter.status(SMALL_TXID, ALGORAND_TESTNET)).toEqual({
      state: 'failed',
      reason: 'overspend',
    });
    expect(await adapter.status(TINY_TXID, ALGORAND_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 77,
      timestampMs: 1_760_000_000_000,
    });
    expect(await adapter.status(BIG_TXID, ALGORAND_TESTNET)).toEqual({ state: 'unknown' });
    await expect(adapter.status('nope', ALGORAND_TESTNET)).rejects.toThrow();
  });
});

describe('algorand send', () => {
  const testnet = (
    over: {
      sender?: Record<string, unknown>;
      recipientAmount?: number;
      senderAmount?: number;
      lastRound?: number;
      simulate?: Reply;
      submit?: Route;
      pending?: Reply;
    } = {},
  ) =>
    node({
      [`GET ${TEST_A}/v2/transactions/params`]: () => ({
        body: params(ALGORAND_TESTNET, over.lastRound ?? 68_321_500),
      }),
      [`GET ${TEST_A}/v2/accounts/${SENDER}`]: () => ({
        body: account(SENDER, over.senderAmount ?? 5_000_000, over.sender),
      }),
      [`GET ${TEST_A}/v2/accounts/${RECIPIENT}`]: () => ({
        body: account(RECIPIENT, over.recipientAmount ?? 1_000_000),
      }),
      [`POST ${TEST_A}/v2/transactions/simulate`]: () =>
        over.simulate ?? { body: { 'txn-groups': [{ 'txn-results': [] }] } },
      [`POST ${TEST_A}/v2/transactions`]: over.submit ?? (() => ({ body: { txId: SMALL_TXID } })),
      [`GET ${TEST_A}/v2/transactions/pending/*`]: () => over.pending,
    });

  it('prepares a pay transaction the core accepts', async () => {
    const { adapter, calls } = testnet();
    const { unsigned, simulation } = await prepareAlgorand(
      adapter,
      intent(RECIPIENT, '1500000'),
      SENDER,
    );
    expect(unsigned).toEqual({ ...tx, firstValid: 68_321_500, lastValid: 68_322_500 });
    expect(simulation).toMatchObject({ ok: true, fee: { amount: '1000' } });
    const sim = calls.find((c) => c.url.includes('/simulate'))!;
    expect((sim.init?.headers as Record<string, string>)['content-type']).toBe(
      'application/msgpack',
    );
  });

  it('flags balance, minimum-balance, rekey and simulation failures', async () => {
    const low = await prepareAlgorand(
      testnet({ senderAmount: 1_600_000 }).adapter,
      intent(RECIPIENT, '1500000'),
      SENDER,
    );
    expect(low.simulation.ok).toBe(false);
    await expect(
      prepareAlgorand(testnet({ recipientAmount: 0 }).adapter, intent(RECIPIENT, '99999'), SENDER),
    ).rejects.toThrow(/minimum balance/);
    const fresh = await prepareAlgorand(
      testnet({ recipientAmount: 0 }).adapter,
      intent(RECIPIENT, '100000'),
      SENDER,
    );
    expect(fresh.simulation.ok).toBe(true);
    expect(fresh.simulation.warnings).toHaveLength(1);
    await expect(
      prepareAlgorand(
        testnet({ sender: { 'auth-addr': RECIPIENT } }).adapter,
        intent(RECIPIENT, '1500000'),
        SENDER,
      ),
    ).rejects.toThrow(/rekeyed/);
    const sim = await prepareAlgorand(
      testnet({
        simulate: {
          body: { 'txn-groups': [{ 'failure-message': 'overspend', 'failed-at': [0] }] },
        },
      }).adapter,
      intent(RECIPIENT, '1500000'),
      SENDER,
    );
    expect(sim.simulation).toMatchObject({ ok: false, error: 'Simulation failed: overspend' });
    await expect(
      prepareAlgorand(
        testnet().adapter,
        { ...intent(RECIPIENT, '1'), chainId: ALGORAND_MAINNET },
        SENDER,
      ),
    ).rejects.toThrow();
  });

  it('keeps approval valid only inside the window', async () => {
    const t = { ...tx, firstValid: 68_321_500, lastValid: 68_322_500 };
    expect(await algorandApprovalValid(testnet().adapter, t)).toBe(true);
    expect(await algorandApprovalValid(testnet({ lastRound: 68_322_490 }).adapter, t)).toBe(false);
    expect(
      await algorandApprovalValid(testnet({ sender: { 'auth-addr': RECIPIENT } }).adapter, t),
    ).toBe(false);
    expect(
      await algorandApprovalValid(testnet({ recipientAmount: 0 }).adapter, {
        ...t,
        microalgos: '5000',
      }),
    ).toBe(false);
  });

  it('broadcasts only the exact signed transaction', async () => {
    let body: Uint8Array | undefined;
    const { adapter } = testnet({
      submit: (_url, init) => {
        body = init?.body as Uint8Array;
        return { body: { txId: SMALL_TXID } };
      },
    });
    expect(await broadcastAlgorand(adapter, tx, `0x${SMALL_SIGNED}`)).toBe(SMALL_TXID);
    expect(bytesToHex(body!)).toBe(SMALL_SIGNED);
    const forged =
      SMALL_SIGNED.slice(0, 20) + (SMALL_SIGNED[20] === '0' ? '1' : '0') + SMALL_SIGNED.slice(21);
    await expect(broadcastAlgorand(adapter, tx, forged)).rejects.toThrow(/verify/);
    await expect(
      broadcastAlgorand(adapter, { ...tx, microalgos: '1500001' }, SMALL_SIGNED),
    ).rejects.toThrow(/not this/);
    await expect(broadcastAlgorand(adapter, tx, `${SMALL_SIGNED}00`)).rejects.toThrow(/not this/);
  });

  it('treats a duplicate of an accepted transaction as success', async () => {
    const dup = testnet({
      submit: () => ({ status: 400, body: { message: 'transaction already in ledger: J2ZU' } }),
      pending: { body: { 'pool-error': '', 'confirmed-round': 68_321_501 } },
    });
    expect(await broadcastAlgorand(dup.adapter, tx, SMALL_SIGNED)).toBe(SMALL_TXID);
    const rejected = testnet({
      submit: () => ({ status: 400, body: { message: 'overspend (account ...)' } }),
    });
    await expect(broadcastAlgorand(rejected.adapter, tx, SMALL_SIGNED)).rejects.toThrow(
      /overspend/,
    );
  });

  it('reports expiry once the chain passes lastValid', async () => {
    expect(await algorandTransferStatus(testnet().adapter, tx, SMALL_TXID)).toEqual({
      state: 'unknown',
    });
    expect(
      await algorandTransferStatus(testnet({ lastRound: 68_322_001 }).adapter, tx, SMALL_TXID),
    ).toEqual({ state: 'expired' });
  });
});
