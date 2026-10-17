import { ed25519 } from '@noble/curves/ed25519.js';
import { base32nopad, base64 } from '@scure/base';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  StellarTx,
  broadcastStellar,
  feeBid,
  prepareStellar,
  stellarApprovalValid,
  stellarTransferStatus,
  stellarTxHash,
  stellarTxXdr,
} from './send.js';
import {
  STELLAR_PUBNET,
  STELLAR_TESTNET,
  StellarAdapter,
  isValidStellarAddress,
  parseStroops,
  resultCode,
  stellarAddressFromPublicKey,
} from './stellar.js';

/** SEP-0005 test 1, m/44'/148'/0'. */
const SEP5_SEED = 'SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN';
const SEP5_ADDRESS = 'GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6';
const RECIPIENT = 'GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX';
const USDC_ISSUER = 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN';
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const seed = () => base32nopad.decode(SEP5_SEED).slice(1, 33);

const tx: StellarTx = {
  chainId: STELLAR_TESTNET,
  from: SEP5_ADDRESS,
  to: RECIPIENT,
  stroops: '15000000',
  fee: 1000,
  seqNum: '12000340488487103',
  maxTime: 1_760_001_800,
  builtAt: 1_760_000_000,
  createAccount: false,
};
/** Produced by `@stellar/stellar-base` for the same fields and pinned by the core (`stellar.rs`). */
const PAYMENT_TX_VECTOR =
  '00000000e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544000003e8002aa23f000000bf0000000100000000000000000000000068e77f080000000000000001000000000000000100000000416edcd6746d5293579a7039ac67bcf1a8698efecf81183bbb0ac877da86ada3000000000000000000e4e1c000000000';
const PAYMENT_HASH_VECTOR = '88d9fbc2c101be1878861eb98a16048e1e361806f377060656d5caaabf56447a';
const PAYMENT_ENVELOPE_VECTOR =
  '0000000200000000e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544000003e8002aa23f000000bf0000000100000000000000000000000068e77f080000000000000001000000000000000100000000416edcd6746d5293579a7039ac67bcf1a8698efecf81183bbb0ac877da86ada3000000000000000000e4e1c000000000000000014e71e54400000040d06acccf6cf7550e2dd025a45fe1ad7305fa59e2744867f4e5c137c79b82a212218b2d42d978c551e5574254bae60a6fbe253c4f9d7f6b9f403ceba35e557b00';
const PAYMENT_ENVELOPE_BASE64 =
  'AAAAAgAAAADjcmgwoLYMtfUshEz/zU7tZeulwVXomyZBFWJyTnHlRAAAA+gAKqI/AAAAvwAAAAEAAAAAAAAAAAAAAABo538IAAAAAAAAAAEAAAAAAAAAAQAAAABBbtzWdG1Sk1eacDmsZ7zxqGmO/s+BGDu7Csh32oatowAAAAAAAAAAAOThwAAAAAAAAAABTnHlRAAAAEDQaszPbPdVDi3QJaRf4a1zBfpZ4nRIZ/TlwTfHm4KiEiGLLULZeMVR5VdCVLrmCm++JTxPnX9rn0A866NeVXsA';
const CREATE_TX_VECTOR =
  '00000000e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544000003e8002aa23f000000bf0000000100000000000000000000000068e77f080000000000000001000000000000000000000000416edcd6746d5293579a7039ac67bcf1a8698efecf81183bbb0ac877da86ada30000000000e4e1c000000000';
const CREATE_HASH_VECTOR = 'c9e0562066e29902d425f2453c7c08a1a351b05f9c7af8a428ab7d6fa04c8db9';

const CHAINS: ChainInfo[] = [
  {
    chainId: STELLAR_PUBNET,
    family: 'stellar',
    name: 'Stellar',
    nativeAsset: { ref: `${STELLAR_PUBNET}:native`, symbol: 'XLM', decimals: 7 },
    testnet: false,
    defaultRpcs: ['https://horizon.stellar.org', 'https://horizon.stellar.lobstr.co'],
  },
  {
    chainId: STELLAR_TESTNET,
    family: 'stellar',
    name: 'Stellar Testnet',
    nativeAsset: { ref: `${STELLAR_TESTNET}:native`, symbol: 'XLM', decimals: 7 },
    testnet: true,
    defaultRpcs: ['https://horizon-testnet.stellar.org'],
  },
];

class TestAdapter extends StellarAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Route = (url: URL, init?: RequestInit) => { status?: number; body: unknown } | undefined;

function horizon(routes: Record<string, Route>, passphrase = TESTNET_PASSPHRASE) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push({ url: url.toString(), ...(init ? { init } : {}) });
    if (url.pathname === '/') return Response.json({ network_passphrase: passphrase });
    const out = routes[url.pathname]?.(url, init);
    if (!out) return Response.json({ status: 404, title: 'Resource Missing' }, { status: 404 });
    return Response.json(out.body, { status: out.status ?? 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });
}

const account = (id: string, sequence: string, xlm = '100.0000000', extra = {}) => ({
  body: {
    account_id: id,
    sequence,
    subentry_count: 0,
    balances: [{ balance: xlm, asset_type: 'native', selling_liabilities: '0.0000000' }],
    ...extra,
  },
});
const ledger = (closedAt: string) => ({
  body: {
    _embedded: {
      records: [
        {
          sequence: 5215584,
          closed_at: closedAt,
          base_reserve_in_stroops: 5000000,
          base_fee_in_stroops: 100,
        },
      ],
    },
  },
});

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: STELLAR_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${STELLAR_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  } as unknown as TxIntent;
}

describe('stellar addresses', () => {
  it('derives the SEP-0005 account id', () => {
    const pub = ed25519.getPublicKey(seed());
    expect(stellarAddressFromPublicKey(pub)).toBe(SEP5_ADDRESS);
    const a = new TestAdapter();
    expect(a.deriveAddress({ curve: 'ed25519', hex: hex(pub) }, STELLAR_TESTNET)).toBe(
      SEP5_ADDRESS,
    );
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, STELLAR_TESTNET),
    ).toThrow();
    // Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7)).
    expect(stellarAddressFromPublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(7)))).toBe(
      'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57',
    );
  });

  it('refuses bad checksums, seeds, muxed ids and other chains', () => {
    expect(isValidStellarAddress(RECIPIENT)).toBe(true);
    expect(isValidStellarAddress(SEP5_ADDRESS.slice(0, -1) + '7')).toBe(false);
    expect(isValidStellarAddress(SEP5_ADDRESS.toLowerCase())).toBe(false);
    expect(isValidStellarAddress(SEP5_SEED)).toBe(false);
    expect(
      isValidStellarAddress(
        'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK',
      ),
    ).toBe(false);
    expect(isValidStellarAddress('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')).toBe(false);
  });

  it('reads seven-decimal Horizon amounts exactly', () => {
    expect(parseStroops('26180.7695472')).toBe('261807695472');
    expect(parseStroops('0.0000000')).toBe('0');
    expect(() => parseStroops('1.5')).toThrow();
    expect(() => parseStroops('-1.0000000')).toThrow();
  });
});

describe('stellar transfers', () => {
  it('encodes the same XDR and hash as the SDK and the core', () => {
    expect(hex(stellarTxXdr(tx))).toBe(PAYMENT_TX_VECTOR);
    expect(stellarTxHash(tx)).toBe(PAYMENT_HASH_VECTOR);
    const create = { ...tx, createAccount: true };
    expect(hex(stellarTxXdr(create))).toBe(CREATE_TX_VECTOR);
    expect(stellarTxHash(create)).toBe(CREATE_HASH_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => stellarTxXdr({ ...tx, stroops: '0' })).toThrow();
    expect(() => stellarTxXdr({ ...tx, stroops: '015000000' })).toThrow();
    expect(() => stellarTxXdr({ ...tx, stroops: '9223372036854775808' })).toThrow();
    expect(() => stellarTxXdr({ ...tx, stroops: '9999999', createAccount: true })).toThrow();
    expect(() => stellarTxXdr({ ...tx, to: tx.from })).toThrow();
    expect(() => stellarTxXdr({ ...tx, fee: 99 })).toThrow();
    expect(() => stellarTxXdr({ ...tx, maxTime: tx.builtAt })).toThrow();
    expect(() => stellarTxXdr({ ...tx, maxTime: tx.builtAt + 86_401 })).toThrow();
    expect(() => stellarTxXdr({ ...tx, seqNum: '0' })).toThrow();
    expect(() =>
      stellarTxXdr({ ...tx, chainId: STELLAR_PUBNET as typeof STELLAR_TESTNET }),
    ).toThrow();
    expect(() => StellarTx.parse({ ...tx, memo: 'hi' })).toThrow();
  });

  it('prepares a create-account transfer for an unfunded recipient', async () => {
    const { fetchImpl } = horizon({
      [`/accounts/${SEP5_ADDRESS}`]: () => account(SEP5_ADDRESS, '12000340488487102'),
      '/fee_stats': () => ({
        body: { last_ledger_base_fee: '100', fee_charged: { p90: '596121', max: '4822731' } },
      }),
      '/ledgers': () => ledger('2025-10-09T08:53:20Z'),
    });
    const a = adapter(fetchImpl);
    const { unsigned, simulation } = await prepareStellar(
      a,
      intent(RECIPIENT, '15000000'),
      SEP5_ADDRESS,
      1_760_000_000_500,
    );
    expect(unsigned).toEqual({
      chainId: STELLAR_TESTNET,
      from: SEP5_ADDRESS,
      to: RECIPIENT,
      stroops: '15000000',
      fee: 596121,
      seqNum: '12000340488487103',
      maxTime: 1_760_001_800,
      builtAt: 1_760_000_000,
      createAccount: true,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('596121');
    expect(simulation.warnings[0]?.kind).toBe('other');
    await expect(
      prepareStellar(a, intent(RECIPIENT, '9999999'), SEP5_ADDRESS, 1_760_000_000_500),
    ).rejects.toThrow(/at least 1 XLM/);
  });

  it('flags a balance that the reserve leaves short', async () => {
    const { fetchImpl } = horizon({
      [`/accounts/${SEP5_ADDRESS}`]: () =>
        account(SEP5_ADDRESS, '7', '2.5000000', { subentry_count: 1 }),
      [`/accounts/${RECIPIENT}`]: () => account(RECIPIENT, '9'),
      '/fee_stats': () => ({ body: { last_ledger_base_fee: '100', fee_charged: { p90: '100' } } }),
      '/ledgers': () => ledger('2025-10-09T08:53:20Z'),
    });
    // 2.5 XLM minus three reserves (1.5 XLM) leaves 1 XLM: not enough for 1 XLM plus the fee.
    const { unsigned, simulation } = await prepareStellar(
      adapter(fetchImpl),
      intent(RECIPIENT, '10000000'),
      SEP5_ADDRESS,
      1_760_000_000_000,
    );
    expect(unsigned.createAccount).toBe(false);
    expect(unsigned.fee).toBe(100);
    expect(simulation.ok).toBe(false);
  });

  it('caps the fee bid under surge pricing', () => {
    expect(feeBid({ last_ledger_base_fee: '100', fee_charged: { p90: '50' } })).toBe(100);
    expect(feeBid({ last_ledger_base_fee: '100', fee_charged: { p90: '99999999' } })).toBe(
      2_000_000,
    );
  });

  it('refuses an endpoint on the wrong network', async () => {
    const { fetchImpl } = horizon({}, 'Public Global Stellar Network ; September 2015');
    await expect(adapter(fetchImpl).getBalances(SEP5_ADDRESS, STELLAR_TESTNET)).rejects.toThrow();
  });

  it('checks approval against the sequence, recipient and ledger time', async () => {
    let seq = '12000340488487102';
    const { fetchImpl } = horizon({
      [`/accounts/${SEP5_ADDRESS}`]: () => account(SEP5_ADDRESS, seq),
      [`/accounts/${RECIPIENT}`]: () => account(RECIPIENT, '9'),
      '/ledgers': () => ledger('2025-10-09T08:53:20Z'),
    });
    const a = adapter(fetchImpl);
    const now = 1_760_000_000_000;
    expect(await stellarApprovalValid(a, tx, now)).toBe(true);
    expect(await stellarApprovalValid(a, { ...tx, createAccount: true }, now)).toBe(false);
    expect(await stellarApprovalValid(a, tx, (tx.maxTime - 30) * 1000)).toBe(false);
    seq = '12000340488487103';
    expect(await stellarApprovalValid(a, tx, now)).toBe(false);
  });

  it('broadcasts only the expected signed envelope as a form post', async () => {
    const signature = ed25519.sign(Buffer.from(PAYMENT_HASH_VECTOR, 'hex'), seed());
    const signed = PAYMENT_ENVELOPE_VECTOR.slice(0, -128) + hex(signature);
    expect(signed).toBe(PAYMENT_ENVELOPE_VECTOR);
    expect(base64.encode(Buffer.from(signed, 'hex'))).toBe(PAYMENT_ENVELOPE_BASE64);
    const { fetchImpl, calls } = horizon({
      '/transactions': (_url, init) =>
        init?.method === 'POST'
          ? { body: { hash: PAYMENT_HASH_VECTOR, successful: true } }
          : undefined,
    });
    const a = adapter(fetchImpl);
    expect(await broadcastStellar(a, tx, `0x${signed}`)).toBe(PAYMENT_HASH_VECTOR);
    const post = calls.find((c) => c.init?.method === 'POST')!;
    expect(new URLSearchParams(String(post.init!.body)).get('tx')).toBe(PAYMENT_ENVELOPE_BASE64);
    const forged = signed.slice(0, -2) + (signed.endsWith('00') ? '01' : '00');
    await expect(broadcastStellar(a, tx, forged)).rejects.toThrow(/verify/);
    await expect(broadcastStellar(a, { ...tx, stroops: '15000001' }, signed)).rejects.toThrow(
      /not this XLM transfer/,
    );
    await expect(broadcastStellar(a, tx, signed + '00')).rejects.toThrow();
  });

  it('surfaces Horizon result codes on rejection', async () => {
    const { fetchImpl } = horizon({
      '/transactions': () => ({
        status: 400,
        body: {
          title: 'Transaction Failed',
          extras: { result_codes: { transaction: 'tx_failed', operations: ['op_underfunded'] } },
        },
      }),
    });
    await expect(broadcastStellar(adapter(fetchImpl), tx, PAYMENT_ENVELOPE_VECTOR)).rejects.toThrow(
      'Broadcast rejected: tx_failed op_underfunded',
    );
  });

  it('reports confirmed, failed and expired transfers', async () => {
    const failedXdr = base64.encode(
      Uint8Array.from(
        Buffer.from('0000000000000064ffffffff0000000100000000000000010000000000000000', 'hex'),
      ),
    );
    expect(resultCode(failedXdr)).toBe('tx_failed: payment code 0');
    const underfunded = base64.encode(
      Uint8Array.from(
        Buffer.from('0000000000000064ffffffff0000000100000000' + '00000001fffffffe00000000', 'hex'),
      ),
    );
    expect(resultCode(underfunded)).toBe('tx_failed: payment code -2');
    let known: unknown;
    let closedAt = '2025-10-09T08:53:20Z';
    const { fetchImpl } = horizon({
      [`/transactions/${PAYMENT_HASH_VECTOR}`]: () => (known ? { body: known } : undefined),
      [`/accounts/${SEP5_ADDRESS}`]: () => account(SEP5_ADDRESS, '12000340488487102'),
      '/ledgers': () => ledger(closedAt),
    });
    const a = adapter(fetchImpl);
    expect(await stellarTransferStatus(a, tx, PAYMENT_HASH_VECTOR)).toEqual({ state: 'unknown' });
    closedAt = '2025-10-09T09:30:00Z';
    expect(await stellarTransferStatus(a, tx, PAYMENT_HASH_VECTOR)).toEqual({ state: 'expired' });
    known = {
      hash: PAYMENT_HASH_VECTOR,
      successful: true,
      ledger: 4363989,
      created_at: '2025-10-09T08:54:00Z',
    };
    expect(await a.status(PAYMENT_HASH_VECTOR, STELLAR_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 4363989,
      timestampMs: Date.parse('2025-10-09T08:54:00Z'),
    });
    known = { ...(known as object), successful: false, result_xdr: underfunded };
    expect(await a.status(PAYMENT_HASH_VECTOR, STELLAR_TESTNET)).toEqual({
      state: 'failed',
      reason: 'tx_failed: payment code -2',
    });
  });
});

describe('stellar reads', () => {
  it('reads an unfunded account as zero', async () => {
    const { fetchImpl } = horizon({});
    const [native] = await adapter(fetchImpl).getBalances(SEP5_ADDRESS, STELLAR_TESTNET);
    expect(native?.amount).toBe('0');
    expect(native?.assetRef).toBe(`${STELLAR_TESTNET}:native`);
  });

  it('reads XLM and Circle USDC on pubnet from two agreeing endpoints', async () => {
    const { fetchImpl, calls } = horizon(
      {
        [`/accounts/${SEP5_ADDRESS}`]: () => ({
          body: {
            account_id: SEP5_ADDRESS,
            sequence: '1',
            subentry_count: 1,
            balances: [
              {
                balance: '12.3456789',
                asset_type: 'credit_alphanum4',
                asset_code: 'USDC',
                asset_issuer: USDC_ISSUER,
              },
              {
                balance: '5.0000000',
                asset_type: 'credit_alphanum4',
                asset_code: 'USDC',
                asset_issuer: RECIPIENT,
              },
              { balance: '26180.7695472', asset_type: 'native' },
            ],
          },
        }),
      },
      'Public Global Stellar Network ; September 2015',
    );
    const holdings = await adapter(fetchImpl).getBalances(SEP5_ADDRESS, STELLAR_PUBNET);
    expect(holdings.map((h) => [h.assetRef, h.amount])).toEqual([
      [`${STELLAR_PUBNET}:native`, '261807695472'],
      [`${STELLAR_PUBNET}:asset:USDC-${USDC_ISSUER}`, '123456789'],
    ]);
    expect(holdings[0]?.provenance?.kind).toBe('agreed');
    expect(new Set(calls.map((c) => new URL(c.url).host))).toEqual(
      new Set(['horizon.stellar.org', 'horizon.stellar.lobstr.co']),
    );
  });

  it('maps payments and account creation into history', async () => {
    const { fetchImpl, calls } = horizon({
      [`/accounts/${SEP5_ADDRESS}/payments`]: () => ({
        body: {
          _embedded: {
            records: [
              {
                paging_token: '18743190035111937',
                transaction_successful: true,
                transaction_hash:
                  '080668e73c748602a0af0a7586e0f101568cea9c48db085ac431dc7d79fcd48b',
                type: 'payment',
                created_at: '2026-08-27T15:11:58Z',
                source_account: SEP5_ADDRESS,
                asset_type: 'native',
                from: SEP5_ADDRESS,
                to: RECIPIENT,
                amount: '2.0000000',
              },
              {
                paging_token: '18601623618076673',
                transaction_successful: true,
                transaction_hash:
                  'b73f22cb3b1e03b2e7bc3499ef996795d22eb805503d331d5f577fb33f226982',
                type: 'create_account',
                created_at: '2026-08-25T17:19:32Z',
                source_account: RECIPIENT,
                starting_balance: '10000.0000000',
                funder: RECIPIENT,
                account: SEP5_ADDRESS,
              },
            ],
          },
        },
      }),
    });
    const page = await adapter(fetchImpl).getHistory(SEP5_ADDRESS, STELLAR_TESTNET, '123');
    expect(page.items.map((i) => [i.hash.slice(0, 6), i.assetDeltas[0]?.amount, i.fee])).toEqual([
      ['080668', '-20000000', null],
      ['b73f22', '100000000000', null],
    ]);
    expect(page.nextCursor).toBeUndefined();
    expect(calls.some((c) => c.url.includes('cursor=123'))).toBe(true);
    await expect(
      adapter(fetchImpl).getHistory(SEP5_ADDRESS, STELLAR_TESTNET, 'x;y'),
    ).rejects.toThrow();
  });
});
