import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { parseBoc, serializeBoc } from './cell.js';
import {
  TonTx,
  broadcastTon,
  prepareTon,
  tonApprovalValid,
  tonExternalMessage,
  tonSigningHash,
  tonTransferStatus,
} from './send.js';
import {
  TON_MAINNET,
  TON_TESTNET,
  TonAdapter,
  isValidTonAddress,
  normalizeTonAddress,
  shortReason,
  tonAddressFromPublicKey,
  walletCode,
} from './ton.js';

const SEED = new Uint8Array(32).fill(7);
const PUB = ed25519.getPublicKey(SEED);
const SENDER = '0QAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinEb6';
const SENDER_RAW = '0:2a6ee6b7ff41bfecafe383386325c7a895f4fe4ce346b18eb9c14a0152d6629c';
/** The v4r2 wallet of seed `[9; 32]` in every spelling `@ton/core` 0.63.1 emits. */
const RECIPIENT_FORMS = [
  '0:1f3841f04e9a3349f64fe1626c6f045b54d6c2d839d3e0001518331d6c203352',
  '0QAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUpnx',
  'kQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUsQ0',
  'UQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUiJ7',
  'EQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUn--',
];
const RECIPIENT = 'kQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUsQ0';
const RECIPIENT_RAW = RECIPIENT_FORMS[0]!;

const tx: TonTx = {
  chainId: TON_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  nanoton: '1500000000',
  seqno: 7,
  validUntil: 1_760_001_800,
  builtAt: 1_760_000_000,
  bounce: true,
  deploy: false,
};
const deployTx: TonTx = { ...tx, seqno: 0, bounce: false, deploy: true };

/** Produced by `@ton/ton` 16.3.0 `createWalletTransferV4` and pinned by the core (`ton.rs`). */
const SIGNING_HASH = 'af5cc817fa13671125a709434d2949f6ea6eddf50d925591d758647ecb8cc8c8';
const NORM_HASH = '1eb1024402549e0cde467e76c5dcbfbd5cc52fa7db9d47da03f1560cc2bd03a0';
const BOC =
  'b5ee9c724101020100aa0001e1880054ddcd6ffe837fd95fc70670c64b8f512be9fc99c68d631d73829402a5acc53806e8f050f25e5827221d1089040294e028b0d5fee31b01d65da6b462ff4c1a46432f380e1b20dbc381eb12d1d3cd5e4bc1d705231e19228f0d5584cd017a4c38394d4d18bb473bf84000000038001c01006862000f9c20f8274d19a4fb27f0b13637822daa6b616c1ce9f0000a8c198eb61019a922cb41780000000000000000000000000000eda805fb';
const DEPLOY_SIGNING_HASH = '3fcc3c232e95d5bc3f588a13f7fbe354da2c5467b164d0f9ebaa37a4730cfbeb';
const DEPLOY_NORM_HASH = 'f8d70d9adebd76454aa6d5f94a1735320e01ea32563ac89db8ec72ea6ec296d0';
const DEPLOY_MSG_HASH = 'cce9347f9b0e3f5cb8a8d19731bc142b6ceb94ddc57fd594980cc1b2aa24d148';
const DEPLOY_BOC =
  'b5ee9c72410217010003ac0003e3880054ddcd6ffe837fd95fc70670c64b8f512be9fc99c68d631d73829402a5acc53811891dbba91016e803be024cbb26053e9d21142ffabd8a17ca834afc09cef4ebefb2eefd1d9c6b581b22d1883f42db2cb62a692ba81879f0dd14d7ef1e06d9a70125353462ed1cefe1000000000000700115160114ff00f4a413f4bcf2c80b020201200310020148040702e6d001d0d3032171b0925f04e022d749c120925f04e002d31f218210706c7567bd22821064737472bdb0925f05e003fa403020fa4401c8ca07cbffc9d0ed44d0810140d721f404305c810108f40a6fa131b3925f07e005d33fc8258210706c7567ba923830e30d03821064737472ba925f06e30d0506007801fa00f40430f8276f2230500aa121bef2e0508210706c7567831eb17080185004cb0526cf1658fa0219f400cb6917cb1f5260cb3f20c98040fb0006008a5004810108f45930ed44d0810140d720c801cf16f400c9ed540172b08e23821064737472831eb17080185005cb055003cf1623fa0213cb6acb1fcb3fc98040fb00925f03e2020120080f020120090e0201580a0b003db29dfb513420405035c87d010c00b23281f2fff274006040423d029be84c600201200c0d0019adce76a26840206b90eb85ffc00019af1df6a26840106b90eb858fc00011b8c97ed44d0d70b1f80059bd242b6f6a2684080a06b90fa0218470d4080847a4937d29910ce6903e9ff9837812801b7810148987159f318404f8f28308d71820d31fd31fd31f02f823bbf264ed44d0d31fd31fd3fff404d15143baf2a15151baf2a205f901541064f910f2a3f80024a4c8cb1f5240cb1f5230cbff5210f400c9ed54f80f01d30721c0009f6c519320d74a96d307d402fb00e830e021c001e30021c002e30001c0039130e30d03a4c8cb1f12cb1fcbff11121314006ed207fa00d4d422f90005c8ca0715cbffc9d077748018c8cb05cb0222cf165005fa0214cb6b12ccccc973fb00c84014810108f451f2a7020070810108d718fa00d33fc8542047810108f451f2a782106e6f746570748018c8cb05cb025006cf165004fa0214cb6a12cb1fcb3fc973fb0002006c810108d718fa00d33f305224810108f459f2a782106473747270748018c8cb05cb025005cf165003fa0213cb6acb1f12cb3fc973fb00000af400c9ed5400510000000029a9a317ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c40006842000f9c20f8274d19a4fb27f0b13637822daa6b616c1ce9f0000a8c198eb61019a922cb417800000000000000000000000000003d2efd08';

const TESTNET_ROOT = 'gj+B8wb/AmlPk1z1AhVI484rhrUpgSr2oSFIh56VoSg=';
const MAINNET_ROOT = 'F6OpKZKqvqeFp6CQmFomXNMfMj2EnaUSOXN+Mh+wVWk=';
const TONCENTER = 'https://testnet.toncenter.com/api/v2';
const TONAPI = 'https://testnet.tonapi.io/v2';

const chain = (chainId: string, testnet: boolean, rpcs: string[]) =>
  ({
    chainId,
    family: 'ton',
    name: testnet ? 'TON Testnet' : 'TON',
    nativeAsset: { ref: `${chainId}:native`, symbol: 'TON', decimals: 9 },
    testnet,
    defaultRpcs: rpcs,
  }) as ChainInfo;
const chains = (rpcs: string[]) => [
  chain(TON_MAINNET, false, ['https://toncenter.com/api/v2']),
  chain(TON_TESTNET, true, rpcs),
];

class TestAdapter extends TonAdapter {
  constructor(
    private readonly list: ChainInfo[],
    fetchImpl?: typeof fetch,
  ) {
    super({
      minIntervalMs: 0,
      rpc: new MemoryRpcPool(list),
      ...(fetchImpl ? { fetch: fetchImpl } : {}),
    });
  }
  override chains(): ChainInfo[] {
    return this.list;
  }
}

type Reply = { status?: number; body: unknown } | undefined;
type Route = (url: URL, body: unknown) => Reply;
const ok = (result: unknown): Reply => ({ body: { ok: true, result } });

function node(routes: Record<string, Route>, root = TESTNET_ROOT) {
  const calls: { url: string; body?: unknown }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ url: url.toString(), ...(body === undefined ? {} : { body }) });
    const path = url.pathname.replace(/^\/(api\/v[23]|v2)/, '');
    if (path === '/getMasterchainInfo')
      return Response.json({ ok: true, result: { init: { root_hash: root }, last: { seqno: 1 } } });
    if (path === '/liteserver/get_masterchain_info')
      return Response.json({ init: { root_hash: bytesToHex(base64.decode(root)) } });
    const out = routes[path]?.(url, body);
    if (!out) return Response.json({ error: 'not found' }, { status: 404 });
    return Response.json(out.body, { status: out.status ?? 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

/** A toncenter wallet: `status` and `seqno` for the sender, an empty recipient. */
function toncenter(
  sender: { state: 'active' | 'uninitialized'; seqno?: number; balance?: string },
  extra: Record<string, Route> = {},
) {
  const balanceOf = (addr: string | null) =>
    normalizeTonAddress(addr ?? '') === SENDER_RAW
      ? { balance: sender.balance ?? '109850250', state: sender.state }
      : { balance: '0', state: 'uninitialized' };
  return node({
    '/getAddressInformation': (u) => ok(balanceOf(u.searchParams.get('address'))),
    '/getWalletInformation': (u) =>
      normalizeTonAddress(u.searchParams.get('address') ?? '') === SENDER_RAW &&
      sender.state === 'active'
        ? ok({ account_state: 'active', seqno: sender.seqno ?? 7 })
        : ok({ account_state: 'uninit' }),
    '/runGetMethod': () => ok({ exit_code: 0, stack: [['num', `0x${bytesToHex(PUB)}`]] }),
    ...extra,
  });
}

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: TON_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${TON_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  } as unknown as TxIntent;
}

const signed = (t: TonTx, seed = SEED) =>
  tonExternalMessage(t, ed25519.getPublicKey(seed), ed25519.sign(tonSigningHash(t), seed));

describe('TON addresses', () => {
  it('derives the v4r2 wallet the SDK derives', () => {
    expect(bytesToHex(walletCode().hash)).toBe(
      'feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0',
    );
    expect(tonAddressFromPublicKey(PUB)).toBe(SENDER);
    expect(normalizeTonAddress(SENDER)).toBe(SENDER_RAW);
    const recipient = ed25519.getPublicKey(new Uint8Array(32).fill(9));
    expect(tonAddressFromPublicKey(recipient)).toBe(RECIPIENT_FORMS[1]);
    expect(tonAddressFromPublicKey(recipient, false)).toBe(RECIPIENT_FORMS[3]);
    const a = new TestAdapter(chains([TONCENTER]));
    expect(a.deriveAddress({ curve: 'ed25519', hex: bytesToHex(PUB) }, TON_TESTNET)).toBe(SENDER);
    expect(a.deriveAddress({ curve: 'ed25519', hex: bytesToHex(PUB) }, TON_MAINNET)).toBe(
      'UQAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinP1w',
    );
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, TON_TESTNET),
    ).toThrow();
  });

  it('accepts every spelling of one account and refuses the rest', () => {
    for (const form of RECIPIENT_FORMS) {
      expect(isValidTonAddress(form)).toBe(true);
      expect(normalizeTonAddress(form)).toBe(RECIPIENT_RAW);
    }
    const std = RECIPIENT_FORMS[4]!.replace(/-/g, '+').replace(/_/g, '/');
    expect(normalizeTonAddress(std)).toBe(RECIPIENT_RAW);
    expect(isValidTonAddress(RECIPIENT.slice(0, -1) + 'A')).toBe(false);
    expect(isValidTonAddress(`-1:${'ab'.repeat(32)}`)).toBe(false);
    expect(
      isValidTonAddress('Ef8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU'),
    ).toBe(false);
    expect(isValidTonAddress('0QAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAz+pnx')).toBe(false);
    expect(isValidTonAddress('')).toBe(false);
  });
});

describe('TON signing', () => {
  it('matches the SDK signing hash, BoC and normalized hash', () => {
    expect(bytesToHex(tonSigningHash(tx))).toBe(SIGNING_HASH);
    expect(signed(tx)).toEqual({ boc: `0x${BOC}`, hash: NORM_HASH });
    expect(bytesToHex(tonSigningHash(deployTx))).toBe(DEPLOY_SIGNING_HASH);
    expect(signed(deployTx)).toEqual({ boc: `0x${DEPLOY_BOC}`, hash: DEPLOY_NORM_HASH });
    const parsed = parseBoc(hexToBytes(DEPLOY_BOC));
    expect(parsed.hashHex()).toBe(DEPLOY_MSG_HASH);
    expect(bytesToHex(serializeBoc(parsed))).toBe(DEPLOY_BOC);
    const corrupt = hexToBytes(BOC);
    corrupt[20]! ^= 1;
    expect(() => parseBoc(corrupt)).toThrow();
  });

  it('refuses the payloads the core refuses', () => {
    const refused = (patch: Partial<TonTx> | Record<string, unknown>) =>
      expect(() => tonSigningHash({ ...tx, ...patch } as TonTx)).toThrow();
    refused({ chainId: TON_MAINNET });
    refused({ nanoton: '0' });
    refused({ nanoton: '01500000000' });
    refused({ nanoton: '18446744073709551616' });
    refused({ nanoton: '1.5' });
    refused({ deploy: true });
    refused({ validUntil: tx.builtAt });
    refused({ validUntil: tx.builtAt + 86_401 });
    refused({ to: SENDER });
    refused({ to: `-1:${'ab'.repeat(32)}` });
    refused({ from: 'kQAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinBs_' });
    refused({ from: SENDER_RAW });
    refused({ memo: 'x' });
  });
});

describe('TON adapter', () => {
  it('refuses an endpoint on another network', async () => {
    const { fetchImpl } = toncenter({ state: 'active' });
    const wrong = node({}, MAINNET_ROOT);
    await expect(
      new TestAdapter(chains([TONCENTER]), wrong.fetchImpl).getBalances(SENDER, TON_TESTNET),
    ).rejects.toThrow();
    const [h] = await new TestAdapter(chains([TONCENTER]), fetchImpl).getBalances(
      SENDER,
      TON_TESTNET,
    );
    expect(h?.amount).toBe('109850250');
  });

  it('retries a rate-limited request before failing over', async () => {
    let limited = 2;
    const { fetchImpl } = node({
      '/getAddressInformation': () =>
        limited-- > 0
          ? { status: 429, body: { ok: false, error: 'Ratelimit exceed', code: 429 } }
          : ok({ balance: '5', state: 'active' }),
    });
    const [h] = await new TestAdapter(chains([TONCENTER]), fetchImpl).getBalances(
      SENDER,
      TON_TESTNET,
    );
    expect(h?.amount).toBe('5');
  });

  it('reads balances, history and status through tonapi', async () => {
    const lt = '41000000000001';
    const apiTx = {
      hash: 'ab'.repeat(32),
      lt: Number(lt),
      account: { address: SENDER_RAW },
      utime: 1_760_000_100,
      total_fees: 2_829_621,
      success: true,
      aborted: false,
      block: '(0,6000000000000000,12345)',
      in_msg: { msg_type: 'ext_in_msg', value: 0 },
      out_msgs: [
        {
          msg_type: 'int_msg',
          value: 10_000_000,
          source: { address: SENDER_RAW },
          destination: { address: RECIPIENT_RAW },
        },
      ],
    };
    const { fetchImpl, calls } = node({
      [`/accounts/${SENDER_RAW}`]: () => ({
        body: { balance: 109_850_250, status: 'active' },
      }),
      [`/blockchain/accounts/${SENDER_RAW}/transactions`]: () => ({
        body: { transactions: [apiTx] },
      }),
      [`/blockchain/messages/${NORM_HASH}/transaction`]: () => ({ body: apiTx }),
    });
    const a = new TestAdapter(chains([TONAPI]), fetchImpl);
    const [h] = await a.getBalances(SENDER, TON_TESTNET);
    expect(h?.amount).toBe('109850250');
    const page = await a.getHistory(SENDER, TON_TESTNET);
    expect(page.items[0]).toMatchObject({
      hash: 'ab'.repeat(32),
      from: SENDER,
      to: RECIPIENT_FORMS[1],
      blockNumber: 12345,
      fee: '2829621',
      assetDeltas: [{ assetRef: `${TON_TESTNET}:native`, amount: '-10000000' }],
      status: 'confirmed',
    });
    expect(page.nextCursor).toBeUndefined();
    expect(await a.status(NORM_HASH, TON_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 12345,
      timestampMs: 1_760_000_100_000,
    });
    expect(await a.status('cd'.repeat(32), TON_TESTNET)).toEqual({ state: 'unknown' });
    expect(calls.every((c) => c.url.startsWith(TONAPI))).toBe(true);
  });

  it('reads toncenter history from the v3 index and pages by lt', async () => {
    const v3 = (lt: string, hash: string) => ({
      account: SENDER_RAW.toUpperCase(),
      hash: base64.encode(hexToBytes(hash)),
      lt,
      now: 1_760_000_000,
      block_ref: { workchain: 0, shard: '8000000000000000', seqno: 42 },
      total_fees: '493452',
      description: { aborted: false },
      in_msg: { source: null, destination: SENDER_RAW, value: null },
      out_msgs: [{ source: SENDER_RAW, destination: RECIPIENT_RAW, value: '10000000' }],
    });
    const { fetchImpl, calls } = node({
      '/transactions': (u) => {
        const rows = [v3('20', '11'.repeat(32)), v3('10', '22'.repeat(32))];
        const end = u.searchParams.get('end_lt');
        return { body: { transactions: rows.filter((r) => !end || BigInt(r.lt) <= BigInt(end)) } };
      },
    });
    const a = new TestAdapter(chains([TONCENTER]), fetchImpl);
    const page = await a.getHistory(SENDER, TON_TESTNET);
    expect(page.items[0]).toMatchObject({
      from: SENDER,
      to: RECIPIENT_FORMS[1],
      blockNumber: 42,
      fee: '493452',
      assetDeltas: [{ amount: '-10000000' }],
    });
    const next = await a.getHistory(SENDER, TON_TESTNET, `20:${'11'.repeat(32)}`);
    expect(next.items.map((i) => i.hash)).toEqual(['22'.repeat(32)]);
    const paged = new URL(calls.find((c) => c.url.includes('end_lt'))!.url);
    expect(paged.pathname).toBe('/api/v3/transactions');
    expect(paged.searchParams.get('end_lt')).toBe('19');
  });

  it('reads v2 history with large integers intact on an endpoint without v3', async () => {
    const custom = 'https://ton-node.example';
    const big = '123456789012345678901';
    const v2 = (lt: string, hash: string) => ({
      utime: 1_760_000_000,
      transaction_id: { lt, hash: base64.encode(hexToBytes(hash)) },
      fee: 1000,
      in_msg: { source: RECIPIENT, destination: SENDER, value: 'X' },
      out_msgs: [],
    });
    const { fetchImpl, calls } = node({
      '/getTransactions': (u) => {
        const rows = [v2('20', '11'.repeat(32)), v2('10', '22'.repeat(32))];
        return {
          body: JSON.parse(
            JSON.stringify({ ok: true, result: u.searchParams.has('lt') ? rows.slice(1) : rows }),
          ),
        };
      },
    });
    // The mock carries the incoming value as a raw JSON number beyond 2^53.
    const raw = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const res = await fetchImpl(input, init);
      const text = (await res.text()).replace(/"value":"X"/g, `"value":${big}`);
      return new Response(text, {
        status: res.status,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    const a = new TestAdapter(chains([custom]), raw);
    const page = await a.getHistory(SENDER, TON_TESTNET);
    expect(page.items).toHaveLength(2);
    expect(page.items[0]).toMatchObject({
      from: RECIPIENT_FORMS[1],
      to: SENDER,
      assetDeltas: [{ amount: big }],
    });
    const next = await a.getHistory(SENDER, TON_TESTNET, `20:${'11'.repeat(32)}`);
    expect(next.items.map((i) => i.hash)).toEqual(['22'.repeat(32)]);
    const paged = calls.find((c) => c.url.includes('lt=20'));
    expect(new URL(paged!.url).searchParams.get('hash')).toBe(
      base64.encode(hexToBytes('11'.repeat(32))),
    );
    await expect(a.getHistory(SENDER, TON_TESTNET, 'nope')).rejects.toThrow('cursor');
  });

  it('explains wallet exit codes', () => {
    expect(
      shortReason('LITE_SERVER_UNKNOWN: cannot apply external message: exitcode=36, steps=1'),
    ).toMatch(/^message expired/);
    expect(shortReason('exit code 35')).toMatch(/^invalid signature/);
  });
});

describe('TON send flow', () => {
  it('prepares a transfer from an active wallet to an inactive recipient', async () => {
    const { fetchImpl } = toncenter({ state: 'active', seqno: 7 });
    const a = new TestAdapter(chains([TONCENTER]), fetchImpl);
    const { unsigned, simulation } = await prepareTon(
      a,
      intent(RECIPIENT, '10000000'),
      SENDER,
      1_760_000_000_000,
    );
    expect(unsigned).toEqual({
      ...tx,
      nanoton: '10000000',
      bounce: false,
      validUntil: 1_760_001_800,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee).toEqual({ assetRef: `${TON_TESTNET}:native`, amount: '10000000' });
    expect(simulation.warnings.some((w) => 'message' in w && /not active/.test(w.message))).toBe(
      true,
    );
  });

  it('deploys an undeployed wallet and refuses what the balance cannot pay', async () => {
    const { fetchImpl } = toncenter({ state: 'uninitialized', balance: '20000000' });
    const a = new TestAdapter(chains([TONCENTER]), fetchImpl);
    const { unsigned, simulation } = await prepareTon(a, intent(RECIPIENT, '10000000'), SENDER);
    expect(unsigned).toMatchObject({ seqno: 0, deploy: true, bounce: false });
    expect(simulation.ok).toBe(false);
    expect(simulation.fee?.amount).toBe('30000000');
    await expect(prepareTon(a, intent(SENDER, '1'), SENDER)).rejects.toThrow();
    await expect(
      prepareTon(a, { ...intent(RECIPIENT, '1'), chainId: TON_MAINNET } as TxIntent, SENDER),
    ).rejects.toThrow('testnet');
  });

  it('approves only while the seqno and deployment still match', async () => {
    const now = 1_760_000_000_000;
    const active = new TestAdapter(
      chains([TONCENTER]),
      toncenter({ state: 'active', seqno: 7 }).fetchImpl,
    );
    expect(await tonApprovalValid(active, tx, now)).toBe(true);
    expect(await tonApprovalValid(active, { ...tx, seqno: 6 }, now)).toBe(false);
    expect(await tonApprovalValid(active, deployTx, now)).toBe(false);
    expect(await tonApprovalValid(active, tx, tx.validUntil * 1000)).toBe(false);
    const fresh = new TestAdapter(
      chains([TONCENTER]),
      toncenter({ state: 'uninitialized' }).fetchImpl,
    );
    expect(await tonApprovalValid(fresh, deployTx, now)).toBe(true);
    expect(await tonApprovalValid(fresh, tx, now)).toBe(false);
  });

  it('broadcasts only the exact signed message of this transfer', async () => {
    const { fetchImpl, calls } = toncenter(
      { state: 'active' },
      { '/sendBocReturnHash': () => ok({ hash: 'x' }) },
    );
    const a = new TestAdapter(chains([TONCENTER]), fetchImpl);
    expect(await broadcastTon(a, tx, `0x${BOC}`)).toBe(NORM_HASH);
    const sent = calls.find((c) => c.url.endsWith('/sendBocReturnHash'));
    expect(sent?.body).toEqual({ boc: base64.encode(hexToBytes(BOC)) });

    await expect(broadcastTon(a, { ...tx, nanoton: '1500000001' }, `0x${BOC}`)).rejects.toThrow(
      'not this TON transfer',
    );
    const forged = signed(tx).boc.replace(/^0x/, '');
    const flipped = hexToBytes(forged);
    flipped[60]! ^= 1;
    await expect(broadcastTon(a, tx, bytesToHex(flipped))).rejects.toThrow();
    // A different key's signature spelled in this wallet's message.
    const other = signed(tx, new Uint8Array(32).fill(9)).boc;
    await expect(broadcastTon(a, tx, other)).rejects.toThrow('Signature does not verify');
    await expect(broadcastTon(a, tx, '0xzz')).rejects.toThrow();

    // A deploying message carries its own key, so no get-method call is needed.
    const before = calls.filter((c) => c.url.endsWith('/runGetMethod')).length;
    expect(await broadcastTon(a, deployTx, `0x${DEPLOY_BOC}`)).toBe(DEPLOY_NORM_HASH);
    expect(calls.filter((c) => c.url.endsWith('/runGetMethod')).length).toBe(before);
  });

  it('refuses a key the wallet does not own', async () => {
    const otherPub = ed25519.getPublicKey(new Uint8Array(32).fill(9));
    const { fetchImpl } = toncenter(
      { state: 'active' },
      {
        '/runGetMethod': () => ok({ exit_code: 0, stack: [['num', `0x${bytesToHex(otherPub)}`]] }),
        '/sendBocReturnHash': () => ok({}),
      },
    );
    const a = new TestAdapter(chains([TONCENTER]), fetchImpl);
    await expect(broadcastTon(a, tx, `0x${BOC}`)).rejects.toThrow('not the sender wallet');
  });

  it('reports wallet verdicts and recognizes a retry of an applied message', async () => {
    const verdict =
      (code: number): Route =>
      () => ({
        status: 500,
        body: {
          ok: false,
          error: `LITE_SERVER_UNKNOWN: cannot apply external message to current state : External message was not accepted\nexitcode=${code}, steps=21`,
          code: 500,
        },
      });
    const expired = new TestAdapter(
      chains([TONCENTER]),
      toncenter({ state: 'active' }, { '/sendBocReturnHash': verdict(36) }).fetchImpl,
    );
    await expect(broadcastTon(expired, tx, BOC)).rejects.toThrow(/message expired/);
    const v3 = {
      account: SENDER_RAW,
      hash: base64.encode(hexToBytes('ef'.repeat(32))),
      lt: '1',
      now: 1_760_000_050,
      block_ref: { workchain: 0, shard: '8000000000000000', seqno: 99 },
      total_fees: '1',
      description: { aborted: false },
      in_msg: null,
      out_msgs: [],
    };
    const replay = new TestAdapter(
      chains([TONCENTER]),
      toncenter(
        { state: 'active' },
        {
          '/sendBocReturnHash': verdict(33),
          '/transactionsByMessage': (u) =>
            u.searchParams.get('msg_hash') === NORM_HASH
              ? { body: { transactions: [v3] } }
              : { body: { transactions: [] } },
          '/transactions': () => ({ body: { transactions: [] } }),
        },
      ).fetchImpl,
    );
    expect(await broadcastTon(replay, tx, BOC)).toBe(NORM_HASH);
    expect(await replay.status(NORM_HASH, TON_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 99,
      timestampMs: 1_760_000_050_000,
    });
  });

  it('reports expiry only once the message can no longer land', async () => {
    const empty: Record<string, Route> = {
      '/transactionsByMessage': () => ({ body: { transactions: [] } }),
      '/transactions': () => ({ body: { transactions: [] } }),
    };
    const waiting = new TestAdapter(
      chains([TONCENTER]),
      toncenter({ state: 'active', seqno: 7 }, empty).fetchImpl,
    );
    expect(await tonTransferStatus(waiting, tx, NORM_HASH, 1_760_000_100_000)).toEqual({
      state: 'unknown',
    });
    expect(await tonTransferStatus(waiting, tx, NORM_HASH, 1_760_002_000_000)).toEqual({
      state: 'expired',
    });
    const moved = new TestAdapter(
      chains([TONCENTER]),
      toncenter({ state: 'active', seqno: 8 }, empty).fetchImpl,
    );
    expect(await tonTransferStatus(moved, tx, NORM_HASH, 1_760_000_100_000)).toEqual({
      state: 'expired',
    });
  });
});
