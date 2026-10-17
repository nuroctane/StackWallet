import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  HYPERLIQUID_MAINNET,
  HYPERLIQUID_TESTNET,
  HyperliquidAdapter,
  decimalToUnits,
  endpointKind,
  hyperliquidAddressFromPublicKey,
  isValidHyperliquidAddress,
  ledgerRecord,
  spotAssetRef,
} from './hyperliquid.js';
import {
  HyperliquidTx,
  amountString,
  broadcastHyperliquid,
  hyperliquidApprovalValid,
  hyperliquidExplorerHash,
  hyperliquidTransferStatus,
  prepareHyperliquid,
  usdSendDigest,
  usdSendLocalId,
  usdSendWire,
  wireSigner,
} from './send.js';

const SECRET = new Uint8Array(32).fill(7);
const SENDER = '0x4a62316623ad457f02cdc5d997ded67a383ec569';
const RECIPIENT = '0x5e9ee1089755c3435139848e47e6635505d5a13a';
const SDK_SECRET = hexToBytes('0123456789012345678901234567890123456789012345678901234567890123');

const tx: HyperliquidTx = {
  chainId: HYPERLIQUID_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  hlUsdMicro: '1500000',
  time: 1_760_000_000_000,
  builtAtMs: 1_760_000_000_000,
};
/** Pinned identically in `crates/stackwallet-core/src/hyperliquid.rs`. */
const DIGEST_VECTOR = '0ebbb76c717b9789670bdd716db9325f366a3180e42899cf0f6a35d2c2bbd822';
const LOCAL_ID_VECTOR = '0xc9070af983a3b8cb20601f8f36307232b8f3b9da029b938cdd8fb8d1c86b8248';
const WIRE_VECTOR =
  '{"action":{"type":"usdSend","signatureChainId":"0x66eee","hyperliquidChain":"Testnet","destination":"0x5e9ee1089755c3435139848e47e6635505d5a13a","amount":"1.5","time":1760000000000},"nonce":1760000000000,"signature":{"r":"0x51356fc44db0039e410f9907cf2e2526c70394c4814b3b8a34d488483dade90c","s":"0x3dcc4cc273b54e3781fb1ca9d0e239808966d097d888b23e31966c38cb0dc416","v":28}}';

function sign(t: HyperliquidTx, secret: Uint8Array): string {
  const sig = secp256k1.sign(usdSendDigest(t), secret, { prehash: false, format: 'recovered' });
  return usdSendWire(t, {
    r: `0x${bytesToHex(sig.slice(1, 33))}`,
    s: `0x${bytesToHex(sig.slice(33))}`,
    v: 27 + sig[0]!,
  });
}

const MAIN_API = 'https://api.hyperliquid.xyz';
const TEST_API = 'https://api.hyperliquid-testnet.xyz';
const TEST_EXPLORER = 'https://rpc.hyperliquid-testnet.xyz/explorer';
const chain = (chainId: string, name: string, testnet: boolean, rpcs: string[]) =>
  ({
    chainId,
    family: 'hyperliquid',
    name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'USDC', decimals: 6 },
    testnet,
    defaultRpcs: rpcs,
  }) as ChainInfo;
const CHAINS: ChainInfo[] = [
  chain(HYPERLIQUID_MAINNET, 'Hyperliquid', false, [MAIN_API]),
  chain(HYPERLIQUID_TESTNET, 'Hyperliquid Testnet', true, [TEST_API, TEST_EXPLORER]),
];
class TestAdapter extends HyperliquidAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Reply = { status?: number; body: unknown } | undefined;
type Route = (body: Record<string, unknown>) => Reply;
const pinned = {
  type: 'txDetails',
  tx: {
    time: 1786559640873,
    user: '0xe973105a27e17350500926ae664dfcfe6006d924',
    action: { type: 'usdSend', hyperliquidChain: 'Testnet' },
    block: 650061450,
    hash: '0xc6176fcffca86f05c7910426bf268a00005287b597ab8dd769e01b22bbac48f0',
    error: null,
  },
};
function node(routes: Record<string, Route>) {
  const calls: { key: string; raw: string }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const raw = String(init?.body ?? '');
    const body = JSON.parse(raw || '{}') as Record<string, unknown>;
    const kind = typeof body['type'] === 'string' ? body['type'] : body['action'] ? 'exchange' : '';
    const key = `${url.origin}${url.pathname} ${kind}`;
    calls.push({ key, raw });
    let reply: Reply;
    if (key === `${TEST_API}/info tokenDetails`)
      reply =
        body['tokenId'] === '0xeb62eee3685fc4c43992febcd9e75443'
          ? { body: { name: 'USDC' } }
          : { status: 500, body: null };
    else if (key === `${MAIN_API}/info tokenDetails`)
      reply =
        body['tokenId'] === '0x6d1e7cde53ba9467b783cb7c530ce054'
          ? { body: { name: 'USDC' } }
          : { status: 500, body: null };
    else if (key === `${TEST_EXPLORER} txDetails` && body['hash'] === pinned.tx.hash)
      reply = { body: pinned };
    else reply = routes[key]?.(body);
    reply ??= { status: 404, body: null };
    return new Response(JSON.stringify(reply.body), {
      status: reply.status ?? 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { adapter: new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) }), calls };
}

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: HYPERLIQUID_TESTNET,
    kind: 'transfer',
    to,
    asset: `${HYPERLIQUID_TESTNET}:native`,
    amount,
    proposer: { kind: 'human', deviceId: 'd' },
    untrustedDestinations: [],
    createdAtMs: 0,
  } as TxIntent;
}

describe('addresses', () => {
  it('derives the same lowercase address as the core', () => {
    const pub = secp256k1.getPublicKey(SECRET, true);
    expect(hyperliquidAddressFromPublicKey(pub)).toBe(SENDER);
    const one = new Uint8Array(32);
    one[31] = 1;
    expect(hyperliquidAddressFromPublicKey(secp256k1.getPublicKey(one, true))).toBe(
      '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf',
    );
    const { adapter } = node({});
    expect(
      adapter.deriveAddress({ curve: 'secp256k1', hex: bytesToHex(pub) }, HYPERLIQUID_TESTNET),
    ).toBe(SENDER);
    expect(() =>
      adapter.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, HYPERLIQUID_TESTNET),
    ).toThrow();
  });

  it('accepts lowercase and EIP-55 spellings only', () => {
    expect(isValidHyperliquidAddress(RECIPIENT)).toBe(true);
    expect(isValidHyperliquidAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(true);
    expect(isValidHyperliquidAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395BdF')).toBe(false);
    expect(isValidHyperliquidAddress(`0x${'0'.repeat(40)}`)).toBe(false);
    expect(isValidHyperliquidAddress(RECIPIENT.slice(2))).toBe(false);
    expect(endpointKind(TEST_EXPLORER)).toBe('explorer');
    expect(endpointKind(TEST_API)).toBe('api');
  });
});

describe('usdSend encoding', () => {
  it('renders amounts like the core', () => {
    expect(amountString(1_000_000n)).toBe('1');
    expect(amountString(1_500_000n)).toBe('1.5');
    expect(amountString(1n)).toBe('0.000001');
    expect(amountString(10_010_000n)).toBe('10.01');
    expect(decimalToUnits('38083929.7112530023', 6, true)).toBe(38083929711253n);
    expect(() => decimalToUnits('1.0000001', 6)).toThrow();
    expect(decimalToUnits('1.0000000', 6)).toBe(1_000_000n);
  });

  it('matches the hyperliquid-python-sdk signing vector', () => {
    const sdk: HyperliquidTx = {
      ...tx,
      from: hyperliquidAddressFromPublicKey(secp256k1.getPublicKey(SDK_SECRET, true)),
      hlUsdMicro: '1000000',
      time: 1_687_816_341_423,
      builtAtMs: 1_687_816_341_423,
    };
    expect(bytesToHex(usdSendDigest(sdk))).toBe(
      'cacf7585cc49ca60c6c5fb3001e226c0ca03c46252c893eea574c78907b7cebe',
    );
    expect(sign(sdk, SDK_SECRET)).toContain(
      '"signature":{"r":"0x637b37dd731507cdd24f46532ca8ba6eec616952c56218baeff04144e4a77073","s":"0x11a6a24900e6e314136d2592e2f8d502cd89b7c15b198e1bee043c9589f9fad7","v":27}',
    );
  });

  it('pins the same digest, id and body as the core', () => {
    expect(bytesToHex(usdSendDigest(tx))).toBe(DIGEST_VECTOR);
    expect(usdSendLocalId(tx)).toBe(LOCAL_ID_VECTOR);
    expect(sign(tx, SECRET)).toBe(WIRE_VECTOR);
    expect(wireSigner(tx, WIRE_VECTOR)).toBe(SENDER);
  });

  it('refuses malformed transfers', () => {
    const bad: unknown[] = [
      { ...tx, chainId: HYPERLIQUID_MAINNET },
      { ...tx, hlUsdMicro: '0' },
      { ...tx, hlUsdMicro: '01' },
      { ...tx, hlUsdMicro: '1000000000000001' },
      { ...tx, to: tx.from },
      { ...tx, to: '0x5E9EE1089755C3435139848e47e6635505D5a13A' },
      { ...tx, time: tx.builtAtMs + 86_400_001 },
      { ...tx, vaultAddress: RECIPIENT },
    ];
    for (const t of bad) expect(() => usdSendDigest(t as HyperliquidTx)).toThrow();
    expect(() => wireSigner({ ...tx, hlUsdMicro: '1500001' }, WIRE_VECTOR)).toThrow();
    expect(() => wireSigner(tx, WIRE_VECTOR.replace('"v":28', '"v":29'))).toThrow();
    expect(wireSigner(tx, WIRE_VECTOR.replace('"v":28', '"v":27'))).not.toBe(SENDER);
  });
});

describe('reads', () => {
  it('reads perp withdrawable and spot balances after proving the network', async () => {
    const { adapter, calls } = node({
      [`${TEST_API}/info clearinghouseState`]: () => ({
        body: { withdrawable: '1008.0100039', marginSummary: {} },
      }),
      [`${TEST_API}/info spotClearinghouseState`]: () => ({
        body: {
          balances: [
            { coin: 'USDC', token: 0, total: '24.93419484', hold: '0.0', entryNtl: '0.0' },
            { coin: 'HYPE', token: 1105, total: '82.37945803', hold: '0.0' },
            { coin: 'FAKE', token: 9, total: '5.0', hold: '0.0' },
          ],
        },
      }),
    });
    const holdings = await adapter.getBalances(
      '0x11178E8FB333EFDF1B4C7B986664A73E71ACB9B7',
      HYPERLIQUID_TESTNET,
    );
    expect(holdings.map((h) => [h.assetRef, h.amount])).toEqual([
      [`${HYPERLIQUID_TESTNET}:native`, '1008010003'],
      [spotAssetRef(HYPERLIQUID_TESTNET, 0), '2493419484'],
      [spotAssetRef(HYPERLIQUID_TESTNET, 1105), '8237945803'],
    ]);
    expect(calls[0]!.key).toBe(`${TEST_API}/info tokenDetails`);
    expect(calls.some((c) => c.raw.includes('0x11178e8fb333efdf1b4c7b986664a73e71acb9b7'))).toBe(
      true,
    );
  });

  it('refuses an endpoint serving the other network', async () => {
    const { adapter } = node({});
    const wrong = new TestAdapter({
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        if (body['type'] === 'tokenDetails') return new Response('null', { status: 500 });
        return new Response('{"withdrawable":"1.0"}', { status: 200 });
      }) as typeof fetch,
      rpc: new MemoryRpcPool(CHAINS),
    });
    await expect(wrong.getBalances(SENDER, HYPERLIQUID_TESTNET)).rejects.toThrow();
    expect(adapter).toBeDefined();
  });

  it('maps ledger entries to perp USDC deltas', () => {
    const native = `${HYPERLIQUID_TESTNET}:native`;
    const send = ledgerRecord(HYPERLIQUID_TESTNET, native, SENDER, {
      time: 1,
      hash: `0x${'ab'.repeat(32)}`,
      delta: {
        type: 'internalTransfer',
        usdc: '2.0',
        user: SENDER,
        destination: RECIPIENT,
        fee: '1.0',
      },
    });
    expect(send.assetDeltas).toEqual([{ assetRef: native, amount: '-2000000' }]);
    expect(send.fee).toBe('1000000');
    expect(send.to).toBe(RECIPIENT);
    const toSpot = ledgerRecord(HYPERLIQUID_TESTNET, native, SENDER, {
      time: 1,
      hash: `0x${'ab'.repeat(32)}`,
      delta: { type: 'accountClassTransfer', usdc: '4.5', toPerp: false },
    });
    expect(toSpot.assetDeltas[0]!.amount).toBe('-4500000');
    const spot = ledgerRecord(HYPERLIQUID_TESTNET, native, SENDER, {
      time: 1,
      hash: `0x${'ab'.repeat(32)}`,
      delta: {
        type: 'spotTransfer',
        token: 'HYPE',
        amount: '1',
        user: SENDER,
        destination: RECIPIENT,
      },
    });
    expect(spot.assetDeltas).toEqual([]);
    expect(spot.description).toBe('spotTransfer');
  });

  it('pages history in windows newest first', async () => {
    const { adapter, calls } = node({
      [`${TEST_API}/info userNonFundingLedgerUpdates`]: () => ({
        body: [
          {
            time: 1_700_000_000_000,
            hash: `0x${'01'.repeat(32)}`,
            delta: { type: 'deposit', usdc: '5.0' },
          },
          {
            time: 1_700_000_100_000,
            hash: `0x${'02'.repeat(32)}`,
            delta: { type: 'withdraw', usdc: '1.0', fee: '1.0', nonce: 1 },
          },
        ],
      }),
    });
    const page = await adapter.getHistory(SENDER, HYPERLIQUID_TESTNET, '1700000200000');
    expect(page.items.map((i) => i.assetDeltas[0]!.amount)).toEqual(['-1000000', '5000000']);
    expect(page.nextCursor).toBe(String(1_700_000_200_000 - 90 * 86_400_000 - 1));
    const body = JSON.parse(calls.at(-1)!.raw) as Record<string, number>;
    expect(body['endTime']).toBe(1_700_000_200_000);
    await expect(adapter.getHistory(SENDER, HYPERLIQUID_TESTNET, 'x')).rejects.toThrow();
  });
});

describe('send', () => {
  const roles = (sender: string, recipient: string) => (body: Record<string, unknown>) => ({
    body: { role: body['user'] === SENDER ? sender : recipient },
  });

  it('prepares a canonical transfer and flags new-account fees', async () => {
    const { adapter } = node({
      [`${TEST_API}/info clearinghouseState`]: () => ({ body: { withdrawable: '10.0' } }),
      [`${TEST_API}/info userRole`]: roles('user', 'missing'),
    });
    const { unsigned, simulation } = await prepareHyperliquid(
      adapter,
      intent('0x5E9EE1089755C3435139848e47e6635505D5a13A', '1500000'),
      SENDER,
      tx.time,
    );
    expect(unsigned).toEqual(tx);
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('1000000');
    expect(simulation.warnings).toHaveLength(1);
  });

  it('reports a sender that never deposited and short balances', async () => {
    const missing = node({
      [`${TEST_API}/info clearinghouseState`]: () => ({ body: { withdrawable: '0.0' } }),
      [`${TEST_API}/info userRole`]: roles('missing', 'user'),
    });
    const a = await prepareHyperliquid(missing.adapter, intent(RECIPIENT, '1'), SENDER, tx.time);
    expect(a.simulation.ok).toBe(false);
    expect(a.simulation.error).toMatch(/deposit/);
    const short = node({
      [`${TEST_API}/info clearinghouseState`]: () => ({ body: { withdrawable: '1.4' } }),
      [`${TEST_API}/info userRole`]: roles('user', 'user'),
    });
    const b = await prepareHyperliquid(
      short.adapter,
      intent(RECIPIENT, '1500000'),
      SENDER,
      tx.time,
    );
    expect(b.simulation.ok).toBe(false);
    await expect(
      prepareHyperliquid(
        short.adapter,
        { ...intent(RECIPIENT, '1'), chainId: HYPERLIQUID_MAINNET },
        SENDER,
      ),
    ).rejects.toThrow();
  });

  it('keeps approval open for a day after build', async () => {
    const { adapter } = node({});
    expect(await hyperliquidApprovalValid(adapter, tx, tx.time + 1000)).toBe(true);
    expect(await hyperliquidApprovalValid(adapter, tx, tx.time + 86_400_000)).toBe(false);
    expect(await hyperliquidApprovalValid(adapter, { ...tx, hlUsdMicro: '0' }, tx.time)).toBe(
      false,
    );
  });

  it('broadcasts only the exact signed transfer', async () => {
    const { adapter, calls } = node({
      [`${TEST_API}/exchange exchange`]: () => ({
        body: { status: 'ok', response: { type: 'default' } },
      }),
    });
    expect(await broadcastHyperliquid(adapter, tx, WIRE_VECTOR)).toBe(LOCAL_ID_VECTOR);
    expect(calls.at(-1)!.raw).toBe(WIRE_VECTOR);
    const other = sign(tx, new Uint8Array(32).fill(9));
    await expect(broadcastHyperliquid(adapter, tx, other)).rejects.toThrow(/recover/);
    const tampered = WIRE_VECTOR.replace('"amount":"1.5"', '"amount":"15"');
    await expect(broadcastHyperliquid(adapter, tx, tampered)).rejects.toThrow();
    await expect(broadcastHyperliquid(adapter, tx, `${WIRE_VECTOR} `)).rejects.toThrow();
    expect(calls.filter((c) => c.key.endsWith('exchange'))).toHaveLength(1);
  });

  it('surfaces rejections', async () => {
    const { adapter } = node({
      [`${TEST_API}/exchange exchange`]: () => ({
        body: {
          status: 'err',
          response: `Must deposit before performing actions. User: ${SENDER}`,
        },
      }),
    });
    await expect(broadcastHyperliquid(adapter, tx, WIRE_VECTOR)).rejects.toThrow(/Must deposit/);
  });

  const onChain = (error: string | null) => ({
    time: tx.time + 500,
    user: SENDER,
    action: {
      type: 'usdSend',
      signatureChainId: '0x66eee',
      hyperliquidChain: 'Testnet',
      destination: RECIPIENT,
      amount: '1.5',
      time: tx.time,
    },
    block: 734596061,
    hash: `0x${'cd'.repeat(32)}`,
    error,
  });

  it('resolves status and the explorer hash from the sender transactions', async () => {
    const { adapter } = node({
      [`${TEST_EXPLORER} userDetails`]: () => ({
        body: {
          type: 'userDetails',
          txs: [{ ...onChain(null), action: { ...onChain(null).action, time: 1 } }, onChain(null)],
        },
      }),
    });
    expect(await hyperliquidTransferStatus(adapter, tx, LOCAL_ID_VECTOR, tx.time)).toEqual({
      state: 'confirmed',
      blockNumber: 734596061,
      timestampMs: tx.time + 500,
    });
    expect(await hyperliquidExplorerHash(adapter, tx)).toBe(`0x${'cd'.repeat(32)}`);
    const failed = node({
      [`${TEST_EXPLORER} userDetails`]: () => ({
        body: { type: 'userDetails', txs: [onChain('Insufficient balance')] },
      }),
    });
    expect(await hyperliquidTransferStatus(failed.adapter, tx, LOCAL_ID_VECTOR)).toEqual({
      state: 'failed',
      reason: 'Insufficient balance',
    });
  });

  it('falls back to the ledger and expires only past the nonce window', async () => {
    const ledgerEntry = {
      time: tx.time + 500,
      hash: `0x${'cd'.repeat(32)}`,
      delta: {
        type: 'internalTransfer',
        usdc: '1.5',
        user: SENDER,
        destination: RECIPIENT,
        fee: '0.0',
      },
    };
    const viaLedger = node({
      [`${TEST_EXPLORER} userDetails`]: () => ({ body: { type: 'userDetails', txs: [] } }),
      [`${TEST_API}/info userNonFundingLedgerUpdates`]: () => ({ body: [ledgerEntry] }),
      [`${TEST_EXPLORER} txDetails`]: () => ({ body: { type: 'txDetails', tx: onChain(null) } }),
    });
    expect(
      (await hyperliquidTransferStatus(viaLedger.adapter, tx, LOCAL_ID_VECTOR, tx.time)).state,
    ).toBe('confirmed');
    const lookalike = node({
      [`${TEST_EXPLORER} userDetails`]: () => ({ body: { type: 'userDetails', txs: [] } }),
      [`${TEST_API}/info userNonFundingLedgerUpdates`]: () => ({ body: [ledgerEntry] }),
      [`${TEST_EXPLORER} txDetails`]: () => ({
        body: {
          type: 'txDetails',
          tx: { ...onChain(null), action: { ...onChain(null).action, time: 5 } },
        },
      }),
    });
    expect(
      (
        await hyperliquidTransferStatus(
          lookalike.adapter,
          tx,
          LOCAL_ID_VECTOR,
          tx.time + 4 * 86_400_000,
        )
      ).state,
    ).toBe('unknown');
    const none = node({
      [`${TEST_EXPLORER} userDetails`]: () => ({ body: { type: 'userDetails', txs: [] } }),
      [`${TEST_API}/info userNonFundingLedgerUpdates`]: () => ({ body: [] }),
    });
    expect(
      (await hyperliquidTransferStatus(none.adapter, tx, LOCAL_ID_VECTOR, tx.time)).state,
    ).toBe('unknown');
    expect(
      (await hyperliquidTransferStatus(none.adapter, tx, LOCAL_ID_VECTOR, tx.time + 3 * 86_400_000))
        .state,
    ).toBe('expired');
  });
});
