import { bech32 } from '@scure/base';
import { MemoryRpcPool, RpcFailoverError, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  ANCHOR_BLOCKS,
  CARDANO_MAINNET,
  CARDANO_PREPROD,
  CardanoAdapter,
  cardanoAddressBytes,
  cardanoAddressFromPublicKey,
  endpointKind,
  isValidCardanoAddress,
  type Utxo,
} from './cardano.js';
import {
  CardanoTx,
  broadcastCardano,
  cardanoApprovalValid,
  cardanoChange,
  cardanoMaxSendable,
  cardanoTransferStatus,
  cardanoTxBody,
  cardanoTxId,
  prepareCardano,
  selectInputs,
} from './send.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const unhex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

// "abandon x11 about", m/1852'/1815'/0'/{0,2}/0, from @emurgo/cardano-serialization-lib 17
// and pinned by the core (`cardano.rs`).
const PAYMENT_PUB = '7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a';
const STAKE_PUB = '012f5dc3115b8a07981e6e50f5a671e2c6fbb26c3ffde1cd1dcaf40a7fe8f160';
const SENDER =
  'addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn';
const SENDER_MAINNET =
  'addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv';
const SENDER_ENTERPRISE = 'addr_test1vq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7ss9hjl0y';
/** CIP-19 test vectors. */
const RECIPIENT =
  'addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae';
const CIP19_ENTERPRISE = 'addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz';
const CIP19_PAYMENT_VK = 'addr_vk1w0l2sr2zgfm26ztc6nl9xy8ghsk5sh6ldwemlpmp9xylzy4dtf7st80zhd';
const CIP19_STAKE_VK = 'stake_vk1px4j0r2fk7ux5p23shz8f3y5y2qam7s954rgf3lg5merqcj6aetsft99wu';

const CHANGE_BODY =
  'a400d90102828258201111111111111111111111111111111111111111111111111111111111111111008258202222222222222222222222222222222222222222222222222222222222222222030182825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c472511a0016e360825839000fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a007f1b1b021a00029805031a055d4a80';
const CHANGE_TXID = 'c4a617268d07fefc80257fb80fd66987415de9c0564934371131f1a2c2c6f5f2';
const CHANGE_TX =
  '84a400d90102828258201111111111111111111111111111111111111111111111111111111111111111008258202222222222222222222222222222222222222222222222222222222222222222030182825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c472511a0016e360825839000fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a007f1b1b021a00029805031a055d4a80a100d90102818258207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a5840b2ab840c40143a9463fd7544d804a3d8599cd3dca5a9f2aa3284e5c7d434bd86eb308d2967b24d712e875044831c69382b6b6b278d4a7a14929421faa0d62808f5f6';
const MAX_BODY =
  'a400d90102828258201111111111111111111111111111111111111111111111111111111111111111008258202222222222222222222222222222222222222222222222222222222222222222030181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c472511a009609a7021a00028cd9031a055d4a80';
const MAX_TXID = '4e7df7d6232382556e7f086ed43f7723ce56a3cabca81d30241f8342f8e1fa29';

const tx: CardanoTx = {
  chainId: CARDANO_PREPROD,
  from: SENDER,
  to: RECIPIENT,
  lovelace: '1500000',
  inputs: [
    { txHash: '11'.repeat(32), index: 0, lovelace: '4000000' },
    { txHash: '22'.repeat(32), index: 3, lovelace: '6000000' },
  ],
  fee: 169_989,
  ttl: 90_000_000,
  builtSlot: 89_992_800,
  minFeeA: 44,
  minFeeB: 155_381,
  coinsPerUtxoByte: 4310,
};
const PARAMS = { minFeeA: 44, minFeeB: 155_381, coinsPerUtxoByte: 4310, maxTxSize: 16_384 };

const INDEXER = 'https://preprod-backend.yoroiwallet.com/api';
const OGMIOS = 'https://preprod.koios.rest/api/v1/ogmios';
const CHAINS: ChainInfo[] = [
  {
    chainId: CARDANO_MAINNET,
    family: 'cardano',
    name: 'Cardano',
    nativeAsset: { ref: `${CARDANO_MAINNET}:native`, symbol: 'ADA', decimals: 6 },
    testnet: false,
    defaultRpcs: ['https://api.yoroiwallet.com/api', 'https://api.koios.rest/api/v1/ogmios'],
  },
  {
    chainId: CARDANO_PREPROD,
    family: 'cardano',
    name: 'Cardano Preprod',
    nativeAsset: { ref: `${CARDANO_PREPROD}:native`, symbol: 'ADA', decimals: 6 },
    testnet: true,
    defaultRpcs: [INDEXER, OGMIOS],
  },
];

class TestAdapter extends CardanoAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

const utxo = (txHash: string, index: number, amount: string, extra: Partial<Utxo> = {}): Utxo => ({
  tx_hash: txHash,
  tx_index: index,
  receiver: SENDER,
  amount,
  assets: [],
  block_num: 1,
  script_ref: null,
  ...extra,
});

interface World {
  slot: number;
  utxos: Utxo[];
  anchor?: string;
  magic?: number;
  txs?: Record<string, unknown>;
  submit?: unknown;
  submitStatus?: number;
  history?: unknown[];
}

function network(world: World) {
  const calls: { url: string; body?: unknown }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, body });
    if (url === OGMIOS) {
      const reply = (result: unknown) =>
        Response.json({ jsonrpc: '2.0', method: body.method, result, id: 1 });
      switch (body.method) {
        case 'queryNetwork/genesisConfiguration':
          return reply({ era: 'shelley', networkMagic: world.magic ?? 1 });
        case 'queryLedgerState/protocolParameters':
          return reply({
            minFeeCoefficient: 44,
            minFeeConstant: { ada: { lovelace: 155381 } },
            minUtxoDepositCoefficient: 4310,
            maxTransactionSize: { bytes: 16384 },
          });
        case 'submitTransaction':
          return Response.json(world.submit, { status: world.submitStatus ?? 200 });
      }
      return Response.json({ error: 'no' }, { status: 400 });
    }
    const path = url.slice(INDEXER.length);
    switch (path) {
      case '/v2.1/lastBlockBySlot':
        return Response.json({
          blockHashes: { '100,1000': world.anchor ?? ANCHOR_BLOCKS[CARDANO_PREPROD] },
        });
      case '/v2/bestblock':
        return Response.json({
          epoch: 319,
          slot: 1,
          globalSlot: world.slot,
          hash: 'ab'.repeat(32),
          height: 5298746,
        });
      case '/txs/utxoForAddresses':
        return Response.json(world.utxos);
      case '/txs/utxoSumForAddresses':
        return Response.json({
          sum: world.utxos.reduce((s, u) => s + BigInt(u.amount), 0n).toString(),
          tokensBalance: [],
        });
      case '/v2/txs/get': {
        const out: Record<string, unknown> = {};
        for (const h of body.txHashes as string[]) if (world.txs?.[h]) out[h] = world.txs[h];
        return Response.json(out);
      }
      case '/v2/txs/history':
        return Response.json(world.history ?? []);
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(world: World) {
  const { fetchImpl, calls } = network(world);
  return { a: new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) }), calls };
}

const intent = (amount: string, to = RECIPIENT): TxIntent =>
  ({
    id: 'i',
    walletId: 'w',
    accountId: 'a',
    chainId: CARDANO_PREPROD,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${CARDANO_PREPROD}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  }) as unknown as TxIntent;

describe('addresses', () => {
  it('derives the same addresses as the SDK and the core', () => {
    const both = unhex(PAYMENT_PUB + STAKE_PUB);
    expect(cardanoAddressFromPublicKey(both)).toBe(SENDER);
    expect(cardanoAddressFromPublicKey(both, CARDANO_MAINNET)).toBe(SENDER_MAINNET);
    expect(cardanoAddressFromPublicKey(unhex(PAYMENT_PUB))).toBe(SENDER_ENTERPRISE);
    expect(() => cardanoAddressFromPublicKey(new Uint8Array(33))).toThrow();
    const a = new TestAdapter();
    expect(
      a.deriveAddress({ curve: 'ed25519', hex: PAYMENT_PUB + STAKE_PUB }, CARDANO_PREPROD),
    ).toBe(SENDER);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: PAYMENT_PUB }, CARDANO_PREPROD),
    ).toThrow();
  });

  it('matches the CIP-19 vectors', () => {
    const words = (s: string) =>
      bech32.fromWords(bech32.decode(s as `${string}1${string}`, 1023).words);
    const pay = words(CIP19_PAYMENT_VK);
    const stake = words(CIP19_STAKE_VK);
    expect(cardanoAddressFromPublicKey(pay)).toBe(CIP19_ENTERPRISE);
    expect(cardanoAddressFromPublicKey(Uint8Array.from([...pay, ...stake]))).toBe(RECIPIENT);
    expect(hex(cardanoAddressBytes(RECIPIENT)!.payment)).toBe(
      hex(cardanoAddressBytes(CIP19_ENTERPRISE)!.payment),
    );
  });

  it('refuses other networks, scripts, Byron and non-canonical spellings', () => {
    expect(isValidCardanoAddress(SENDER)).toBe(true);
    expect(isValidCardanoAddress(SENDER_MAINNET)).toBe(false);
    expect(isValidCardanoAddress(SENDER_MAINNET, CARDANO_MAINNET)).toBe(true);
    expect(isValidCardanoAddress(SENDER, CARDANO_MAINNET)).toBe(false);
    expect(isValidCardanoAddress(SENDER.toUpperCase())).toBe(false);
    expect(isValidCardanoAddress(`${SENDER.slice(0, -1)}q`)).toBe(false);
    const script = bech32.encode(
      'addr_test',
      bech32.toWords(Uint8Array.from([0x70, ...new Uint8Array(28)])),
      1023,
    );
    expect(isValidCardanoAddress(script)).toBe(false);
    const wrongNet = bech32.encode(
      'addr_test',
      bech32.toWords(Uint8Array.from([0x61, ...new Uint8Array(28)])),
      1023,
    );
    expect(isValidCardanoAddress(wrongNet)).toBe(false);
    expect(
      isValidCardanoAddress('Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi'),
    ).toBe(false);
    expect(endpointKind(OGMIOS)).toBe('ogmios');
    expect(endpointKind(INDEXER)).toBe('indexer');
  });
});

describe('transaction encoding', () => {
  it('pins the same body, id and signed bytes as the SDK and the core', () => {
    expect(hex(cardanoTxBody(tx))).toBe(CHANGE_BODY);
    expect(cardanoTxId(tx)).toBe(CHANGE_TXID);
    expect(cardanoChange(tx)).toBe(8_330_011n);
    const max = { ...tx, lovelace: '9832871', fee: 167_129 };
    expect(hex(cardanoTxBody(max))).toBe(MAX_BODY);
    expect(cardanoTxId(max)).toBe(MAX_TXID);
  });

  it('refuses what the core refuses', () => {
    const bad: Partial<CardanoTx>[] = [
      { fee: 169_988 },
      { fee: 1_000_001 },
      { lovelace: '969749' },
      { lovelace: '9000000' },
      { lovelace: '01500000' },
      { lovelace: '9832872', fee: 167_129 },
      { inputs: [...tx.inputs].reverse() },
      { inputs: [tx.inputs[0]!, tx.inputs[0]!] },
      { to: SENDER },
      { ttl: tx.builtSlot },
      { ttl: tx.builtSlot + 86_401 },
      { to: SENDER_MAINNET },
      { chainId: CARDANO_MAINNET as typeof CARDANO_PREPROD },
    ];
    for (const b of bad) expect(() => cardanoTxBody({ ...tx, ...b }), JSON.stringify(b)).toThrow();
    expect(() => CardanoTx.parse({ ...tx, memo: 'x' })).toThrow();
    expect(hex(cardanoTxBody({ ...tx, lovelace: '969750' })).length).toBeGreaterThan(0);
  });
});

describe('selection', () => {
  const utxos = [
    utxo('11'.repeat(32), 0, '4000000'),
    utxo('22'.repeat(32), 3, '6000000'),
    utxo('33'.repeat(32), 0, '50000000', { assets: [{ policyId: 'x' }] }),
    utxo('44'.repeat(32), 0, '50000000', { receiver: SENDER_ENTERPRISE }),
  ];

  it('takes the largest ADA-only UTxOs and pays the protocol minimum fee', () => {
    const one = selectInputs(utxos, SENDER, RECIPIENT, 1_500_000n, PARAMS, 90_000_000);
    expect(one.inputs).toEqual([{ txHash: '22'.repeat(32), index: 3, lovelace: '6000000' }]);
    const two = selectInputs(utxos, SENDER, RECIPIENT, 8_000_000n, PARAMS, 90_000_000);
    expect(two.inputs.map((i) => i.txHash)).toEqual(['11'.repeat(32), '22'.repeat(32)]);
    expect(two.fee).toBe(169_989);
    for (const s of [one, two])
      cardanoTxBody({
        ...tx,
        lovelace: s === one ? '1500000' : '8000000',
        inputs: s.inputs,
        fee: s.fee,
      });
    expect(() => selectInputs(utxos, SENDER, RECIPIENT, 10_000_000n, PARAMS, 90_000_000)).toThrow();
    expect(() => selectInputs(utxos, SENDER, RECIPIENT, 900_000n, PARAMS, 90_000_000)).toThrow(
      /at least/,
    );
  });

  it('pays a remainder too small for change as fee', () => {
    const s = selectInputs(
      [utxo('11'.repeat(32), 0, '2000000')],
      SENDER,
      RECIPIENT,
      1_800_000n,
      PARAMS,
      90_000_000,
    );
    expect(s.change).toBe(0n);
    expect(s.fee).toBe(200_000);
    expect(s.absorbed).toBeGreaterThan(0n);
    cardanoTxBody({ ...tx, lovelace: '1800000', inputs: s.inputs, fee: s.fee });
  });

  it('computes the send-max amount of the SDK vector', () => {
    expect(cardanoMaxSendable(utxos, SENDER, RECIPIENT, PARAMS, 90_000_000)).toBe(9_832_871n);
  });
});

describe('adapter and send flow', () => {
  it('prepares a transfer the core accepts', async () => {
    const { a } = adapter({
      slot: 89_992_800,
      utxos: [utxo('11'.repeat(32), 0, '4000000'), utxo('22'.repeat(32), 3, '6000000')],
    });
    const { unsigned, simulation } = await prepareCardano(a, intent('8000000'), SENDER);
    expect(unsigned).toEqual({ ...tx, lovelace: '8000000' });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('169989');
    await expect(
      prepareCardano(a, { ...intent('1'), chainId: CARDANO_MAINNET } as TxIntent, SENDER),
    ).rejects.toThrow();
  });

  it('checks approval against the tip and the live inputs', async () => {
    const live = [utxo('11'.repeat(32), 0, '4000000'), utxo('22'.repeat(32), 3, '6000000')];
    expect(await cardanoApprovalValid(adapter({ slot: 89_992_800, utxos: live }).a, tx)).toBe(true);
    expect(await cardanoApprovalValid(adapter({ slot: tx.ttl - 100, utxos: live }).a, tx)).toBe(
      false,
    );
    expect(
      await cardanoApprovalValid(adapter({ slot: 89_992_800, utxos: live.slice(1) }).a, tx),
    ).toBe(false);
  });

  it('broadcasts only the exact signed transaction', async () => {
    const ok = { jsonrpc: '2.0', result: { transaction: { id: CHANGE_TXID } }, id: 1 };
    const { a, calls } = adapter({ slot: 1, utxos: [], submit: ok });
    expect(await broadcastCardano(a, tx, `0x${CHANGE_TX}`)).toBe(CHANGE_TXID);
    const submitted = calls.find(
      (c) => (c.body as { method?: string })?.method === 'submitTransaction',
    );
    expect(submitted?.body).toMatchObject({ params: { transaction: { cbor: CHANGE_TX } } });

    const sigAt = CHANGE_TX.length - 4 - 2;
    const flipped = `${CHANGE_TX.slice(0, sigAt)}${CHANGE_TX[sigAt] === '0' ? '1' : '0'}${CHANGE_TX.slice(sigAt + 1)}`;
    await expect(broadcastCardano(a, tx, flipped)).rejects.toThrow(/Signature/);
    await expect(broadcastCardano(a, { ...tx, fee: 170_000 }, CHANGE_TX)).rejects.toThrow(
      /not this ADA/,
    );
    await expect(broadcastCardano(a, tx, `${CHANGE_TX}00`)).rejects.toThrow(/not this ADA/);

    const other = adapter({
      slot: 1,
      utxos: [],
      submit: { ...ok, result: { transaction: { id: 'ab'.repeat(32) } } },
    });
    await expect(broadcastCardano(other.a, tx, CHANGE_TX)).rejects.toThrow(/different/);

    const spent = {
      jsonrpc: '2.0',
      error: { code: 3117, message: 'unknown output references' },
      id: 1,
    };
    const confirmed = {
      hash: CHANGE_TXID,
      tx_state: 'Successful',
      block_num: 7,
      time: '2026-10-16T00:00:00.000Z',
      inputs: [],
      outputs: [],
    };
    const retry = adapter({
      slot: 1,
      utxos: [],
      submit: spent,
      submitStatus: 400,
      txs: { [CHANGE_TXID]: confirmed },
    });
    expect(await broadcastCardano(retry.a, tx, CHANGE_TX)).toBe(CHANGE_TXID);
    const rejected = adapter({
      slot: 1,
      utxos: [],
      submit: { ...spent, error: { code: 3123, message: 'value not conserved' } },
      submitStatus: 400,
    });
    await expect(broadcastCardano(rejected.a, tx, CHANGE_TX)).rejects.toThrow(/3123/);
  });

  it('reports confirmed, pending and expired transfers', async () => {
    const live = [utxo('11'.repeat(32), 0, '4000000'), utxo('22'.repeat(32), 3, '6000000')];
    const confirmed = {
      hash: CHANGE_TXID,
      tx_state: 'Successful',
      block_num: 7,
      time: '2026-10-16T00:00:00.000Z',
      inputs: [],
      outputs: [],
    };
    expect(
      await cardanoTransferStatus(
        adapter({ slot: 1, utxos: live, txs: { [CHANGE_TXID]: confirmed } }).a,
        tx,
        CHANGE_TXID,
      ),
    ).toMatchObject({ state: 'confirmed', blockNumber: 7 });
    expect(
      await cardanoTransferStatus(adapter({ slot: 89_995_000, utxos: live }).a, tx, CHANGE_TXID),
    ).toEqual({ state: 'unknown' });
    expect(
      await cardanoTransferStatus(adapter({ slot: tx.ttl + 1, utxos: live }).a, tx, CHANGE_TXID),
    ).toEqual({ state: 'expired' });
    expect(
      await cardanoTransferStatus(
        adapter({ slot: 89_995_000, utxos: live.slice(1) }).a,
        tx,
        CHANGE_TXID,
      ),
    ).toEqual({ state: 'expired' });
  });

  it('reads balances and history after the endpoint proves its network', async () => {
    const live = [utxo('11'.repeat(32), 0, '4000000'), utxo('22'.repeat(32), 3, '6000000')];
    const history = [
      {
        hash: CHANGE_TXID,
        fee: '169989',
        tx_state: 'Successful',
        block_num: 9,
        block_hash: 'cd'.repeat(32),
        time: '2026-10-16T00:00:00.000Z',
        inputs: [{ address: SENDER, amount: '10000000', assets: [] }],
        outputs: [
          { address: RECIPIENT, amount: '1500000', assets: [] },
          { address: SENDER, amount: '8330011', assets: [] },
        ],
      },
    ];
    const { a } = adapter({ slot: 1, utxos: live, history });
    const [h] = await a.getBalances(SENDER, CARDANO_PREPROD);
    expect(h).toMatchObject({
      assetRef: `${CARDANO_PREPROD}:native`,
      amount: '10000000',
      provenance: { kind: 'single', endpoint: INDEXER },
    });
    const page = await a.getHistory(SENDER, CARDANO_PREPROD);
    expect(page.items[0]).toMatchObject({
      hash: CHANGE_TXID,
      from: SENDER,
      to: RECIPIENT,
      fee: '169989',
      status: 'confirmed',
      blockNumber: 9,
      assetDeltas: [{ amount: '-1669989' }],
    });
    expect(page.nextCursor).toBeUndefined();
    await expect(a.getHistory(SENDER, CARDANO_PREPROD, 'nope')).rejects.toThrow();

    const wrong = adapter({ slot: 1, utxos: live, anchor: 'ee'.repeat(32) });
    await expect(wrong.a.getBalances(SENDER, CARDANO_PREPROD)).rejects.toBeInstanceOf(
      RpcFailoverError,
    );
    const wrongMagic = adapter({ slot: 1, utxos: live, magic: 764824073 });
    await expect(wrongMagic.a.protocolParams(CARDANO_PREPROD)).rejects.toBeInstanceOf(
      RpcFailoverError,
    );
    expect(await adapter({ slot: 1, utxos: live }).a.protocolParams(CARDANO_PREPROD)).toEqual(
      PARAMS,
    );
  });
});
