import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MemoryRpcPool, chainsForFamily, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  OBYTE_TESTNET,
  ObyteAdapter,
  ObyteInput,
  ObyteTx,
  base32Decode,
  base32Encode,
  base64Encode,
  buildUnit,
  chash160,
  computeCommissions,
  createObyteAdapter,
  isValidObyteAddress,
  jsonSourceString,
  obyteAddressFromPublicKey,
  unitId,
  unitSighashHex,
} from './obyte.js';
import { broadcastObyte, obyteApprovalValid, obyteTransferStatus, prepareObyte } from './send.js';
import type { ObyteHubTransport } from './obyte.js';

// Keys 0x0a…/0x0b… match the Rust core tests; every vector below was produced
// by the vendored ocore oracle (.nur/obyte-oracle) with native secp256k1.
const SECRET_A = Uint8Array.from({ length: 32 }, () => 0x0a);
const SECRET_B = Uint8Array.from({ length: 32 }, () => 0x0b);
const PUB_A = secp256k1.getPublicKey(SECRET_A, true);
const PUB_B = secp256k1.getPublicKey(SECRET_B, true);
const ADDR_A = 'CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B';
const ADDR_B = 'JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ';
const PUB_A_B64 = 'A/dqOdBWhuNKRCCJfjWTcYNhRd05c+OYJWi2D4Qzrd5u';
const PUB_B_B64 = 'AlUsYwtktUv1AhDJ4lPTi9SUnHLiKHNQD2KFwr7eMSqE';

const PARENT_1 = 'PwPxpfwrYPDQfYuicOFTVkIiKLfdIOHRRgiUPAmBEXk=';
const PARENT_2 = 'kiDPph+cb8xgtphZHAif409MRyYlp8DmKaVCfnCuUgc=';
const LAST_BALL = 'qUfV9bnmLQLiApJ3vWI5Gl/L7NVjsziHiLD2sappBa4=';
const LAST_BALL_UNIT = 'mYm62exZUBgCYPdOHBBhEg6JNIuWDqAv/vGE/+jkd8A=';
const INPUT_UNIT = 'zdr7KkULWJyBVwuXZDHybnbb/F3Q5byBwVlxgrL1mkU=';
const TESTNET_GENESIS = 'TvqutGPz3T4Cs6oiChxFlclY92M2MvCvfXR5/FETato=';

const V1_WIRE =
  '{"unit":{"alt":"2","authors":[{"address":"CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B","authentifiers":{"r":"K10wN1JJZMAnCysII9gdqeDj5EG2E916H+aTFbrXEn8gilMOR/KZTUmKl00vraVRtWJP0mXYrOrCy4e1Rf1Raw=="},"definition":["sig",{"pubkey":"A/dqOdBWhuNKRCCJfjWTcYNhRd05c+OYJWi2D4Qzrd5u"}]}],"headers_commission":469,"last_ball":"qUfV9bnmLQLiApJ3vWI5Gl/L7NVjsziHiLD2sappBa4=","last_ball_unit":"mYm62exZUBgCYPdOHBBhEg6JNIuWDqAv/vGE/+jkd8A=","messages":[{"app":"payment","payload":{"inputs":[{"message_index":0,"output_index":0,"unit":"zdr7KkULWJyBVwuXZDHybnbb/F3Q5byBwVlxgrL1mkU="}],"outputs":[{"address":"CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B","amount":1476},{"address":"JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ","amount":1000}]},"payload_hash":"QNa67aASnpOaNnhiSVLCSmw1TcxMu4nbjAgQbfkd8R4=","payload_location":"inline"}],"parent_units":["PwPxpfwrYPDQfYuicOFTVkIiKLfdIOHRRgiUPAmBEXk=","kiDPph+cb8xgtphZHAif409MRyYlp8DmKaVCfnCuUgc="],"payload_commission":311,"timestamp":1792194192,"tps_fee":0,"unit":"HPyRHXyVdRL9AVvtXNIVbXlUj/AkWhySLVaNd+/i5BY=","version":"4.0t"}}';
const V2_WIRE =
  '{"unit":{"alt":"2","authors":[{"address":"JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ","authentifiers":{"r":"SYLnnwcR7G/G6H5Gpj0qgjZDLYkEevLis6he0bVEpRInvnqhgrP0rGDMev6dGM9qMm/jLagHzArlFPxusL/s0Q=="}}],"headers_commission":406,"last_ball":"qUfV9bnmLQLiApJ3vWI5Gl/L7NVjsziHiLD2sappBa4=","last_ball_unit":"mYm62exZUBgCYPdOHBBhEg6JNIuWDqAv/vGE/+jkd8A=","messages":[{"app":"payment","payload":{"inputs":[{"message_index":0,"output_index":1,"unit":"zdr7KkULWJyBVwuXZDHybnbb/F3Q5byBwVlxgrL1mkU="},{"message_index":2,"output_index":0,"unit":"PwPxpfwrYPDQfYuicOFTVkIiKLfdIOHRRgiUPAmBEXk="}],"outputs":[{"address":"CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B","amount":50},{"address":"JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ","amount":841}]},"payload_hash":"5iTCXtL8Sbu7p1XhmklP/aWZPwfmzmHgCsBNfuudE50=","payload_location":"inline"}],"parent_units":["kiDPph+cb8xgtphZHAif409MRyYlp8DmKaVCfnCuUgc="],"payload_commission":400,"timestamp":1792200001,"tps_fee":3,"unit":"kOfHH88PZQA09EeNDefrFmJlQljfLLsuyLeYKMKG2Ts=","version":"4.0t"}}';

function txV1(): ObyteTx {
  return ObyteTx.parse({
    chainId: OBYTE_TESTNET,
    from: ADDR_A,
    authorPubkey: PUB_A_B64,
    to: ADDR_B,
    bytes: '1000',
    timestamp: 1792194192,
    tpsFee: 0,
    parentUnits: [PARENT_1, PARENT_2],
    lastBall: LAST_BALL,
    lastBallUnit: LAST_BALL_UNIT,
    inputs: [
      ObyteInput.parse({ unit: INPUT_UNIT, messageIndex: 0, outputIndex: 0, amount: '3256' }),
    ],
    firstUnit: true,
  });
}

function txV2(): ObyteTx {
  return ObyteTx.parse({
    chainId: OBYTE_TESTNET,
    from: ADDR_B,
    authorPubkey: PUB_B_B64,
    to: ADDR_A,
    bytes: '50',
    timestamp: 1792200001,
    tpsFee: 3,
    parentUnits: [PARENT_2],
    lastBall: LAST_BALL,
    lastBallUnit: LAST_BALL_UNIT,
    inputs: [
      ObyteInput.parse({ unit: INPUT_UNIT, messageIndex: 0, outputIndex: 1, amount: '1000' }),
      ObyteInput.parse({ unit: PARENT_1, messageIndex: 2, outputIndex: 0, amount: '700' }),
    ],
    firstUnit: false,
  });
}

/** Sign exactly like the core: RFC6979 over the unit hash, no extra prehash. */
function signWire(unsigned: ObyteTx, secret: Uint8Array): { wire: string; id: string } {
  const sighash = unitSighashHex(unsigned);
  const sig = secp256k1.sign(Buffer.from(sighash, 'hex'), secret, { prehash: false, lowS: true });
  const unit = buildUnit(unsigned, base64Encode(sig instanceof Uint8Array ? sig : sig));
  const id = unitId(unit);
  const wire = `{"unit":${jsonSourceString({ ...unit, unit: id })}}`;
  return { wire, id };
}

const CHAIN: ChainInfo = {
  chainId: OBYTE_TESTNET,
  family: 'obyte',
  name: 'Obyte Testnet',
  nativeAsset: { ref: `${OBYTE_TESTNET}:native`, symbol: 'GBYTE', decimals: 0 },
  testnet: true,
  explorerTxUrl: 'https://testnet.obyte.io/#{hash}',
  defaultRpcs: ['https://hub.test'],
  extra: { coinType: 592 },
  layer: 'L1',
};

function node(routes: Record<string, (body: Record<string, unknown>) => unknown>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.pathname);
    const route = routes[url.pathname];
    if (!route) return new Response('{}', { status: 404 });
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const out = route(body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapterWith(
  fetchImpl: typeof fetch,
  postJoint?: ObyteHubTransport['postJoint'],
): ObyteAdapter {
  return createObyteAdapter({
    fetch: fetchImpl,
    rpc: new MemoryRpcPool([CHAIN]),
    hub: async () => ({
      postJoint: postJoint ?? (async () => 'accepted'),
      close: () => {},
    }),
  });
}

const genesisRoute = {
  '/api/get_joint': (body: Record<string, unknown>) => {
    if (body.unit === TESTNET_GENESIS)
      return {
        data: {
          joint: {
            unit: {
              version: '4.0t',
              alt: '2',
              authors: [{ address: ADDR_A, authentifiers: { r: 'x'.repeat(88) } }],
            },
          },
        },
      };
    return { error: 'joint not found' };
  },
};

describe('obyte addresses', () => {
  it('derives the same addresses as the Rust core', () => {
    expect(obyteAddressFromPublicKey(PUB_A)).toBe(ADDR_A);
    expect(obyteAddressFromPublicKey(PUB_B)).toBe(ADDR_B);
    const a = adapterWith(node(genesisRoute).fetchImpl);
    expect(a.deriveAddress({ curve: 'secp256k1', hex: bytesToHex(PUB_A) }, OBYTE_TESTNET)).toBe(
      ADDR_A,
    );
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, OBYTE_TESTNET),
    ).toThrow();
  });

  it('validates checksums and casing', () => {
    expect(isValidObyteAddress(ADDR_A)).toBe(true);
    // Live testnet witness addresses (checked against ocore).
    expect(isValidObyteAddress('2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX')).toBe(true);
    expect(isValidObyteAddress('2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7')).toBe(true);
    expect(isValidObyteAddress('2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GA')).toBe(false);
    expect(isValidObyteAddress(ADDR_A.toLowerCase())).toBe(false);
    expect(isValidObyteAddress('SHORT')).toBe(false);
  });

  it('base32 round-trips', () => {
    const bytes = base32Decode(ADDR_A)!;
    expect(base32Encode(bytes)).toBe(ADDR_A);
    expect(base32Decode('aaaa')).toBeUndefined();
  });

  it('chash160 matches the published witness address', () => {
    const source = legacyDef('AqYvfx6o4sFL4qXVaBPUKMMpYkk8dYI9OFaT7N6RhGPq');
    expect(chash160(source)).toBe('2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX');
  });
});

function legacyDef(pubkey: string): string {
  // "s\x00sig\x00[\x00s\x00sig..." — ocore legacy source of ["sig",{pubkey}]
  const components: string[] = [];
  components.push('[');
  components.push('s', 'sig');
  components.push('pubkey', 's', pubkey);
  components.push(']');
  return components.join('\x00');
}

describe('obyte unit construction', () => {
  it('matches the ocore oracle vectors byte-exactly', () => {
    const v1 = txV1();
    const c1 = computeCommissions(v1);
    expect(c1.headers).toBe(469);
    expect(c1.payload).toBe(311);
    expect(c1.change).toBe(1476n);
    expect(unitSighashHex(v1)).toBe(
      'b53bc529d95704096f28a70d7a76ca370fe14a8a109972d640865d91ce040a61',
    );
    const s1 = signWire(v1, SECRET_A);
    expect(s1.id).toBe('HPyRHXyVdRL9AVvtXNIVbXlUj/AkWhySLVaNd+/i5BY=');
    expect(s1.wire).toBe(V1_WIRE);

    const v2 = txV2();
    const c2 = computeCommissions(v2);
    expect(c2.headers).toBe(406);
    expect(c2.payload).toBe(400);
    expect(unitSighashHex(v2)).toBe(
      '2eeccc6ff07ca7c1a237e24779c2cd7ddcd3b4a9c0d6ba6e7bb9c99a38fa3dfb',
    );
    const s2 = signWire(v2, SECRET_B);
    expect(s2.id).toBe('kOfHH88PZQA09EeNDefrFmJlQljfLLsuyLeYKMKG2Ts=');
    expect(s2.wire).toBe(V2_WIRE);
  });

  it('refuses hostile fields', () => {
    expect(() => txV1().bytes && ObyteTx.parse({ ...txV1(), bytes: '0' })).toThrow();
    expect(() => ObyteTx.parse({ ...txV1(), bytes: '01000' })).toThrow();
    expect(() => ObyteTx.parse({ ...txV1(), bytes: '9000000000000001' })).toThrow();
    expect(() => ObyteTx.parse({ ...txV1(), to: ADDR_A.toLowerCase() })).toThrow();
    expect(() => ObyteTx.parse({ ...txV1(), parentUnits: [] })).toThrow();
    expect(() => ObyteTx.parse({ ...txV1(), inputs: [] })).toThrow();
    expect(() =>
      buildUnit({ ...txV1(), inputs: [{ ...txV1().inputs[0]!, amount: '1500' }] }, ''),
    ).toThrow();
  });
});

describe('obyte adapter reads', () => {
  it('proves the network via the genesis joint and reads balances', async () => {
    const { fetchImpl } = node({
      ...genesisRoute,
      '/api/light/get_balances': () => ({
        data: {
          [ADDR_A]: { base: { stable: 5000, pending: 17, total: 5017 } },
        },
      }),
    });
    const adapter = adapterWith(fetchImpl);
    const holdings = await adapter.getBalances(ADDR_A, OBYTE_TESTNET);
    expect(holdings[0]!.amount).toBe('5000');
    expect(holdings[0]!.notice).toContain('17');
  });

  it('rejects an endpoint serving the wrong network', async () => {
    const { fetchImpl } = node({
      '/api/get_joint': () => ({
        data: {
          joint: {
            unit: { version: '4.0', alt: '1', authors: [{ address: ADDR_A, authentifiers: {} }] },
          },
        },
      }),
      '/api/light/get_balances': () => ({ data: {} }),
    });
    const adapter = adapterWith(fetchImpl);
    await expect(adapter.getBalances(ADDR_A, OBYTE_TESTNET)).rejects.toThrow();
  });

  it('maps unit status from get_joint', async () => {
    const joint = (ball?: string) => ({
      data: {
        joint: {
          unit: {
            version: '4.0t',
            alt: '2',
            authors: [{ address: ADDR_A, authentifiers: { r: 'x'.repeat(88) } }],
            main_chain_index: 123,
            timestamp: 1792194192,
          },
          ...(ball ? { ball } : {}),
        },
      },
    });
    const confirmed = adapterWith(
      node({
        '/api/get_joint': (body) =>
          body.unit === TESTNET_GENESIS
            ? genesisRoute['/api/get_joint']!(body)
            : joint('b'.repeat(43) + '='),
      }).fetchImpl,
    );
    expect(await confirmed.status('A'.repeat(43) + '=', OBYTE_TESTNET)).toEqual({
      state: 'confirmed',
      blockNumber: 123,
      timestampMs: 1792194192000,
    });
    const pending = adapterWith(
      node({
        '/api/get_joint': (body) =>
          body.unit === TESTNET_GENESIS
            ? genesisRoute['/api/get_joint']!(body)
            : body.unit === 'A'.repeat(43) + '='
              ? joint()
              : { error: 'joint not found' },
      }).fetchImpl,
    );
    expect((await pending.status('A'.repeat(43) + '=', OBYTE_TESTNET)).state).toBe('pending');
    expect((await pending.status('B'.repeat(43) + '=', OBYTE_TESTNET)).state).toBe('unknown');
  });

  it('reads history joints and maps payment messages', async () => {
    const paymentUnit = (from: string, to: string, amount: number, ball?: string) => ({
      unit: {
        version: '4.0t',
        alt: '2',
        timestamp: 1792194192,
        main_chain_index: 99,
        unit: 'C'.repeat(43) + '=',
        authors: [{ address: from, authentifiers: { r: 'x'.repeat(88) } }],
        messages: [
          {
            app: 'payment',
            payload_location: 'inline',
            payload_hash: 'D'.repeat(43) + '=',
            payload: { outputs: [{ address: to, amount }] },
          },
        ],
      },
      ...(ball ? { ball } : {}),
    });
    const { fetchImpl } = node({
      ...genesisRoute,
      '/api/get_witnesses': () => ({ data: [ADDR_A] }),
      '/api/light/get_history': () => ({
        data: { joints: [paymentUnit(ADDR_B, ADDR_A, 700, 'E'.repeat(43) + '=')] },
      }),
    });
    const adapter = adapterWith(fetchImpl);
    const page = await adapter.getHistory(ADDR_A, OBYTE_TESTNET);
    expect(page.items).toHaveLength(1);
    expect(page.items[0]).toMatchObject({
      from: ADDR_B,
      to: ADDR_B,
      status: 'confirmed',
      blockNumber: 99,
      timestampMs: 1792194192000,
    });
    expect(page.items[0]!.assetDeltas[0]!.amount).toBe('700');
  });
});

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'i',
    walletId: 'w',
    accountId: 'a',
    chainId: OBYTE_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${OBYTE_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  };
}

const PARENTS_RESPONSE = {
  data: {
    timestamp: 1792194192,
    parent_units: [PARENT_1, PARENT_2],
    last_stable_mc_ball: LAST_BALL,
    last_stable_mc_ball_unit: LAST_BALL_UNIT,
    last_stable_mc_ball_mci: 3985249,
    tps_fee: 0,
  },
};

function inputUnitJoint(amount: number) {
  return {
    data: {
      joint: {
        unit: {
          authors: [{ address: ADDR_A }],
          messages: [
            {
              app: 'payment',
              payload: { outputs: [{ address: ADDR_A, amount }] },
            },
          ],
        },
      },
    },
  };
}

describe('obyte send flow', () => {
  function prepareAdapter(definition: unknown = null) {
    return adapterWith(
      node({
        ...genesisRoute,
        '/api/light/get_definition': () =>
          definition === null ? { error: 'no definition' } : { data: definition },
        '/api/light/get_parents_and_last_ball_and_witness_list_unit': () => PARENTS_RESPONSE,
        '/api/light/pick_divisible_coins_for_amount': () => ({
          data: {
            inputs_with_proofs: [
              { input: { unit: INPUT_UNIT, message_index: 0, output_index: 0 } },
            ],
            total_amount: 100000,
          },
        }),
        '/api/get_joint': (body: Record<string, unknown>) =>
          body.unit === TESTNET_GENESIS
            ? genesisRoute['/api/get_joint']!(body)
            : inputUnitJoint(100000),
      }).fetchImpl,
    );
  }

  it('prepares a first spend with the embedded definition', async () => {
    const adapter = prepareAdapter(null);
    const { unsigned, simulation } = await prepareObyte(
      adapter,
      intent(ADDR_B, '1000'),
      ADDR_A,
      PUB_A_B64,
    );
    expect(unsigned.firstUnit).toBe(true);
    expect(unsigned.timestamp).toBe(1792194192);
    expect(unsigned.parentUnits).toEqual([PARENT_1, PARENT_2]);
    expect(simulation.ok).toBe(true);
    // fees: 469 headers + 311 payload (definition embedded)
    expect(simulation.fee.amount).toBe('780');
    expect(computeCommissions(unsigned).change).toBe(98220n);
    expect(simulation.warnings[0]?.kind).toBe('other');
  });

  it('prepares a repeat spend without the definition', async () => {
    const adapter = prepareAdapter(['sig', { pubkey: PUB_A_B64 }]);
    const { unsigned, simulation } = await prepareObyte(
      adapter,
      intent(ADDR_B, '1000'),
      ADDR_A,
      PUB_A_B64,
    );
    expect(unsigned.firstUnit).toBe(false);
    expect(simulation.ok).toBe(true);
    expect(simulation.warnings).toHaveLength(0);
    // no definition: 406 headers + 311 payload
    expect(simulation.fee.amount).toBe('717');
  });

  it('rejects a public key that does not own the from address', async () => {
    const adapter = prepareAdapter();
    await expect(prepareObyte(adapter, intent(ADDR_B, '1000'), ADDR_A, PUB_B_B64)).rejects.toThrow(
      /derive the from address/,
    );
  });

  it('approval stays valid while the hub clock is close', async () => {
    const adapter = prepareAdapter();
    const unsigned = txV1();
    await expect(obyteApprovalValid(adapter, unsigned)).resolves.toBe(true);
    // a timestamp far in the hub's future is refused
    await expect(
      obyteApprovalValid(adapter, { ...unsigned, timestamp: 1792194192 + 1000 }),
    ).resolves.toBe(false);
    // a timestamp stale by more than a day is refused
    await expect(
      obyteApprovalValid(adapter, { ...unsigned, timestamp: 1792194192 - 90_000 }),
    ).resolves.toBe(false);
  });

  it('broadcasts only a wire that matches the unsigned tx with a valid signature', async () => {
    const posted: unknown[] = [];
    const unsigned = txV1();
    const { wire, id } = signWire(unsigned, SECRET_A);
    const adapterB = adapterWith(node(genesisRoute).fetchImpl, async (joint) => {
      posted.push(joint);
      return 'accepted';
    });
    await expect(broadcastObyte(adapterB, unsigned, wire)).resolves.toBe(id);
    expect(posted).toHaveLength(1);

    // tampered amount
    const tampered = wire.replace('"amount":1000', '"amount":1001');
    await expect(broadcastObyte(adapterB, unsigned, tampered)).rejects.toThrow(/differs/);
    // wrong-key signature
    const { wire: wrongSig } = signWire(unsigned, SECRET_B);
    await expect(broadcastObyte(adapterB, unsigned, wrongSig)).rejects.toThrow(/verify/);
    // not JSON
    await expect(broadcastObyte(adapterB, unsigned, 'nope')).rejects.toThrow(/JSON/);
  });

  it('surfaces hub broadcast errors', async () => {
    const adapter = adapterWith(node(genesisRoute).fetchImpl, async () => ({
      error: 'bad signature at path r',
    }));
    const unsigned = txV1();
    const { wire } = signWire(unsigned, SECRET_A);
    await expect(broadcastObyte(adapter, unsigned, wire)).rejects.toThrow(/Broadcast rejected/);
  });

  it('reports transfer status through the adapter', async () => {
    const adapter = adapterWith(
      node({
        '/api/get_joint': (body) =>
          body.unit === TESTNET_GENESIS
            ? genesisRoute['/api/get_joint']!(body)
            : { error: 'joint not found' },
      }).fetchImpl,
    );
    await expect(obyteTransferStatus(adapter, txV1(), 'A'.repeat(43) + '=')).resolves.toEqual({
      state: 'unknown',
    });
  });
});
