import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  TezosTx,
  broadcastTezos,
  forgeTezos,
  prepareTezos,
  tezosApprovalValid,
  tezosOperationHash,
  tezosSigningDigest,
  tezosTransferStatus,
} from './send.js';
import {
  NETWORKS,
  TEZOS_MAINNET,
  TEZOS_SHADOWNET,
  TezosAdapter,
  isValidTezosAddress,
  tezosAddressBytes,
  tezosAddressFromPublicKey,
} from './tezos.js';

const SEED = new Uint8Array(32).fill(7);
const PUBLIC = ed25519.getPublicKey(SEED);
const PUBLIC_HEX = bytesToHex(PUBLIC);
// Taquito 25.0.0 vectors (`.nur/tezos-sdk/vector.mjs`); the Shadownet node's
// forge RPC reproduced the same bytes, and the Rust core pins them too.
const SENDER = 'tz1Qr9uevaimfiPS6X1otehsKrwvZjX7bsyL';
const RECIPIENT = 'tz1fRryceCL4hCAGhoKiNm8oUqA54ZBFuHGV';
const TZ2 = 'tz29sUbQkQxxNVXNWmxepLyN4L4iStKf9x8Y';
const TZ3 = 'tz3PSXUovu1WTaZmUWSCuTPkMorvqWdNEYHV';
const TZ4 = 'tz4DfyP6p6Lt5nnjJ9tLfFL1PW2dyCE5VeGs';
const KT1 = 'KT1EojJ4VZAAd3rt3vRTTXb9ofsRWwL2Q56G';
const BRANCH = 'BKnG8VoprFn4jYo8qWdGo3LGwpV9xqtqyb4deycpahXkr3C6drE';
const REVEAL_TRANSFER =
  '09090909090909090909090909090909090909090909090909090909090909096b003923a4e9144201ffcc3d4ac891d14a14df438c52f602cec2f105e8070000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c006c003923a4e9144201ffcc3d4ac891d14a14df438c52c203cfc2f105a9019502e0c65b0000d91569fa225ce7ef4d794d706cab5f1c18f7d0da00';
const REVEAL_TRANSFER_SIG =
  'dd44ee8fdcff3ea4ff91ca1b5df81a8ae784f2f4d754a7338c13b328b58cbf4bd734b5b022afca3ec3a78bb9c7777ef7e9e22ea9cfb82dda22e6a2f75fa6b10a';
const REVEAL_TRANSFER_HASH = 'onrstUdQcArgPF85uKfE3yY7QSUF1W8UAL16rudLxG63okS6Zqv';

const tx: TezosTx = {
  chainId: TEZOS_SHADOWNET,
  from: SENDER,
  to: RECIPIENT,
  mutez: '1500000',
  branch: BRANCH,
  counter: 12_345_678,
  fee: 450,
  gasLimit: 169,
  storageLimit: 277,
  reveal: { fee: 374, gasLimit: 1000 },
};

const RPC = 'https://rpc.shadow.test';
const TZKT = 'https://tzkt.shadow.test';
const MAIN_RPC = 'https://rpc.mainone.test';
const MAIN_RPC2 = 'https://rpc.maintwo.test';

function chain(chainId: string, rpcs: string[], testnet: boolean): ChainInfo {
  return {
    chainId,
    family: 'tezos',
    name: chainId,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'XTZ', decimals: 6 },
    testnet,
    defaultRpcs: rpcs,
  };
}
const CHAINS = [
  chain(TEZOS_MAINNET, [MAIN_RPC, MAIN_RPC2], false),
  chain(TEZOS_SHADOWNET, [RPC], true),
];

class TestAdapter extends TezosAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Route = (body: unknown) => unknown;
function node(routes: Record<string, Route>) {
  const calls: { url: string; body?: unknown }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const key = url.origin + url.pathname;
    const body = init?.body ? (JSON.parse(String(init.body)) as unknown) : undefined;
    calls.push({ url: url.href, ...(body !== undefined ? { body } : {}) });
    const route = routes[key];
    if (!route) return new Response('null', { status: 404 });
    const out = route(body);
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new TestAdapter({
    fetch: fetchImpl,
    rpc: new MemoryRpcPool(CHAINS),
    indexers: new MemoryRpcPool([
      chain(TEZOS_SHADOWNET, [TZKT], true),
      chain(TEZOS_MAINNET, ['https://tzkt.main.test'], false),
    ]),
  });
}

const intent = (to = RECIPIENT, amount = '1500000'): TxIntent =>
  ({
    id: 'i',
    walletId: 'w',
    accountId: 'a',
    chainId: TEZOS_SHADOWNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${TEZOS_SHADOWNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  }) as unknown as TxIntent;

const shadowChain = () => ({ [`${RPC}/chains/main/chain_id`]: () => 'NetXsqzbfFenSTS' });
const header = (level: number, hash = BRANCH) => ({
  hash,
  level,
  chain_id: 'NetXsqzbfFenSTS',
});

describe('tezos addresses', () => {
  it('derives the tz1 address Taquito derives', () => {
    expect(tezosAddressFromPublicKey(PUBLIC)).toBe(SENDER);
    expect(tezosAddressFromPublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(8)))).toBe(
      RECIPIENT,
    );
    const a = new TestAdapter();
    expect(a.deriveAddress({ curve: 'ed25519', hex: PUBLIC_HEX }, TEZOS_SHADOWNET)).toBe(SENDER);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, TEZOS_SHADOWNET),
    ).toThrow();
  });

  it('accepts canonical implicit addresses only', () => {
    for (const a of [SENDER, TZ2, TZ3, TZ4]) expect(isValidTezosAddress(a)).toBe(true);
    expect(tezosAddressBytes(TZ2)![0]).toBe(1);
    expect(tezosAddressBytes(TZ4)![0]).toBe(3);
    expect(isValidTezosAddress(KT1)).toBe(false);
    expect(isValidTezosAddress(SENDER.slice(0, -1) + 'M')).toBe(false);
    expect(isValidTezosAddress(SENDER.toLowerCase())).toBe(false);
    expect(isValidTezosAddress(`tz1${TZ2.slice(3)}`)).toBe(false);
    expect(isValidTezosAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false);
  });
});

describe('tezos forging', () => {
  it('forges, signs and hashes exactly like Taquito and the core', () => {
    const forged = forgeTezos(tx, PUBLIC);
    expect(bytesToHex(forged)).toBe(REVEAL_TRANSFER);
    const sig = ed25519.sign(tezosSigningDigest(forged), SEED);
    expect(bytesToHex(sig)).toBe(REVEAL_TRANSFER_SIG);
    expect(tezosOperationHash(Uint8Array.from([...forged, ...sig]))).toBe(REVEAL_TRANSFER_HASH);
  });

  it('reproduces the operation Shadownet included at level 5506037', () => {
    const live: TezosTx = {
      ...tx,
      mutez: '1000000',
      branch: 'BM37M44HghFhLuj4Rfx5YVTX3KhzqNRdiLYU4HfiVzcCnmNkDEX',
      counter: 33_463_037,
      fee: 550,
      gasLimit: 2201,
      storageLimit: 257,
      reveal: { fee: 128, gasLimit: 271 },
    };
    const forged = forgeTezos(live, PUBLIC);
    const sig = ed25519.sign(tezosSigningDigest(forged), SEED);
    expect(tezosOperationHash(Uint8Array.from([...forged, ...sig]))).toBe(
      'ooss2qoWjSUpyUr3U9vhceXRpJA1GdgG5jp4LP7o7L2k7ECyRXQ',
    );
  });

  it('forges transfers to tz2 and tz4 recipients like Taquito', () => {
    const tz2 = forgeTezos(
      {
        ...tx,
        to: TZ2,
        mutez: '9007199254740991',
        counter: 1,
        fee: 100_000,
        gasLimit: 10_000,
        storageLimit: 0,
        reveal: undefined,
      },
      PUBLIC,
    );
    expect(bytesToHex(tz2.subarray(32))).toBe(
      '6c003923a4e9144201ffcc3d4ac891d14a14df438c52a08d0601904e00ffffffffffffff0f0001111111111111111111111111111111111111111100',
    );
    const tz4 = forgeTezos(
      {
        ...tx,
        to: TZ4,
        mutez: '42',
        counter: 99,
        fee: 1000,
        gasLimit: 200,
        storageLimit: 300,
        reveal: undefined,
      },
      PUBLIC,
    );
    expect(bytesToHex(tz4.subarray(32))).toBe(
      '6c003923a4e9144201ffcc3d4ac891d14a14df438c52e80763c801ac022a0003333333333333333333333333333333333333333300',
    );
  });

  it('refuses hostile fields', () => {
    const bad: Partial<Record<keyof TezosTx | 'parameters', unknown>>[] = [
      { chainId: TEZOS_MAINNET },
      { chainId: 'tezos:NetXnHfVqm9iesp' },
      { mutez: '0' },
      { mutez: '01' },
      { mutez: '9223372036854775808' },
      { to: SENDER },
      { to: KT1 },
      { from: TZ2 },
      { branch: BRANCH.slice(0, -1) + 'F' },
      { counter: 0 },
      { fee: 99 },
      { fee: 100_001 },
      { gasLimit: 100_001 },
      { storageLimit: 1001 },
      { reveal: { fee: 374, gasLimit: 10_001 } },
      { reveal: { fee: 374, gasLimit: 1000, publicKey: 'edpk' } },
      { parameters: '00' },
    ];
    for (const patch of bad)
      expect(
        () => forgeTezos({ ...tx, ...patch } as TezosTx, PUBLIC),
        JSON.stringify(patch),
      ).toThrow();
    expect(() => forgeTezos(tx, ed25519.getPublicKey(new Uint8Array(32).fill(8)))).toThrow();
  });
});

describe('tezos reads', () => {
  it('refuses a node serving another network', async () => {
    const { fetchImpl } = node({
      [`${RPC}/chains/main/chain_id`]: () => 'NetXdQprcVkpaWU',
      [`${RPC}/chains/main/blocks/head/context/contracts/${SENDER}/balance`]: () => '5',
    });
    await expect(adapter(fetchImpl).getBalances(SENDER, TEZOS_SHADOWNET)).rejects.toThrow();
  });

  it('cross-checks mainnet balances across two nodes', async () => {
    const { fetchImpl } = node({
      [`${MAIN_RPC}/chains/main/chain_id`]: () => 'NetXdQprcVkpaWU',
      [`${MAIN_RPC2}/chains/main/chain_id`]: () => 'NetXdQprcVkpaWU',
      [`${MAIN_RPC}/chains/main/blocks/head/context/contracts/${SENDER}/balance`]: () =>
        '9223372036854775807',
      [`${MAIN_RPC2}/chains/main/blocks/head/context/contracts/${SENDER}/balance`]: () =>
        '9223372036854775807',
    });
    const [h] = await adapter(fetchImpl).getBalances(SENDER, TEZOS_MAINNET);
    expect(h!.amount).toBe('9223372036854775807');
    expect(h!.assetRef).toBe(`${TEZOS_MAINNET}:native`);
    expect(h!.provenance?.kind).toBe('agreed');
  });

  it('maps TzKT history with fees, burns and a lastId cursor', async () => {
    const op = (id: number, extra: Record<string, unknown>) => ({
      type: 'transaction',
      id,
      level: 100 + id,
      timestamp: '2026-10-16T12:06:51Z',
      hash: REVEAL_TRANSFER_HASH,
      sender: { address: SENDER },
      target: { address: RECIPIENT },
      amount: 1000,
      bakerFee: 491,
      storageFee: 0,
      allocationFee: 64250,
      status: 'applied',
      ...extra,
    });
    const { fetchImpl, calls } = node({
      [`${TZKT}/v1/head`]: () => ({ chainId: 'NetXsqzbfFenSTS', level: 1 }),
      [`${TZKT}/v1/accounts/${SENDER}/operations`]: () => [
        op(3, {}),
        op(2, { sender: { address: RECIPIENT }, target: { address: SENDER }, bakerFee: 400 }),
        op(1, { status: 'failed', allocationFee: 0 }),
        op(0, { type: 'reveal', target: null, amount: undefined, allocationFee: 0 }),
      ],
    });
    const page = await adapter(fetchImpl).getHistory(SENDER, TEZOS_SHADOWNET, '77');
    expect(calls.at(-1)!.url).toContain('lastId=77');
    expect(page.items.map((i) => [i.assetDeltas[0]?.amount, i.fee, i.status])).toEqual([
      ['-1000', '64741', 'confirmed'],
      ['1000', '0', 'confirmed'],
      ['0', '491', 'failed'],
      [undefined, '491', 'confirmed'],
    ]);
    expect(page.items[3]!.description).toBe('reveal');
    expect(page.nextCursor).toBeUndefined();
    await expect(
      adapter(fetchImpl).getHistory(SENDER, TEZOS_SHADOWNET, '1; drop'),
    ).rejects.toThrow();
  });

  it('refuses an indexer on another network', async () => {
    const { fetchImpl } = node({
      [`${TZKT}/v1/head`]: () => ({ chainId: 'NetXdQprcVkpaWU', level: 1 }),
      [`${TZKT}/v1/accounts/${SENDER}/operations`]: () => [],
    });
    await expect(adapter(fetchImpl).getHistory(SENDER, TEZOS_SHADOWNET)).rejects.toThrow();
  });

  it('lists the TzKT indexers per network', () => {
    expect(NETWORKS[TEZOS_SHADOWNET]!.indexers).toEqual(['https://api.shadownet.tzkt.io']);
    expect(NETWORKS[TEZOS_MAINNET]!.indexers).toEqual(['https://api.tzkt.io']);
  });
});

describe('tezos transfers', () => {
  const contracts = (counter: string, balance: string, managerKey: string | null) => ({
    [`${RPC}/chains/main/blocks/head/context/contracts/${SENDER}`]: () => ({
      balance,
      counter,
      revealed: managerKey !== null,
    }),
    [`${RPC}/chains/main/blocks/head/context/contracts/${SENDER}/manager_key`]: () => managerKey,
  });

  it('prepares a reveal and transfer priced from the simulation', async () => {
    let simulated: unknown;
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${RPC}/chains/main/blocks/head/header`]: () => header(5_000_000),
      ...contracts('33462632', '10000000', null),
      [`${RPC}/chains/main/blocks/head/helpers/scripts/run_operation`]: (body) => {
        simulated = body;
        return {
          contents: [
            {
              kind: 'reveal',
              metadata: { operation_result: { status: 'applied', consumed_milligas: '170200' } },
            },
            {
              kind: 'transaction',
              metadata: {
                operation_result: {
                  status: 'applied',
                  consumed_milligas: '2168755',
                  allocated_destination_contract: true,
                },
              },
            },
          ],
        };
      },
    });
    const { unsigned, simulation } = await prepareTezos(
      adapter(fetchImpl),
      intent(),
      SENDER,
      PUBLIC_HEX,
    );
    expect(unsigned).toMatchObject({
      counter: 33462633,
      gasLimit: 2269,
      storageLimit: 257,
      reveal: { gasLimit: 271, fee: 128 },
      branch: BRANCH,
    });
    const size = forgeTezos(unsigned, PUBLIC).length + 64;
    expect(unsigned.fee).toBe(100 + 227 + size + 10);
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe(String(unsigned.fee + 128 + 64250));
    expect(simulation.warnings).toHaveLength(2);
    const sim = simulated as {
      operation: { contents: { kind: string; public_key?: string; counter: string }[] };
    };
    expect(sim.operation.contents.map((c) => [c.kind, c.counter])).toEqual([
      ['reveal', '33462633'],
      ['transaction', '33462634'],
    ]);
    expect(sim.operation.contents[0]!.public_key).toBe(
      'edpkvRQaXJ26ZAFi2ZNq5Hb5wXcc3S1Q8kVaXNjxXDfmtWEp9DkpFZ',
    );
  });

  it('reports an empty sender without failing the prepare', async () => {
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${RPC}/chains/main/blocks/head/header`]: () => header(5_000_000),
      ...contracts('33462632', '0', null),
      [`${RPC}/chains/main/blocks/head/helpers/scripts/run_operation`]: () =>
        new Response(
          JSON.stringify([
            { kind: 'branch', id: 'proto.025-PsUshuai.implicit.empty_implicit_contract' },
          ]),
          { status: 500 },
        ),
    });
    const { unsigned, simulation } = await prepareTezos(
      adapter(fetchImpl),
      intent(),
      SENDER,
      PUBLIC_HEX,
    );
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toBe('Sender account is empty on Shadownet');
    expect(unsigned.reveal?.gasLimit).toBe(1000);
    expect(() => TezosTx.parse(unsigned)).not.toThrow();
  });

  it('needs the public key only when the account is unrevealed', async () => {
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${RPC}/chains/main/blocks/head/header`]: () => header(5_000_000),
      ...contracts('10', '10000000', null),
    });
    await expect(prepareTezos(adapter(fetchImpl), intent(), SENDER)).rejects.toThrow(/public key/);
    await expect(
      prepareTezos(adapter(fetchImpl), intent(), SENDER, bytesToHex(new Uint8Array(32).fill(1))),
    ).rejects.toThrow(/derive/);
    await expect(
      prepareTezos(adapter(fetchImpl), { ...intent(), chainId: TEZOS_MAINNET } as TxIntent, SENDER),
    ).rejects.toThrow();
  });

  it('keeps approval only while the branch, counter and reveal state hold', async () => {
    let head = 1000;
    let counter = String(tx.counter - 1);
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${RPC}/chains/main/blocks/head/header`]: () =>
        header(head, 'BLrKpTTWgxVKvu1sNTdX1qsGJF5ax7Cy86ojdpTvMqyrnU8Hm2g'),
      [`${RPC}/chains/main/blocks/head/context/constants`]: () => ({
        max_operations_time_to_live: 600,
      }),
      [`${RPC}/chains/main/blocks/${BRANCH}/header`]: () => header(900),
      [`${RPC}/chains/main/blocks/head/context/contracts/${SENDER}`]: () => ({
        balance: '1',
        counter,
      }),
      [`${RPC}/chains/main/blocks/head/context/contracts/${SENDER}/manager_key`]: () => null,
    });
    const a = adapter(fetchImpl);
    expect(await tezosApprovalValid(a, tx)).toBe(true);
    counter = String(tx.counter);
    expect(await tezosApprovalValid(a, tx)).toBe(false);
    counter = String(tx.counter - 1);
    head = 900 + 600 - 60;
    expect(await tezosApprovalValid(a, tx)).toBe(false);
  });

  it('broadcasts only the ledger operation with a valid signature', async () => {
    const injected: unknown[] = [];
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${RPC}/injection/operation`]: (body) => {
        injected.push(body);
        return REVEAL_TRANSFER_HASH;
      },
    });
    const a = adapter(fetchImpl);
    const wire = `0x${REVEAL_TRANSFER}${REVEAL_TRANSFER_SIG}`;
    expect(await broadcastTezos(a, tx, wire)).toBe(REVEAL_TRANSFER_HASH);
    expect(injected).toEqual([REVEAL_TRANSFER + REVEAL_TRANSFER_SIG]);
    const flipped =
      REVEAL_TRANSFER_SIG.slice(0, -1) + (REVEAL_TRANSFER_SIG.endsWith('a') ? 'b' : 'a');
    await expect(broadcastTezos(a, tx, `0x${REVEAL_TRANSFER}${flipped}`)).rejects.toThrow(/verify/);
    await expect(broadcastTezos(a, { ...tx, mutez: '1500001' }, wire)).rejects.toThrow();
    // A different revealed key is caught even though the sender is unchanged.
    const other = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(8)));
    const swapped = REVEAL_TRANSFER.replace(PUBLIC_HEX, other);
    await expect(broadcastTezos(a, tx, `0x${swapped}${REVEAL_TRANSFER_SIG}`)).rejects.toThrow();
    expect(injected).toHaveLength(1);
  });

  it('verifies the signature without a reveal when the key is supplied', async () => {
    const plain: TezosTx = { ...tx, reveal: undefined, counter: 5 };
    const forged = forgeTezos(plain, PUBLIC);
    const sig = ed25519.sign(tezosSigningDigest(forged), SEED);
    const hash = tezosOperationHash(Uint8Array.from([...forged, ...sig]));
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${RPC}/injection/operation`]: () => hash,
    });
    const a = adapter(fetchImpl);
    const wire = bytesToHex(forged) + bytesToHex(sig);
    expect(await broadcastTezos(a, plain, wire, PUBLIC_HEX)).toBe(hash);
    expect(await broadcastTezos(a, plain, wire)).toBe(hash);
    const bad = bytesToHex(forged) + bytesToHex(new Uint8Array(64));
    await expect(broadcastTezos(a, plain, bad, PUBLIC_HEX)).rejects.toThrow(/verify/);
  });

  it('surfaces node rejections and a mismatched hash', async () => {
    let reply: unknown = new Response(
      JSON.stringify([
        { kind: 'temporary', id: 'proto.025-PsUshuai.contract.counter_in_the_past' },
      ]),
      { status: 500 },
    );
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${RPC}/injection/operation`]: () => reply,
    });
    const a = adapter(fetchImpl);
    const wire = `${REVEAL_TRANSFER}${REVEAL_TRANSFER_SIG}`;
    await expect(broadcastTezos(a, tx, wire)).rejects.toThrow(/counter_in_the_past/);
    reply = 'opPaEV1KrNreA2PV7e3WELT5euXHHr7ZaumSr22xMXuB4vg5vvW';
    await expect(broadcastTezos(a, tx, wire)).rejects.toThrow(/different operation hash/);
  });

  it('reports status from TzKT and expiry only past the branch TTL', async () => {
    let ops: unknown[] = [];
    let head = 1400;
    const { fetchImpl } = node({
      ...shadowChain(),
      [`${TZKT}/v1/head`]: () => ({ chainId: 'NetXsqzbfFenSTS', level: 1 }),
      [`${TZKT}/v1/operations/${REVEAL_TRANSFER_HASH}`]: () => ops,
      [`${RPC}/chains/main/blocks/head/header`]: () =>
        header(head, 'BLrKpTTWgxVKvu1sNTdX1qsGJF5ax7Cy86ojdpTvMqyrnU8Hm2g'),
      [`${RPC}/chains/main/blocks/head/context/constants`]: () => ({
        max_operations_time_to_live: 600,
      }),
      [`${RPC}/chains/main/blocks/${BRANCH}/header`]: () => header(900),
    });
    const a = adapter(fetchImpl);
    expect(await tezosTransferStatus(a, tx, REVEAL_TRANSFER_HASH)).toEqual({ state: 'unknown' });
    head = 1501;
    expect(await tezosTransferStatus(a, tx, REVEAL_TRANSFER_HASH)).toEqual({ state: 'expired' });
    const base = {
      id: 1,
      level: 950,
      timestamp: '2026-10-16T12:06:51Z',
      hash: REVEAL_TRANSFER_HASH,
    };
    ops = [
      { ...base, type: 'reveal', status: 'applied' },
      { ...base, id: 2, type: 'transaction', status: 'applied', amount: 1500000 },
    ];
    expect(await tezosTransferStatus(a, tx, REVEAL_TRANSFER_HASH)).toEqual({
      state: 'confirmed',
      blockNumber: 950,
      timestampMs: Date.parse('2026-10-16T12:06:51Z'),
    });
    ops = [
      { ...base, type: 'reveal', status: 'applied' },
      {
        ...base,
        id: 2,
        type: 'transaction',
        status: 'failed',
        errors: [{ type: 'contract.balance_too_low' }],
      },
    ];
    expect(await tezosTransferStatus(a, tx, REVEAL_TRANSFER_HASH)).toEqual({
      state: 'failed',
      reason: 'contract.balance_too_low',
    });
    await expect(a.status('not-a-hash', TEZOS_SHADOWNET)).rejects.toThrow();
  });
});
