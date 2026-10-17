import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { MemoryRpcPool } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  ERA_PERIOD,
  SubstrateTx,
  assembleExtrinsic,
  broadcastSubstrate,
  extrinsicHash,
  mortalEra,
  prepareSubstrate,
  scaleCompact,
  signingPayload,
  substrateApprovalValid,
  substrateTransferStatus,
} from './send.js';
import {
  SUBSTRATE_CHAINS,
  SUBSTRATE_WESTEND,
  SUBSTRATE_WESTEND_ASSET_HUB,
  SubstrateAdapter,
  accountStorageKey,
  assetAccountStorageKey,
  decodeAccount,
  isValidSubstrateAddress,
  ss58Decode,
  ss58Encode,
  substrateAddressFromPublicKey,
} from './substrate.js';

const SEED = new Uint8Array(32).fill(7);
/** `Keyring({ type: 'ed25519' }).addFromSeed(seed 7)` in @polkadot/keyring. */
const SENDER = '5HMuAqymF33H73ZiBpmZ3TigFzHCopV9doyb9UfQdyDgZMUp';
const BOB = '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty';
const ALICE_PUB = 'd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d';
const WESTEND_GENESIS = '0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e';
const AH_GENESIS = '0x67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9';
const POLKADOT_AH = 'polkadot:68d56f15f85d3136970ec16946040bc1';

const tx: SubstrateTx = {
  chainId: SUBSTRATE_WESTEND,
  from: SENDER,
  to: BOB,
  planck: '1500000000000',
  tip: '0',
  nonce: 5,
  specVersion: 1_025_002,
  transactionVersion: 27,
  genesisHash: WESTEND_GENESIS,
  blockHash: `0x${'ab'.repeat(32)}`,
  blockNumber: 1_000_000,
  eraPeriod: 256,
  metadataHashMode: 0,
};
const ahTx: SubstrateTx = {
  ...tx,
  chainId: SUBSTRATE_WESTEND_ASSET_HUB,
  transactionVersion: 16,
  genesisHash: AH_GENESIS,
};
/** Produced by the Rust core's encoder for the same fields (`substrate.rs` tests). */
const PAYLOAD_VECTOR =
  '0403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0098f73e5d010704140000eaa30f001b000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423eabababababababababababababababababababababababababababababababab00';
/** @polkadot/api `transferKeepAlive(BOB, 1.5e12).sign(pair, ...)` with the same fields. */
const WESTEND_EXTRINSIC =
  '0x49028400ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c001a72697254403fde1160a275be1784e7da116b03865790103431a482f17a565cbdf8821bd69823877847a8fd52c5861fa3466c9da223b9321f603b441af3ba0407041400000403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0098f73e5d01';
const WESTEND_HASH = '0x1b92d20f51c1470efdff7a9975a488eaa014919931f32f84ff55c8524260e24e';
const AH_EXTRINSIC =
  '0x4d028400ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c00a0031f0b5a0d823327011e1036ecae3cfe03632329f44b3493ff1663d45765da2f029a128fd74cb01ce8e4a749222ae80e6168ed9d9557d4be8c40077444b1080704140000000a03008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0098f73e5d01';
const AH_HASH = '0x639878e2c8c7069168579d75ee1761fa3a7a4d7fe87a8cc1153ea6c6d659c925';

const signatureOf = (wire: string) => hexToBytes(wire.slice(2)).slice(37, 101);

type Handler = (params: unknown[], url: string) => unknown;
class RpcFailure extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

function node(handlers: Record<string, Handler>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
    calls.push(body.method);
    const handler = handlers[body.method];
    if (!handler)
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'not found' } }),
      );
    try {
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, result: handler(body.params, url) }),
      );
    } catch (err) {
      const e = err as RpcFailure;
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: e.code, message: e.message } }),
      );
    }
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  // One endpoint per chain keeps the mocked observations deterministic.
  const chains = SUBSTRATE_CHAINS.map((c) => ({ ...c, defaultRpcs: c.defaultRpcs.slice(0, 1) }));
  return new SubstrateAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) });
}

/** `AccountInfo` with u128 balances. */
function accountInfo(nonce: number, free: bigint, reserved = 0n, frozen = 0n): string {
  const le = (v: bigint, n: number) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = Number((v >> BigInt(8 * i)) & 0xffn);
    return bytesToHex(out);
  };
  return `0x${le(BigInt(nonce), 4)}${le(0n, 4)}${le(1n, 4)}${le(0n, 4)}${le(free, 16)}${le(reserved, 16)}${le(frozen, 16)}${le(1n << 127n, 16)}`;
}

const keyOf = (addr: string) => accountStorageKey(ss58Decode(addr)!.account);
const header = (n: number) => ({
  number: `0x${n.toString(16)}`,
  parentHash: `0x${(n - 1).toString(16).padStart(64, '0')}`,
});
const hashOf = (n: number) => `0x${n.toString(16).padStart(64, '0')}`;
const numberOf = (h: string) => Number.parseInt(h.slice(2), 16);

describe('substrate addresses', () => {
  it('derives SS58 addresses that match @polkadot/keyring', () => {
    const pub = ed25519.getPublicKey(SEED);
    expect(bytesToHex(pub)).toBe(
      'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c',
    );
    expect(substrateAddressFromPublicKey(pub)).toBe(SENDER);
    const a = new SubstrateAdapter();
    expect(a.deriveAddress({ curve: 'ed25519', hex: bytesToHex(pub) }, SUBSTRATE_WESTEND)).toBe(
      SENDER,
    );
    expect(
      a.deriveAddress(
        { curve: 'ed25519', hex: bytesToHex(pub) },
        'polkadot:91b171bb158e2d3848fa23a9f1c25182',
      ),
    ).toBe('16JCKBEq6pJkYaaE9TpZBcYq7cGrW83HiJi5JmemC4FCjso9');
    expect(
      a.deriveAddress(
        { curve: 'ed25519', hex: bytesToHex(pub) },
        'polkadot:8b8c140b0af9db70686583e3f6bf2a59',
      ),
    ).toBe('cFPAg9C99Bd84TCzSmTXBa7GvSt5LxxbAP2p6CMwRWvhNjWij');
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02'.padEnd(66, '1') }, SUBSTRATE_WESTEND),
    ).toThrow();
  });

  it('matches the published Alice addresses', () => {
    const alice = hexToBytes(ALICE_PUB);
    expect(ss58Encode(alice, 42)).toBe('5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY');
    expect(ss58Encode(alice, 0)).toBe('15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5');
    expect(ss58Decode('cFPAg9C99Bd84TCzSmTXBa7GvSt5LxxbAP2p6CMwRWvhNjWij')?.prefix).toBe(2112);
  });

  it('refuses bad checksums, other networks and the zero account', () => {
    expect(isValidSubstrateAddress(SENDER, SUBSTRATE_WESTEND)).toBe(true);
    expect(isValidSubstrateAddress(SENDER.slice(0, -1) + 'q', SUBSTRATE_WESTEND)).toBe(false);
    expect(
      isValidSubstrateAddress(
        '15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5',
        SUBSTRATE_WESTEND,
      ),
    ).toBe(false);
    expect(isValidSubstrateAddress('15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5')).toBe(true);
    expect(isValidSubstrateAddress(ss58Encode(new Uint8Array(32), 42))).toBe(false);
    expect(isValidSubstrateAddress('0x8eaf04151687736326c9fea17e25fc5287613693')).toBe(false);
    // Hydration displays prefix 63 while its runtime constant is 0; both name the same account.
    const hydration = 'polkadot:afdc188f45c71dacbaa0b62e16a91f72';
    const alice = hexToBytes(ALICE_PUB);
    expect(isValidSubstrateAddress(ss58Encode(alice, 63), hydration)).toBe(true);
    expect(isValidSubstrateAddress(ss58Encode(alice, 0), hydration)).toBe(true);
    expect(isValidSubstrateAddress(ss58Encode(alice, 2), hydration)).toBe(false);
  });
});

describe('substrate storage', () => {
  it('builds the Assets.Account key a live Asset Hub node returned', () => {
    // From state_getKeysPaged on Polkadot Asset Hub, asset 1984 (USDt).
    const live =
      '0x682a59d51ab9e48a8c8cc418ff9708d2b99d880ec681799c0cf30e8886371da9a319d0e87221ca1ee751c1529f201522c007000000064a5b7db2b0c8271fe85bce78da1e08622ff9ded7476d40178685d0a0a9d28cd396472dba36eb735f48ca54a0c7d7';
    const account = hexToBytes(live.slice(-64));
    expect(assetAccountStorageKey(1984, account)).toBe(live);
    expect(accountStorageKey(account).slice(0, 66)).toBe(
      '0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9',
    );
  });

  it('decodes AccountInfo with u128 and u64 balances', () => {
    const westend =
      '0x010000000000000001000000000000002793cfdb120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080';
    expect(decodeAccount(westend, { balanceBytes: 16, store: 'system' })).toEqual({
      nonce: 1,
      free: 0x12dbcf9327n,
      reserved: 0n,
      frozen: 0n,
    });
    const tao =
      '0x00000000000000000100000000000000e0787b0d000000000000000000000000000000000000000000000000000000000000000000000080';
    expect(decodeAccount(tao, { balanceBytes: 8, store: 'system' }).free).toBe(0x0d7b78e0n);
    expect(() => decodeAccount(tao, { balanceBytes: 16, store: 'system' })).toThrow();
    expect(decodeAccount(null, { balanceBytes: 16, store: 'system' }).free).toBe(0n);
  });

  it('reads native and USDt balances on Polkadot Asset Hub', async () => {
    const owner = ss58Encode(hexToBytes(ALICE_PUB), 0);
    const account = hexToBytes(ALICE_PUB);
    const { fetchImpl } = node({
      chain_getBlockHash: () =>
        '0x68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f',
      state_getStorage: ([key]) => {
        if (key === accountStorageKey(account))
          return accountInfo(3, 5n * 10n ** 10n, 10n ** 10n, 2n * 10n ** 10n);
        if (key === assetAccountStorageKey(1984, account))
          return '0x0a3a00000000000000000000000000000001';
        return null;
      },
    });
    const holdings = await adapter(fetchImpl).getBalances(owner, POLKADOT_AH);
    expect(holdings[0]).toMatchObject({ assetRef: `${POLKADOT_AH}:native`, amount: '60000000000' });
    expect(holdings[0]!.notice).toContain('40000000000 is transferable');
    expect(holdings[1]).toMatchObject({ assetRef: `${POLKADOT_AH}:asset:1984`, amount: '14858' });
    expect(holdings[2]).toMatchObject({ assetRef: `${POLKADOT_AH}:asset:1337`, amount: '0' });
  });

  it('refuses an endpoint that serves another network', async () => {
    const { fetchImpl } = node({
      chain_getBlockHash: () =>
        '0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3',
      state_getStorage: () => null,
    });
    await expect(adapter(fetchImpl).getBalances(SENDER, SUBSTRATE_WESTEND)).rejects.toThrow();
  });
});

describe('substrate transfers', () => {
  it('encodes the same signing payload as the core', () => {
    expect(bytesToHex(signingPayload(tx))).toBe(PAYLOAD_VECTOR);
    expect(bytesToHex(Uint8Array.from(mortalEra(1_000_000, 256)))).toBe('0704');
    expect(bytesToHex(Uint8Array.from(scaleCompact(1_500_000_000_000n)))).toBe('0b0098f73e5d01');
    expect(bytesToHex(Uint8Array.from(scaleCompact(16384n)))).toBe('02000100');
    expect(bytesToHex(Uint8Array.from(scaleCompact((1n << 128n) - 1n)))).toBe(
      `33${'ff'.repeat(16)}`,
    );
  });

  it('assembles the extrinsic @polkadot/api signs, and its signature verifies', () => {
    for (const [t, wire, hash] of [
      [tx, WESTEND_EXTRINSIC, WESTEND_HASH],
      [ahTx, AH_EXTRINSIC, AH_HASH],
    ] as const) {
      const sig = signatureOf(wire);
      const built = assembleExtrinsic(t, sig);
      expect(`0x${bytesToHex(built)}`).toBe(wire);
      expect(extrinsicHash(built)).toBe(hash);
      expect(ed25519.verify(sig, signingPayload(t), ed25519.getPublicKey(SEED))).toBe(true);
    }
  });

  it('refuses hostile fields', () => {
    expect(() => signingPayload({ ...tx, planck: '0' })).toThrow();
    expect(() => signingPayload({ ...tx, planck: '01' })).toThrow();
    expect(() => signingPayload({ ...tx, planck: (1n << 128n).toString() })).toThrow();
    expect(() => signingPayload({ ...tx, to: tx.from })).toThrow();
    expect(() =>
      signingPayload({ ...tx, to: '15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5' }),
    ).toThrow();
    expect(() => signingPayload({ ...tx, transactionVersion: 28 })).toThrow();
    expect(() => signingPayload({ ...tx, genesisHash: AH_GENESIS })).toThrow();
    expect(() => signingPayload({ ...tx, eraPeriod: 100 })).toThrow();
    expect(() => signingPayload({ ...tx, tip: '1000000000001' })).toThrow();
    expect(() => signingPayload({ ...tx, blockHash: `0x${'00'.repeat(32)}` })).toThrow();
    expect(() =>
      signingPayload({
        ...tx,
        chainId: 'polkadot:91b171bb158e2d3848fa23a9f1c25182' as typeof SUBSTRATE_WESTEND,
      }),
    ).toThrow();
    expect(() => SubstrateTx.parse({ ...tx, call: '00' })).toThrow();
  });

  it('prepares a Westend transfer from the finalized head and live runtime', async () => {
    const { fetchImpl } = node({
      chain_getBlockHash: () => WESTEND_GENESIS,
      state_getRuntimeVersion: () => ({
        specName: 'westend',
        specVersion: 1_025_002,
        transactionVersion: 27,
      }),
      chain_getFinalizedHead: () => hashOf(33_315_393),
      chain_getHeader: ([h]) => header(h ? numberOf(h as string) : 33_315_396),
      system_accountNextIndex: () => 7,
      payment_queryInfo: () => ({ partialFee: '16227473774' }),
      state_getStorage: ([key]) => (key === keyOf(SENDER) ? accountInfo(7, 10n ** 13n) : null),
    });
    const a = adapter(fetchImpl);
    const intent = {
      id: 't',
      walletId: 'w',
      accountId: 'a',
      chainId: SUBSTRATE_WESTEND,
      kind: 'transfer' as const,
      to: BOB,
      asset: `${SUBSTRATE_WESTEND}:native`,
      amount: '1500000000000',
      proposer: { kind: 'human' as const, deviceId: 'd' },
      untrustedDestinations: [],
      createdAtMs: 0,
    };
    const { unsigned, simulation } = await prepareSubstrate(a, intent as never, SENDER);
    expect(unsigned).toMatchObject({
      nonce: 7,
      blockNumber: 33_315_393,
      blockHash: hashOf(33_315_393),
      eraPeriod: ERA_PERIOD,
      specVersion: 1_025_002,
      genesisHash: WESTEND_GENESIS,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('16227473774');
    expect(simulation.warnings.some((w) => w.kind === 'other')).toBe(true);
    const small = await prepareSubstrate(a, { ...intent, amount: '1000' } as never, SENDER);
    expect(small.simulation.ok).toBe(false);
  });

  it('refuses to prepare once the runtime bumps its transaction version', async () => {
    const { fetchImpl } = node({
      chain_getBlockHash: () => WESTEND_GENESIS,
      state_getRuntimeVersion: () => ({
        specName: 'westend',
        specVersion: 1_026_000,
        transactionVersion: 28,
      }),
    });
    const intent = {
      chainId: SUBSTRATE_WESTEND,
      kind: 'transfer',
      to: BOB,
      asset: `${SUBSTRATE_WESTEND}:native`,
      amount: '1',
    };
    await expect(prepareSubstrate(adapter(fetchImpl), intent as never, SENDER)).rejects.toThrow();
  });

  it('approves only while runtime, nonce and era still match', async () => {
    let spec = 1_025_002;
    let best = 1_000_100;
    let nonce = 5;
    const { fetchImpl } = node({
      chain_getBlockHash: () => WESTEND_GENESIS,
      state_getRuntimeVersion: () => ({
        specName: 'westend',
        specVersion: spec,
        transactionVersion: 27,
      }),
      chain_getHeader: () => header(best),
      system_accountNextIndex: () => nonce,
    });
    const a = adapter(fetchImpl);
    await expect(substrateApprovalValid(a, tx)).resolves.toBe(true);
    nonce = 6;
    await expect(substrateApprovalValid(a, tx)).resolves.toBe(false);
    nonce = 5;
    best = 1_000_000 + 256 - 11;
    await expect(substrateApprovalValid(a, tx)).resolves.toBe(false);
    best = 1_000_100;
    spec = 1_025_003;
    await expect(substrateApprovalValid(a, tx)).resolves.toBe(false);
  });

  it('broadcasts only the ledger transfer with a valid sender signature', async () => {
    const seen: unknown[] = [];
    const { fetchImpl } = node({
      chain_getBlockHash: () => WESTEND_GENESIS,
      state_getRuntimeVersion: () => ({
        specName: 'westend',
        specVersion: 1_025_002,
        transactionVersion: 27,
      }),
      author_submitExtrinsic: ([x]) => {
        seen.push(x);
        return WESTEND_HASH;
      },
    });
    const a = adapter(fetchImpl);
    await expect(broadcastSubstrate(a, tx, WESTEND_EXTRINSIC)).resolves.toBe(WESTEND_HASH);
    await expect(
      broadcastSubstrate(a, { ...tx, planck: '1500000000001' }, WESTEND_EXTRINSIC),
    ).rejects.toThrow();
    await expect(broadcastSubstrate(a, tx, WESTEND_EXTRINSIC + '00')).rejects.toThrow();
    const forged = `${WESTEND_EXTRINSIC.slice(0, 80)}${WESTEND_EXTRINSIC[80] === '0' ? '1' : '0'}${WESTEND_EXTRINSIC.slice(81)}`;
    await expect(broadcastSubstrate(a, tx, forged)).rejects.toThrow('Signature');
    expect(seen).toEqual([WESTEND_EXTRINSIC]);
  });

  it('treats a resubmission the pool already holds as success', async () => {
    const { fetchImpl } = node({
      chain_getBlockHash: () => WESTEND_GENESIS,
      state_getRuntimeVersion: () => ({
        specName: 'westend',
        specVersion: 1_025_002,
        transactionVersion: 27,
      }),
      author_submitExtrinsic: () => {
        throw new RpcFailure(1013, 'Transaction Already Imported');
      },
    });
    await expect(broadcastSubstrate(adapter(fetchImpl), tx, WESTEND_EXTRINSIC)).resolves.toBe(
      WESTEND_HASH,
    );
  });

  it('finds the inclusion block by nonce and confirms the recipient was credited', async () => {
    const included = 1_000_137;
    let finalized = 1_000_050;
    let credited = BigInt(tx.planck);
    const { fetchImpl, calls } = node({
      chain_getBlockHash: ([n]) => (n === 0 ? WESTEND_GENESIS : hashOf(n as number)),
      chain_getFinalizedHead: () => hashOf(finalized),
      chain_getHeader: ([h]) => header(numberOf(h as string)),
      state_getStorage: ([key, at]) => {
        const n = numberOf(at as string);
        if (key === keyOf(SENDER)) return accountInfo(n >= included ? 6 : 5, 10n ** 13n);
        if (key === keyOf(BOB))
          return accountInfo(0, n >= included ? 10n ** 12n + credited : 10n ** 12n);
        return '0x80b4a3c0a1010000';
      },
      chain_getBlock: ([h]) => ({
        block: {
          header: header(numberOf(h as string)),
          extrinsics: ['0x280403000b80b4a3c0a10101', WESTEND_EXTRINSIC],
        },
      }),
    });
    const a = adapter(fetchImpl);
    await expect(substrateTransferStatus(a, tx, WESTEND_HASH)).resolves.toEqual({
      state: 'pending',
    });
    finalized = 1_000_200;
    const status = await substrateTransferStatus(a, tx, WESTEND_HASH);
    expect(status).toMatchObject({ state: 'confirmed', blockNumber: included });
    expect(calls.filter((c) => c === 'chain_getBlock')).toHaveLength(1);
    credited = 0n;
    await expect(substrateTransferStatus(a, tx, WESTEND_HASH)).resolves.toMatchObject({
      state: 'failed',
    });
    await expect(substrateTransferStatus(a, tx, `0x${'11'.repeat(32)}`)).resolves.toEqual({
      state: 'expired',
    });
  });

  it('reports expiry once the era is finalized without the nonce advancing', async () => {
    let finalized = tx.blockNumber + tx.eraPeriod - 2;
    const { fetchImpl } = node({
      chain_getBlockHash: () => WESTEND_GENESIS,
      chain_getFinalizedHead: () => hashOf(finalized),
      chain_getHeader: ([h]) => header(numberOf(h as string)),
      state_getStorage: () => accountInfo(5, 10n ** 13n),
    });
    const a = adapter(fetchImpl);
    await expect(substrateTransferStatus(a, tx, WESTEND_HASH)).resolves.toEqual({
      state: 'pending',
    });
    finalized += 1;
    await expect(substrateTransferStatus(a, tx, WESTEND_HASH)).resolves.toEqual({
      state: 'expired',
    });
  });
});
