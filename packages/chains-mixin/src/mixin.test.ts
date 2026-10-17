import { MemoryRpcPool } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  MIXIN_CHAINS,
  MIXIN_MAINNET,
  MixinAdapter,
  createMixinAdapter,
  isValidMixinAddress,
  mixinAddressFromPublicKey,
} from './mixin.js';
import {
  MixinTx,
  broadcastMixin,
  mixinApprovalValid,
  mixinTransferStatus,
  parseUnsignedPrefix,
  prepareMixin,
  verifySignedWire,
} from './send.js';

/** Go `NewAddressFromSeed` vector (common/address_test.go), seed = bytes 1..64. */
const GO_ADDRESS =
  'XIN8AJMgQUD11jZYN9ggbQDqkmozrha3zPEZxEkKxVFBufZpEVMtrR6PjtmgtNAH6jrg8dTUQFb9waqqw9euU7Ea8AC6DEu8';
const GO_SPEND_PUB = [
  '36bb0e309e7e9a82f152',
  '7df2c6b0e48181589097',
  'fe90c1282c558207ea27',
  'ce66',
].join('');
const GO_VIEW_PUB = [
  'af8f69545b784e71de5e',
  '0a0261cb107aea99e9d7',
  'fe0df35537899cd9f05e',
  'a644',
].join('');

/**
 * The exact 318-byte wire the Rust core signed for the probe transfer and the
 * live kernel accepted for validation (it rejected only the unknown input
 * with `input not found 0101…01:0`). txid is the kernel-computable payload hash.
 */
const PROBE_WIRE =
  '77770005a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc00010101010101010101010101010101010101010101010101010101010101010101000000000000000000020000000408f0d180000119156107d6ed47b0f0e52b8757be8e71af093d241af2db5bef60d05ead3393c5cf87cb20135bb302ca810555817fb23c993263f69d965f79a70dc8390cb46a870003fffe0100000000000402faf08000010c59811d167532ee0dc8c2a3adaa78f8af839ad4d7e21932250ec5ea3d4be07bb48fcd6377f68f89861100dc74e5a7b3bec949633b481ec4915737ee2b45a05e0003fffe01000000000000000000010001000025e6290e1a08735dc1775697d31c61d10793b7c53ebdc842bf504052b2ec085506bf44f42a0073a38795e1c8f7a545fb9b57c843c4611938f3e9e8d154948007';
const PROBE_TXID = [
  'a4c0322739cb87bc4b31',
  '2bd4500baca9b99a0eb0',
  '2345360f6f57b97f60d0',
  'ac7d',
].join('');
const PROBE_KEY = [
  '19156107d6ed47b0f0e5',
  '2b8757be8e71af093d24',
  '1af2db5bef60d05ead33',
  '93c5',
].join('');
const PROBE_MASK = [
  'cf87cb20135bb302ca81',
  '0555817fb23c993263f6',
  '9d965f79a70dc8390cb4',
  '6a87',
].join('');

const tx: MixinTx = {
  chainId: MIXIN_MAINNET,
  // The wire check reads inputs/outputs, not addresses; one valid address serves both.
  from: GO_ADDRESS,
  to: GO_ADDRESS,
  xinat: '150000000',
  inputs: [
    {
      hash: '01'.repeat(32),
      index: 0,
      key: PROBE_KEY,
      mask: PROBE_MASK,
      xinat: '200000000',
    },
  ],
  toSeed: '05'.repeat(64),
  changeSeed: '06'.repeat(64),
};

function intent(overrides: Partial<TxIntent> = {}): TxIntent {
  return {
    chainId: MIXIN_MAINNET,
    kind: 'transfer',
    to: GO_ADDRESS,
    asset: `${MIXIN_MAINNET}:native`,
    amount: '150000000',
    ...overrides,
  } as TxIntent;
}

/** Mocks the kernel POST envelope; `routes` map method to data-or-Error. */
function kernel(routes: Record<string, (params: unknown[]) => unknown>) {
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
    const route = routes[body.method];
    if (!route) return Response.json({ error: 'invalid method' });
    const result = route(body.params ?? []);
    if (result instanceof Error) return Response.json({ error: result.message });
    return Response.json({ data: result });
  }) as typeof fetch;
  return new MixinAdapter({
    fetch: fetchImpl,
    rpc: new MemoryRpcPool(
      MIXIN_CHAINS.map((c) => ({ ...c, defaultRpcs: ['https://kernel.test'] })),
    ),
  });
}

const INFO = {
  getinfo: () => ({
    network: ['74c6cdb7d51af57037fa', 'a1f5544f8331ced001df', '5964331911ca51385993', 'b375'].join(
      '',
    ),
  }),
};

describe('mixin addresses', () => {
  it('validates the Go vector address and round-trips its bytes', () => {
    expect(isValidMixinAddress(GO_ADDRESS)).toBe(true);
    expect(
      mixinAddressFromPublicKey(
        Uint8Array.from((GO_SPEND_PUB + GO_VIEW_PUB).match(/../g)!.map((b) => parseInt(b, 16))),
      ),
    ).toBe(GO_ADDRESS);
    expect(isValidMixinAddress(`${GO_ADDRESS.slice(0, -1)}7`)).toBe(false);
    expect(isValidMixinAddress(GO_ADDRESS.toLowerCase())).toBe(false);
    expect(isValidMixinAddress('XIN8AJMg')).toBe(false);
    expect(
      isValidMixinAddress(
        'BTC8AJMgQUD11jZYN9ggbQDqkmozrha3zPEZxEkKxVFBufZpEVMtrR6PjtmgtNAH6jrg8dTUQFb9waqqw9euU7Ea8AC6DEu8',
      ),
    ).toBe(false);
  });

  it('derives addresses only from 64-byte ed25519 account keys', () => {
    const a = createMixinAdapter();
    expect(
      a.deriveAddress({ curve: 'ed25519', hex: GO_SPEND_PUB + GO_VIEW_PUB }, MIXIN_MAINNET),
    ).toBe(GO_ADDRESS);
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '11'.repeat(32) }, MIXIN_MAINNET),
    ).toThrow();
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: GO_SPEND_PUB + GO_VIEW_PUB }, MIXIN_MAINNET),
    ).toThrow();
  });
});

describe('mixin transfers', () => {
  it('verifies the live-probed wire against its tx and computes the kernel txid', () => {
    expect(verifySignedWire(tx, PROBE_WIRE)).toBe(PROBE_TXID);
    const prefix = parseUnsignedPrefix(
      Uint8Array.from(PROBE_WIRE.match(/../g)!.map((b) => parseInt(b, 16))),
    );
    expect(prefix.inputs).toEqual([{ hash: '01'.repeat(32), index: 0 }]);
    expect(prefix.outputs.map((o) => o.amount.toString())).toEqual(['150000000', '50000000']);
    expect(prefix.outputs.map((o) => o.script)).toEqual(['fffe01', 'fffe01']);
  });

  it('refuses substituted or malformed wires', () => {
    expect(() => verifySignedWire(tx, PROBE_WIRE.toUpperCase())).toThrow();
    expect(() => verifySignedWire(tx, PROBE_WIRE.slice(0, -2))).toThrow();
    expect(() => verifySignedWire({ ...tx, xinat: '150000001' }, PROBE_WIRE)).toThrow(
      /different amount/,
    );
    expect(() =>
      verifySignedWire(
        { ...tx, inputs: [{ ...tx.inputs[0]!, hash: '02'.repeat(32) }] },
        PROBE_WIRE,
      ),
    ).toThrow(/other inputs/);
    // burning the change must fail: a wire without the change output
    expect(() =>
      verifySignedWire({ ...tx, inputs: [{ ...tx.inputs[0]!, xinat: '150000000' }] }, PROBE_WIRE),
    ).toThrow(/change/);
    expect(() => verifySignedWire(tx, 'zz')).toThrow();
    expect(() => MixinTx.parse({ ...tx, extra: '00' } as Record<string, unknown>)).toThrow();
  });

  it('requires the UTXO provider for balances and preparation', async () => {
    const adapter = kernel(INFO);
    await expect(adapter.getBalances(GO_ADDRESS, MIXIN_MAINNET)).rejects.toThrow(/utxos/i);
    await expect(prepareMixin(adapter, intent(), GO_ADDRESS)).rejects.toThrow(/view-key scan/);
  });

  it('prepares from provided UTXOs and refuses undercovered amounts', async () => {
    const utxos = async () => [
      { hash: '01'.repeat(32), index: 0, key: PROBE_KEY, mask: PROBE_MASK, xinat: '100000000' },
      { hash: '02'.repeat(32), index: 1, key: PROBE_KEY, mask: PROBE_MASK, xinat: '100000000' },
    ];
    const adapter = new MixinAdapter({ utxos });
    const { unsigned, simulation } = await prepareMixin(adapter, intent(), GO_ADDRESS, () =>
      new Uint8Array(64).fill(5),
    );
    expect(unsigned.inputs).toHaveLength(2);
    expect(simulation.ok).toBe(true);
    expect(simulation.fee?.amount).toBe('0');
    const short = await prepareMixin(adapter, intent({ amount: '500000000' }), GO_ADDRESS, () =>
      new Uint8Array(64).fill(5),
    );
    expect(short.simulation.ok).toBe(false);
    expect(short.simulation.error).toMatch(/do not cover/);
  });

  it('validates approval against live UTXO locks', async () => {
    const open = kernel({
      ...INFO,
      getutxo: () => ({ amount: '2.00000000', lock: null }),
    });
    await expect(mixinApprovalValid(open, tx)).resolves.toBe(true);
    const locked = kernel({
      ...INFO,
      getutxo: () => ({ amount: '2.00000000', lock: 'ab'.repeat(32) }),
    });
    await expect(mixinApprovalValid(locked, tx)).resolves.toBe(false);
    const gone = kernel({ ...INFO, getutxo: () => null });
    await expect(mixinApprovalValid(gone, tx)).resolves.toBe(false);
  });

  it('broadcasts only the verified wire and checks the returned hash', async () => {
    let seenHex: string | undefined;
    const good = kernel({
      ...INFO,
      sendrawtransaction: (params) => {
        seenHex = String(params[0]);
        return { hash: PROBE_TXID };
      },
    });
    await expect(broadcastMixin(good, tx, PROBE_WIRE)).resolves.toBe(PROBE_TXID);
    expect(seenHex).toBe(PROBE_WIRE);
    const wrongHash = kernel({ ...INFO, sendrawtransaction: () => ({ hash: 'ff'.repeat(32) }) });
    await expect(broadcastMixin(wrongHash, tx, PROBE_WIRE)).rejects.toThrow(/expected/);
    const rejected = kernel({
      ...INFO,
      sendrawtransaction: () => new Error('input not found ' + '01'.repeat(32) + ':0'),
    });
    // Kernel rejections surface through the failover wrapper with the cause message.
    await expect(broadcastMixin(rejected, tx, PROBE_WIRE)).rejects.toThrow(/input not found/);
  });

  it('maps durable/cache/absent to confirmed/pending/unknown', async () => {
    const confirmed = kernel({
      ...INFO,
      gettransaction: () => ({ hex: 'abcd', snapshot: 'cd'.repeat(32) }),
    });
    await expect(mixinTransferStatus(confirmed, tx, PROBE_TXID)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 0,
    });
    const pending = kernel({ ...INFO, gettransaction: () => ({ hex: 'abcd' }) });
    await expect(mixinTransferStatus(pending, tx, PROBE_TXID)).resolves.toEqual({
      state: 'pending',
    });
    const cached = kernel({
      ...INFO,
      gettransaction: () => null,
      getcachetransaction: () => ({ hex: 'abcd' }),
    });
    await expect(mixinTransferStatus(cached, tx, PROBE_TXID)).resolves.toEqual({
      state: 'pending',
    });
    const unknown = kernel({
      ...INFO,
      gettransaction: () => null,
      getcachetransaction: () => null,
    });
    await expect(mixinTransferStatus(unknown, tx, PROBE_TXID)).resolves.toEqual({
      state: 'unknown',
    });
  });

  it('rejects an endpoint serving another network', async () => {
    const evil = kernel({ getinfo: () => ({ network: '00'.repeat(32) }) });
    await expect(mixinApprovalValid(evil, tx)).rejects.toThrow(/another Mixin kernel network/);
  });
});
