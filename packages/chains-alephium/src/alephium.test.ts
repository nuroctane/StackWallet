import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MemoryRpcPool } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  ALEPHIUM_CHAINS,
  ALEPHIUM_TESTNET,
  AlephiumAdapter,
  alphAddressFromPublicKey,
  alphGroupOfAddress,
  isValidAlphAddress,
} from './alephium.js';
import {
  ALPH_GAS_AMOUNT,
  ALPH_GAS_PRICE,
  AlephiumTx,
  alphApprovalValid,
  alphTransferStatus,
  alphTxId,
  broadcastAlph,
  encodeAlphUnsignedTx,
  prepareAlph,
} from './send.js';

/** Private key 1 (its compressed public key is PUB1). */
const KEY_ONE = '0000000000000000000000000000000000000000000000000000000000000001';
const PUB1 = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const ADDR1 = '13nr2XuF1VYfEgBLsXBQFrZcfzNvACP8cDz5CdAwk6BUz';
const ADDR2 = '1Dxa5jAd2GouRJUPAsqmPGFFnJj6mmWoC6A2kvBacwykc';
const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

const tx: AlephiumTx = {
  chainId: ALEPHIUM_TESTNET,
  from: ADDR1,
  publicKey: PUB1,
  to: ADDR2,
  attoalph: '1234567890123456789',
  change: '500000000000000000',
  inputs: [{ hint: -1985788861, key: 'ab'.repeat(32) }],
  gasAmount: 20_000,
  gasPrice: '100000000000',
};
/** Produced by `@alephium/web3`'s `unsignedTxCodec` for the same fields; pinned by `alephium.rs` too. */
const UNSIGNED_VECTOR =
  '00010080004e20c1174876e8000189a34443abababababababababababababababababababababababababababababababab000279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c4112210f47de9811500c08897cdf88a1d9a12667b5bebcf74c06d02e95d38fb5ae44d5fc0f41699cd0100000000000000000000c406f05b59d3b20000002975f1d28b92b6e84499b83b0797ef5235553eeb7edaa0cea243c1128c2fe73700000000000000000000';
const TXID_VECTOR = '11e03f7ffff566989708c4bb38f9b52b0db635d1ebf68666a6edd440eab11413';
/** `@alephium/web3` `sign(TXID_VECTOR, key 1)` — deterministic RFC 6979, low-S. */
const SIGNATURE_VECTOR =
  '02810c1c0ceb735982cad9f8e9bb6d27d7fa25ca45c44befd7a0422136877d4f751858ecb702fca362a4ecfae98c2a8254954387c376b81ef352648c851d8ecc';

const UTXO = { hint: -1372518565, key: 'cd'.repeat(32), amount: '25000000000000000000' };

function node(routes: Record<string, (body: Record<string, unknown>) => unknown>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.host + url.pathname + url.search);
    const route = routes[url.pathname];
    if (!route) return new Response('{}', { status: 404 });
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const out = route(body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new AlephiumAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool([...ALEPHIUM_CHAINS]) });
}

const okRoutes: Record<string, () => unknown> = {
  '/infos/chain-params': () => ({ networkId: 1, groups: 4 }),
  [`/addresses/${ADDR1}/utxos`]: () => ({ utxos: [{ ref: UTXO, amount: UTXO.amount }] }),
};

describe('alephium addresses', () => {
  it('derives the base58 P2PKH address and group of private key 1', () => {
    expect(alphAddressFromPublicKey(hexToBytes(PUB1))).toBe(ADDR1);
    expect(alphGroupOfAddress(ADDR1)).toBe(3);
    expect(alphGroupOfAddress(ADDR2)).toBe(3);
    const a = new AlephiumAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: PUB1 }, ALEPHIUM_TESTNET)).toBe(ADDR1);
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, ALEPHIUM_TESTNET),
    ).toThrow();
  });

  it('refuses hex, truncated and zero-hash addresses', () => {
    expect(isValidAlphAddress(ADDR1)).toBe(true);
    expect(isValidAlphAddress('0x79be667ef9dcbbac55a06295ce870b07029bfcdb')).toBe(false);
    expect(isValidAlphAddress('13nr2XuF')).toBe(false);
    expect(isValidAlphAddress('tgx7VNFoP9DJiFMFgXXtafQZkUvyEdDHT9ryamHJYrjq')).toBe(false);
    expect(isValidAlphAddress('')).toBe(false);
  });
});

describe('alephium transfers', () => {
  it('encodes the same unsigned bytes and txid as the core and the SDK', () => {
    expect(Buffer.from(encodeAlphUnsignedTx(tx)).toString('hex')).toBe(UNSIGNED_VECTOR);
    expect(alphTxId(tx)).toBe(TXID_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => encodeAlphUnsignedTx({ ...tx, attoalph: '0' })).toThrow();
    expect(() => encodeAlphUnsignedTx({ ...tx, attoalph: '01' })).toThrow();
    expect(() => encodeAlphUnsignedTx({ ...tx, to: tx.from })).toThrow();
    expect(() => encodeAlphUnsignedTx({ ...tx, change: '1' })).toThrow();
    expect(() => encodeAlphUnsignedTx({ ...tx, gasPrice: '99999999999' })).toThrow();
    expect(() => encodeAlphUnsignedTx({ ...tx, inputs: [] })).toThrow();
    expect(() =>
      encodeAlphUnsignedTx({
        ...tx,
        publicKey: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
      }),
    ).toThrow();
    expect(() => encodeAlphUnsignedTx({ ...tx, chainId: 'alephium:0' as never })).toThrow();
  });

  it('prepares a testnet transfer with change from the UTXO set', async () => {
    const { fetchImpl } = node(okRoutes);
    const intent: TxIntent = {
      id: 'i',
      walletId: 'w',
      accountId: 'a',
      chainId: ALEPHIUM_TESTNET,
      proposer: { kind: 'human', deviceId: 'd' },
      kind: 'transfer',
      to: ADDR2,
      asset: `${ALEPHIUM_TESTNET}:native`,
      amount: '1000000000000000000',
      createdAtMs: 0,
    } as unknown as TxIntent;
    const { unsigned, simulation } = await prepareAlph(adapter(fetchImpl), intent, ADDR1, PUB1);
    expect(simulation.ok).toBe(true);
    expect(unsigned.inputs).toEqual([{ hint: UTXO.hint, key: UTXO.key }]);
    expect(unsigned.change).toBe(
      (BigInt(UTXO.amount) - 10n ** 18n - 20000n * 10n ** 11n).toString(),
    );
    expect(simulation.fee.amount).toBe('2000000000000000');
    encodeAlphUnsignedTx(unsigned);
  });

  it('flags locked and token-carrying UTXOs as unspendable', async () => {
    const { fetchImpl } = node({
      ...okRoutes,
      [`/addresses/${ADDR1}/utxos`]: () => ({
        utxos: [
          { ref: UTXO, amount: UTXO.amount, lockTime: Date.now() + 60_000 },
          {
            ref: { hint: 1, key: 'ef'.repeat(32) },
            amount: '3000000000000000000',
            tokens: [{ id: 'ab'.repeat(32), amount: '1' }],
          },
        ],
      }),
    });
    const intent = {
      chainId: ALEPHIUM_TESTNET,
      kind: 'transfer',
      to: ADDR2,
      asset: `${ALEPHIUM_TESTNET}:native`,
      amount: '1000000000000000000',
    } as unknown as TxIntent;
    const { simulation } = await prepareAlph(adapter(fetchImpl), intent, ADDR1, PUB1);
    expect(simulation.ok).toBe(false);
    expect(simulation.warnings[0]).toMatchObject({ kind: 'other' });
  });

  it('approves only while every input UTXO is still spendable', async () => {
    const prepared: AlephiumTx = { ...tx, inputs: [{ hint: UTXO.hint, key: UTXO.key }] };
    const live = adapter(node(okRoutes).fetchImpl);
    expect(await alphApprovalValid(live, prepared)).toBe(true);
    const spent = adapter(
      node({ ...okRoutes, [`/addresses/${ADDR1}/utxos`]: () => ({ utxos: [] }) }).fetchImpl,
    );
    expect(await alphApprovalValid(spent, prepared)).toBe(false);
  });

  it('broadcasts only the exact transfer plus a valid signature', async () => {
    const prepared: AlephiumTx = { ...tx, inputs: [{ hint: UTXO.hint, key: UTXO.key }] };
    const unsigned = Buffer.from(encodeAlphUnsignedTx(prepared)).toString('hex');
    const id = alphTxId(prepared);
    const sig = bytesToHex(
      secp256k1.sign(hexToBytes(id), hexToBytes(KEY_ONE), { prehash: false, format: 'compact' }),
    );
    const wire = `${unsigned}010000014040${sig}00`;
    let submitted: Record<string, unknown> | undefined;
    const { fetchImpl } = node({
      ...okRoutes,
      '/transactions/submit': (body) => {
        submitted = body;
        return { txId: id, fromGroup: 3, toGroup: 3 };
      },
    });
    const hash = await broadcastAlph(adapter(fetchImpl), prepared, wire);
    expect(hash).toBe(id);
    expect(submitted).toEqual({ unsignedTx: unsigned, signature: sig });

    await expect(broadcastAlph(adapter(fetchImpl), prepared, `0x${unsigned}01`)).rejects.toThrow(
      'Signed bytes are not this ALPH transfer',
    );
    // A signature by another key is refused before any broadcast.
    const other = bytesToHex(
      secp256k1.sign(hexToBytes(id), hexToBytes('ab'.repeat(32)), {
        prehash: false,
        format: 'compact',
      }),
    );
    const badWire = `${unsigned}010000014040${other}00`;
    await expect(broadcastAlph(adapter(fetchImpl), prepared, badWire)).rejects.toThrow(
      'not signed by its sender',
    );
  });

  it('reports status from the node and failure once an input was spent', async () => {
    const id = alphTxId(tx);
    const routes: Record<string, () => unknown> = {
      ...okRoutes,
      '/transactions/status': () => ({ type: 'TxNotFound' }),
    };
    const a = adapter(node(routes).fetchImpl);
    expect((await a.status(id, ALEPHIUM_TESTNET)).state).toBe('unknown');
    // The prepared transfer spends the live UTXO, so its absence says nothing yet.
    const live: AlephiumTx = { ...tx, inputs: [{ hint: UTXO.hint, key: UTXO.key }] };
    expect((await alphTransferStatus(a, live, id)).state).toBe('unknown');

    const spent = adapter(
      node({ ...routes, [`/addresses/${ADDR1}/utxos`]: () => ({ utxos: [] }) }).fetchImpl,
    );
    const gone = await alphTransferStatus(spent, live, id);
    expect(gone.state).toBe('failed');

    const confirmed = adapter(
      node({
        ...routes,
        '/transactions/status': () => ({
          type: 'Confirmed',
          blockHash: 'ef'.repeat(32),
          txIndex: 0,
        }),
        [`/blockflow/blocks/${'ef'.repeat(32)}`]: () => ({
          hash: 'ef'.repeat(32),
          timestamp: 1_792_176_886_249,
          height: 514740,
          chainFrom: 3,
          chainTo: 3,
        }),
      }).fetchImpl,
    );
    const done = await confirmed.status(id, ALEPHIUM_TESTNET);
    expect(done).toEqual({
      state: 'confirmed',
      blockNumber: 514740,
      timestampMs: 1_792_176_886_249,
    });
  });

  it('pins the SDK signature vector (cross-check with the Rust test)', () => {
    // The core signs with RFC 6979 + low-S over the tx id as the digest.
    const sig = secp256k1.sign(hexToBytes(TXID_VECTOR), hexToBytes(KEY_ONE), {
      prehash: false,
      format: 'compact',
    });
    expect(bytesToHex(sig)).toBe(SIGNATURE_VECTOR);
  });
});
