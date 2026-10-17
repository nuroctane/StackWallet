import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  XrplTx,
  broadcastXrpl,
  prepareXrpl,
  xrplApprovalValid,
  xrplBlobHash,
  xrplFields,
  xrplSigningHash,
  xrplSigningPayload,
  xrplTransferStatus,
} from './send.js';
import {
  LSF_REQUIRE_DEST_TAG,
  XRPL_MAINNET,
  XRPL_TESTNET,
  XrplAdapter,
  isValidXrplAddress,
  webSocketUrl,
  xrplAddressFromPublicKey,
  type WebSocketCtor,
} from './xrpl.js';

const ONE = hexToBytes('00'.repeat(31) + '01');
const ONE_PUBLIC = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
/** `ripple-keypairs.deriveAddress` of secret key 1. */
const ONE_ADDRESS = 'rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH';
const RECIPIENT = 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe';
const GENESIS = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

const tx: XrplTx = {
  chainId: XRPL_TESTNET,
  from: ONE_ADDRESS,
  to: RECIPIENT,
  drops: '1500000',
  fee: 12,
  sequence: 1_234_567,
  lastLedgerSequence: 21_564_000,
  builtAtLedger: 21_563_550,
  destinationTag: 12345,
  publicKeyHex: ONE_PUBLIC,
};
/** `ripple-binary-codec`, `ripple-keypairs` and `xrpl` output for the same fields; pinned by the core (`xrpl.rs`). */
const TAG_SIGNING_VECTOR =
  '535458001200002200000000240012D6872E00003039201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817988114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8';
const TAG_BLOB_VECTOR =
  '1200002200000000240012D6872E00003039201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179874463044022059D7EFE1EDC50C6A8CD48DA5DD29BA0E959E317D2DE7F317A365CF20790FBDBF02203E04418A7B5925331F805BD0662C7CC07B864BF63ACA83E5295ECEBCD660E2CB8114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8';
const TAG_HASH_VECTOR = '2F4B4D918AB68BF6A51D0388BC07F6411814CD67CC6702BD3D9308AEB28A03B5';
const SIGNING_VECTOR =
  '535458001200002200000000240012D687201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817988114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8';
const BLOB_VECTOR =
  '1200002200000000240012D687201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817987446304402204642E4ECDB7CE25974D21CF06F3920982BC2CE36F985B666F0AF6EE790467563022074486FE5A9E8440D584CE89703E44762BDE755E80A36E6106F35DE4CC3BD2F998114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8';
const HASH_VECTOR = '495B5003C925F46D0EFD2D37D98433AD5E6DFC9AFBDBE647541713557EF4A93C';
const hexUp = (b: Uint8Array) => bytesToHex(b).toUpperCase();

const chain = (chainId: string, name: string, testnet: boolean, rpcs: string[]): ChainInfo => ({
  chainId,
  family: 'xrpl',
  name,
  nativeAsset: { ref: `${chainId}:native`, symbol: 'XRP', decimals: 6 },
  testnet,
  defaultRpcs: rpcs,
});
const CHAINS: ChainInfo[] = [
  chain(XRPL_MAINNET, 'XRP Ledger', false, ['https://xrplcluster.com', 'https://xrpl.ws']),
  chain(XRPL_TESTNET, 'XRP Ledger Testnet', true, ['https://testnet.xrpl-labs.com']),
];

class TestAdapter extends XrplAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Handler = (params: Record<string, unknown>) => unknown;

function rippled(methods: Record<string, Handler>, networkId = 1) {
  const calls: { url: string; method: string; params: Record<string, unknown> }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params: [Record<string, unknown>];
    };
    calls.push({ url: String(input), method: body.method, params: body.params[0] });
    if (body.method === 'server_state' && !methods.server_state)
      return Response.json({
        result: {
          status: 'success',
          state: {
            network_id: networkId,
            validated_ledger: {
              seq: 21_563_549,
              base_fee: 10,
              reserve_base: 1_000_000,
              reserve_inc: 200_000,
            },
          },
        },
      });
    const handler = methods[body.method];
    const result = handler ? handler(body.params[0]) : { status: 'error', error: 'unknownCmd' };
    return Response.json({ result });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });
}

const notFound = { status: 'error', error: 'actNotFound', error_message: 'Account not found.' };
const accountData = (Account: string, Balance: string, Sequence: number, extra = {}) => ({
  status: 'success',
  validated: true,
  account_data: { Account, Balance, Flags: 0, OwnerCount: 0, Sequence, ...extra },
});
const feeResult = (open = '10') => ({
  status: 'success',
  ledger_current_index: 21_563_550,
  drops: { base_fee: '10', minimum_fee: '10', median_fee: '5000', open_ledger_fee: open },
});

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: XRPL_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${XRPL_TESTNET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  } as unknown as TxIntent;
}

describe('xrpl addresses', () => {
  it('derives classic addresses from compressed and uncompressed keys', () => {
    expect(xrplAddressFromPublicKey(hexToBytes(ONE_PUBLIC))).toBe(ONE_ADDRESS);
    expect(xrplAddressFromPublicKey(secp256k1.getPublicKey(ONE, false))).toBe(ONE_ADDRESS);
    // The genesis account from the XRPL docs.
    expect(
      xrplAddressFromPublicKey(
        hexToBytes('0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020'),
      ),
    ).toBe(GENESIS);
    const a = new TestAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: ONE_PUBLIC }, XRPL_TESTNET)).toBe(
      ONE_ADDRESS,
    );
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '11'.repeat(32) }, XRPL_TESTNET),
    ).toThrow();
  });

  it('refuses bad checksums, X-addresses, seeds and black holes', () => {
    expect(isValidXrplAddress(RECIPIENT)).toBe(true);
    expect(isValidXrplAddress(GENESIS)).toBe(true);
    expect(isValidXrplAddress('rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYf')).toBe(false);
    expect(isValidXrplAddress('XVLhHMPHU98es4dbozjVtdWzVrDjtV18pX8yuPT7y4xaEHi')).toBe(false);
    expect(isValidXrplAddress('snoPBrXtMeMyMHUVTgbuqAfg1SUTb')).toBe(false);
    expect(isValidXrplAddress('rrrrrrrrrrrrrrrrrrrrrhoLvTp')).toBe(false);
    expect(isValidXrplAddress('rrrrrrrrrrrrrrrrrrrrBZbvji')).toBe(false);
    expect(isValidXrplAddress(` ${RECIPIENT}`)).toBe(false);
  });
});

describe('xrpl payments', () => {
  it('encodes and signs exactly like the SDK and the core', () => {
    expect(hexUp(xrplSigningPayload(tx))).toBe(TAG_SIGNING_VECTOR);
    const sig = secp256k1.sign(xrplSigningHash(tx), ONE, { prehash: false, format: 'der' });
    const blob = xrplFields(tx, sig);
    expect(hexUp(blob)).toBe(TAG_BLOB_VECTOR);
    expect(xrplBlobHash(blob)).toBe(TAG_HASH_VECTOR);
    const untagged: XrplTx = { ...tx };
    delete untagged.destinationTag;
    expect(hexUp(xrplSigningPayload(untagged))).toBe(SIGNING_VECTOR);
    const sig2 = secp256k1.sign(xrplSigningHash(untagged), ONE, { prehash: false, format: 'der' });
    expect(hexUp(xrplFields(untagged, sig2))).toBe(BLOB_VECTOR);
    expect(xrplBlobHash(hexToBytes(BLOB_VECTOR))).toBe(HASH_VECTOR);
  });

  it('refuses hostile fields', () => {
    for (const drops of ['0', '01500000', '100000000000000001', '1.5'])
      expect(() => xrplFields({ ...tx, drops })).toThrow();
    expect(() => xrplFields({ ...tx, to: tx.from })).toThrow();
    expect(() => xrplFields({ ...tx, fee: 9 })).toThrow();
    expect(() => xrplFields({ ...tx, fee: 1_000_001 })).toThrow();
    expect(() => xrplFields({ ...tx, sequence: 0 })).toThrow();
    expect(() => xrplFields({ ...tx, lastLedgerSequence: tx.builtAtLedger })).toThrow();
    expect(() => xrplFields({ ...tx, lastLedgerSequence: tx.builtAtLedger + 2001 })).toThrow();
    expect(() => xrplFields({ ...tx, destinationTag: 2 ** 32 })).toThrow();
    expect(() => xrplFields({ ...tx, publicKeyHex: '03' + ONE_PUBLIC.slice(2) })).toThrow();
    expect(() => xrplFields({ ...tx, publicKeyHex: ONE_PUBLIC.toUpperCase() })).toThrow();
    expect(() => xrplFields({ ...tx, chainId: XRPL_MAINNET as typeof XRPL_TESTNET })).toThrow();
    expect(() => XrplTx.parse({ ...tx, memo: 'hi' })).toThrow();
  });

  it('prepares a payment with the open-ledger fee and the current sequence', async () => {
    const { fetchImpl, calls } = rippled({
      account_info: (p) =>
        p.account === ONE_ADDRESS
          ? accountData(ONE_ADDRESS, '50000000', 1_234_567)
          : accountData(RECIPIENT, '1', 9),
      fee: () => feeResult('15'),
    });
    const { unsigned, simulation } = await prepareXrpl(
      adapter(fetchImpl),
      intent(RECIPIENT, '1500000'),
      ONE_ADDRESS,
      ONE_PUBLIC,
      { destinationTag: 12345 },
    );
    expect(unsigned).toEqual({
      ...tx,
      fee: 15,
      lastLedgerSequence: 21_563_850,
    });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('15');
    const sender = calls.find(
      (c) => c.method === 'account_info' && c.params.account === ONE_ADDRESS,
    );
    expect(sender?.params.ledger_index).toBe('current');
  });

  it('enforces the base reserve for unfunded recipients and the sender reserve', async () => {
    const { fetchImpl } = rippled({
      account_info: (p) =>
        p.account === ONE_ADDRESS
          ? accountData(ONE_ADDRESS, '2000000', 5, { OwnerCount: 2 })
          : notFound,
      fee: () => feeResult(),
    });
    const a = adapter(fetchImpl);
    await expect(
      prepareXrpl(a, intent(RECIPIENT, '999999'), ONE_ADDRESS, ONE_PUBLIC),
    ).rejects.toThrow(/at least 1000000 drops/);
    // 2 XRP minus 1 XRP base and 0.4 XRP owner reserve leaves 0.6 XRP.
    const { unsigned, simulation } = await prepareXrpl(
      a,
      intent(RECIPIENT, '1000000'),
      ONE_ADDRESS,
      ONE_PUBLIC,
    );
    expect(unsigned.destinationTag).toBeUndefined();
    expect(simulation.ok).toBe(false);
    expect(simulation.warnings[0]?.kind).toBe('other');
  });

  it('flags a recipient that requires a destination tag', async () => {
    const { fetchImpl } = rippled({
      account_info: (p) =>
        p.account === ONE_ADDRESS
          ? accountData(ONE_ADDRESS, '50000000', 5)
          : accountData(RECIPIENT, '1', 9, { Flags: LSF_REQUIRE_DEST_TAG }),
      fee: () => feeResult('99999999'),
    });
    const { unsigned, simulation } = await prepareXrpl(
      adapter(fetchImpl),
      intent(RECIPIENT, '1500000'),
      ONE_ADDRESS,
      ONE_PUBLIC,
    );
    expect(unsigned.fee).toBe(100_000);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/destination tag/);
  });

  it('refuses an endpoint on the wrong network', async () => {
    const { fetchImpl } = rippled({ account_info: () => notFound }, 0);
    await expect(adapter(fetchImpl).getBalances(ONE_ADDRESS, XRPL_TESTNET)).rejects.toThrow();
  });

  it('checks approval against the sequence, recipient and ledger window', async () => {
    let seq = 1_234_567;
    let current = 21_563_600;
    let funded = true;
    const { fetchImpl } = rippled({
      account_info: (p) =>
        p.account === ONE_ADDRESS
          ? accountData(ONE_ADDRESS, '50000000', seq)
          : funded
            ? accountData(RECIPIENT, '1', 9)
            : notFound,
      fee: () => ({ ...feeResult(), ledger_current_index: current }),
    });
    const a = adapter(fetchImpl);
    expect(await xrplApprovalValid(a, tx)).toBe(true);
    funded = false;
    expect(await xrplApprovalValid(a, { ...tx, drops: '999999' })).toBe(false);
    expect(await xrplApprovalValid(a, { ...tx, drops: '1000000' })).toBe(true);
    funded = true;
    current = tx.lastLedgerSequence - 20;
    expect(await xrplApprovalValid(a, tx)).toBe(false);
    current = 21_563_600;
    seq += 1;
    expect(await xrplApprovalValid(a, tx)).toBe(false);
  });

  it('broadcasts only the expected signed blob', async () => {
    const { fetchImpl, calls } = rippled({
      submit: () => ({
        status: 'success',
        engine_result: 'tesSUCCESS',
        engine_result_message: 'The transaction was applied.',
        tx_json: { hash: TAG_HASH_VECTOR },
      }),
    });
    const a = adapter(fetchImpl);
    expect(await broadcastXrpl(a, tx, `0x${TAG_BLOB_VECTOR.toLowerCase()}`)).toBe(TAG_HASH_VECTOR);
    expect(calls.find((c) => c.method === 'submit')?.params.tx_blob).toBe(TAG_BLOB_VECTOR);
    // Flip one bit of s: still DER, but no longer a valid signature.
    const forged = TAG_BLOB_VECTOR.replace('2CB8114', '2CA8114');
    await expect(broadcastXrpl(a, tx, forged)).rejects.toThrow(/verify/);
    await expect(broadcastXrpl(a, { ...tx, drops: '1500001' }, TAG_BLOB_VECTOR)).rejects.toThrow(
      /not this XRP payment/,
    );
    await expect(broadcastXrpl(a, tx, BLOB_VECTOR)).rejects.toThrow(/not this XRP payment/);
    await expect(broadcastXrpl(a, tx, TAG_BLOB_VECTOR + '00')).rejects.toThrow();
  });

  it('surfaces engine results on rejection and accepts its own past-sequence retry', async () => {
    let known = false;
    const { fetchImpl } = rippled({
      submit: () => ({
        status: 'success',
        engine_result: known ? 'tefPAST_SEQ' : 'tefMAX_LEDGER',
        engine_result_message: 'Ledger sequence too high.',
      }),
      tx: () =>
        known
          ? {
              status: 'success',
              hash: TAG_HASH_VECTOR,
              validated: true,
              ledger_index: 21_563_560,
              meta: { TransactionResult: 'tesSUCCESS' },
            }
          : { status: 'error', error: 'txnNotFound' },
    });
    const a = adapter(fetchImpl);
    await expect(broadcastXrpl(a, tx, TAG_BLOB_VECTOR)).rejects.toThrow(
      'Broadcast rejected: tefMAX_LEDGER Ledger sequence too high.',
    );
    known = true;
    expect(await broadcastXrpl(a, tx, TAG_BLOB_VECTOR)).toBe(TAG_HASH_VECTOR);
  });

  it('reports pending, confirmed, failed and expired payments', async () => {
    let found: unknown;
    let validatedSeq = 21_563_900;
    const { fetchImpl } = rippled({
      tx: () => found ?? { status: 'error', error: 'txnNotFound' },
      account_info: () => accountData(ONE_ADDRESS, '50000000', tx.sequence),
      server_state: () => ({
        status: 'success',
        state: {
          network_id: 1,
          validated_ledger: {
            seq: validatedSeq,
            base_fee: 10,
            reserve_base: 1e6,
            reserve_inc: 2e5,
          },
        },
      }),
    });
    const a = adapter(fetchImpl);
    expect(await xrplTransferStatus(a, tx, TAG_HASH_VECTOR)).toEqual({ state: 'unknown' });
    validatedSeq = tx.lastLedgerSequence + 1;
    expect(await xrplTransferStatus(a, tx, TAG_HASH_VECTOR)).toEqual({ state: 'expired' });
    found = { status: 'success', hash: TAG_HASH_VECTOR, validated: false };
    validatedSeq = 21_563_900;
    expect(await xrplTransferStatus(a, tx, TAG_HASH_VECTOR)).toEqual({ state: 'pending' });
    found = {
      status: 'success',
      hash: TAG_HASH_VECTOR,
      validated: true,
      ledger_index: 21_563_560,
      close_time_iso: '2026-10-15T22:19:01Z',
      meta: { TransactionResult: 'tesSUCCESS' },
    };
    expect(await xrplTransferStatus(a, tx, TAG_HASH_VECTOR)).toEqual({
      state: 'confirmed',
      blockNumber: 21_563_560,
      timestampMs: Date.parse('2026-10-15T22:19:01Z'),
    });
    found = { ...(found as object), meta: { TransactionResult: 'tecNO_DST_INSUF_XRP' } };
    expect(await a.status(TAG_HASH_VECTOR.toLowerCase(), XRPL_TESTNET)).toEqual({
      state: 'failed',
      reason: 'tecNO_DST_INSUF_XRP',
    });
  });
});

describe('xrpl websocket transport', () => {
  it('maps rippled JSON-RPC ports to their WebSocket ports only', () => {
    expect(webSocketUrl('https://s.altnet.rippletest.net:51234')).toBe(
      'wss://s.altnet.rippletest.net:51233/',
    );
    expect(webSocketUrl('https://s1.ripple.com:51234/')).toBe('wss://s1.ripple.com/');
    expect(webSocketUrl('https://xrplcluster.com')).toBeUndefined();
    expect(webSocketUrl('http://s1.ripple.com:51234')).toBeUndefined();
    expect(webSocketUrl('https://u:p@s1.ripple.com:51234')).toBeUndefined();
  });

  it('reads balances over a socket and maps top-level errors', async () => {
    const urls: string[] = [];
    let funded = true;
    class FakeSocket {
      onopen: (() => void) | null = null;
      onmessage: ((ev: { data: string }) => void) | null = null;
      onerror: (() => void) | null = null;
      onclose: (() => void) | null = null;
      constructor(url: string) {
        urls.push(url);
        setTimeout(() => this.onopen?.(), 0);
      }
      send(data: string) {
        const req = JSON.parse(data) as { id: number; command: string };
        const reply =
          req.command === 'server_state'
            ? {
                id: req.id,
                status: 'success',
                type: 'response',
                result: { state: { network_id: 1 } },
              }
            : funded
              ? {
                  id: req.id,
                  status: 'success',
                  type: 'response',
                  result: accountData(ONE_ADDRESS, '42', 3),
                }
              : { id: req.id, status: 'error', type: 'response', error: 'actNotFound' };
        setTimeout(() => {
          this.onmessage?.({ data: JSON.stringify({ id: 99, type: 'other' }) });
          this.onmessage?.({ data: JSON.stringify(reply) });
        }, 0);
      }
      close() {
        this.onclose = null;
      }
    }
    const chains = [
      chain(XRPL_TESTNET, 'XRP Ledger Testnet', true, ['https://s.altnet.rippletest.net:51234']),
    ];
    class WsAdapter extends XrplAdapter {
      override chains(): ChainInfo[] {
        return chains;
      }
    }
    const a = new WsAdapter({
      rpc: new MemoryRpcPool(chains),
      webSocket: FakeSocket as unknown as WebSocketCtor,
      fetch: (() => Promise.reject(new Error('no http'))) as unknown as typeof fetch,
    });
    expect((await a.getBalances(ONE_ADDRESS, XRPL_TESTNET))[0]?.amount).toBe('42');
    funded = false;
    expect((await a.getBalances(ONE_ADDRESS, XRPL_TESTNET))[0]?.amount).toBe('0');
    expect(new Set(urls)).toEqual(new Set(['wss://s.altnet.rippletest.net:51233/']));
  });
});

describe('xrpl reads', () => {
  it('reads an unfunded account as zero', async () => {
    const { fetchImpl } = rippled({ account_info: () => notFound });
    const [native] = await adapter(fetchImpl).getBalances(ONE_ADDRESS, XRPL_TESTNET);
    expect(native?.amount).toBe('0');
    expect(native?.assetRef).toBe(`${XRPL_TESTNET}:native`);
  });

  it('reads mainnet XRP from two agreeing endpoints', async () => {
    const { fetchImpl, calls } = rippled(
      { account_info: () => accountData(GENESIS, '56785837001', 44196) },
      0,
    );
    const [native] = await adapter(fetchImpl).getBalances(GENESIS, XRPL_MAINNET);
    expect(native?.amount).toBe('56785837001');
    expect(native?.provenance?.kind).toBe('agreed');
    expect(new Set(calls.map((c) => new URL(c.url).host))).toEqual(
      new Set(['xrplcluster.com', 'xrpl.ws']),
    );
  });

  it('maps payments and other transactions into history', async () => {
    const { fetchImpl, calls } = rippled({
      account_tx: () => ({
        status: 'success',
        marker: { ledger: 21_000_000, seq: 3 },
        transactions: [
          {
            hash: TAG_HASH_VECTOR,
            ledger_index: 21_563_560,
            close_time_iso: '2026-10-15T22:19:01Z',
            validated: true,
            tx_json: {
              TransactionType: 'Payment',
              Account: ONE_ADDRESS,
              Destination: RECIPIENT,
              DeliverMax: '1500000',
              Fee: '12',
            },
            meta: { TransactionResult: 'tesSUCCESS', delivered_amount: '1500000' },
          },
          {
            hash: HASH_VECTOR,
            ledger_index: 21_563_000,
            validated: true,
            tx_json: {
              TransactionType: 'Payment',
              Account: RECIPIENT,
              Destination: ONE_ADDRESS,
              Fee: '10',
            },
            meta: { TransactionResult: 'tesSUCCESS', delivered_amount: '25000000' },
          },
          {
            hash: 'A'.repeat(64),
            validated: true,
            tx_json: { TransactionType: 'TrustSet', Account: ONE_ADDRESS, Fee: '10' },
            meta: { TransactionResult: 'tesSUCCESS' },
          },
        ],
      }),
    });
    const a = adapter(fetchImpl);
    const page = await a.getHistory(ONE_ADDRESS, XRPL_TESTNET, '21000100:7');
    expect(page.items.map((i) => [i.hash.slice(0, 6), i.assetDeltas[0]?.amount, i.fee])).toEqual([
      ['2F4B4D', '-1500000', '12'],
      ['495B50', '25000000', null],
      ['AAAAAA', undefined, '10'],
    ]);
    expect(page.items[2]?.description).toBe('TrustSet');
    expect(page.nextCursor).toBe('21000000:3');
    expect(calls.find((c) => c.method === 'account_tx')?.params.marker).toEqual({
      ledger: 21_000_100,
      seq: 7,
    });
    await expect(a.getHistory(ONE_ADDRESS, XRPL_TESTNET, 'x;y')).rejects.toThrow();
  });
});
