import { MemoryRpcPool } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  STARCOIN_BARNARD,
  STARCOIN_CHAINS,
  STARCOIN_MAINNET,
  StarcoinAdapter,
  createStarcoinAdapter,
  isValidStarcoinAddress,
  starcoinAddressFromPublicKey,
} from './starcoin.js';
import {
  StarcoinTx,
  broadcastStarcoin,
  prepareStarcoin,
  rawTransactionId,
  rawUserTransactionBytes,
  signedTxHash,
  signedWireBytes,
  signingMessage,
  starcoinApprovalValid,
  starcoinTransferStatus,
} from './send.js';

/** Vectors produced by `@starcoin/starcoin` 2.3.7 and the Rust core for secret 0x07..07. */
const PUBLIC = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c';
const SENDER = '0xe61b780ad0935f3363bc7fce64edbdad';
const RECIPIENT = '0xd8f5a2f3b1c4e5a69788776655443322';
const RAW_HEX =
  'e61b780ad0935f3363bc7fce64edbdad290000000000000002000000000000000000000000000000010f5472616e73666572536372697074731d706565725f746f5f706565725f776974685f6d657461646174615f76320107000000000000000000000000000000010353544303535443000310d8f5a2f3b1c4e5a697887766554433221015cd5b0700000000000000000000000000809698000000000001000000000000000d3078313a3a5354433a3a53544380e14e6800000000fb';
const RAW_ID = '0x028c49948238b53c1fe4c2c4acb871f48b17b6e9fe1aa9d85c71c044af8aba3f';
const SIGNED_HEX =
  'e61b780ad0935f3363bc7fce64edbdad290000000000000002000000000000000000000000000000010f5472616e73666572536372697074731d706565725f746f5f706565725f776974685f6d657461646174615f76320107000000000000000000000000000000010353544303535443000310d8f5a2f3b1c4e5a697887766554433221015cd5b0700000000000000000000000000809698000000000001000000000000000d3078313a3a5354433a3a53544380e14e6800000000fb0020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c402313b4bb295d7ef908f38e9e24dfa5cc695f66e65025c4a7d1dc8728c4ccba6ad411bade3850e263afa6b936ff925d40cf46e22c349b9469f31d4f0582471708';
const TX_HASH = '0xb14893aea75d9bea680fc5742b6a0659c7973f414c69d1711c77af20180f1bf4';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

const tx: StarcoinTx = {
  chainId: STARCOIN_BARNARD,
  from: SENDER,
  to: RECIPIENT,
  nano: '123456789',
  sequenceNumber: 41,
  maxGasAmount: 10_000_000,
  gasUnitPrice: 1,
  expirationTimestampSecs: 1_750_000_000,
};

function intent(overrides: Partial<TxIntent> = {}): TxIntent {
  return {
    chainId: STARCOIN_BARNARD,
    kind: 'transfer',
    to: RECIPIENT,
    asset: `${STARCOIN_BARNARD}:native`,
    amount: '123456789',
    ...overrides,
  } as TxIntent;
}

function rpc(routes: Record<string, (params: unknown[]) => unknown>) {
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
    const route = routes[body.method];
    if (!route)
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'not found' } }),
        { status: 200 },
      );
    const result = route(body.params ?? []);
    if (result instanceof Error)
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: result.message } }),
        { status: 200 },
      );
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
  }) as typeof fetch;
  return new StarcoinAdapter({
    fetch: fetchImpl,
    rpc: new MemoryRpcPool(
      STARCOIN_CHAINS.map((c) => ({ ...c, defaultRpcs: ['https://node.test'] })),
    ),
  });
}

const INFO = {
  'chain.info': () => ({ chain_id: 251, head: { number: '7000000' } }),
};

describe('starcoin addresses', () => {
  it('derives the SDK address of the fixed key', () => {
    expect(starcoinAddressFromPublicKey(hexToBytes(PUBLIC))).toBe(SENDER);
    const a = createStarcoinAdapter();
    expect(a.deriveAddress({ curve: 'ed25519', hex: PUBLIC }, STARCOIN_BARNARD)).toBe(SENDER);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, STARCOIN_BARNARD),
    ).toThrow();
  });

  it('validates canonical addresses only', () => {
    expect(isValidStarcoinAddress(SENDER)).toBe(true);
    expect(isValidStarcoinAddress('0x00000000000000000000000000000001')).toBe(true);
    expect(isValidStarcoinAddress('0x00000000000000000000000000000000')).toBe(false);
    expect(isValidStarcoinAddress(SENDER.toUpperCase().replace('0X', '0x'))).toBe(false);
    expect(isValidStarcoinAddress('0x1')).toBe(false);
    expect(isValidStarcoinAddress(SENDER.slice(2))).toBe(false);
  });
});

describe('starcoin transfers', () => {
  it('encodes the same BCS bytes as the core and the SDK', () => {
    expect(bytesToHexLocal(rawUserTransactionBytes(tx))).toBe(RAW_HEX);
    expect(rawTransactionId(tx)).toBe(RAW_ID);
    expect(signingMessage(tx).length).toBe(32 + RAW_HEX.length / 2);
  });

  it('hashes the signed bytes like the SDK', () => {
    const wire = signedWireBytes(tx, SIGNED_HEX);
    expect(signedTxHash(wire)).toBe(TX_HASH);
  });

  it('refuses hostile fields', () => {
    expect(() => rawUserTransactionBytes({ ...tx, nano: '0' })).toThrow();
    expect(() => rawUserTransactionBytes({ ...tx, nano: '01' })).toThrow();
    expect(() => rawUserTransactionBytes({ ...tx, to: tx.from })).toThrow();
    expect(() => rawUserTransactionBytes({ ...tx, gasUnitPrice: 0 })).toThrow();
    expect(() =>
      rawUserTransactionBytes({ ...tx, chainId: STARCOIN_MAINNET as typeof STARCOIN_BARNARD }),
    ).toThrow();
    expect(() => signedWireBytes(tx, `0x${'00'.repeat(64)}`)).toThrow();
    const wrongKey = hexToBytes(SIGNED_HEX);
    const flip = RAW_HEX.length / 2 + 3;
    wrongKey[flip] = wrongKey[flip]! ^ 1;
    expect(() => signedWireBytes(tx, bytesToHexLocal(wrongKey))).toThrow();
  });

  it('prepares a Barnard transfer from node state', async () => {
    const adapter = rpc({
      ...INFO,
      'state.get_resource': (_p: unknown[]) => {
        const params = _p as unknown[];
        return String(params[1]).includes('Balance')
          ? { raw: '0x0010a5d4e80000000000000000000000' } // 1000 STC
          : { json: { sequence_number: 7 } };
      },
      'txpool.gas_price': () => '2',
      'txpool.next_sequence_number': () => null,
    });
    const prepared = await prepareStarcoin(adapter, intent(), SENDER, 1_760_000_000_000);
    expect(prepared.unsigned.sequenceNumber).toBe(7);
    expect(prepared.unsigned.gasUnitPrice).toBe(2);
    expect(prepared.unsigned.expirationTimestampSecs).toBe(1_760_000_000 + 1800);
    expect(prepared.simulation.ok).toBe(true);
    expect(prepared.simulation.fee.amount).toBe('8000000');
  });

  it('fails preparation for a missing sender account', async () => {
    const adapter = rpc({
      ...INFO,
      'state.get_resource': () => new Error('resource not found'),
      'txpool.gas_price': () => '1',
      'txpool.next_sequence_number': () => null,
    });
    const prepared = await prepareStarcoin(adapter, intent(), SENDER);
    expect(prepared.simulation.ok).toBe(false);
    expect(prepared.simulation.error).toMatch(/does not exist/);
  });

  it('validates approval against expiry and sequence', async () => {
    const fresh = { ...tx, expirationTimestampSecs: 1_760_000_000, sequenceNumber: 7 };
    const adapter = rpc({
      ...INFO,
      'chain.get_block_by_number': () => ({ header: { timestamp: '1759900000000' } }),
      'state.get_resource': () => ({ json: { sequence_number: 7 } }),
    });
    expect(await starcoinApprovalValid(adapter, fresh, 1_759_900_000_000)).toBe(true);
    expect(await starcoinApprovalValid(adapter, fresh, 1_759_999_950_000)).toBe(false);
    const moved = rpc({
      ...INFO,
      'chain.get_block_by_number': () => ({ header: { timestamp: '1759900000000' } }),
      'state.get_resource': () => ({ json: { sequence_number: 8 } }),
    });
    expect(await starcoinApprovalValid(moved, fresh, 1_759_900_000_000)).toBe(false);
  });

  it('broadcasts exactly the expected wire and returns the tx hash', async () => {
    let submitted: unknown;
    const adapter = rpc({
      ...INFO,
      'txpool.submit_hex_transaction': (params) => {
        submitted = params[0];
        return TX_HASH;
      },
    });
    const hash = await broadcastStarcoin(adapter, tx, `0x${SIGNED_HEX}`);
    expect(hash).toBe(TX_HASH);
    expect(submitted).toBe(`0x${SIGNED_HEX}`);
    // Corrupting a byte inside the raw transaction must be caught before submit.
    const corrupted = hexToBytes(SIGNED_HEX);
    corrupted[10] = corrupted[10]! ^ 1;
    await expect(broadcastStarcoin(adapter, tx, `0x${bytesToHexLocal(corrupted)}`)).rejects.toThrow(
      /not this STC transfer/,
    );
  });

  it('reports confirmed, failed, unknown and expired', async () => {
    const confirmed = rpc({
      ...INFO,
      'chain.get_transaction_info': () => ({ status: 'Executed', block_number: '7000001' }),
    });
    expect(await adapter_status(confirmed)).toEqual({ state: 'confirmed', blockNumber: 7000001 });
    const failed = rpc({
      ...INFO,
      'chain.get_transaction_info': () => ({ status: 'MoveAbort', block_number: '7000001' }),
    });
    expect((await adapter_status(failed)).state).toBe('failed');
    const unknown = rpc({
      ...INFO,
      'chain.get_transaction_info': () => new Error('not found'),
      'chain.get_block_by_number': () => ({ header: { timestamp: '1750000100000' } }),
    });
    const old = { ...tx, expirationTimestampSecs: 1_750_000_000 };
    expect(await starcoinTransferStatus(unknown, old, TX_HASH)).toEqual({ state: 'expired' });
    const young = rpc({
      ...INFO,
      'chain.get_transaction_info': () => new Error('not found'),
      'chain.get_block_by_number': () => ({ header: { timestamp: '1749999000000' } }),
    });
    expect(await starcoinTransferStatus(young, old, TX_HASH)).toEqual({ state: 'unknown' });
  });
});

function bytesToHexLocal(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function adapter_status(a: StarcoinAdapter) {
  return a.status(TX_HASH, STARCOIN_BARNARD);
}
