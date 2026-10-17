import { ed25519 } from '@noble/curves/ed25519.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  AETERNITY_TESTNET,
  AeternityTx,
  aeternityApprovalValid,
  aeternityTransferStatus,
  broadcastAeternity,
  prepareAeternity,
  spendRlp,
  spendSighash,
  spendUnsignedTx,
} from './send.js';
import {
  AeternityAdapter,
  aeternityAddressFromPublicKey,
  aeternityTxHash,
  decodeChecked,
  decodeSpendTx,
  encodeChecked,
  isValidAeternityAddress,
  parseAeJson,
} from './aeternity.js';

/** seed 0x07*32; vectors produced by @aeternity/aepp-sdk 15.0.1. */
const SECRET = '07'.repeat(32);
const SENDER = 'ak_2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK';
const RECIPIENT = 'ak_4yo5ZzPDUKCsoucyTX2GfktgoyjxM9cjFUWqkiQsUJrWLdLS7';

const tx: AeternityTx = {
  chainId: AETERNITY_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  aettos: '123456789012345678',
  fee: '20000000000000',
  ttl: 12345,
  nonce: 42,
};
/** Pinned by the Rust core's encoder (`aeternity.rs` tests) and the aepp-sdk. */
const UNSIGNED_RLP_HEX =
  'f85b0c01a101ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca10109090909090909090909090909090909090909090909090909090909090909098801b69b4ba630f34e8612309ce540008230392a80';
const UNSIGNED_TX =
  'tx_+FsMAaEB6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iyhAQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJiAG2m0umMPNOhhIwnOVAAIIwOSqAy8BfRA==';
const SIGHASH_HEX = '61655f7561747656f261cb0755469bae1d31646afced7e80eb228dca3c05c306c4f158a21fac';
const SIGNED_TX =
  'tx_+KULAfhCuEA1SmSAelItWslxxrdAjm3YUesQzOrfdXhyCFaQYDn49S+WmAOUi/cZt8lAZwB02trpaO+B+5MS+v2AokE2IlECuF34WwwBoQHqSmxj4pxSCr71UHsTLsX5lUd2rr6+e5JCHuppFEbSLKEBCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQmIAbabS6Yw806GEjCc5UAAgjA5KoApenxY';
const TX_HASH = 'th_KFzgyySVPVKzB6bk5redoSMLhDNmDyhEZyi2zHnzSVPcKGsxf';

const CHAINS: ChainInfo[] = [
  {
    chainId: AETERNITY_TESTNET,
    family: 'aeternity',
    name: 'Aeternity testnet',
    nativeAsset: { ref: `${AETERNITY_TESTNET}:native`, symbol: 'AE', decimals: 18 },
    testnet: true,
    defaultRpcs: ['https://node-a.example', 'https://node-b.example'],
  },
];

function node(routes: Record<string, (body: unknown) => unknown>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(`${init?.method ?? 'GET'} ${url.host}${url.pathname}${url.search}`);
    const key = url.pathname;
    const route = routes[key];
    if (!route) return new Response('{"reason":"not found"}', { status: 404 });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const out = route(body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const okStatus = () => ({ network_id: 'ae_uat', top_block_height: 1_304_587 });

function adapter(fetchImpl: typeof fetch) {
  const a = new AeternityAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });
  // The lead wires aeternity into the curated catalog; tests inject it directly.
  a.chains = () => CHAINS;
  return a;
}

describe('aeternity addresses', () => {
  it('derives the base58check ak_ address of the SDK seed', () => {
    const pub = ed25519.getPublicKey(Uint8Array.from(Buffer.from(SECRET, 'hex')));
    expect(aeternityAddressFromPublicKey(pub)).toBe(SENDER);
    const a = new AeternityAdapter();
    a.chains = () => CHAINS;
    expect(
      a.deriveAddress(
        { curve: 'ed25519', hex: Buffer.from(pub).toString('hex') },
        AETERNITY_TESTNET,
      ),
    ).toBe(SENDER);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '00'.repeat(32) }, AETERNITY_TESTNET),
    ).toThrow();
  });

  it('round-trips checked encodings and refuses bad ones', () => {
    expect(isValidAeternityAddress(SENDER)).toBe(true);
    expect(isValidAeternityAddress(RECIPIENT)).toBe(true);
    expect(isValidAeternityAddress(SENDER.slice(0, -1) + 'L')).toBe(false);
    expect(isValidAeternityAddress(SENDER.replace('ak_', 'ct_'))).toBe(false);
    expect(isValidAeternityAddress('ak_' + '1'.repeat(51))).toBe(false);
    const payload = decodeChecked(SENDER, 'ak')!;
    expect(encodeChecked('ak', payload)).toBe(SENDER);
    expect(aeternityTxHash(SIGNED_TX)).toBe(TX_HASH);
    expect(decodeChecked(SIGNED_TX, 'tx')!.length).toBeGreaterThan(150);
  });

  it('keeps balances above 2^53 exact', () => {
    const parsed = parseAeJson('{"balance":5000000000000000000,"nonce":3}') as Record<
      string,
      unknown
    >;
    expect(parsed.balance).toBe('5000000000000000000');
    expect(parsed.nonce).toBe(3);
  });
});

describe('aeternity transfers', () => {
  it('encodes the same unsigned RLP as the core and the SDK', () => {
    expect(Buffer.from(spendRlp(tx)).toString('hex')).toBe(UNSIGNED_RLP_HEX);
    expect(spendUnsignedTx(tx)).toBe(UNSIGNED_TX);
    expect(Buffer.from(spendSighash(tx)).toString('hex')).toBe(SIGHASH_HEX);
  });

  it('decodes the signed SDK vector back to the spend fields', () => {
    const spend = decodeSpendTx(SIGNED_TX);
    expect(spend).toMatchObject({
      senderId: SENDER,
      recipientId: RECIPIENT,
      amount: '123456789012345678',
      fee: '20000000000000',
      nonce: '42',
      signatures: 1,
    });
  });

  it('refuses hostile fields', () => {
    expect(() => spendRlp({ ...tx, aettos: '0' as string })).toThrow();
    expect(() => spendRlp({ ...tx, aettos: '01' })).toThrow();
    expect(() => spendRlp({ ...tx, to: tx.from })).toThrow();
    expect(() => spendRlp({ ...tx, fee: '1' })).toThrow();
    expect(() => spendRlp({ ...tx, nonce: 0 })).toThrow();
    expect(() =>
      spendRlp({ ...tx, chainId: 'aet:ae_mainnet' as typeof AETERNITY_TESTNET }),
    ).toThrow();
    expect(() => spendRlp({ ...tx, payload: 'ba_AAAA' } as unknown as AeternityTx)).toThrow();
  });

  it('prepares a testnet spend with the node nonce and ttl', async () => {
    const { fetchImpl } = node({
      '/v3/status': okStatus,
      [`/v3/accounts/${SENDER}`]: () => ({ balance: '5000000000000000000', nonce: 0 }),
      [`/v3/accounts/${SENDER}/next-nonce`]: () => ({ next_nonce: 1 }),
      [`/v3/accounts/${RECIPIENT}`]: () => ({ balance: 0, nonce: 0 }),
      [`/v3/accounts/${RECIPIENT}/next-nonce`]: () => ({ next_nonce: 1 }),
    });
    const intent = {
      chainId: AETERNITY_TESTNET,
      kind: 'transfer',
      to: RECIPIENT,
      asset: `${AETERNITY_TESTNET}:native`,
      amount: '1000000000000000',
    } as unknown as TxIntent;
    const { unsigned, simulation } = await prepareAeternity(adapter(fetchImpl), intent, SENDER);
    expect(unsigned).toMatchObject({
      aettos: '1000000000000000',
      fee: '20000000000000',
      ttl: 1_304_647,
      nonce: 1,
    });
    expect(simulation.ok).toBe(true);
  });

  it('rejects a mismatched network before any other call', async () => {
    const { fetchImpl, calls } = node({
      '/v3/status': () => ({ network_id: 'ae_mainnet', top_block_height: 1 }),
    });
    await expect(adapter(fetchImpl).getBalances(SENDER, AETERNITY_TESTNET)).rejects.toThrow(
      /network_id/,
    );
    expect(calls.filter((c) => !c.endsWith('/v3/status'))).toEqual([]);
  });

  it('reports zero for accounts the node has never seen', async () => {
    const { fetchImpl } = node({ '/v3/status': okStatus });
    const holdings = await adapter(fetchImpl).getBalances(SENDER, AETERNITY_TESTNET);
    expect(holdings[0]!.amount).toBe('0');
  });

  it('broadcasts only bytes that are exactly this transfer', async () => {
    const { fetchImpl } = node({
      '/v3/status': okStatus,
      '/v3/transactions': (body) => {
        const b = body as { tx: string };
        const hash = aeternityTxHash(b.tx);
        return { tx_hash: hash };
      },
    });
    const a = adapter(fetchImpl);
    // The SDK-signed vector is exactly this tx, so it passes the wire check.
    await expect(broadcastAeternity(a, tx, SIGNED_TX)).resolves.toBe(TX_HASH);
    await expect(broadcastAeternity(a, tx, UNSIGNED_TX)).rejects.toThrow();
    await expect(broadcastAeternity(a, { ...tx, aettos: '1' }, SIGNED_TX)).rejects.toThrow(
      /not this AE transfer/,
    );
  });

  it('checks approval against nonce and ttl', async () => {
    const live = { ...tx, nonce: 7, ttl: 1_304_647 };
    const routes = {
      '/v3/status': okStatus,
      [`/v3/accounts/${SENDER}`]: () => ({ balance: '5000000000000000000', nonce: 6 }),
      [`/v3/accounts/${SENDER}/next-nonce`]: () => ({ next_nonce: 7 }),
    };
    const { fetchImpl } = node(routes);
    await expect(aeternityApprovalValid(adapter(fetchImpl), live)).resolves.toBe(true);
    const stale = node({
      ...routes,
      [`/v3/accounts/${SENDER}/next-nonce`]: () => ({ next_nonce: 8 }),
    });
    await expect(aeternityApprovalValid(adapter(stale.fetchImpl), live)).resolves.toBe(false);
    const expired = node({
      ...routes,
      '/v3/status': () => ({ network_id: 'ae_uat', top_block_height: 1_304_647 }),
    });
    await expect(aeternityApprovalValid(adapter(expired.fetchImpl), live)).resolves.toBe(false);
  });

  it('maps node answers to transfer status and expiry', async () => {
    const live = { ...tx, ttl: 100 };
    const confirmed = node({
      '/v3/status': okStatus,
      [`/v3/transactions/${TX_HASH}`]: () => ({ block_height: 1_304_587, block_hash: 'mh_x' }),
    });
    await expect(
      aeternityTransferStatus(adapter(confirmed.fetchImpl), live, TX_HASH),
    ).resolves.toMatchObject({ state: 'confirmed', blockNumber: 1_304_587 });
    const unknownPastTtl = node({ '/v3/status': okStatus });
    await expect(
      aeternityTransferStatus(adapter(unknownPastTtl.fetchImpl), live, TX_HASH),
    ).resolves.toEqual({ state: 'expired' });
    const unknownNoTtl = node({ '/v3/status': okStatus });
    await expect(
      aeternityTransferStatus(adapter(unknownNoTtl.fetchImpl), { ...live, ttl: 0 }, TX_HASH),
    ).resolves.toEqual({ state: 'unknown' });
  });
});
