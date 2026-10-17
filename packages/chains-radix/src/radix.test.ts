import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { bech32m } from '@scure/base';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  NETWORKS,
  RADIX_STOKENET,
  RadixAdapter,
  attosToXrd,
  isValidRadixAddress,
  radixAddressBytes,
  radixAddressFromPublicKey,
  radixHashString,
  xrdToAttos,
} from './radix.js';
import {
  LOCK_FEE_ATTOS,
  RadixTx,
  broadcastRadix,
  compileNotarized,
  intentHash,
  prepareRadix,
  radixApprovalValid,
  radixTransferStatus,
  signTransfer,
  signedIntentHash,
  txidOf,
} from './send.js';

const SEED = new Uint8Array(32).fill(7);
const PUBLIC = ed25519.getPublicKey(SEED);
// Radix Engine Toolkit 1.0.6 vectors (`.nur/radix-sdk/oracle-vector2.txt`);
// the same key pair the Tezos and Solana families pin against.
const FROM = 'account_tdx_2_12ynqzf78g3mtyufkch3ccqpmv6ugnawgqqe0hq0tc06y73dr0sf2qk';
const TO = 'account_tdx_2_169qlmuyvq8vcfdtlgmjllvy4ehs2tky7y8ckkmkhpq776j8vec5c2a';
const INTENT_HASH = 'a7560a350d769274146a88741dd0b64c3620734b0510a8ca722100e623289a3e';
const TXID = 'txid_tdx_2_15atq5dgdw6f8g9r23p6pm59kfsmzqu6tq5g23jnjyyqwvgegnglq3380l4';
const SIGNED_ID = 'signedintent_tdx_2_1v2sfsgzdszle5djcwr0sy93qmghf9xmfk4p7agrn4dnszhmv900synhlt4';
const COMPILED =
  '4d22030221022104210707020a64000000000000000a6e000000000000000915cd5b07220101200720ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c01010800002022044103800051260127c74476b27136c5e38c003b66b889f5c80032fb81ebc3f44f45a30c086c6f636b5f6665652101850000f44482916345000000000000000000000000000000004103800051260127c74476b27136c5e38c003b66b889f5c80032fb81ebc3f44f45a30c087769746864726177210280005da66318c6318c61f5a61b4c6318c6318cf794aa8d295f14e6318c6318c6850000167b0d12d11400000000000000000000000000000000000280005da66318c6318c61f5a61b4c6318c6318cf794aa8d295f14e6318c6318c6850000167b0d12d1140000000000000000000000000000000041038000d141fdf08c01d984b57f46e5ffb095cde0a5d89e21f16b6ed7083ded48ec0c147472795f6465706f7369745f6f725f61626f7274210281000000002200002020002200002022010102200720ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c2101200740422cd583dd91743c1ba895f35c6d7760e76658ddaabc1d881bd26180d9c481f5dfa376a6f4f9b5291db847ce50a89157196fd59ec636b7e1986677626a68ac082201012101200740d592ac09da6e63bcf203d7c77b22f1eb875cfecdcf84ad4732ae4f121899397012b513eb5a8a8c87df8578136a51a2f29da45e4d66cfc5edceb4180225a9e703';

const tx: RadixTx = {
  chainId: RADIX_STOKENET,
  from: FROM,
  to: TO,
  attos: '1500000000000000000',
  startEpochInclusive: 100,
  endEpochExclusive: 110,
  nonce: 123456789,
  tipPercentage: 0,
};

const GATEWAY = 'https://gw.stokenet.test';
function chain(chainId: string, rpcs: string[]): ChainInfo {
  return {
    chainId,
    family: 'radix',
    name: chainId,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'XRD', decimals: 18 },
    testnet: true,
    defaultRpcs: rpcs,
  };
}
const CHAINS = [chain(RADIX_STOKENET, [GATEWAY])];

class TestAdapter extends RadixAdapter {
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
const adapter = (fetchImpl: typeof fetch) =>
  new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });

const gatewayStatus = (epoch: number, network = 'stokenet') => ({
  ledger_state: { network, epoch, proposer_round_timestamp: '2026-10-16T00:00:00.000Z' },
});
const statusRoute = (epoch = 14000): Record<string, Route> => ({
  [`${GATEWAY}/status/gateway-status`]: () => gatewayStatus(epoch),
});
const entityDetails = (xrdAmount: string | undefined) => ({
  items:
    xrdAmount === undefined
      ? []
      : [
          {
            address: FROM,
            fungible_resources: {
              items: [
                {
                  resource_address: NETWORKS[RADIX_STOKENET]!.xrdResource,
                  vaults: { items: [{ amount: xrdAmount }] },
                },
              ],
            },
          },
        ],
});

const intent = (to = TO, amount = '1500000000000000000'): TxIntent =>
  ({
    id: 'i',
    walletId: 'w',
    accountId: 'a',
    chainId: RADIX_STOKENET,
    proposer: { kind: 'human', deviceId: 'd' },
    kind: 'transfer',
    to,
    asset: `${RADIX_STOKENET}:native`,
    amount,
    untrustedDestinations: [],
    createdAtMs: 0,
  }) as unknown as TxIntent;

describe('radix addresses', () => {
  it('derives the virtual account RET derives', () => {
    expect(radixAddressFromPublicKey(PUBLIC, RADIX_STOKENET)).toBe(FROM);
    const a = new TestAdapter();
    expect(a.deriveAddress({ curve: 'ed25519', hex: bytesToHex(PUBLIC) }, RADIX_STOKENET)).toBe(
      FROM,
    );
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02' + '11'.repeat(32) }, RADIX_STOKENET),
    ).toThrow();
  });

  it('accepts canonical Stokenet accounts only', () => {
    expect(isValidRadixAddress(FROM, RADIX_STOKENET)).toBe(true);
    expect(isValidRadixAddress(TO, RADIX_STOKENET)).toBe(true);
    // The mainnet encoding of the same node id is not a Stokenet address.
    const mainnet = bech32m.encode(
      'account_rdx',
      bech32m.toWords(radixAddressBytes(FROM, NETWORKS[RADIX_STOKENET]!.accountHrp)!),
    );
    expect(isValidRadixAddress(mainnet, RADIX_STOKENET)).toBe(false);
    // A package entity (0x0d) under the account HRP is refused.
    const pkg = radixAddressBytes(FROM, NETWORKS[RADIX_STOKENET]!.accountHrp)!;
    pkg[0] = 0x0d;
    expect(
      isValidRadixAddress(
        bech32m.encode(NETWORKS[RADIX_STOKENET]!.accountHrp, bech32m.toWords(pkg)),
        RADIX_STOKENET,
      ),
    ).toBe(false);
    expect(isValidRadixAddress(FROM.slice(0, -1) + 'z', RADIX_STOKENET)).toBe(false);
    expect(isValidRadixAddress(FROM.toUpperCase(), RADIX_STOKENET)).toBe(false);
  });
});

describe('radix transfer encoding', () => {
  it('compiles and hashes exactly like the Radix Engine Toolkit', () => {
    expect(bytesToHex(intentHash(tx, PUBLIC))).toBe(INTENT_HASH);
    expect(txidOf(tx, PUBLIC)).toBe(TXID);
    const { wireHex, txid } = signTransfer(tx, SEED);
    expect(wireHex).toBe(COMPILED);
    expect(txid).toBe(TXID);
  });

  it('hashes the signed intent like RET', () => {
    const sig = ed25519.sign(intentHash(tx, PUBLIC), SEED);
    const id = radixHashString('signedintent_tdx_2_', signedIntentHash(tx, PUBLIC, sig));
    expect(id).toBe(SIGNED_ID);
    // Both signatures verify over the hashes they attest to.
    expect(ed25519.verify(sig, intentHash(tx, PUBLIC), PUBLIC)).toBe(true);
    const notary = ed25519.sign(signedIntentHash(tx, PUBLIC, sig), SEED);
    expect(ed25519.verify(notary, signedIntentHash(tx, PUBLIC, sig), PUBLIC)).toBe(true);
  });

  it('refuses hostile or malformed payloads', () => {
    expect(() => signTransfer({ ...tx, attos: '0' }, SEED)).toThrow();
    expect(() => signTransfer({ ...tx, attos: '015' }, SEED)).toThrow();
    expect(() => signTransfer({ ...tx, to: FROM }, SEED)).toThrow();
    expect(() => signTransfer({ ...tx, tipPercentage: 101 }, SEED)).toThrow();
    expect(() =>
      signTransfer({ ...tx, endEpochExclusive: tx.startEpochInclusive + 101 }, SEED),
    ).toThrow();
    expect(() => signTransfer({ ...tx, from: TO, to: FROM }, SEED)).toThrow();
    expect(() => signTransfer(tx, new Uint8Array(32).fill(6))).toThrow(
      'Sender differs from signing key',
    );
    expect(() => RadixTx.parse({ ...tx, blobs: ['00'] })).toThrow();
    expect(() => RadixTx.parse({ ...tx, chainId: 'radix:mainnet' })).toThrow();
  });
});

describe('radix amounts', () => {
  it('converts gateway decimals without floats', () => {
    expect(xrdToAttos('1.5')).toBe(1500000000000000000n);
    expect(xrdToAttos('-0.000000000000000001')).toBe(-1n);
    expect(xrdToAttos('24000000000')).toBe(24000000000n * 10n ** 18n);
    expect(attosToXrd(1500000000000000000n)).toBe('1.5');
    expect(attosToXrd(-1n)).toBe('-0.000000000000000001');
    expect(() => xrdToAttos('1.0000000000000000001')).toThrow();
  });
});

describe('radix prepare', () => {
  it('builds the unsigned transfer from the live epoch', async () => {
    const { fetchImpl, calls } = node({
      ...statusRoute(14000),
      [`${GATEWAY}/state/entity/details`]: () => entityDetails('10.5'),
    });
    const { unsigned, simulation } = await prepareRadix(adapter(fetchImpl), intent(), FROM);
    expect(unsigned.startEpochInclusive).toBe(14000);
    expect(unsigned.endEpochExclusive).toBe(14010);
    expect(unsigned.tipPercentage).toBe(0);
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe(LOCK_FEE_ATTOS.toString());
    expect(calls.some((c) => c.url.includes('/status/gateway-status'))).toBe(true);
  });

  it('flags a balance that cannot cover the lock', async () => {
    const { fetchImpl } = node({
      ...statusRoute(),
      [`${GATEWAY}/state/entity/details`]: () => entityDetails('1'),
    });
    const { simulation } = await prepareRadix(adapter(fetchImpl), intent(), FROM);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/fee lock/);
  });

  it('refuses other intents and networks', async () => {
    const { fetchImpl } = node(statusRoute());
    await expect(prepareRadix(adapter(fetchImpl), intent(TO, '0'), FROM)).rejects.toThrow();
    const bad = { ...intent(), chainId: 'radix:mainnet' } as unknown as TxIntent;
    await expect(prepareRadix(adapter(fetchImpl), bad, FROM)).rejects.toThrow(/Stokenet/);
  });

  it('rejects a gateway serving the wrong network', async () => {
    const { fetchImpl } = node({
      [`${GATEWAY}/status/gateway-status`]: () => gatewayStatus(14000, 'mainnet'),
    });
    await expect(prepareRadix(adapter(fetchImpl), intent(), FROM)).rejects.toThrow(/network/i);
  });
});

describe('radix balances and status', () => {
  it('sums XRD vaults and treats an unknown account as zero', async () => {
    const funded = node({
      ...statusRoute(),
      [`${GATEWAY}/state/entity/details`]: () => entityDetails('2.25'),
    });
    const [holding] = await adapter(funded.fetchImpl).getBalances(FROM, RADIX_STOKENET);
    expect(holding!.amount).toBe('2250000000000000000');
    const empty = node({
      ...statusRoute(),
      [`${GATEWAY}/state/entity/details`]: () => entityDetails(undefined),
    });
    const [zero] = await adapter(empty.fetchImpl).getBalances(FROM, RADIX_STOKENET);
    expect(zero!.amount).toBe('0');
  });

  it('maps gateway transaction status', async () => {
    const committed = node({
      ...statusRoute(),
      [`${GATEWAY}/transaction/status`]: () => ({
        ledger_state: gatewayStatus(14000).ledger_state,
        status: 'CommittedSuccess',
        known_payloads: [],
        receipt: { status: 'CommittedSuccess', fee_summary: { xrd_total_fee: '0.0038' } },
      }),
    });
    const a = adapter(committed.fetchImpl);
    const ok = await a.status(TXID, RADIX_STOKENET);
    expect(ok.state).toBe('confirmed');
    const failed = node({
      ...statusRoute(),
      [`${GATEWAY}/transaction/status`]: () => ({
        ledger_state: gatewayStatus(14000).ledger_state,
        status: 'CommittedFailure',
        known_payloads: [],
        receipt: { status: 'CommittedFailure', error_message: 'insufficient balance' },
      }),
    });
    const bad = await adapter(failed.fetchImpl).status(TXID, RADIX_STOKENET);
    expect(bad).toEqual({ state: 'failed', reason: 'insufficient balance' });
    const unknown = node({
      ...statusRoute(),
      [`${GATEWAY}/transaction/status`]: () => ({
        ledger_state: gatewayStatus(14000).ledger_state,
        status: 'Unknown',
        known_payloads: [],
      }),
    });
    expect(await adapter(unknown.fetchImpl).status(TXID, RADIX_STOKENET)).toEqual({
      state: 'unknown',
    });
  });

  it('expires a pending intent once its end epoch passes', async () => {
    const unknownStatus = {
      ledger_state: gatewayStatus(14000).ledger_state,
      status: 'Unknown',
      known_payloads: [],
    };
    const { fetchImpl } = node({
      [`${GATEWAY}/status/gateway-status`]: () => gatewayStatus(20000),
      [`${GATEWAY}/transaction/status`]: () => unknownStatus,
    });
    const a = adapter(fetchImpl);
    expect(await radixApprovalValid(a, tx)).toBe(false);
    await expect(radixTransferStatus(a, tx, TXID)).resolves.toEqual({ state: 'expired' });
  });
});

describe('radix broadcast', () => {
  const submitOk = {
    ...statusRoute(),
    [`${GATEWAY}/transaction/submit`]: () => ({ duplicate: false }),
  };

  it('accepts only bytes that re-derive from the checked transfer', async () => {
    const { fetchImpl, calls } = node(submitOk);
    const { wireHex } = signTransfer(tx, SEED);
    const txid = await broadcastRadix(adapter(fetchImpl), tx, wireHex);
    expect(txid).toBe(TXID);
    const submit = calls.find((c) => c.url.includes('/transaction/submit'));
    expect((submit?.body as { notarized_transaction_hex: string }).notarized_transaction_hex).toBe(
      wireHex,
    );
  });

  it('rejects a tampered or foreign payload before any network call', async () => {
    const { fetchImpl, calls } = node(submitOk);
    const { wireHex } = signTransfer(tx, SEED);
    const bytes = hexToBytes(wireHex);
    // Flip one instruction byte (the second "withdraw" character).
    bytes[bytes.indexOf(0x77, 100)] = 0x78;
    await expect(broadcastRadix(adapter(fetchImpl), tx, bytesToHex(bytes))).rejects.toThrow(
      /not this XRD transfer/,
    );
    // A wire signed by a key that does not own the sender account.
    const otherSecret = new Uint8Array(32).fill(6);
    const otherPublic = ed25519.getPublicKey(otherSecret);
    const otherIntentSig = ed25519.sign(intentHash(tx, otherPublic), otherSecret);
    const otherNotarySig = ed25519.sign(
      signedIntentHash(tx, otherPublic, otherIntentSig),
      otherSecret,
    );
    const foreign = compileNotarized(tx, otherPublic, otherIntentSig, otherNotarySig);
    await expect(broadcastRadix(adapter(fetchImpl), tx, bytesToHex(foreign.bytes))).rejects.toThrow(
      /Notary key/,
    );
    const other = signTransfer({ ...tx, attos: '1500000000000000001' }, SEED);
    await expect(broadcastRadix(adapter(fetchImpl), tx, other.wireHex)).rejects.toThrow();
    expect(calls.some((c) => c.url.includes('/transaction/submit'))).toBe(false);
  });

  it('surfaces a node rejection with the gateway detail', async () => {
    const { fetchImpl } = node({
      ...statusRoute(),
      [`${GATEWAY}/transaction/submit`]: () =>
        new Response(
          JSON.stringify({
            message: 'Subintent in transaction was already processed',
            code: 400,
            details: { type: 'InvalidTransaction' },
          }),
          { status: 400 },
        ),
    });
    const { wireHex } = signTransfer(tx, SEED);
    await expect(broadcastRadix(adapter(fetchImpl), tx, wireHex)).rejects.toThrow(
      /Broadcast rejected: HTTP 400 InvalidTransaction/,
    );
  });

  it('compiles a deterministic layout for the template comparison', () => {
    const a = compileNotarized(tx, PUBLIC, new Uint8Array(64), new Uint8Array(64));
    const b = compileNotarized(tx, PUBLIC, new Uint8Array(64), new Uint8Array(64));
    expect(a.publicKeyAts).toEqual(b.publicKeyAts);
    expect(a.bytes.length).toBe(hexToBytes(COMPILED).length);
  });
});
