import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  MULTIVERSX_DEVNET,
  MULTIVERSX_MAINNET,
  MultiversxAdapter,
  endpointKind,
  esdtAssetRef,
  isMultiversxContract,
  isValidMultiversxAddress,
  multiversxAddressBytes,
  multiversxAddressFromPublicKey,
} from './multiversx.js';
import {
  MAX_ATTOEGLD,
  MultiversxTx,
  broadcastMultiversx,
  multiversxApprovalValid,
  multiversxTransferStatus,
  prepareMultiversx,
  signingJson,
  transferHash,
  transferProto,
} from './send.js';

const SEED = new Uint8Array(32).fill(7);
const SENDER = 'erd1af9xcclzn3fq40h42pa3xtk9lx25wa4wh6l8hyjzrm4xj9zx6gkq38dn52';
const RECIPIENT = 'erd1zwv0vtrdrfzhc5d6df9470da9a5le2fjzcscmjye0eqkh5taj09qjg4tnr';
const ALICE = 'erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th';
const ALICE_PUB = '0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1';
const CONTRACT = 'erd1qqqqqqqqqqqqqpgqeel2kumf0r8ffyhth7pqdujjat9nx0862jpsg2pqaq';

const tx: MultiversxTx = {
  chainId: MULTIVERSX_DEVNET,
  from: SENDER,
  to: RECIPIENT,
  attoegld: '1500000000000000000',
  nonce: 42,
  gasPrice: 1_000_000_000,
  gasLimit: 50_000,
};
/** `@multiversx/sdk-core` 16.0.0 output for these fields; the core (`multiversx.rs`) pins the same. */
const SIGNING_VECTOR =
  '{"nonce":42,"value":"1500000000000000000","receiver":"erd1zwv0vtrdrfzhc5d6df9470da9a5le2fjzcscmjye0eqkh5taj09qjg4tnr","sender":"erd1af9xcclzn3fq40h42pa3xtk9lx25wa4wh6l8hyjzrm4xj9zx6gkq38dn52","gasPrice":1000000000,"gasLimit":50000,"chainID":"D","version":2}';
const SIGNATURE_VECTOR =
  '7d2c795035e59013e1d7aa043a19565537c87cbe9cfff4b9220d29ab1364b43ed6329c8df70d01b44b6a03b2e2782476699f0d55ffc5758ef8a489ce84095c08';
const PROTO_VECTOR =
  '082a12090014d1120d7b1600001a201398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca2a20ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c388094ebdc0340d08603520144580262407d2c795035e59013e1d7aa043a19565537c87cbe9cfff4b9220d29ab1364b43ed6329c8df70d01b44b6a03b2e2782476699f0d55ffc5758ef8a489ce84095c08';
const HASH_VECTOR = 'c59864fb0b542181600d1974dbe74f183e64838adbbf5e66cb4c233c805bb416';
/** Nonce 0, value 1: the devnet gateway's `/transaction/simulate` reported this hash. */
const NONCE_ZERO_HASH = 'af045283bc1da1b9cc97be16a7fbbefb8b42098d2f46600218f0563cbf227902';

const DEV_API = 'https://devnet-api.multiversx.com';
const DEV_GW = 'https://devnet-gateway.multiversx.com';
const MAIN_API = 'https://api.multiversx.com';
const MAIN_GW = 'https://gateway.multiversx.com';

const chain = (chainId: string, name: string, testnet: boolean, rpcs: string[]) =>
  ({
    chainId,
    family: 'multiversx',
    name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'EGLD', decimals: 18 },
    testnet,
    defaultRpcs: rpcs,
  }) as ChainInfo;
const CHAINS: ChainInfo[] = [
  chain(MULTIVERSX_MAINNET, 'MultiversX', false, [MAIN_API, MAIN_GW]),
  chain(MULTIVERSX_DEVNET, 'MultiversX Devnet', true, [DEV_API, DEV_GW]),
];

class TestAdapter extends MultiversxAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Reply = { status?: number; body: unknown } | undefined;
type Route = (url: URL, init?: RequestInit) => Reply;
const config = (chainId: string) => ({
  data: {
    config: {
      erd_chain_id: chainId,
      erd_min_gas_limit: 50_000,
      erd_min_gas_price: 1_000_000_000,
      erd_gas_per_data_byte: 1500,
    },
  },
  code: 'successful',
});

function node(routes: Record<string, Route>, rpcs?: Record<string, string[]>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const key = `${init?.method ?? 'GET'} ${url.origin}${url.pathname}`;
    calls.push(key);
    const route = Object.entries(routes).find(([k]) =>
      k.endsWith('*') ? key.startsWith(k.slice(0, -1)) : key === k,
    );
    const reply = route?.[1](url, init) ?? { status: 404, body: { message: 'not found' } };
    return new Response(JSON.stringify(reply.body), {
      status: reply.status ?? 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  const chains = CHAINS.map((c) =>
    rpcs?.[c.chainId] ? { ...c, defaultRpcs: rpcs[c.chainId]! } : c,
  );
  return { adapter: new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) }), calls };
}

const devConfig = { [`GET ${DEV_API}/network/config`]: () => ({ body: config('D') }) };
const gwConfig = { [`GET ${DEV_GW}/network/config`]: () => ({ body: config('D') }) };

function intent(to: string, amount: string): TxIntent {
  return {
    id: 'tx',
    walletId: 'w',
    accountId: 'a',
    chainId: MULTIVERSX_DEVNET,
    kind: 'transfer',
    to,
    asset: `${MULTIVERSX_DEVNET}:native`,
    amount,
    proposer: { kind: 'human', deviceId: 'd' },
    untrustedDestinations: [],
    createdAtMs: 0,
  } as TxIntent;
}

const signed = (t: MultiversxTx) => {
  const sig = ed25519.sign(new TextEncoder().encode(signingJson(t)), SEED);
  return {
    sig,
    json: `${signingJson(t).slice(0, -1)},"signature":"${bytesToHex(sig)}"}`,
  };
};

describe('multiversx addresses', () => {
  it('derives the sdk-core and published addresses', () => {
    expect(multiversxAddressFromPublicKey(ed25519.getPublicKey(SEED))).toBe(SENDER);
    expect(multiversxAddressFromPublicKey(hexToBytes(ALICE_PUB))).toBe(ALICE);
    const a = new TestAdapter();
    expect(a.deriveAddress({ curve: 'ed25519', hex: ALICE_PUB }, MULTIVERSX_DEVNET)).toBe(ALICE);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: '02'.padEnd(66, '1') }, MULTIVERSX_DEVNET),
    ).toThrow();
    expect(() => a.deriveAddress({ curve: 'ed25519', hex: ALICE_PUB }, 'mvx:T')).toThrow();
  });

  it('accepts only canonical lowercase erd1 bech32 of 32 bytes', () => {
    expect(isValidMultiversxAddress(ALICE)).toBe(true);
    expect(isValidMultiversxAddress(ALICE.toUpperCase())).toBe(false);
    expect(isValidMultiversxAddress(`${ALICE.slice(0, -1)}q`)).toBe(false);
    expect(isValidMultiversxAddress(multiversxAddressFromPublicKey(new Uint8Array(32)))).toBe(
      false,
    );
    expect(isValidMultiversxAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false);
    expect(bytesToHex(multiversxAddressBytes(ALICE)!)).toBe(ALICE_PUB);
    expect(isMultiversxContract(CONTRACT)).toBe(true);
    expect(isMultiversxContract(ALICE)).toBe(false);
  });

  it('tells gateways from the API by host', () => {
    expect(endpointKind(DEV_GW)).toBe('gateway');
    expect(endpointKind(DEV_API)).toBe('api');
  });
});

describe('multiversx transfers', () => {
  it('encodes the same signing JSON, protobuf and hash as sdk-core and the core', () => {
    expect(signingJson(tx)).toBe(SIGNING_VECTOR);
    const { sig } = signed(tx);
    expect(bytesToHex(sig)).toBe(SIGNATURE_VECTOR);
    expect(bytesToHex(transferProto(tx, sig))).toBe(PROTO_VECTOR);
    expect(transferHash(tx, sig)).toBe(HASH_VECTOR);
    const zero = { ...tx, nonce: 0, attoegld: '1' };
    expect(transferHash(zero, signed(zero).sig)).toBe(NONCE_ZERO_HASH);
  });

  it('refuses hostile fields', () => {
    expect(() => signingJson({ ...tx, attoegld: '0' })).toThrow();
    expect(() => signingJson({ ...tx, attoegld: '01' })).toThrow();
    expect(() => signingJson({ ...tx, attoegld: (MAX_ATTOEGLD + 1n).toString() })).toThrow();
    expect(signingJson({ ...tx, attoegld: MAX_ATTOEGLD.toString() })).toContain('31415926');
    expect(() => signingJson({ ...tx, to: tx.from })).toThrow();
    expect(() => signingJson({ ...tx, gasLimit: 49_999 })).toThrow();
    expect(() => signingJson({ ...tx, gasPrice: 101_000_000_000 })).toThrow();
    expect(() =>
      signingJson({ ...tx, chainId: MULTIVERSX_MAINNET as typeof MULTIVERSX_DEVNET }),
    ).toThrow();
    expect(() => signingJson({ ...tx, data: 'aGk=' } as MultiversxTx)).toThrow();
  });

  it('prepares a devnet transfer at the network minimum gas', async () => {
    const { adapter } = node({
      ...devConfig,
      [`GET ${DEV_API}/accounts/${SENDER}`]: () => ({
        body: { address: SENDER, balance: '2000000000000000000', nonce: 42 },
      }),
    });
    const { unsigned, simulation } = await prepareMultiversx(
      adapter,
      intent(RECIPIENT, '1500000000000000000'),
      SENDER,
    );
    expect(unsigned).toEqual(tx);
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('50000000000000');
    const broke = await prepareMultiversx(adapter, intent(CONTRACT, '1999999999999999999'), SENDER);
    expect(broke.simulation.ok).toBe(false);
    expect(broke.simulation.warnings[0]).toMatchObject({ kind: 'destinationIsContract' });
    await expect(
      prepareMultiversx(
        adapter,
        { ...intent(RECIPIENT, '1'), chainId: MULTIVERSX_MAINNET },
        SENDER,
      ),
    ).rejects.toThrow();
  });

  it('refuses an endpoint that serves another MultiversX network', async () => {
    const { adapter } = node(
      {
        [`GET ${DEV_API}/network/config`]: () => ({ body: config('1') }),
        [`GET ${DEV_API}/accounts/*`]: () => ({
          body: { address: SENDER, balance: '1', nonce: 0 },
        }),
      },
      { [MULTIVERSX_DEVNET]: [DEV_API] },
    );
    await expect(adapter.getBalances(SENDER, MULTIVERSX_DEVNET)).rejects.toThrow();
  });

  it('keeps approval only while the nonce is unchanged', async () => {
    let nonce = 42;
    const { adapter } = node({
      ...devConfig,
      [`GET ${DEV_API}/accounts/${SENDER}`]: () => ({
        body: { address: SENDER, balance: '2000000000000000000', nonce },
      }),
    });
    await expect(multiversxApprovalValid(adapter, tx)).resolves.toBe(true);
    nonce = 43;
    await expect(multiversxApprovalValid(adapter, tx)).resolves.toBe(false);
  });

  it('broadcasts only the ledger transfer with a verifying signature', async () => {
    const seen: unknown[] = [];
    const { adapter } = node({
      ...devConfig,
      [`POST ${DEV_API}/transactions`]: (_u, init) => {
        seen.push(JSON.parse(String(init!.body)));
        return { body: { txHash: HASH_VECTOR, receiver: RECIPIENT, sender: SENDER } };
      },
    });
    const { json } = signed(tx);
    await expect(broadcastMultiversx(adapter, tx, json)).resolves.toBe(HASH_VECTOR);
    await expect(
      broadcastMultiversx(adapter, { ...tx, attoegld: '1500000000000000001' }, json),
    ).rejects.toThrow();
    await expect(
      broadcastMultiversx(adapter, tx, json.replace('"version":2', '"version":2,"data":"aGk="')),
    ).rejects.toThrow();
    const forged = json.replace(SIGNATURE_VECTOR, `${SIGNATURE_VECTOR.slice(0, -2)}09`);
    await expect(broadcastMultiversx(adapter, tx, forged)).rejects.toThrow(/verify/);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ nonce: 42, signature: SIGNATURE_VECTOR, chainID: 'D' });
  });

  it('surfaces a rejection unless the network already has the hash', async () => {
    let known = false;
    const { adapter } = node(
      {
        ...gwConfig,
        [`POST ${DEV_GW}/transaction/send`]: () => ({
          status: 400,
          body: {
            data: null,
            error: `transaction generation failed: insufficient funds for address ${SENDER}`,
            code: 'internal_issue',
          },
        }),
        [`GET ${DEV_GW}/transaction/*`]: () =>
          known
            ? {
                body: {
                  data: { transaction: { hash: HASH_VECTOR, status: 'pending', nonce: 42 } },
                  code: 'successful',
                },
              }
            : {
                status: 500,
                body: { data: null, error: 'transaction not found', code: 'internal_issue' },
              },
      },
      { [MULTIVERSX_DEVNET]: [DEV_GW] },
    );
    const { json } = signed(tx);
    await expect(broadcastMultiversx(adapter, tx, json)).rejects.toThrow(/insufficient funds/);
    known = true;
    await expect(broadcastMultiversx(adapter, tx, json)).resolves.toBe(HASH_VECTOR);
  });

  it('reports expiry only when a gateway sees the nonce consumed without the hash', async () => {
    let nonce = 42;
    const { adapter } = node({
      ...devConfig,
      ...gwConfig,
      [`GET ${DEV_API}/transactions/*`]: () => ({
        status: 404,
        body: { message: 'Transaction not found' },
      }),
      [`GET ${DEV_GW}/transaction/*`]: () => ({
        status: 500,
        body: { data: null, error: 'transaction not found', code: 'internal_issue' },
      }),
      [`GET ${DEV_GW}/address/${SENDER}`]: () => ({
        body: { data: { account: { address: SENDER, balance: '0', nonce } }, code: 'successful' },
      }),
    });
    await expect(multiversxTransferStatus(adapter, tx, HASH_VECTOR)).resolves.toEqual({
      state: 'unknown',
    });
    nonce = 43;
    await expect(multiversxTransferStatus(adapter, tx, HASH_VECTOR)).resolves.toEqual({
      state: 'expired',
    });
  });

  it('maps API statuses', async () => {
    const { adapter } = node({
      ...devConfig,
      [`GET ${DEV_API}/transactions/${HASH_VECTOR}`]: () => ({
        body: { txHash: HASH_VECTOR, status: 'success', round: 23731902, timestamp: 1792152603 },
      }),
      [`GET ${DEV_API}/transactions/${NONCE_ZERO_HASH}`]: () => ({
        body: { txHash: NONCE_ZERO_HASH, status: 'fail' },
      }),
    });
    await expect(adapter.status(HASH_VECTOR, MULTIVERSX_DEVNET)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 23731902,
      timestampMs: 1792152603000,
    });
    await expect(adapter.status(NONCE_ZERO_HASH, MULTIVERSX_DEVNET)).resolves.toMatchObject({
      state: 'failed',
    });
  });
});

describe('multiversx reads', () => {
  it('reads EGLD and USDC on mainnet', async () => {
    const big = '31415926000000000000000000';
    const { adapter } = node({
      [`GET ${MAIN_API}/network/config`]: () => ({ body: config('1') }),
      [`GET ${MAIN_GW}/network/config`]: () => ({ body: config('1') }),
      [`GET ${MAIN_API}/accounts/${ALICE}`]: () => ({
        body: { address: ALICE, balance: big, nonce: 95 },
      }),
      [`GET ${MAIN_API}/accounts/${ALICE}/tokens/USDC-c76f1f`]: () => ({
        body: { identifier: 'USDC-c76f1f', balance: '42' },
      }),
      [`GET ${MAIN_GW}/address/${ALICE}`]: () => ({
        body: { data: { account: { address: ALICE, balance: big, nonce: 95 } } },
      }),
      [`GET ${MAIN_GW}/address/${ALICE}/esdt/USDC-c76f1f`]: () => ({
        body: { data: { tokenData: { balance: '42' } } },
      }),
    });
    const holdings = await adapter.getBalances(ALICE, MULTIVERSX_MAINNET);
    // Both default hosts are one operator, so they do not count as two witnesses.
    expect(holdings[0]).toMatchObject({ amount: big, provenance: { kind: 'single' } });
    expect(holdings[1]).toMatchObject({
      assetRef: esdtAssetRef(MULTIVERSX_MAINNET, 'USDC-c76f1f'),
      amount: '42',
    });
  });

  it('reads API history with EGLD deltas and fees', async () => {
    const { adapter } = node({
      ...devConfig,
      [`GET ${DEV_API}/accounts/${SENDER}/transactions`]: (url) => {
        expect(url.searchParams.get('from')).toBe('0');
        return {
          body: [
            {
              txHash: HASH_VECTOR,
              sender: SENDER,
              receiver: RECIPIENT,
              value: '1500000000000000000',
              fee: '50000000000000',
              status: 'success',
              round: 7,
              timestamp: 1792152603,
            },
            {
              txHash: NONCE_ZERO_HASH,
              sender: RECIPIENT,
              receiver: SENDER,
              value: '0',
              fee: '158410000000000',
              status: 'fail',
              function: 'ESDTTransfer',
            },
          ],
        };
      },
    });
    const page = await adapter.getHistory(SENDER, MULTIVERSX_DEVNET);
    expect(page.items[0]).toMatchObject({
      assetDeltas: [{ amount: '-1500000000000000000' }],
      fee: '50000000000000',
      status: 'confirmed',
      timestampMs: 1792152603000,
    });
    expect(page.items[1]).toMatchObject({
      assetDeltas: [],
      fee: '0',
      status: 'failed',
      description: 'ESDTTransfer',
    });
    expect(page.nextCursor).toBeUndefined();
    await expect(adapter.getHistory(SENDER, MULTIVERSX_DEVNET, '-1')).rejects.toThrow();
  });
});
