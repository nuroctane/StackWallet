import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { Builder, parseBoc, serializeBoc } from './cell.js';
import {
  EVER_WALLET_CODE_HASH,
  EVERSCALE_MAINNET,
  EverscaleAdapter,
  Slice,
  VENOM_TESTNET,
  everWalletCode,
  everscaleAddressFromPublicKey,
  isValidEverscaleAddress,
  parseAccountBoc,
  parseTransactionBoc,
} from './everscale.js';
import {
  EverscaleTx,
  broadcastEverscale,
  everscaleExternalMessage,
  everscaleSigningHash,
  everscaleTransferStatus,
  prepareEverscale,
} from './send.js';

const SEED = new Uint8Array(32).fill(7);
const PUB = ed25519.getPublicKey(SEED);
const PUB_HEX = bytesToHex(PUB);
const SENDER = '0:252413205e86517432e0c2ab74a857b0d2e3369989cbef1df1f2c16a8b89ff09';
const RECIPIENT = '0:120094dedd73dfa077fe4bdaeb97e66455ca8ace3ed68b194979a1b78bc98ee5';
const publicKey = { curve: 'ed25519' as const, hex: PUB_HEX };

/**
 * Pinned against `nekoton-wasm` (`.nur/ever-ref/vectors-final.json`); the
 * same vectors are asserted byte-for-byte in the core's `everscale` tests.
 */
const NODEPLOY: EverscaleTx = {
  chainId: VENOM_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  evers: '123456789',
  timeMs: 1_792_159_903_042,
  expireAt: 1_792_159_963,
  builtAtMs: 1_792_159_903_042,
  bounce: false,
  deploy: false,
};
const DEPLOY: EverscaleTx = {
  ...NODEPLOY,
  timeMs: 1_792_159_903_028,
  builtAtMs: 1_792_159_903_028,
  deploy: true,
};
const NODEPLOY_SIGNING_HASH = '755186d7281139e94388bd5c6bd82330b255b3cbae5db409235a14ddf7f77085';
const NODEPLOY_MSG_HASH = 'b907f619cf50e26efc241ad4f36a2c65e8e2ea067e219090e9adaeac0ab29e02';
const NODEPLOY_SIGNATURE =
  '87bf772dd4b4bd29420d2c231bed297e6e70d8b9d178bfd7dfb031357a16f9671409f0cd482295c4adef6345480976acc425160bf45f5d044e9a18830ebfab05';
const NODEPLOY_BOC =
  'b5ee9c724101040100d200014588004a482640bd0ca2e865c18556e950af61a5c66d331397de3be3e582d51713fe120c0101e1c3dfbb96ea5a5e94a10696118df694bf37386c5ce8bc5febefd8189abd0b7cb38a04f866a4114ae256f7b1a2a404bb5662128b05fa2fae82274d0c41875fd582fa929b18f8a71482afbd541ec4cbb17e6551ddabafaf9ee49087ba9a4511b48b0000006851437b509ab48c36d33b991b20020165800240129bdbae7bf40effc97b5d72fccc8ab95159c7dad163292f3436f17931dca0000000000000000000000000eb79a2a038030000839ebf0d';
const DEPLOY_SIGNING_HASH = '77add642b963a951782720857438b4c855af1782b51e5ddd18ac7659bb637112';
const DEPLOY_MSG_HASH = '14ffaae648c16a52e40551670663a5da376ab0b076bac43e6c2f04c44bd6c9bc';
const DEPLOY_SIGNATURE =
  'b0c27f0ba4187feca7608227919776ae2b8b087b542df0af234a45debfffccb5e56339036c728d9688f933aa0825271a720bc9a353b788c6743aaff305a1ad0f';
const DEPLOY_BOC =
  'b5ee9c7241020b010001fb00034788004a482640bd0ca2e865c18556e950af61a5c66d331397de3be3e582d51713fe1211b00107080114ff00f4a413f4bcf2c80b0202012003040004d23002e6f271d70101c000f27a8308d718ed44d08307d701d70b3fc8f828cf1623cf16c9f9000371d70101c3009a8307d7015113baf2e064de8040d7018020d7018020d701541675f910f2a8f823bbf27966bef823810708a08103e8a85220bcb1f274022082104cee646cbae30f01c8cbffcb3fc9ed54050600983002d74cd0fa408306d70171d70178d701d74cf80070801004aa0214b1c8cb055005cf165003fa02cb6922d021cf3121d749a08409b998337001cb0058cf1697307101cb0012cce2c901fb00003e8210169e3e11ba8e11f800029320d74a9778d701d402fb00e8d19332f23ce20050ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c000000000000000001e1d8613f85d20c3ff653b04113c8cbbb5715c5843daa16f85791a522ef5fffe65af2b19c81b63946cb447c99d50412938d3905e4d1a9dbc4633a1d57f982d0d687fa929b18f8a71482afbd541ec4cbb17e6551ddabafaf9ee49087ba9a4511b48b0000006851437b4d1ab48c36d33b991b20090165800240129bdbae7bf40effc97b5d72fccc8ab95159c7dad163292f3436f17931dca0000000000000000000000000eb79a2a0380a0000ab97d59a';
const NODEPLOY_SDK_BOC =
  'te6ccgEBBAEA0gABRYgASkgmQL0MouhlwYVW6VCvYaXGbTMTl9474+WC1RcT/hIMAQHhw9+7lupaXpShBpYRjfaUvzc4bFzovF/r79gYmr0LfLOKBPhmpBFK4lb3saKkBLtWYhKLBfovroInTQxBh1/VgvqSmxj4pxSCr71UHsTLsX5lUd2rr6+e5JCHuppFEbSLAAAAaFFDe1CatIw20zuZGyACAWWAAkASm9uue/QO/8l7XXL8zIq5UVnH2tFjKS80NvF5MdygAAAAAAAAAAAAAAAA63mioDgDAAA=';

const chain = (chainId: string, testnet: boolean, rpcs: string[]) =>
  ({
    chainId,
    family: 'everscale',
    name: testnet ? 'Venom Testnet' : 'Everscale',
    nativeAsset: { ref: `${chainId}:native`, symbol: testnet ? 'VENOM' : 'EVER', decimals: 9 },
    testnet,
    defaultRpcs: rpcs,
  }) as ChainInfo;

class TestAdapter extends EverscaleAdapter {
  constructor(
    private readonly list: ChainInfo[],
    fetchImpl?: typeof fetch,
  ) {
    super({
      rpc: new MemoryRpcPool(list),
      ...(fetchImpl ? { fetch: fetchImpl } : {}),
    });
  }
  override chains(): ChainInfo[] {
    return this.list;
  }
}

/** A key block cell whose only checked content is `tag 0x11ef55aa` + global id. */
function keyBlockBoc(globalId: number): string {
  return base64.encode(serializeBoc(new Builder().uint(0x11ef55aa, 32).uint(globalId, 32).build()));
}

/** A synthetic but wire-valid account cell for an active EverWallet. */
function accountBoc(address: string, balance: bigint, timestampMs: bigint): string {
  const hash = hexToBytes(address.slice(2));
  const data = new Builder().bytes(PUB).uint(timestampMs, 64).build();
  const acc = new Builder()
    .bit(true)
    .bytes(hash)
    .coins(0n)
    .bit(false)
    .uint(1234n, 64)
    .coins(balance)
    .bit(false)
    .bit(false) // active: state_init inline
    .bit(false) // split_depth none
    .bit(false) // special none
    .bit(true)
    .bit(true)
    .bit(false)
    .ref(everWalletCode())
    .ref(data)
    .build();
  return base64.encode(serializeBoc(acc));
}

/** A synthetic but wire-valid transaction cell: one internal in-message, one out. */
function transactionBoc(opts: {
  account: string;
  lt: bigint;
  now: number;
  inValue: bigint;
  outValue: bigint;
  aborted?: boolean;
}): string {
  const inMsg = new Builder()
    .uint(0b00, 2) // message + int_msg_info$0
    .uint(0b011, 3) // ihr_disabled bounce bounced (bounced reads as any bits here)
    .address(hexToBytes(RECIPIENT.slice(2)))
    .address(hexToBytes(opts.account.slice(2)))
    .coins(opts.inValue)
    .bit(false) // CurrencyCollection: no extra currencies
    .build();
  const outMsg = new Builder()
    .uint(0b00, 2)
    .uint(0b011, 3)
    .address(hexToBytes(opts.account.slice(2)))
    .address(hexToBytes(RECIPIENT.slice(2)))
    .coins(opts.outValue)
    .bit(false)
    .build();
  const outMap = new Builder()
    .uint(0b10, 2) // hml_long
    .uint(15, 4)
    .uint(0, 15)
    .ref(outMsg)
    .build();
  const msgs = new Builder().bit(true).ref(inMsg).bit(true).ref(outMap).build();
  const stateUpdate = new Builder().uint(0b10, 2).build();
  const description = new Builder()
    .uint(0b0000, 4) // trans_ord
    .bit(false) // credit_first
    .bit(false) // storage_ph none
    .bit(true) // credit_ph some
    .bit(false) // due_fees none
    .coins(opts.inValue)
    .bit(false) // CurrencyCollection: no extra currencies
    .bit(true) // tr_compute_phase_vm$1
    .bit(!opts.aborted) // success
    .bit(false)
    .bit(false)
    .coins(1000n) // gas_fees (bare Grams)
    .uint(0, 3) // gas_used
    .uint(0, 3) // gas_limit
    .bit(false) // gas_credit
    .uint(0, 8) // mode
    .uint(0, 32) // exit_code
    .bit(false) // exit_arg
    .uint(0, 32) // vm_steps
    .bytes(new Uint8Array(64))
    .bit(false) // action none
    .bit(opts.aborted === true) // aborted
    .build();
  const tx = new Builder()
    .uint(0b0111, 4)
    .bytes(hexToBytes(opts.account.slice(2)))
    .uint(opts.lt, 64)
    .bytes(new Uint8Array(32))
    .uint(0n, 64)
    .uint(opts.now, 32)
    .uint(1, 15)
    .uint(0b0001, 4) // orig uninit? end active — flags only
    .coins(1000n)
    .bit(false) // CurrencyCollection: no extra currencies
    .ref(msgs)
    .ref(stateUpdate)
    .ref(description)
    .build();
  return base64.encode(serializeBoc(tx));
}

type Reply = { status?: number; body: unknown } | undefined;
type JrpcRoute = (params: Record<string, unknown>) => Reply;

/** A mocked nekoton JRPC endpoint. */
function jrpcFetch(routes: Record<string, JrpcRoute>, globalId = 1002) {
  const calls: { method: string; params: unknown }[] = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params: Record<string, unknown>;
    };
    calls.push({ method: body.method, params: body.params });
    if (body.method === 'getLatestKeyBlock')
      return Response.json({ jsonrpc: '2.0', id: 1, result: { block: keyBlockBoc(globalId) } });
    const out = routes[body.method]?.(body.params);
    if (!out)
      return Response.json(
        { jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'not found' } },
        { status: 404 },
      );
    return Response.json(out.body, { status: out.status ?? 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const jrpcState = (boc: string) => ({
  jsonrpc: '2.0',
  id: 1,
  result: {
    account: { type: 'exists', boc },
    genTimings: { genLt: '1', genUtime: 1 },
    lastTransactionId: { isExact: true, lt: '1', hash: 'ab'.repeat(32) },
  },
});

describe('addresses', () => {
  it('derive from the state init hash and match pinned vectors', () => {
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])]);
    expect(everscaleAddressFromPublicKey(publicKey)).toBe(SENDER);
    expect(adapter.deriveAddress(publicKey, VENOM_TESTNET)).toBe(SENDER);
    // A real EverWallet observed on Everscale mainnet.
    expect(
      everscaleAddressFromPublicKey({
        curve: 'ed25519',
        hex: '25343c7251e5636db35fc769fb329615085be3c5858d523411daf1f4dbb24256',
      }),
    ).toBe('0:a1c1fd9383ea500bfcbad0b2110700dd121c7e152c910f1311a0b40aa54a4088');
    expect(everWalletCode().hashHex()).toBe(EVER_WALLET_CODE_HASH);
  });

  it('validates strictly', () => {
    expect(isValidEverscaleAddress(SENDER)).toBe(true);
    expect(isValidEverscaleAddress(SENDER.toUpperCase())).toBe(false);
    expect(isValidEverscaleAddress(`-1:${SENDER.slice(2)}`)).toBe(false);
    expect(isValidEverscaleAddress('0:00')).toBe(false);
  });
});

describe('messages match the official SDK', () => {
  it('nodeploy', () => {
    expect(bytesToHex(everscaleSigningHash(NODEPLOY, publicKey))).toBe(NODEPLOY_SIGNING_HASH);
    const signature = ed25519.sign(everscaleSigningHash(NODEPLOY, publicKey), SEED);
    expect(bytesToHex(signature)).toBe(NODEPLOY_SIGNATURE);
    const msg = everscaleExternalMessage(NODEPLOY, publicKey, hexToBytes(NODEPLOY_SIGNATURE));
    expect(msg.hash).toBe(NODEPLOY_MSG_HASH);
    expect(msg.boc).toBe(NODEPLOY_BOC);
    // The SDK's own serialization is the same cell tree.
    expect(parseBoc(base64.decode(NODEPLOY_SDK_BOC)).hashHex()).toBe(NODEPLOY_MSG_HASH);
  });

  it('deploy', () => {
    expect(bytesToHex(everscaleSigningHash(DEPLOY, publicKey))).toBe(DEPLOY_SIGNING_HASH);
    const msg = everscaleExternalMessage(DEPLOY, publicKey, hexToBytes(DEPLOY_SIGNATURE));
    expect(msg.hash).toBe(DEPLOY_MSG_HASH);
    expect(msg.boc).toBe(DEPLOY_BOC);
  });
});

describe('cell decoding', () => {
  it('reads the account boc layout', () => {
    const account = parseAccountBoc(
      base64.decode(accountBoc(SENDER, 5_000_000_000n, 1_700_000_000_000n)),
    );
    expect(account.status).toBe('active');
    expect(account.balance).toBe(5_000_000_000n);
    expect(account.codeHash).toBe(EVER_WALLET_CODE_HASH);
    expect(account.timestampMs).toBe(1_700_000_000_000n);
  });

  it('reads the transaction boc layout', () => {
    const tx = parseTransactionBoc(
      base64.decode(
        transactionBoc({
          account: SENDER,
          lt: 99n,
          now: 1_700_000_000,
          inValue: 0n,
          outValue: 42n,
        }),
      ),
    );
    expect(tx.lt).toBe('99');
    expect(tx.utime).toBe(1_700_000_000);
    expect(tx.aborted).toBe(false);
    expect(tx.inMsg?.external).toBe(false);
    expect(tx.inMsg?.source).toBe(RECIPIENT);
    expect(tx.inMsg?.value).toBe(0n);
    expect(tx.outMsgs).toHaveLength(1);
    expect(tx.outMsgs[0]?.value).toBe(42n);
    expect(tx.outMsgs[0]?.destination).toBe(RECIPIENT);
  });

  it('flags an aborted transaction', () => {
    const tx = parseTransactionBoc(
      base64.decode(
        transactionBoc({
          account: SENDER,
          lt: 99n,
          now: 1_700_000_000,
          inValue: 0n,
          outValue: 0n,
          aborted: true,
        }),
      ),
    );
    expect(tx.aborted).toBe(true);
  });
});

const intent = (amount = '123456789'): TxIntent =>
  ({
    id: 'tx1',
    walletId: 'w1',
    accountId: 'a1',
    chainId: VENOM_TESTNET,
    kind: 'transfer',
    to: RECIPIENT,
    asset: `${VENOM_TESTNET}:native`,
    amount,
    proposer: { kind: 'human' },
    createdAtMs: 1,
  }) as unknown as TxIntent;

describe('send path', () => {
  it('prepares a nodeploy transfer with a timestamp past the stored one', async () => {
    const { fetchImpl, calls } = jrpcFetch({
      getContractState: (p) => ({
        body:
          p.address === SENDER
            ? jrpcState(accountBoc(SENDER, 10_000_000_000n, 1_700_000_000_000n))
            : jrpcState(accountBoc(RECIPIENT, 1n, 1n)),
      }),
    });
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])], fetchImpl);
    const now = 1_700_000_100_000;
    const { unsigned, simulation } = await prepareEverscale(adapter, intent(), SENDER, now);
    expect(unsigned.deploy).toBe(false);
    expect(unsigned.bounce).toBe(true);
    expect(unsigned.timeMs).toBe(1_700_000_100_000);
    expect(unsigned.expireAt).toBeGreaterThan(Math.floor(now / 1000));
    expect(simulation.ok).toBe(true);
    expect(calls.some((c) => c.method === 'getLatestKeyBlock')).toBe(true);
  });

  it('deploys when the wallet is not on-chain yet and sends non-bounceable', async () => {
    const { fetchImpl } = jrpcFetch({
      getContractState: () => ({
        body: {
          jsonrpc: '2.0',
          id: 1,
          result: {
            account: { type: 'notExists' },
            genTimings: { genLt: '1', genUtime: 1 },
            lastTransactionId: { isExact: true, lt: '1', hash: 'ab'.repeat(32) },
          },
        },
      }),
    });
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])], fetchImpl);
    const { unsigned, simulation } = await prepareEverscale(
      adapter,
      intent(),
      SENDER,
      1_700_000_100_000,
    );
    expect(unsigned.deploy).toBe(true);
    expect(unsigned.bounce).toBe(false);
    expect(simulation.warnings.length).toBeGreaterThan(1);
  });

  it('refuses a foreign wallet contract as sender', async () => {
    const other = new Builder()
      .bit(true)
      .bytes(hexToBytes(SENDER.slice(2)))
      .coins(0n)
      .bit(false)
      .uint(1n, 64)
      .coins(10_000_000_000n)
      .bit(false)
      .bit(false)
      .bit(false)
      .bit(false)
      .bit(true)
      .bit(true)
      .bit(false)
      .ref(new Builder().uint(0xdec0de, 24).build()) // not EverWallet code
      .ref(new Builder().bytes(PUB).uint(1n, 64).build())
      .build();
    const { fetchImpl } = jrpcFetch({
      getContractState: (p) => ({
        body:
          p.address === SENDER
            ? jrpcState(base64.encode(serializeBoc(other)))
            : jrpcState(accountBoc(RECIPIENT, 1n, 1n)),
      }),
    });
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])], fetchImpl);
    await expect(prepareEverscale(adapter, intent(), SENDER, 1_700_000_100_000)).rejects.toThrow(
      'not an EverWallet',
    );
  });

  it('broadcasts the pinned signed message and returns its hash', async () => {
    const { fetchImpl } = jrpcFetch({
      sendMessage: () => ({ body: { jsonrpc: '2.0', id: 1, result: null } }),
    });
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])], fetchImpl);
    const hash = await broadcastEverscale(adapter, NODEPLOY, NODEPLOY_BOC);
    expect(hash).toBe(NODEPLOY_MSG_HASH);
  });

  it('refuses a tampered wire message', async () => {
    const { fetchImpl } = jrpcFetch({
      sendMessage: () => ({ body: { jsonrpc: '2.0', id: 1, result: null } }),
    });
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])], fetchImpl);
    const tampered = everscaleExternalMessage(
      { ...NODEPLOY, evers: '123456790' },
      publicKey,
      hexToBytes(NODEPLOY_SIGNATURE),
    );
    await expect(broadcastEverscale(adapter, NODEPLOY, tampered.boc)).rejects.toThrow(
      'Signed bytes are not this transfer',
    );
    await expect(broadcastEverscale(adapter, NODEPLOY, 'deadbeef')).rejects.toThrow(
      'Signed bytes are not this transfer',
    );
  });

  it('tracks the transfer through getDstTransaction', async () => {
    const txBoc = transactionBoc({
      account: SENDER,
      lt: 7n,
      now: 1_700_000_000,
      inValue: 0n,
      outValue: 123456789n,
    });
    const { fetchImpl } = jrpcFetch({
      getDstTransaction: () => ({
        body: { jsonrpc: '2.0', id: 1, result: { lt: '7', hash: 'cd'.repeat(32) } },
      }),
      getTransaction: () => ({ body: { jsonrpc: '2.0', id: 1, result: txBoc } }),
    });
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])], fetchImpl);
    const status = await everscaleTransferStatus(adapter, NODEPLOY, NODEPLOY_MSG_HASH);
    expect(status.state).toBe('confirmed');
  });

  it('reports expired once expireAt passed and the hash never landed', async () => {
    const { fetchImpl } = jrpcFetch({
      getDstTransaction: () => ({ body: { jsonrpc: '2.0', id: 1, result: null } }),
      getTransaction: () => ({ body: { jsonrpc: '2.0', id: 1, result: null } }),
      getContractState: () => ({ body: jrpcState(accountBoc(SENDER, 10n, 1n)) }),
    });
    const adapter = new TestAdapter([chain(VENOM_TESTNET, true, ['http://node'])], fetchImpl);
    const status = await everscaleTransferStatus(
      adapter,
      NODEPLOY,
      NODEPLOY_MSG_HASH,
      NODEPLOY.expireAt * 1000 + 120_000,
    );
    expect(status.state).toBe('expired');
  });
});

describe('everscale graphql dialect', () => {
  it('checks the global id and reads balances', async () => {
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const { query } = JSON.parse(String(init?.body)) as { query: string };
      if (query.includes('blocks')) return Response.json({ data: { blocks: [{ global_id: 42 }] } });
      if (query.includes('accounts'))
        return Response.json({
          data: {
            accounts: [{ balance: '0x11a379e56c', acc_type: 1, code_hash: null, data: null }],
          },
        });
      return Response.json({ data: {} });
    }) as typeof fetch;
    const adapter = new TestAdapter([chain(EVERSCALE_MAINNET, false, ['http://gql'])], fetchImpl);
    const holdings = await adapter.getBalances(SENDER, EVERSCALE_MAINNET);
    expect(holdings[0]?.amount).toBe('75757118828');
    expect(holdings[0]?.provenance?.kind).toBe('single');
  });

  it('refuses an endpoint on the wrong network', async () => {
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const { query } = JSON.parse(String(init?.body)) as { query: string };
      if (query.includes('blocks')) return Response.json({ data: { blocks: [{ global_id: 1 }] } });
      return Response.json({ data: { accounts: [] } });
    }) as typeof fetch;
    const adapter = new TestAdapter([chain(EVERSCALE_MAINNET, false, ['http://gql'])], fetchImpl);
    await expect(adapter.getBalances(SENDER, EVERSCALE_MAINNET)).rejects.toThrow();
  });
});

describe('slice reader', () => {
  it('reads big-endian ints, coins and refs', () => {
    const inner = new Builder().uint(7, 8).build();
    const cell = new Builder().uint(0b101, 3).coins(255n).bit(false).ref(inner).build();
    const s = new Slice(cell);
    expect(s.uint(3)).toBe(5n);
    expect(s.coins()).toBe(255n);
    expect(s.ref().hashHex()).toBe(inner.hashHex());
  });
});
