import { MemoryRpcPool } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { CHROMIA_CHAINS, CHROMIA_TESTNET, ChromiaAdapter } from './chromia.js';
import {
  ChromiaRegisterTx,
  ChromiaTx,
  broadcastChromia,
  chromiaApprovalValid,
  chromiaTransferStatus,
  chromiaTxId,
  prepareChromia,
  prepareChromiaRegistration,
  transferBody,
  registerBody,
} from './send.js';
import {
  CHROMIA_NETWORKS,
  chromiaAccountIdFromPublicKey,
  gtvDecode,
  gtvEncode,
  isValidChromiaAddress,
} from './chromia.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

/**
 * Vectors produced by postchain-client 2.1.5 / @chromia/ft4 2.1.0
 * (.nur/chromia-oracle/oracle3.cjs) for private key 0x07..07, and accepted by
 * the live testnet economy chain (rejected only on account state).
 */
const PUBKEY = '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const ACCOUNT = '40e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122';
const BRID = CHROMIA_NETWORKS[CHROMIA_TESTNET]!.brid;
const BODY_VECTOR =
  'a58201503082014ca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a581fc3081f9a55d305ba20d0c0b6674342e66745f61757468a54a3048a122042040e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122a1220420e0463c0b221e1498aae3631e413e135288aa13cab1dd72e5fe2f501bc3613bcba5653063a20e0c0c6674342e7472616e73666572a551304fa1220420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12204209ef73a786a66f435b3b40e72f5e9d85a4b09815997e087c809913e1e7ec686b4a605020316e360a531302fa2050c036e6f70a5263024a12204201111111111111111111111111111111111111111111111111111111111111111a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const TXID_VECTOR = '67d8fd5597f0d50c152655010140be38fd6444cea8c630e8e5200b0091af0006';
const WIRE_VECTOR =
  'a58201a03082019ca58201503082014ca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a581fc3081f9a55d305ba20d0c0b6674342e66745f61757468a54a3048a122042040e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122a1220420e0463c0b221e1498aae3631e413e135288aa13cab1dd72e5fe2f501bc3613bcba5653063a20e0c0c6674342e7472616e73666572a551304fa1220420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12204209ef73a786a66f435b3b40e72f5e9d85a4b09815997e087c809913e1e7ec686b4a605020316e360a531302fa2050c036e6f70a5263024a12204201111111111111111111111111111111111111111111111111111111111111111a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa5463044a1420440be8a7acd0f86775d4568b4c091fdeb4e2db6546c6ddb5293fbf967420d981cd776407de6af5bf1a5815db87ac20f9d02c735ff004cb079391c2547275b67d93e';
const REG_BODY_VECTOR =
  'a581df3081dca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a5818c308189a5673065a2170c156674342e7261735f7472616e736665725f6f70656ea54a3048a5423040a303020100a5353033a50c300aa2030c0141a2030c0154a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa0020500a0020500a51e301ca2160c146674342e72656769737465725f6163636f756e74a5023000a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const REG_TXID_VECTOR = 'e73776b378023517a0640ed5dac5059c4ab047f3189e481dcdc3c84eeeb56cf0';
const REG_WIRE_VECTOR =
  'a582012e3082012aa581df3081dca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a5818c308189a5673065a2170c156674342e7261735f7472616e736665725f6f70656ea54a3048a5423040a303020100a5353033a50c300aa2030c0141a2030c0154a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa0020500a0020500a51e301ca2160c146674342e72656769737465725f6163636f756e74a5023000a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa5463044a1420440cb0d0ef924e7f6a359e61ddc9fd1f00020816f5ace6b733923cda7d7fad4ae826640d16f36018b8ed6118afcc4c13e5895667f4f6e2643a8c5c5320fe460afec';

const tx: ChromiaTx = {
  chainId: CHROMIA_TESTNET,
  from: ACCOUNT,
  signer: PUBKEY,
  to: 'aa'.repeat(32),
  uchr: '1500000',
  nonce: '11'.repeat(32),
};
const registerTx: ChromiaRegisterTx = {
  chainId: CHROMIA_TESTNET,
  from: ACCOUNT,
  signer: PUBKEY,
  register: true,
};

interface NodeState {
  account?: unknown;
  balance?: unknown;
  status?: Record<string, unknown>;
  broadcast?: { status: number; body: string };
  blocks?: unknown;
}

function node(state: NodeState) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.pathname);
    if (url.pathname === `/config/${BRID}/features`)
      return Response.json({ merkle_hash_version: 2 });
    if (url.pathname === `/query_gtv/${BRID}`) {
      const body = init!.body as unknown as Uint8Array;
      const decoded = gtvDecode(body) as [string, Record<string, unknown>];
      const [name, args] = decoded;
      let value: unknown = null;
      if (name === 'ft4.get_account_by_id') {
        // Only the oracle account exists; every other id is unregistered.
        value =
          bytesToHex((args.id as Uint8Array) ?? new Uint8Array()) === ACCOUNT
            ? (state.account ?? null)
            : null;
      } else if (name === 'ft4.get_asset_balance') value = state.balance ?? null;
      return new Response(gtvEncode(value as never) as unknown as BodyInit, {
        status: 200,
        headers: { 'Content-Type': 'application/octet-stream' },
      });
    }
    if (url.pathname.startsWith(`/tx/${BRID}/`) && url.pathname.endsWith('/status'))
      return Response.json(state.status ?? { status: 'unknown' });
    if (url.pathname === `/tx/${BRID}` && init?.method === 'POST') {
      const b = state.broadcast ?? { status: 200, body: '{}' };
      return new Response(b.body, { status: b.status });
    }
    if (url.pathname === `/blocks/${BRID}`)
      return Response.json(state.blocks ?? [{ rid: 'aa'.repeat(32), height: 1914400 }]);
    return new Response('{}', { status: 404 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new ChromiaAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHROMIA_CHAINS) });
}

describe('chromia addresses', () => {
  it('derives the FT4 account id of private key 7', () => {
    expect(chromiaAccountIdFromPublicKey(hexToBytes(PUBKEY))).toBe(ACCOUNT);
    const a = new ChromiaAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: PUBKEY }, CHROMIA_TESTNET)).toBe(ACCOUNT);
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, CHROMIA_TESTNET),
    ).toThrow();
  });

  it('validates account id hex', () => {
    expect(isValidChromiaAddress(ACCOUNT)).toBe(true);
    expect(isValidChromiaAddress(ACCOUNT.toUpperCase())).toBe(false);
    expect(isValidChromiaAddress('0x' + ACCOUNT)).toBe(false);
    expect(isValidChromiaAddress(ACCOUNT.slice(0, 62))).toBe(false);
  });
});

describe('chromia transfers', () => {
  it('encodes the same body and rid as the SDK oracle', () => {
    expect(bytesToHex(gtvEncode(transferBody(tx)))).toBe(BODY_VECTOR);
    expect(chromiaTxId(tx)).toBe(TXID_VECTOR);
    expect(bytesToHex(gtvEncode(registerBody(registerTx)))).toBe(REG_BODY_VECTOR);
    expect(chromiaTxId(registerTx)).toBe(REG_TXID_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => transferBody({ ...tx, uchr: '0' })).toThrow();
    expect(() => transferBody({ ...tx, uchr: '01' })).toThrow();
    expect(() => transferBody({ ...tx, to: tx.from })).toThrow();
    expect(() => transferBody({ ...tx, nonce: '00'.repeat(32) })).toThrow();
    expect(() => transferBody({ ...tx, signer: '04' + PUBKEY.slice(2) })).toThrow();
    expect(() =>
      transferBody({ ...tx, chainId: 'chromia:0x15c0ca99bee60a3b' as typeof CHROMIA_TESTNET }),
    ).toThrow();
  });

  it('prepares a transfer for a registered, funded account', async () => {
    const { fetchImpl } = node({
      account: { id: hexToBytes(ACCOUNT) },
      balance: 5_000_000n,
    });
    const intent = {
      chainId: CHROMIA_TESTNET,
      kind: 'transfer',
      to: tx.to,
      asset: `${CHROMIA_TESTNET}:native`,
      amount: '1500000',
    } as TxIntent;
    const { unsigned, simulation } = await prepareChromia(
      adapter(fetchImpl),
      intent,
      ACCOUNT,
      PUBKEY,
    );
    expect(simulation.ok).toBe(true);
    expect(unsigned.uchr).toBe('1500000');
    expect(unsigned.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(unsigned.nonce).not.toBe(tx.nonce);
  });

  it('warns when the recipient is unregistered and fails when the sender is', async () => {
    const funded = node({ account: { id: hexToBytes(ACCOUNT) }, balance: 5_000_000n });
    const intent = {
      chainId: CHROMIA_TESTNET,
      kind: 'transfer',
      to: tx.to,
      asset: `${CHROMIA_TESTNET}:native`,
      amount: '1500000',
    } as TxIntent;
    const prepared = await prepareChromia(adapter(funded.fetchImpl), intent, ACCOUNT, PUBKEY);
    expect(prepared.simulation.warnings.some((w) => w.kind === 'other')).toBe(true);

    const missing = node({ account: null, balance: null });
    const failed = await prepareChromia(adapter(missing.fetchImpl), intent, ACCOUNT, PUBKEY);
    expect(failed.simulation.ok).toBe(false);
    expect(failed.simulation.error).toMatch(/no FT4 account/);
  });

  it('prepares a self-claim registration only while the account is missing', async () => {
    const missing = node({ account: null });
    const reg = await prepareChromiaRegistration(adapter(missing.fetchImpl), ACCOUNT, PUBKEY);
    expect(reg.simulation.ok).toBe(true);
    expect(reg.unsigned.register).toBe(true);
    const present = node({ account: { id: hexToBytes(ACCOUNT) } });
    const again = await prepareChromiaRegistration(adapter(present.fetchImpl), ACCOUNT, PUBKEY);
    expect(again.simulation.ok).toBe(false);
  });

  it('keeps approval valid while the account state matches the tx kind', async () => {
    const present = node({ account: { id: hexToBytes(ACCOUNT) } });
    expect(await chromiaApprovalValid(adapter(present.fetchImpl), tx)).toBe(true);
    const missing = node({ account: null });
    expect(await chromiaApprovalValid(adapter(missing.fetchImpl), tx)).toBe(false);
    expect(await chromiaApprovalValid(adapter(missing.fetchImpl), registerTx)).toBe(true);
  });
});

describe('chromia broadcast and status', () => {
  it('broadcasts exactly the oracle wire and returns the rid', async () => {
    const { fetchImpl, calls } = node({ broadcast: { status: 200, body: '{}' } });
    const rid = await broadcastChromia(adapter(fetchImpl), tx, WIRE_VECTOR);
    expect(rid).toBe(TXID_VECTOR);
    expect(calls.some((p) => p === `/tx/${BRID}`)).toBe(true);
    const regRid = await broadcastChromia(adapter(fetchImpl), registerTx, REG_WIRE_VECTOR);
    expect(regRid).toBe(REG_TXID_VECTOR);
  });

  it('refuses wires that are not this transaction', async () => {
    const { fetchImpl } = node({});
    const a = adapter(fetchImpl);
    // The registration wire is valid GTV but a different body.
    await expect(broadcastChromia(a, tx, REG_WIRE_VECTOR)).rejects.toThrow(/not this Chromia/);
    // Truncated signature.
    await expect(broadcastChromia(a, tx, WIRE_VECTOR.slice(0, -2))).rejects.toThrow();
    // Garbage.
    await expect(broadcastChromia(a, tx, 'deadbeef')).rejects.toThrow();
    // A reserialized body with a second signature.
    const body = gtvDecode(hexToBytes(WIRE_VECTOR)) as unknown[];
    const sig = (body[1] as unknown[])[0] as Uint8Array;
    const twoSigs = bytesToHex(gtvEncode([body[0], [sig, sig]] as never));
    await expect(broadcastChromia(a, tx, twoSigs)).rejects.toThrow(/exactly one/);
  });

  it('maps node statuses, with rejections carrying the reason', async () => {
    const { fetchImpl } = node({
      status: { status: 'rejected', rejectReason: 'MISSING ACCOUNT: Account not found' },
    });
    const st = await chromiaTransferStatus(adapter(fetchImpl), tx, TXID_VECTOR);
    expect(st).toEqual({ state: 'failed', reason: 'MISSING ACCOUNT: Account not found' });

    const waiting = node({ status: { status: 'waiting' } });
    expect(await chromiaTransferStatus(adapter(waiting.fetchImpl), tx, TXID_VECTOR)).toEqual({
      state: 'pending',
    });

    const unknown = node({ status: { status: 'unknown' } });
    expect(await chromiaTransferStatus(adapter(unknown.fetchImpl), tx, TXID_VECTOR)).toEqual({
      state: 'unknown',
    });
  });

  it('reports confirmations with the block the tx appears in', async () => {
    const { fetchImpl } = node({
      status: { status: 'confirmed' },
      blocks: [
        { rid: 'bb'.repeat(32), height: 1914401, transactions: [] },
        {
          rid: 'aa'.repeat(32),
          height: 1914400,
          transactions: [{ rid: TXID_VECTOR.toUpperCase() }],
        },
      ],
    });
    expect(await chromiaTransferStatus(adapter(fetchImpl), tx, TXID_VECTOR)).toEqual({
      state: 'confirmed',
      blockNumber: 1914400,
    });
  });

  it('cross-checks balances and flags unregistered accounts', async () => {
    const { fetchImpl } = node({ account: { id: hexToBytes(ACCOUNT) }, balance: 1_500_000n });
    const holdings = await adapter(fetchImpl).getBalances(ACCOUNT, CHROMIA_TESTNET);
    expect(holdings[0]!.amount).toBe('1500000');
    expect(holdings[0]!.notice).toBeUndefined();

    const missing = node({ account: null, balance: null });
    const zero = await adapter(missing.fetchImpl).getBalances(ACCOUNT, CHROMIA_TESTNET);
    expect(zero[0]!.amount).toBe('0');
    expect(zero[0]!.notice).toMatch(/pending/);
  });
});
