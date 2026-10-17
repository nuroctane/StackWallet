import { MemoryRpcPool } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  KEETA_CHAINS,
  KEETA_TEST,
  KeetaAdapter,
  isValidKeetaAddress,
  keetaAddressBytes,
  keetaAddressFromPublicKey,
  keetaTokenBytes,
  BASE_TOKEN,
} from './keeta.js';
import {
  KeetaTx,
  blockHash,
  broadcastKeeta,
  keetaApprovalValid,
  keetaTransferStatus,
  prepareKeeta,
  unsignedBlock,
} from './send.js';

const PUB_SEVEN = '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const SENDER = 'keeta_aabjrhalo3fvmolr7xe354y6ybwdkyhtesow52pf3a6foysvs3qf6326j34n5yq';
const RECIPIENT = 'keeta_aabhtptgp345zo5mkwqgffooq4fqoau37tns3tri3fm7fak3c34bpgftsw4yiua';
const HEAD = '22'.repeat(32).toUpperCase();
const HEAD_NEXT = '33'.repeat(32).toUpperCase();

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

const tx: KeetaTx = {
  chainId: KEETA_TEST,
  from: SENDER,
  to: RECIPIENT,
  attoKta: '1500000000',
  previous: '11'.repeat(32),
  timestamp: 1_760_000_000,
};

/** Byte-exact against `@keetanetwork/keetanet-client` 0.18.8 Block.Builder output. */
const UNSIGNED_VECTOR =
  '3081b70201000204544553540500180f32303235313030393038353332305a04220002989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f0500042011111111111111111111111111111111111111111111111111111111111111113051a04f304d0422000279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798020459682f0004210370829795df00bad194780cc1e1d2c0c90d7162e0c85eb22f63307bed3eaa754a';
const HASH_VECTOR = '871150734C5D92FE65756B5B5EE9DD1E84A63DA2467D53D479C31243C6397A4E';
/** SDK signature over sha3-256(blockHash); RFC6979, low-s, r||s. */
const SDK_SIGNATURE =
  '60c1be91558eb4ab0af050a60943434e1dc4439eb8871b538605b434735b6b5502d18f6327576bf897ebafddd297783b7805382e67718fb7f8a8138d9afa9308';

const TOKEN = BASE_TOKEN[KEETA_TEST]!;
const tokenAccount = {
  account: TOKEN,
  currentHeadBlock: HEAD,
  currentHeadBlockHeight: '0x7',
  representative: null,
  info: { account: TOKEN, name: 'KTA', description: 'Keeta', metadata: '' },
  balances: [],
};
const tokenHeadBlock = {
  blockhash: HEAD,
  block: {
    version: 1,
    date: '2026-10-17T01:00:01.761Z',
    previous: '00'.repeat(32).toUpperCase(),
    account: TOKEN,
    purpose: 0,
    signer: TOKEN,
    network: '0x54455354',
    operations: [],
    $hash: HEAD,
  },
};
function senderAccount(head: string | null, balance: string | null = '0xDE0B6B3A7640000') {
  return {
    account: SENDER,
    currentHeadBlock: head,
    currentHeadBlockHeight: head ? '0x3' : null,
    representative: null,
    info: { account: SENDER, name: '', description: '', metadata: '' },
    balances: balance === null ? [] : [{ token: TOKEN, balance }],
  };
}

function node(routes: Record<string, (url: URL, body: unknown) => unknown>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.host + url.pathname);
    const path = url.pathname.replace(/^\/api(?=\/)/, '');
    const route = routes[path] ?? routes[`${url.host}${path}`];
    if (!route) return new Response('{}', { status: 404 });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const out = route(url, body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  return new KeetaAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(KEETA_CHAINS) });
}

const intent: TxIntent = {
  chainId: KEETA_TEST,
  kind: 'transfer',
  to: RECIPIENT,
  asset: `${KEETA_TEST}:native`,
  amount: '1500000000',
} as TxIntent;

describe('keeta addresses', () => {
  it('derives the keeta_ address of private key 7 (SDK vector)', () => {
    // 33-byte compressed SEC1 of private key 7, per the SDK probe.
    const pub = hexToBytes('02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f');
    expect(keetaAddressFromPublicKey(pub)).toBe(SENDER);
    const a = new KeetaAdapter({ rpc: new MemoryRpcPool(KEETA_CHAINS) });
    expect(a.deriveAddress({ curve: 'secp256k1', hex: PUB_SEVEN }, KEETA_TEST)).toBe(SENDER);
    expect(() => a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, KEETA_TEST)).toThrow();
  });

  it('validates checksums, lengths and identifier types', () => {
    expect(isValidKeetaAddress(SENDER)).toBe(true);
    expect(isValidKeetaAddress(RECIPIENT)).toBe(true);
    expect(isValidKeetaAddress(`${SENDER.slice(0, -1)}x`)).toBe(false);
    expect(isValidKeetaAddress(SENDER.toUpperCase())).toBe(false);
    expect(isValidKeetaAddress(TOKEN)).toBe(false);
    expect(keetaAddressBytes(TOKEN)).toBeUndefined();
    expect(keetaTokenBytes(TOKEN)?.[0]).toBe(0x03);
    expect(keetaTokenBytes(SENDER)).toBeUndefined();
  });
});

describe('keeta blocks', () => {
  it('encodes the same unsigned block bytes as the core and the SDK', () => {
    expect(Buffer.from(unsignedBlock(tx)).toString('hex')).toBe(UNSIGNED_VECTOR);
    expect(blockHash(tx)).toBe(HASH_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => unsignedBlock({ ...tx, attoKta: '0' })).toThrow();
    expect(() => unsignedBlock({ ...tx, attoKta: '01' })).toThrow();
    expect(() => unsignedBlock({ ...tx, to: tx.from })).toThrow();
    expect(() => unsignedBlock({ ...tx, previous: '0'.repeat(64) })).toThrow();
    expect(() => unsignedBlock({ ...tx, timestamp: 0 })).toThrow();
    expect(() => unsignedBlock({ ...tx, chainId: 'keeta:main' as typeof KEETA_TEST })).toThrow();
  });

  it('prepares a test-network transfer from the sender head block', async () => {
    const { fetchImpl } = node({
      [`/node/ledger/account/${TOKEN}`]: () => tokenAccount,
      [`/node/ledger/block/${HEAD}`]: () => tokenHeadBlock,
      [`/node/ledger/account/${SENDER}`]: () => senderAccount(HEAD),
    });
    const a = adapter(fetchImpl);
    const { unsigned, simulation } = await prepareKeeta(a, intent, SENDER, 1_760_000_000_123);
    expect(unsigned).toEqual({ ...tx, previous: HEAD.toLowerCase() });
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe('0');
  });

  it('refuses an endpoint that serves another Keeta network', async () => {
    const wrong = {
      ...tokenAccount,
      info: { account: TOKEN, name: '', description: '', metadata: '' },
      currentHeadBlock: null,
      balances: [],
    };
    const { fetchImpl } = node({
      [`/node/ledger/account/${TOKEN}`]: () => wrong,
      [`/node/ledger/account/${SENDER}`]: () => senderAccount(HEAD),
    });
    await expect(prepareKeeta(adapter(fetchImpl), intent, SENDER)).rejects.toThrow(
      /does not serve this Keeta network/,
    );
  });

  it('reports insufficient balance and missing head block', async () => {
    const { fetchImpl } = node({
      [`/node/ledger/account/${TOKEN}`]: () => tokenAccount,
      [`/node/ledger/block/${HEAD}`]: () => tokenHeadBlock,
      [`/node/ledger/account/${SENDER}`]: () => senderAccount(HEAD, '0x1'),
    });
    const poor = await prepareKeeta(adapter(fetchImpl), intent, SENDER);
    expect(poor.simulation.ok).toBe(false);
    expect(poor.simulation.error).toMatch(/Balance/);

    const fresh = node({
      [`/node/ledger/account/${TOKEN}`]: () => tokenAccount,
      [`/node/ledger/block/${HEAD}`]: () => tokenHeadBlock,
      [`/node/ledger/account/${SENDER}`]: () => senderAccount(null, null),
    });
    const noHead = await prepareKeeta(adapter(fresh.fetchImpl), intent, SENDER);
    expect(noHead.simulation.ok).toBe(false);
    expect(noHead.simulation.error).toMatch(/no head block/);
  });

  it('approval holds while the sender head is unchanged', async () => {
    let head: string | null = HEAD;
    const prepared = { ...tx, previous: HEAD.toLowerCase() };
    const { fetchImpl } = node({
      [`/node/ledger/account/${TOKEN}`]: () => tokenAccount,
      [`/node/ledger/block/${HEAD}`]: () => tokenHeadBlock,
      [`/node/ledger/account/${SENDER}`]: () => senderAccount(head),
    });
    const a = adapter(fetchImpl);
    await expect(keetaApprovalValid(a, prepared)).resolves.toBe(true);
    head = HEAD_NEXT;
    await expect(keetaApprovalValid(a, prepared)).resolves.toBe(false);
  });

  it('broadcasts only the ledger block plus one 64-byte signature', async () => {
    let published: unknown;
    const { fetchImpl } = node({
      'publish-aid.test.network.api.keeta.com/publish': (_url, body) => {
        published = body;
        return { publish: true };
      },
    });
    const unsigned = unsignedBlock(tx);
    const signed = Buffer.concat([Buffer.from(unsigned), Buffer.alloc(66)]);
    // Fix the appended signature TLV: outer length grows by 66 and the tail is 04 40 || sig64.
    const fixed = Buffer.from(unsigned);
    const body = Buffer.concat([
      fixed.subarray(3),
      Buffer.from([0x04, 0x40]),
      Buffer.from(SDK_SIGNATURE, 'hex'),
    ]);
    const contentLen = body.length;
    const full = Buffer.concat([Buffer.from([0x30, 0x81, contentLen]), body]);
    void signed;
    const hash = await broadcastKeeta(adapter(fetchImpl), tx, full.toString('base64'));
    expect(hash).toBe(HASH_VECTOR);
    expect((published as { network: string }).network).toBe('test');
    expect((published as { blocks: string[] }).blocks[0]).toBe(full.toString('base64'));

    // A block whose bytes differ from the prepared one is refused before any POST.
    const tampered = Buffer.from(full);
    tampered[10]! ^= 1;
    let posts = 0;
    const counting = node({
      'publish-aid.test.network.api.keeta.com/publish': () => {
        posts++;
        return { publish: true };
      },
    });
    await expect(
      broadcastKeeta(adapter(counting.fetchImpl), tx, tampered.toString('base64')),
    ).rejects.toThrow(/not this KTA block/);
    expect(posts).toBe(0);
  });

  it('reports pending, confirmed and dropped transfers', async () => {
    const prepared = { ...tx, previous: HEAD.toLowerCase() };
    const block = {
      version: 1,
      date: '2025-10-09T08:53:20.000Z',
      previous: HEAD,
      account: SENDER,
      signer: SENDER,
      network: '0x54455354',
      operations: [{ type: 0, to: RECIPIENT, amount: '0x59682F00', token: TOKEN }],
      $hash: HASH_VECTOR,
    };
    const routes: Record<string, (url: URL, body: unknown) => unknown> = {
      [`/node/ledger/account/${TOKEN}`]: () => tokenAccount,
      [`/node/ledger/block/${HEAD}`]: () => tokenHeadBlock,
      [`/node/ledger/block/${HASH_VECTOR}`]: () => ({ blockhash: HASH_VECTOR, block }),
      [`/vote/${HASH_VECTOR}`]: () => ({ blockhash: HASH_VECTOR, votes: [] }),
      [`/node/ledger/account/${SENDER}`]: () => senderAccount(HEAD),
    };
    const { fetchImpl } = node(routes);
    const a = adapter(fetchImpl);
    expect((await a.status(HASH_VECTOR, KEETA_TEST)).state).toBe('pending');
    routes[`/vote/${HASH_VECTOR}`] = () => ({
      blockhash: HASH_VECTOR,
      votes: [
        {
          issuer: 'keeta_aabi4bd3f7jrt67mxcq44ozj65bh4bp2mygmrkedxggu2rxwn2ztuw3b6exivbq',
          $permanent: true,
        },
      ],
    });
    const confirmed = await keetaTransferStatus(a, prepared, HASH_VECTOR);
    expect(confirmed.state).toBe('confirmed');
    routes[`/node/ledger/block/${HASH_VECTOR}`] = () => ({ blockhash: HASH_VECTOR, block: null });
    routes[`/node/ledger/account/${SENDER}`] = () => senderAccount(HEAD_NEXT);
    const dropped = await keetaTransferStatus(a, prepared, HASH_VECTOR);
    expect(dropped.state).toBe('dropped');
  });

  it('reads the KTA balance and maps history SENDs', async () => {
    const sendBlock = {
      version: 1,
      date: '2025-10-09T08:53:20.000Z',
      previous: HEAD,
      account: SENDER,
      signer: SENDER,
      network: '0x54455354',
      operations: [{ type: 0, to: RECIPIENT, amount: '0x59682F00', token: TOKEN }],
      $hash: HASH_VECTOR,
    };
    const { fetchImpl } = node({
      [`/node/ledger/account/${TOKEN}`]: () => tokenAccount,
      [`/node/ledger/block/${HEAD}`]: () => tokenHeadBlock,
      [`/node/ledger/account/${SENDER}`]: () => senderAccount(HEAD),
      [`/node/ledger/account/${SENDER}/history`]: () => ({
        history: [{ voteStaple: { votes: [], blocks: [sendBlock] } }],
      }),
    });
    const a = adapter(fetchImpl);
    const balances = await a.getBalances(SENDER, KEETA_TEST);
    expect(balances[0]?.amount).toBe('1000000000000000000');
    expect(balances[0]?.assetRef).toBe(`${KEETA_TEST}:native`);
    const page = await a.getHistory(SENDER, KEETA_TEST);
    expect(page.items).toHaveLength(1);
    expect(page.items[0]?.hash).toBe(HASH_VECTOR);
    expect(page.items[0]?.assetDeltas[0]?.amount).toBe('-1500000000');
    expect(page.items[0]?.to).toBe(RECIPIENT);
  });
});
