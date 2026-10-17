import { MemoryRpcPool } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  AELF_CHAINS,
  AELF_MAINNET,
  AELF_TESTNET,
  AelfAdapter,
  createAelfAdapter,
  decodeGetBalanceOutput,
  isValidAelfAddress,
  aelfAddressFromPublicKey,
} from './aelf.js';
import {
  AelfTx,
  FEE_ALLOWANCE_ELVES,
  REF_BLOCK_WINDOW,
  aelfApprovalValid,
  aelfTransferStatus,
  broadcastAelf,
  prepareAelf,
  transferRaw,
  transferTxId,
} from './send.js';

/** aelf-sdk `getWalletByPrivateKey` vectors (uncompressed-pubkey sha256d, base58check). */
const KEY1_COMPRESSED = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const KEY1_ADDRESS = '2QCi3Fy1QXZKFmP6tSBtxCXsaztNzeiDfNgWTamcsj428v4cPZ';
const KEY2_ADDRESS = '2YZDdbxdmb8ve4r8WuqP88zy2noy5wwWb22X8QBhnheNdXCKVK';
/** Produced by the official aelf-sdk for the fields below (`crates/stackwallet-core/src/aelf.rs` pins it too). */
const RAW_VECTOR =
  '0a220a20b860f56795fc03f3c21685383d1b5a2f2954f49b7e398b8d2a0193933621155f12220a200e9a238616169860ba4fb502f8e87ce62db9ef321f29fd76d6e1ce30a0e0cdba18cec2f1052204a1b2c3d42a085472616e73666572322e0a220a20cb58bf657f03cf52498df98acaceca4ecb272db2879409e8fe1cc2ec735298121203454c461880a3c347';
const TXID_VECTOR = '37da92b5f44c40c806a479b2067cb6ea2041a87b37a9d27b204297900e481155';
const HEAD_HASH = 'a1b2c3d4' + '00'.repeat(28);
const HEAD = 12_345_678;

const tx: AelfTx = {
  chainId: AELF_TESTNET,
  from: KEY1_ADDRESS,
  to: KEY2_ADDRESS,
  elves: '150000000',
  refBlockNumber: HEAD,
  refBlockPrefix: 'a1b2c3d4',
};

/** GetBalanceOutput { symbol: 'ELF', owner, balance } as the node returns it (base64). */
function balanceResponse(balance: bigint): string {
  const owner = Uint8Array.from(
    RAW_VECTOR.slice(8, 8 + 64)
      .match(/../g)!
      .map((b) => parseInt(b, 16)),
  );
  const enc = new TextEncoder();
  const bytes = [
    0x0a,
    3,
    ...enc.encode('ELF'),
    0x12,
    34,
    0x0a,
    32,
    ...owner,
    ...(balance > 0n ? [0x18, ...varint(balance)] : []),
  ];
  return Buffer.from(bytes).toString('base64');
}
function varint(v: bigint): number[] {
  const out: number[] = [];
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) b |= 0x80;
    out.push(b);
  } while (v > 0n);
  return out;
}

function node(routes: Record<string, (body: Record<string, unknown>) => unknown>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const key = `${init?.method ?? 'GET'} ${url.pathname}`;
    calls.push(key);
    const route = routes[key];
    if (!route) return new Response('{}', { status: 404 });
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const out = route(body);
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  const chains = AELF_CHAINS.map((c) => ({ ...c, defaultRpcs: ['https://node.example'] }));
  return new AelfAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) });
}

const chainStatus =
  (id: string, height = HEAD) =>
  () => ({
    ChainId: id,
    BestChainHeight: height,
    BestChainHash: HEAD_HASH,
    LongestChainHeight: height,
    LongestChainHash: HEAD_HASH,
  });

describe('aelf addresses', () => {
  it('derives the base58check address of private key 1', () => {
    const compressed = Uint8Array.from(KEY1_COMPRESSED.match(/../g)!.map((b) => parseInt(b, 16)));
    expect(aelfAddressFromPublicKey(compressed)).toBe(KEY1_ADDRESS);
    const a = createAelfAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: KEY1_COMPRESSED }, AELF_TESTNET)).toBe(
      KEY1_ADDRESS,
    );
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, AELF_TESTNET),
    ).toThrow();
  });

  it('refuses bad checksums, hex addresses, ELF_ prefixes and the zero address', () => {
    expect(isValidAelfAddress(KEY2_ADDRESS)).toBe(true);
    expect(isValidAelfAddress(KEY2_ADDRESS.slice(0, -1) + '1')).toBe(false);
    expect(isValidAelfAddress(`ELF_${KEY2_ADDRESS}_tDVV`)).toBe(false);
    expect(isValidAelfAddress('0x8ba1f109551bd432803012645ac136ddd64dba72')).toBe(false);
  });

  it('decodes GetBalanceOutput varints and absent zero balances', () => {
    expect(decodeGetBalanceOutput(Uint8Array.from([0x0a, 3, 69, 76, 70]))).toBe(0n);
    expect(
      decodeGetBalanceOutput(Uint8Array.from([0x0a, 3, 69, 76, 70, 0x18, 0x80, 0xa3, 0xc3, 0x47])),
    ).toBe(150000000n);
  });
});

describe('aelf transfers', () => {
  it('encodes the same Transaction bytes and id as the core and aelf-sdk', () => {
    expect(Buffer.from(transferRaw(tx)).toString('hex')).toBe(RAW_VECTOR);
    expect(transferTxId(tx)).toBe(TXID_VECTOR);
  });

  it('refuses hostile fields', () => {
    expect(() => transferRaw({ ...tx, elves: '0' })).toThrow();
    expect(() => transferRaw({ ...tx, elves: '0150000000' })).toThrow();
    expect(() => transferRaw({ ...tx, to: tx.from })).toThrow();
    expect(() => transferRaw({ ...tx, refBlockPrefix: 'A1B2C3D4' })).toThrow();
    expect(() => transferRaw({ ...tx, refBlockNumber: 0 })).toThrow();
    expect(() => transferRaw({ ...tx, chainId: AELF_MAINNET as typeof AELF_TESTNET })).toThrow();
  });

  it('prepares a tDVV transfer from the chain status and checks the balance', async () => {
    const { fetchImpl } = node({
      'GET /api/blockChain/chainStatus': chainStatus('tDVV'),
      'POST /api/blockChain/executeTransaction': () =>
        JSON.stringify(balanceResponse(200_000_000n)),
    });
    const a = adapter(fetchImpl);
    const intent = {
      id: 't',
      walletId: 'w',
      accountId: 'a',
      chainId: AELF_TESTNET,
      kind: 'transfer' as const,
      to: KEY2_ADDRESS,
      asset: `${AELF_TESTNET}:native`,
      amount: '150000000',
      proposer: { kind: 'human' as const, deviceId: 'd' },
      untrustedDestinations: [],
      createdAtMs: 0,
    };
    const { unsigned, simulation } = await prepareAelf(a, intent as never, KEY1_ADDRESS);
    expect(unsigned.refBlockNumber).toBe(HEAD);
    expect(unsigned.refBlockPrefix).toBe('a1b2c3d4');
    expect(simulation.ok).toBe(true);
    expect(simulation.fee.amount).toBe(FEE_ALLOWANCE_ELVES);
  });

  it('flags a balance that covers the amount but not the fee allowance', async () => {
    const { fetchImpl } = node({
      'GET /api/blockChain/chainStatus': chainStatus('tDVV'),
      'POST /api/blockChain/executeTransaction': () =>
        JSON.stringify(balanceResponse(150_500_000n)),
    });
    const a = adapter(fetchImpl);
    const intent = {
      chainId: AELF_TESTNET,
      kind: 'transfer' as const,
      to: KEY2_ADDRESS,
      asset: `${AELF_TESTNET}:native`,
      amount: '150000000',
    };
    const { simulation } = await prepareAelf(a, intent as never, KEY1_ADDRESS);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/fee/);
  });

  it('refuses an endpoint that serves another aelf chain', async () => {
    const { fetchImpl } = node({
      'GET /api/blockChain/chainStatus': chainStatus('AELF'),
      'POST /api/blockChain/executeTransaction': () => JSON.stringify(balanceResponse(1n)),
    });
    await expect(adapter(fetchImpl).getBalances(KEY1_ADDRESS, AELF_TESTNET)).rejects.toThrow();
  });

  it('reads the ELF balance through a throwaway-signed view call', async () => {
    let rawTransaction = '';
    const { fetchImpl } = node({
      'GET /api/blockChain/chainStatus': chainStatus('tDVV'),
      'POST /api/blockChain/executeTransaction': (b) => {
        rawTransaction = String(b.RawTransaction);
        return JSON.stringify(balanceResponse(950_000_001n));
      },
    });
    const holdings = await adapter(fetchImpl).getBalances(KEY1_ADDRESS, AELF_TESTNET);
    expect(holdings[0]!.amount).toBe('950000001');
    // The view call is a signed Transfer-free GetBalance transaction.
    expect(rawTransaction).toContain('47657442616c616e6365');
    expect(rawTransaction.length % 2).toBe(0);
  });

  it('broadcasts only the ledger transfer with one signature', async () => {
    const seen: string[] = [];
    const { fetchImpl } = node({
      'GET /api/blockChain/chainStatus': chainStatus('tDVV'),
      'POST /api/blockChain/sendTransaction': (b) => {
        seen.push(String(b.RawTransaction));
        return { TransactionId: TXID_VECTOR };
      },
    });
    const a = adapter(fetchImpl);
    const signed = `${RAW_VECTOR}82f10441${'11'.repeat(65)}`;
    await expect(broadcastAelf(a, tx, signed)).resolves.toBe(TXID_VECTOR);
    await expect(broadcastAelf(a, { ...tx, elves: '150000001' }, signed)).rejects.toThrow();
    await expect(broadcastAelf(a, tx, signed + '00')).rejects.toThrow();
    expect(seen).toHaveLength(1);
  });

  it('maps transactionResult states and reports expiry past the ref window', async () => {
    let status = 'NOTEXISTED';
    let head = HEAD + 1;
    const { fetchImpl } = node({
      'GET /api/blockChain/chainStatus': () => ({
        ChainId: 'tDVV',
        BestChainHeight: head,
        BestChainHash: HEAD_HASH,
      }),
      'GET /api/blockChain/transactionResult': () => ({
        TransactionId: TXID_VECTOR,
        Status: status,
        BlockNumber: HEAD,
      }),
    });
    const a = adapter(fetchImpl);
    await expect(aelfTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({ state: 'unknown' });
    head = HEAD + REF_BLOCK_WINDOW + 1;
    await expect(aelfTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({ state: 'expired' });
    status = 'MINED';
    await expect(aelfTransferStatus(a, tx, TXID_VECTOR)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: HEAD,
    });
    status = 'FAILED';
    await expect(aelfTransferStatus(a, tx, TXID_VECTOR)).resolves.toMatchObject({
      state: 'failed',
    });
  });

  it('keeps approval valid only inside the reference block window', async () => {
    let head = HEAD + 10;
    const { fetchImpl } = node({
      'GET /api/blockChain/chainStatus': () => ({
        ChainId: 'tDVV',
        BestChainHeight: head,
        BestChainHash: HEAD_HASH,
      }),
    });
    const a = adapter(fetchImpl);
    await expect(aelfApprovalValid(a, tx)).resolves.toBe(true);
    head = HEAD + REF_BLOCK_WINDOW + 1;
    await expect(aelfApprovalValid(a, tx)).resolves.toBe(false);
    head = HEAD - 1;
    await expect(aelfApprovalValid(a, tx)).resolves.toBe(false);
  });
});
