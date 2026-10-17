import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  ICP_INDEX,
  ICP_LEDGER,
  ICP_MAINNET,
  IcpAdapter,
  accountBalanceArgs,
  candidDecode,
  crc32,
  decodeBalance,
  decodeIndexTransactions,
  field,
  icpAccountIdentifier,
  icpDerPublicKey,
  icpPrincipal,
  idlHash,
  isValidIcpAddress,
  queryBlocksArgs,
} from './icp.js';
import {
  ICP_FEE_E8S,
  IcpTx,
  broadcastIcp,
  candidTransferArgs,
  certificateReply,
  deriveRequestId,
  icpApprovalValid,
  prepareIcp,
} from './send.js';

// secp256k1 private key 0x0707…07 and 0x00…01, vectors from @dfinity SDK 2.4.1.
const KEY7_SEC1 = '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const KEY7_DER =
  '3056301006072a8648ce3d020106052b8104000a03420004989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f631f4d05b3ae518776ee08755a7703e64b2ebc32547504de0b55a142d4ecdf80';
const KEY7_PRINCIPAL = 'ebb18233c45a50841a64c0076e3ea4a3bfa332c603cb2362436985db02';
const KEY7_ACCOUNT = 'b7350197f5cc3597b65d5647d94b48b6d5e6a3ec7760e3bc91baba0b4597bdb5';
const KEY1_ACCOUNT = '1a230b1734a5a64feba98d21979a3d9384c92e27e6bba1fdd29c6028003764c3';
const KEY1_SEC1 = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

/** Pinned against `crates/stackwallet-core/src/icp.rs` (same bytes as @dfinity/candid). */
const CANDID_VECTOR =
  '4449444c066d7b6c01e0a9b302786e006c01d6f68e8001786e036c06fbca0100c6fcb60201ba89e5c20478a2de94eb060282f3f3910c04d8a38ca80d010105201a230b1734a5a64feba98d21979a3d9384c92e27e6bba1fdd29c6028003764c310270000000000002a0000000000000000010000b0d4acc66c1860e3160000000000';
const REQUEST_ID = '958da04033ffa8369aa967501b442ef0427e81a409d26bb51e0a505a100538a4';

// Live-captured boundary node replies (`.nur/icp-fixtures.json`).
const FIX_BALANCE_ZERO = '4449444c016c01e0a9b3027801000000000000000000';
const FIX_QUERY_BLOCKS_GENESIS =
  '4449444c196c0597928bda010186dda8bf0a03a4c7a8ce0c7891fb95920d7883f4f4c40f106e026d7b6d046c03dec389dc0405d6a9bbae0a0cc39c99ad0f016c04ba89e5c2047893a6c6900901a78882820a0682f3f3910c0c6e076b04adfaedfb0108ef80e5df020dc2f5d599030ecbd6fda00b0f6c07c6fcb60209eaca8a9e0402b98792ea077cd8bbb2840c09919c9cbf0d0adea7f7da0d0bcb96dcb40e026c01e0a9b302786e096e0c6c01d6f68e8001786c03eaca8a9e0402d8a38ca80d09cb96dcb40e016c02fbca0102d8a38ca80d096c05fbca0102c6fcb60209eaca8a9e0402d8a38ca80d09cb96dcb40e016d116c03c5b39af80712e2e8ada00878e6a99ef809786a0113011401016c02e2e8ada00878e6a99ef809786b02bc8a0115c5fed201166c0186dda8bf0a036b02b0ad8cd40417b0ad8fcd0c186c02c1a482a6057880d5dbdd05786c0290c6c1960571c498b1b50d78010001c904d9d9f7a2647472656583018301830182045820cb16921e0f07f1c9a9a22df7d9bf55ba00937e5218b9948b3758c087ab88aed583024863616e69737465728301830183018301820458201cf32a7d511284e554c73e704fd4150abf8fe75ce4e0268485b47dfae253ed7b830183024a000000000000000201018301830183024e6365727469666965645f6461746182035820efd1310627d65136882ca2e912fa87fd905f611cc72cf6baa0ce9d6cea14771582045820d8f64f7afca6a55d4ee6ded9b0200bac6651caf4c7a1920212b5a03c9bf1df36820458203acf246687995b712c35ae03a70bd02daf2c843660a7cd874b424dd4232f6cf382045820f87391f3bc59200447c667a0a94f2227a50a6ddaa0ed70ab7dd0c14a359ce96a82045820f61468e8df663046f534ffba8db57cd105717bfc4f3ac8006513a67d3a0533e382045820135104acfb21df0a85a428a05431fd1030b02e63804ffe38d755657ed786d1ab82045820547478959208546578cd3558e0425308a3e46c3b0b505c4123ce5465428c07c882045820944305f7033ff77752bb76b514a74526fbd50f0f91fdc67f3ce2735d06d7865d830182045820fdebf1ae95f515b4f4d2054cd08f537a8e9476f63948e3ae377abd0c39a3f4ff830182045820d41135896006abe66def7f86d653417e8188d53be524ef13fbc3f5acc18d048883024474696d65820349fabeaecbdab2c3ef18697369676e61747572655830b0ad3d3ce6ee3140f73709980b03bf0ed79d49a7ad33e6e6a527f596d68363f67b651dc13c581dcf2df2496f17c9aa9200f96956020000000080635602000000000101010a000000000000000901010a6765745f626c6f636b7300000000000000000100000000000000';
const FIX_INDEX_EMPTY =
  '4449444c136b02bc8a0101c5fed201126c039cbab69c0278d581cdb40c02f6f2aaac0d116d036c02dbb70178dec389dc04046c05ba89e5c2047893a6c6900905a78882820a07d6a9bbae0a0b82f3f3910c0b6e066d7b6b04adfaedfb0108ef80e5df020dc2f5d599030fcbd6fda00b106c06c6fcb60209eaca8a9e0471d8bbb2840c09919c9cbf0d0adea7f7da0d0bcb96dcb40e716c01e0a9b302786e096e0c6c01d6f68e8001786c03eaca8a9e0471d8a38ca80d09cb96dcb40e0e6e716c02fbca0171d8a38ca80d096c05fbca0171c6fcb60209eaca8a9e0471d8a38ca80d09cb96dcb40e0e6e786c01c7ebc4d0097101000000000000000000000000';
const FIX_CALL_CERTIFICATE =
  'd9d9f7a264747265658301820458203397a6929295ef1905aaa9c42a1789db2e1fa7d02819d2def570cff40cb58b148301830183024e726571756573745f73746174757383018301830182045820f459f57bccf7b14ff9911b94d894081083be5a3686c398a3737c4dc02e1c3c0c830183018301830182045820b4256a8e45a194038837d2294f46ba94cee4533f523d424b5cdb54b2a0d2fa48830183018301830183018204582019ddf74e7c6818117df1735eb7872183ce990e8dca7a3f632635f458ac0393f58301830258202bfd9699bc470a46ab71b2264be457dffa3dedd73fb1ce05122ab0a304ffd6d183018302457265706c79820358624449444c076b02bc8a0178c5fed201016b05b79eb35d02a1c3ebfd0703c7c6b5f60a05cce5b6900f7feb9cdbd50f066c01a7a5f3cc0e786c01bf9bb7f00d046c01e0a9b302786c018bbdf29b01786c019cbab69c02040100010400000000000000008302467374617475738203477265706c696564820458201f558ad76c7cba69c97b5c8ca67fbda10c13d96b44fe2d3289821471cbe5b2b28204582091b360d1e9f62246c86abf4298658d852e96a0c0b76e40de0eef90f89e77296682045820975f8c69f2873f9ada486b3777d7fb22f53c77db5c47ea9cfc55665b7da2f50a820458200a0e073fc1a88d4fe4864fd1e7abaf9555d22dc00d5fc6fbf5539638406f2e2c820458200be31f854d41f660f7b206005913fd16501f7c42315f112881e9d7f58f28cfa282045820cb0ea58e77d5fcf03f3ae4339ed02d7f1f783d2b6f30080837e3b73bc9b5703582045820dbf357b0a29fdd889a740cd6edceb66cd37394edf1e9288a1e4ea5f2a9823692820458206e1983eb44da6191bf1fb16929adec906afd43c94f5904ba56dd15287d3fa06f82045820adfe2731ade1ddd16779ef542717d8e530e1a1bfcf96283beaa30eb1c4c8294b82045820659c1516f200d1177f628b1e7414a34af3eb399c7c13cadf4b0f92bfba30be2f82045820866379eb4524df15f2de370a6442e94b5bc50dcae3390331817df24bf7b7fe8a830182045820586c77035f384429ff0e650ea48043bc1dff27f81aeeb2025348514871bc8e1e83024474696d65820349abc5bcc7e5b2c3ef18697369676e61747572655830b088c176766da0e96c77442cb9be4f19ef4cb86193f6a270e6973e5b004c69996b334a4d8c365fa4ca601302a565ea72';
const FIX_CALL_REQUEST_ID = '2bfd9699bc470a46ab71b2264be457dffa3dedd73fb1ce05122ab0a304ffd6d1';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const bytesToHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** Candid reply `variant { Ok: nat64; Err: null }` with Ok(blockHeight). */
function candidOkReply(height: bigint): Uint8Array {
  const head = hexToBytes('4449444c016b02bc8a0178c5fed2017f010000');
  const out = new Uint8Array(head.length + 8);
  out.set(head, 0);
  for (let i = 0; i < 8; i++) out[head.length + i] = Number((height >> BigInt(8 * i)) & 0xffn);
  return out;
}

const CHAIN: ChainInfo = {
  chainId: ICP_MAINNET,
  family: 'icp',
  name: 'Internet Computer',
  nativeAsset: { ref: `${ICP_MAINNET}:native`, symbol: 'ICP', decimals: 8 },
  testnet: false,
  explorerTxUrl: 'https://www.icpexplorer.org/#/tx/{hash}',
  defaultRpcs: ['https://icp-api.io', 'https://ic0.app'],
  priceId: 'internet-computer',
  layer: 'L1',
};

const ROOT_KEY =
  '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103814200814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae';

/** Minimal CBOR encoder for mocked node responses (maps of text keys). */
function mockCbor(value: unknown): Uint8Array {
  const enc = (v: unknown, out: number[]): void => {
    if (v instanceof Uint8Array) {
      out.push(...head(2, v.length), ...v);
    } else if (typeof v === 'number') {
      out.push(...head(0, v));
    } else if (typeof v === 'string') {
      const b = new TextEncoder().encode(v);
      out.push(...head(3, b.length), ...b);
    } else if (Array.isArray(v)) {
      out.push(...head(4, v.length));
      for (const item of v) enc(item, out);
    } else if (v && typeof v === 'object') {
      const entries = Object.entries(v);
      out.push(...head(5, entries.length));
      for (const [k, val] of entries) {
        enc(k, out);
        enc(val, out);
      }
    } else throw new Error('unsupported mock value');
  };
  const head = (major: number, len: number): number[] =>
    len < 24
      ? [(major << 5) | len]
      : len < 256
        ? [(major << 5) | 24, len]
        : [(major << 5) | 25, len >> 8, len & 0xff];
  const out: number[] = [];
  enc(value, out);
  return Uint8Array.from(out);
}

function mockFetch(routes: Record<string, (body: Uint8Array) => Uint8Array | null>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.host + url.pathname);
    const asBody = (b: Uint8Array) =>
      b.buffer.slice(b.byteOffset, b.byteOffset + b.length) as ArrayBuffer;
    if (url.pathname === '/api/v2/status')
      return new Response(asBody(mockCbor({ root_key: hexToBytes(ROOT_KEY) })), { status: 200 });
    const route = routes[url.pathname];
    if (!route) return new Response('not found', { status: 404 });
    const body = init?.body ? new Uint8Array(init.body as ArrayBuffer) : new Uint8Array();
    const out = route(body);
    if (out === null) return new Response(null, { status: 202 });
    return new Response(asBody(out), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

/** The lead wires the catalog; tests inject the chain entry directly. */
class TestAdapter extends IcpAdapter {
  override chains(): ChainInfo[] {
    return [CHAIN];
  }
}

function adapter(fetchImpl: typeof fetch) {
  return new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool([CHAIN]) });
}

const tx: IcpTx = {
  chainId: ICP_MAINNET,
  from: KEY7_ACCOUNT,
  to: KEY1_ACCOUNT,
  e8s: '1500000',
  memo: 42,
  createdAtNanos: '1760000000000000000',
  ingressExpiryNanos: '1760000300000000000',
};

describe('icp addresses', () => {
  it('crc32 and idlHash match known values', () => {
    expect(crc32(new TextEncoder().encode('123456789'))).toBe(0xcbf43926);
    expect(idlHash('e8s')).toBe(5_035_232);
    expect(idlHash('to')).toBe(25_979);
    expect(idlHash('fee')).toBe(5_094_982);
    expect(idlHash('memo')).toBe(1_213_809_850);
  });

  it('derives the principal and account id of the dfinity vectors', () => {
    const pub = hexToBytes(KEY7_SEC1);
    expect(bytesToHex(icpDerPublicKey(pub))).toBe(KEY7_DER);
    expect(bytesToHex(icpPrincipal(pub))).toBe(KEY7_PRINCIPAL);
    expect(icpAccountIdentifier(hexToBytes(KEY7_PRINCIPAL))).toBe(KEY7_ACCOUNT);
    const a = adapter(mockFetch({}).fetchImpl);
    expect(a.deriveAddress({ curve: 'secp256k1', hex: bytesToHex(pub) }, ICP_MAINNET)).toBe(
      KEY7_ACCOUNT,
    );
    expect(a.deriveAddress({ curve: 'secp256k1', hex: KEY1_SEC1 }, ICP_MAINNET)).toBe(KEY1_ACCOUNT);
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, ICP_MAINNET),
    ).toThrow();
  });

  it('refuses bad account identifiers', () => {
    expect(isValidIcpAddress(KEY7_ACCOUNT)).toBe(true);
    expect(isValidIcpAddress(KEY7_ACCOUNT.toUpperCase())).toBe(false);
    expect(isValidIcpAddress(KEY7_ACCOUNT.slice(0, 62) + '00')).toBe(false);
    expect(isValidIcpAddress('00'.repeat(32))).toBe(false);
    expect(isValidIcpAddress('xyz')).toBe(false);
  });
});

describe('icp transfers', () => {
  it('encodes the same TransferArgs bytes as the core', () => {
    expect(bytesToHex(candidTransferArgs(tx))).toBe(CANDID_VECTOR);
    expect(bytesToHex(deriveRequestId(tx, hexToBytes(KEY7_PRINCIPAL)))).toBe(REQUEST_ID);
  });

  it('refuses hostile fields', () => {
    expect(() => candidTransferArgs({ ...tx, e8s: '0' })).toThrow();
    expect(() => candidTransferArgs({ ...tx, to: tx.from })).toThrow();
    expect(() => candidTransferArgs({ ...tx, to: KEY7_ACCOUNT.slice(0, 62) + '00' })).toThrow();
    expect(() =>
      candidTransferArgs({ ...tx, chainId: 'icp:testnet' as typeof ICP_MAINNET }),
    ).toThrow();
  });

  it('reads the transfer reply out of a live certificate fixture', () => {
    const reply = certificateReply(
      hexToBytes(FIX_CALL_CERTIFICATE),
      hexToBytes(FIX_CALL_REQUEST_ID),
    );
    const decoded = candidDecode(reply);
    expect(typeof decoded).toBe('object');
    const variant = decoded as { id: number; value: unknown };
    expect(variant.id).toBe(idlHash('Err'));
    const err = variant.value as { id: number; value: Map<number, unknown> };
    expect(err.id).toBe(idlHash('InsufficientFunds'));
    const balance = err.value.get(idlHash('balance')) as Map<number, unknown>;
    expect(balance.get(idlHash('e8s'))).toBe(0n);
  });

  it('decodes live query fixtures', () => {
    expect(decodeBalance(hexToBytes(FIX_BALANCE_ZERO))).toBe('0');
    // Captured after genesis was archived: the block lives in archived_blocks.
    const blocks = candidDecode(hexToBytes(FIX_QUERY_BLOCKS_GENESIS));
    expect(field(blocks, 'chain_length')).toBeTypeOf('bigint');
    expect(field(blocks, 'blocks')).toHaveLength(0);
    expect(field(blocks, 'archived_blocks')).toHaveLength(1);
    const index = decodeIndexTransactions(hexToBytes(FIX_INDEX_EMPTY));
    expect(index.balance).toBe(0n);
    expect(index.transactions).toEqual([]);
  });

  it('prepares a mainnet transfer and catches insufficient funds', async () => {
    const { fetchImpl } = mockFetch({
      [`/api/v3/canister/${ICP_LEDGER}/query`]: () =>
        mockCbor({ status: 'replied', reply: { arg: hexToBytes(FIX_BALANCE_ZERO) } }),
    });
    const a = adapter(fetchImpl);
    const intent = {
      chainId: ICP_MAINNET,
      kind: 'transfer',
      to: KEY1_ACCOUNT,
      asset: `${ICP_MAINNET}:native`,
      amount: '1500000',
    } as const;
    const prepared = await prepareIcp(a, intent as never, KEY7_ACCOUNT, 1_760_000_000_000);
    expect(prepared.unsigned).toEqual({
      ...tx,
      memo: 0,
      ingressExpiryNanos: '1760000240000000000',
    });
    expect(prepared.simulation.ok).toBe(false);
    expect(prepared.simulation.error).toMatch(/does not cover/);
    expect(prepared.simulation.fee.amount).toBe(ICP_FEE_E8S.toString());
  });

  it('gates approval on the ingress expiry', () => {
    const a = adapter(mockFetch({}).fetchImpl);
    expect(icpApprovalValid(a, tx, 1_760_000_000_000)).toBe(true);
    expect(icpApprovalValid(a, tx, 1_760_000_290_000)).toBe(false);
  });

  it('broadcasts only the exact envelope and decodes the reply', async () => {
    const { secp256k1 } = await import('@noble/curves/secp256k1.js');
    const { sha256 } = await import('@noble/hashes/sha2.js');
    const { cborEncodeEnvelope } = await import('./icp.js');
    const principal = hexToBytes(KEY7_PRINCIPAL);
    const requestId = deriveRequestId(tx, principal);
    const sighash = sha256(
      Uint8Array.from([...new TextEncoder().encode('\x0Aic-request'), ...requestId]),
    );
    const secret = new Uint8Array(32).fill(7);
    const sig = secp256k1.sign(sighash, secret, { prehash: false });
    const wire = bytesToHex(
      cborEncodeEnvelope([
        [
          'content',
          {
            map: [
              ['request_type', { text: 'call' }],
              ['canister_id', { bytes: Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 2, 1, 1]) }],
              ['method_name', { text: 'transfer' }],
              ['arg', { bytes: candidTransferArgs(tx) }],
              ['sender', { bytes: principal }],
              ['ingress_expiry', { tag: 2n, value: { bytes: hexToBytes('186cc6f2ae14b800') } }],
            ].map(([k, v]) => [{ text: k }, v] as never),
          },
        ],
        ['sender_pubkey', { bytes: hexToBytes(KEY7_DER) }],
        ['sender_sig', { bytes: sig }],
      ]),
    );
    // A minimal but structurally valid certificate: request_status -> id -> reply.
    const okReply = candidOkReply(123_456n);
    const cert = mockCbor({
      tree: [
        1,
        [
          2,
          new TextEncoder().encode('request_status'),
          [
            2,
            requestId,
            [
              1,
              [2, new TextEncoder().encode('reply'), [3, okReply]],
              [2, new TextEncoder().encode('status'), [3, new TextEncoder().encode('replied')]],
            ],
          ],
        ],
        [4, new Uint8Array(32)],
      ],
      signature: new Uint8Array(48),
    });
    const { fetchImpl } = mockFetch({
      [`/api/v3/canister/${ICP_LEDGER}/call`]: () =>
        mockCbor({ status: 'replied', certificate: cert }),
    });
    const a = adapter(fetchImpl);
    await expect(broadcastIcp(a, tx, `0x${wire}`, bytesToHex(requestId))).resolves.toBe('123456');
    // A tampered signature fails before any network call.
    const bad = `${wire.slice(0, -128)}${'00'.repeat(64)}`;
    await expect(broadcastIcp(a, tx, `0x${bad}`, bytesToHex(requestId))).rejects.toThrow(
      'invalid signature',
    );
    // A wrong request id is refused.
    await expect(broadcastIcp(a, tx, `0x${wire}`, FIX_CALL_REQUEST_ID)).rejects.toThrow(
      'Request id does not match',
    );
  });

  it('reports block height status from query_blocks', async () => {
    const { fetchImpl } = mockFetch({
      [`/api/v3/canister/${ICP_LEDGER}/query`]: () =>
        mockCbor({ status: 'replied', reply: { arg: hexToBytes(FIX_QUERY_BLOCKS_GENESIS) } }),
    });
    const a = adapter(fetchImpl);
    const status = await a.status('0', ICP_MAINNET);
    expect(status.state).toBe('confirmed');
    expect((status as { blockNumber: number }).blockNumber).toBe(0);
    await expect(a.status('not-a-height', ICP_MAINNET)).rejects.toThrow('Invalid ICP block height');
  });

  it('reads balances cross-checked and history from the index canister', async () => {
    const { fetchImpl, calls } = mockFetch({
      [`/api/v3/canister/${ICP_LEDGER}/query`]: () =>
        mockCbor({ status: 'replied', reply: { arg: hexToBytes(FIX_BALANCE_ZERO) } }),
      [`/api/v3/canister/${ICP_INDEX}/query`]: () =>
        mockCbor({ status: 'replied', reply: { arg: hexToBytes(FIX_INDEX_EMPTY) } }),
    });
    const a = adapter(fetchImpl);
    const holdings = await a.getBalances(KEY7_ACCOUNT, ICP_MAINNET);
    expect(holdings).toHaveLength(1);
    expect(holdings[0]!.amount).toBe('0');
    expect(holdings[0]!.provenance?.kind).toBe('agreed');
    expect(calls.filter((c) => c.includes(ICP_LEDGER)).length).toBe(2);
    const page = await a.getHistory(KEY7_ACCOUNT, ICP_MAINNET);
    expect(page.items).toEqual([]);
    await expect(a.getHistory(KEY7_ACCOUNT, ICP_MAINNET, 'not-a-cursor')).rejects.toThrow(
      'Invalid history cursor',
    );
  });
});
