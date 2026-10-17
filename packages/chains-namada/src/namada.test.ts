import { describe, expect, it, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';

import {
  NAMADA_HOUSEFIRE,
  NAMADA_MAINNET,
  NAMADA_CHAINS,
  NAM_TOKEN,
  NamadaAdapter,
  isValidNamadaAddress,
  namadaAddressFromPublicKey,
} from './namada.js';
import {
  NamadaTx,
  broadcastNamada,
  encodeSignedTransfer,
  namadaApprovalValid,
  prepareNamada,
  sighashes,
  transferHash,
} from './send.js';

// The same fixed test key the Rust suite and the `.nur` oracle use.
const SECRET = hexToBytes('07'.repeat(32));
const PUB = ed25519.getPublicKey(SECRET);
const SENDER = 'tnam1qpfe0prje04hulwjdvsjqtmucpfxpttxyy7v2689';
const RECIPIENT = 'tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5';
const WASM_HASH = '9a950b45d233c8f6fabfa5c473800c182f7666fe0c35c1a612f66a5f094758fe';
const INNER_SIG = hexToBytes(
  '09892caf565c4974e722cde36e808471a523498032235f47227ded7395b80e304b44aa0518a93b41c365d0a4c886cfce5a843c4e204a7bf62c3ec3d39a98d007',
);
const WRAPPER_SIG = hexToBytes(
  'd8bd536fb11f474d6cc2b78800e7d484347fa276c420070f95ef5e821a501d4235a655cc8dbf35c5f18c8491280b3dd3654e7c5cc285a5c8c0d93609d8902f01',
);
const WIRE =
  '0af0061e000000686f757365666972652d616c706163612e636330643365306330333362650023000000323032362d31302d31365432313a30303a30302e3030303030303030302b30303a303001000000bd2cacb080ac06e6ae7e7b29629594403c32cdcb8b0502ca40203c8d4c6f92c3c9a06b58d5e3330340114bfed6da25ec44ae4e8d553d3fefe047a59d17c658710000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000000600503d6b0ce56e316df06d2dbfce52c9d48844df4a00ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c50c300000000000004000000020102030405060708009a950b45d233c8f6fabfa5c473800c182f7666fe0c35c1a612f66a5f094758fe011000000074785f7472616e736665722e7761736d0008070605040302019f000000010000000153978472cbeb7e7dd26b21202f7cc05260ad662100503d6b0ce56e316df06d2dbfce52c9d48844df4a15cd5b0700000000000000000000000000000000000000000000000000000000060100000000e54868c1a502fa105374d2bb3236195125c1d19800503d6b0ce56e316df06d2dbfce52c9d48844df4a15cd5b0700000000000000000000000000000000000000000000000000000000060003010000008dd33d3eec3b798eb08d176eeeb39831793efbf76cab3d17e9df634a56d674b6000153978472cbeb7e7dd26b21202f7cc05260ad662101000000000009892caf565c4974e722cde36e808471a523498032235f47227ded7395b80e304b44aa0518a93b41c365d0a4c886cfce5a843c4e204a7bf62c3ec3d39a98d007030400000063905a23bbbe5bce76ee8f87deeffcd02d6be2fc29af02c7ca401f5b054c3fc7bd2cacb080ac06e6ae7e7b29629594403c32cdcb8b0502ca40203c8d4c6f92c3c9a06b58d5e3330340114bfed6da25ec44ae4e8d553d3fefe047a59d17c658710993480f2675651115eb55cebf6b3568287b0dbc446144852462c865e0a58cdb010100000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c010000000000d8bd536fb11f474d6cc2b78800e7d484347fa276c420070f95ef5e821a501d4235a655cc8dbf35c5f18c8491280b3dd3654e7c5cc285a5c8c0d93609d8902f01';
const WRAPPER_HASH = '63905a23bbbe5bce76ee8f87deeffcd02d6be2fc29af02c7ca401f5b054c3fc7';

const TX: NamadaTx = {
  chainId: NAMADA_HOUSEFIRE,
  from: SENDER,
  to: RECIPIENT,
  namnam: '123456789',
  token: NAM_TOKEN,
  feeToken: NAM_TOKEN,
  feePerGas: '1',
  gasLimit: 50000,
  wasmCodeHash: WASM_HASH,
  timestamp: '2026-10-16T21:00:00.000000000+00:00',
  codeSalt: '0102030405060708',
  dataSalt: '0807060504030201',
};

describe('addresses', () => {
  it('derives the implicit account of an ed25519 key', () => {
    expect(namadaAddressFromPublicKey(PUB)).toBe(SENDER);
  });

  it('validates canonical spendable addresses only', () => {
    expect(isValidNamadaAddress(SENDER)).toBe(true);
    expect(isValidNamadaAddress(RECIPIENT)).toBe(true);
    expect(isValidNamadaAddress('tnam1qpfe0prje04hulwjdvsjqtmucpfxpttxyy7v2688')).toBe(false);
    expect(isValidNamadaAddress(SENDER.toUpperCase())).toBe(false);
    // Internal accounts (multitoken) are not spendable recipients.
    expect(isValidNamadaAddress('tnam1pyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqej6juv')).toBe(false);
    expect(isValidNamadaAddress('stc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq')).toBe(false);
  });

  it('adapter maps keys and validates per chain', () => {
    const adapter = new NamadaAdapter();
    expect(adapter.chains().map((c) => c.chainId)).toContain(NAMADA_MAINNET);
    expect(
      adapter.deriveAddress(
        { curve: 'ed25519', hex: Buffer.from(PUB).toString('hex') },
        NAMADA_MAINNET,
      ),
    ).toBe(SENDER);
    expect(adapter.validateAddress(SENDER, NAMADA_HOUSEFIRE)).toBe(true);
    expect(() => adapter.validateAddress(SENDER, 'namada:unknown')).toThrow();
  });
});

describe('wire format', () => {
  it('matches the Rust and oracle vectors byte-for-byte', () => {
    const parts = encodeSignedTransfer(TX, INNER_SIG, WRAPPER_SIG, PUB);
    expect(Buffer.from(parts.wire).toString('hex')).toBe(WIRE);
    expect(Buffer.from(parts.wrapperHash).toString('hex')).toBe(WRAPPER_HASH);
    expect(transferHash(TX, PUB)).toBe(WRAPPER_HASH);
  });

  it('reproduces both sighashes the Rust signer sees', () => {
    const hashes = sighashes(TX, INNER_SIG, PUB);
    expect(hashes.inner).toBe('dbf8a642b30cedbce9eb5bee78d1d92131e6a0d7663448245447cd7925a23743');
    expect(hashes.wrapper).toBe('832d746bfd040f14a6b4561b94baa41e6bb97d8492c0518c3155f0fd58c332fd');
    // The oracle's ed25519 signatures verify over these digests.
    expect(ed25519.verify(INNER_SIG, hexToBytes(hashes.inner), PUB)).toBe(true);
    expect(ed25519.verify(WRAPPER_SIG, hexToBytes(hashes.wrapper), PUB)).toBe(true);
  });

  it('fresh signatures over the same fields reproduce the same shape', () => {
    const hashes = sighashes(TX, new Uint8Array(64), PUB);
    const inner = ed25519.sign(hexToBytes(hashes.inner), SECRET);
    const wrapper = ed25519.sign(hexToBytes(sighashes(TX, inner, PUB).wrapper), SECRET);
    const parts = encodeSignedTransfer(TX, inner, wrapper, PUB);
    expect(parts.wire.length).toBe(hexToBytes(WIRE).length);
    expect(namadaApprovalValid(TX, Buffer.from(parts.wire).toString('hex'), PUB)).toBe(true);
  });

  it('rejects tampered signed bytes', () => {
    expect(namadaApprovalValid(TX, WIRE, PUB)).toBe(true);
    const tampered = `${WIRE.slice(0, 100)}${WIRE[100] === '0' ? '1' : '0'}${WIRE.slice(101)}`;
    expect(namadaApprovalValid(TX, tampered, PUB)).toBe(false);
    expect(namadaApprovalValid(TX, WIRE.slice(0, -2), PUB)).toBe(false);
    const other = { ...TX, namnam: '123456790' };
    expect(namadaApprovalValid(other, WIRE, PUB)).toBe(false);
  });
});

const b64 = (hex: string) => Buffer.from(hexToBytes(hex)).toString('base64');

function mockFetch(balanceNamnam = '200000000'): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes('indexer.namada.net/api/v1/gas-price/'))
      return new Response(JSON.stringify([{ token: NAM_TOKEN, minDenomAmount: '1' }]));
    if (url.includes('indexer.namada.net')) return new Response('not found', { status: 404 });
    const body = JSON.parse(String(init?.body));
    const result = (() => {
      switch (body.method) {
        case 'status':
          return {
            node_info: { network: 'housefire-alpaca.cc0d3e0c033be' },
            sync_info: { latest_block_height: '1234' },
          };
        case 'abci_query': {
          const path = body.params.path as string;
          if (path.includes('wasm/hash/')) return { code: 0, value: b64(WASM_HASH) };
          const amount = new Uint8Array(32);
          new DataView(amount.buffer).setBigUint64(0, BigInt(balanceNamnam), true);
          return { code: 0, value: Buffer.from(amount).toString('base64') };
        }
        case 'broadcast_tx_commit':
          return {
            check_tx: { code: 0, log: '' },
            tx_result: { code: 0, log: '' },
            hash: WRAPPER_HASH.toUpperCase(),
            height: '1235',
          };
        default:
          throw new Error(`unexpected method ${body.method}`);
      }
    })();
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }));
  }) as unknown as typeof fetch;
}

const intent = (amount: string) => ({
  chainId: NAMADA_HOUSEFIRE,
  kind: 'transfer' as const,
  asset: `${NAMADA_HOUSEFIRE}:native`,
  to: RECIPIENT,
  amount,
});

describe('send flow', () => {
  it('prepares a transfer with chain-sourced wasm hash and fee', async () => {
    const adapter = new NamadaAdapter({ fetch: mockFetch() });
    const { unsigned, simulation } = await prepareNamada(
      adapter,
      intent('1000000') as never,
      SENDER,
      PUB,
      new Date('2026-10-16T21:00:00Z'),
    );
    expect(unsigned.wasmCodeHash).toBe(WASM_HASH);
    expect(unsigned.feePerGas).toBe('1');
    expect(unsigned.gasLimit).toBe(50000);
    expect(unsigned.timestamp).toBe('2026-10-16T21:00:00.000000000+00:00');
    expect(simulation.ok).toBe(true);
    expect(simulation.fee?.amount).toBe('50000');
  });

  it('flags an unaffordable transfer in the simulation', async () => {
    const adapter = new NamadaAdapter({ fetch: mockFetch('100') });
    const { simulation } = await prepareNamada(adapter, intent('1000000') as never, SENDER, PUB);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/Balance/);
  });

  it('reads the balance from the multitoken storage key', async () => {
    const fetchMock = mockFetch('50991780312');
    const adapter = new NamadaAdapter({ fetch: fetchMock });
    const holdings = await adapter.getBalances(SENDER, NAMADA_HOUSEFIRE);
    expect(holdings[0]?.amount).toBe('50991780312');
    const calls = (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls;
    const abci = calls.find((c) => String(c[1]?.body).includes('abci_query'));
    expect(String(abci?.[1]?.body)).toContain('/shell/value/#tnam1pyqq');
    expect(String(abci?.[1]?.body)).toContain(`/#${NAM_TOKEN}/balance/#${SENDER}`);
  });

  it('refuses mainnet transfers until a funded e2e exists', async () => {
    const adapter = new NamadaAdapter({ fetch: mockFetch() });
    await expect(
      prepareNamada(adapter, { ...intent('1'), chainId: NAMADA_MAINNET } as never, SENDER, PUB),
    ).rejects.toThrow(/housefire/);
    expect(() => NamadaTx.parse({ ...TX, chainId: NAMADA_MAINNET })).toThrow();
  });

  it('broadcasts only bytes that re-encode to the approved transfer', async () => {
    const adapter = new NamadaAdapter({ fetch: mockFetch() });
    const hash = await broadcastNamada(adapter, TX, WIRE, PUB);
    expect(hash).toBe(WRAPPER_HASH);
    await expect(broadcastNamada(adapter, { ...TX, namnam: '2' }, WIRE, PUB)).rejects.toThrow(
      /not this NAM transfer/,
    );
  });
});
