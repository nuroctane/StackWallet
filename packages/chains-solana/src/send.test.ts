import { createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { base58, base64 } from '@scure/base';
import { getCompiledTransactionMessageDecoder, getTransactionDecoder } from '@solana/kit';
import { MemoryRpcPool, chainsForFamily } from '@stackwallet/chains';
import {
  WasmCoreClient,
  type SolanaTx,
  type TxIntent,
  type WasmModule,
} from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { createSolanaAdapter } from './solana.js';
import {
  broadcastSolana,
  nativeTransferMessage,
  prepareSolana,
  SOLANA_DEVNET,
  solanaBlockhashValid,
  solanaTransferStatus,
} from './send.js';

const GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
const SYSTEM = '11111111111111111111111111111111';
const from = base58.encode(new Uint8Array(32).fill(7));
const to = base58.encode(new Uint8Array(32).fill(8));
const tx: SolanaTx = {
  chainId: SOLANA_DEVNET,
  from,
  to,
  lamports: '1000',
  recentBlockhash: base58.encode(new Uint8Array(32).fill(9)),
  lastValidBlockHeight: 100,
};
const hash = base58.encode(new Uint8Array(64).fill(4));
const intent: TxIntent = {
  id: 't',
  walletId: 'w',
  accountId: 'a',
  chainId: SOLANA_DEVNET,
  kind: 'transfer',
  to,
  asset: `${SOLANA_DEVNET}:native`,
  amount: '1000',
  proposer: { kind: 'human', deviceId: 'd' },
  createdAtMs: 1,
  usdMicros: null,
  untrustedDestinations: [],
};

function adapter(overrides: Record<string, unknown> = {}, calls: [string, unknown[]][] = []) {
  const results: Record<string, unknown> = {
    getGenesisHash: GENESIS,
    getLatestBlockhash: { value: { blockhash: tx.recentBlockhash, lastValidBlockHeight: 100 } },
    getFeeForMessage: { value: 5000 },
    getBalance: { value: 100000 },
    getAccountInfo: { value: null },
    simulateTransaction: { value: { err: null } },
    isBlockhashValid: { value: true },
    sendTransaction: hash,
    getSlot: 200,
    getBlockHeight: 100,
    getSignatureStatuses: { context: { slot: 200 }, value: [null] },
    ...overrides,
  };
  return createSolanaAdapter({
    fetch: async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      calls.push([body.method, body.params]);
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: results[body.method] }));
    },
  });
}

describe('native SOL transfer preparation', () => {
  it('SDK decodes exactly one native transfer and the simulation uses these message bytes', async () => {
    const calls: [string, unknown[]][] = [];
    const prepared = await prepareSolana(adapter({}, calls), intent, from);
    expect(prepared.unsigned).toEqual(tx);
    const message = nativeTransferMessage(tx);
    const decoded = getCompiledTransactionMessageDecoder().decode(message);
    expect(decoded.version).toBe('legacy');
    if (decoded.version !== 'legacy') throw new Error('Expected a legacy transfer');
    expect(decoded.header).toEqual({
      numSignerAccounts: 1,
      numReadonlySignerAccounts: 0,
      numReadonlyNonSignerAccounts: 1,
    });
    expect(decoded.staticAccounts).toEqual([from, to, SYSTEM]);
    expect(decoded.instructions).toEqual([
      {
        programAddressIndex: 2,
        accountIndices: [0, 1],
        data: new Uint8Array([2, 0, 0, 0, 232, 3, 0, 0, 0, 0, 0, 0]),
      },
    ]);
    const simulated = calls.find(([method]) => method === 'simulateTransaction')![1];
    expect(base64.decode(simulated[0] as string).slice(65)).toEqual(message);
    expect(simulated[1]).toMatchObject({ sigVerify: false, replaceRecentBlockhash: false });
    expect(prepared.simulation).toMatchObject({
      ok: true,
      fee: { amount: '5000' },
      assetDeltas: [{ amount: '-1000' }, { amount: '-5000' }],
    });
    expect(calls.filter(([m]) => m === 'getGenesisHash')).toHaveLength(5);
  });

  it('rejects wrong clusters before sending and safely fails over to a matching cluster', async () => {
    const calls: [string, unknown[]][] = [];
    await expect(
      broadcastSolana(
        adapter({ getGenesisHash: base58.encode(new Uint8Array(32).fill(10)) }, calls),
        SOLANA_DEVNET,
        `0x${'01'.repeat(215)}`,
      ),
    ).rejects.toThrow();
    expect(calls.map(([m]) => m)).toEqual(['getGenesisHash']);
    const rpc = new MemoryRpcPool(chainsForFamily('solana'));
    rpc.setEndpoints(SOLANA_DEVNET, ['https://wrong.example', 'https://correct.example']);
    const sol = createSolanaAdapter({
      rpc,
      fetch: async (url, init) => {
        const { method } = JSON.parse(String(init?.body)) as { method: string };
        const result =
          method === 'getGenesisHash'
            ? String(url).includes('wrong')
              ? base58.encode(new Uint8Array(32).fill(10))
              : GENESIS
            : { value: true };
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
      },
    });
    expect(await solanaBlockhashValid(sol, tx)).toBe(true);
  });

  it('records simulation and insufficient-funds failures and rejects imprecise RPC amounts', async () => {
    const insufficient = await prepareSolana(
      adapter({ getBalance: { value: 5000 } }),
      intent,
      from,
    );
    expect(insufficient.simulation).toMatchObject({
      ok: false,
      error: 'Balance does not cover the transfer and fee',
    });
    const failed = await prepareSolana(
      adapter({ simulateTransaction: { value: { err: { InstructionError: [0, 'Custom'] } } } }),
      intent,
      from,
    );
    expect(failed.simulation.ok).toBe(false);
    await expect(
      prepareSolana(adapter({ getBalance: { value: Number.MAX_SAFE_INTEGER + 1 } }), intent, from),
    ).rejects.toThrow();
    await expect(
      prepareSolana(adapter({ simulateTransaction: { value: {} } }), intent, from),
    ).rejects.toThrow();
    await expect(
      prepareSolana(adapter({ getFeeForMessage: { value: null } }), intent, from),
    ).rejects.toThrow(/expired/);
    const contract = await prepareSolana(
      adapter({ getAccountInfo: { value: { owner: from, executable: true } } }),
      intent,
      from,
    );
    expect(contract.simulation.warnings).toEqual([{ kind: 'destinationIsContract', address: to }]);
  });

  it('refuses mainnet, unsupported assets, unsafe amounts and extra fields', async () => {
    await expect(
      prepareSolana(
        adapter(),
        { ...intent, chainId: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' },
        from,
      ),
    ).rejects.toThrow(/Devnet/);
    for (const lamports of ['0', '01', '-1', '18446744073709551616'])
      expect(() => nativeTransferMessage({ ...tx, lamports })).toThrow();
    expect(() => nativeTransferMessage({ ...tx, to: from })).toThrow();
    expect(() => nativeTransferMessage({ ...tx, to: SYSTEM })).toThrow();
    expect(() => nativeTransferMessage({ ...tx, instructions: [] } as SolanaTx)).toThrow();
  });

  it('waits for finality, treats processed errors as pending and expires only after the inclusive height', async () => {
    expect(await solanaTransferStatus(adapter(), tx, hash)).toEqual({ state: 'unknown' });
    const calls: [string, unknown[]][] = [];
    expect(await solanaTransferStatus(adapter({ getBlockHeight: 101 }, calls), tx, hash)).toEqual({
      state: 'expired',
    });
    expect(calls.filter(([m]) => m !== 'getGenesisHash').map(([m]) => m)).toEqual([
      'getSlot',
      'getBlockHeight',
      'getSignatureStatuses',
    ]);
    for (const confirmationStatus of ['processed', 'confirmed']) {
      expect(
        await solanaTransferStatus(
          adapter({
            getBlockHeight: 101,
            getSignatureStatuses: {
              context: { slot: 200 },
              value: [{ slot: 1, err: { InstructionError: [0, 'Custom'] }, confirmationStatus }],
            },
          }),
          tx,
          hash,
        ),
      ).toEqual({ state: 'pending' });
    }
    expect(
      await solanaTransferStatus(
        adapter({
          getSignatureStatuses: {
            context: { slot: 200 },
            value: [{ slot: 1, err: null, confirmationStatus: 'finalized' }],
          },
        }),
        tx,
        hash,
      ),
    ).toEqual({ state: 'confirmed', blockNumber: 1 });
    expect(
      await solanaTransferStatus(
        adapter({
          getSignatureStatuses: {
            context: { slot: 200 },
            value: [{ slot: 1, err: 'failure', confirmationStatus: 'finalized' }],
          },
        }),
        tx,
        hash,
      ),
    ).toMatchObject({ state: 'failed' });
    expect(
      await solanaTransferStatus(
        adapter({
          getBlockHeight: 101,
          getSignatureStatuses: { context: { slot: 199 }, value: [null] },
        }),
        tx,
        hash,
      ),
    ).toEqual({ state: 'unknown' });
  });
});

const wasmDir = resolve(import.meta.dirname, '../../../apps/web/public/wasm');
describe.skipIf(!existsSync(resolve(wasmDir, 'stackwallet_wasm_bg.wasm')))(
  'real core SOL wire interoperability',
  () => {
    it('SDK decodes core-signed bytes; Node verifies the Ed25519 signature; sealed history reopens', async () => {
      const module = (await import(
        pathToFileURL(resolve(wasmDir, 'stackwallet_wasm.js')).href
      )) as WasmModule;
      await module.default?.({
        module_or_path: readFileSync(resolve(wasmDir, 'stackwallet_wasm_bg.wasm')),
      });
      const core = new WasmCoreClient(module);
      const pass = 'disposable SOL interoperability fixture';
      const vault = await core.createVault(pass);
      try {
        await vault.importPhrase(
          'w',
          'test test test test test test test test test test test junk',
          1,
        );
        const path = "m/44'/501'/0'/0'";
        const pub = await vault.singlePublicKey('w', 'ed25519', path);
        const from = base58.encode(Buffer.from(pub, 'hex'));
        const unsigned = { ...tx, from };
        await vault.txPropose(intent, 'd', 2);
        const signer = { walletId: 'w', path, address: from };
        await expect(
          vault.txAttach({
            txId: 't',
            signer,
            unsigned: { ...unsigned, to: tx.recentBlockhash },
            simulation: {},
            simulationOk: true,
            deviceId: 'd',
            nowMs: 3,
          }),
        ).rejects.toThrow(/destination/);
        await vault.txAttach({
          txId: 't',
          signer,
          unsigned,
          simulation: { ok: true },
          simulationOk: true,
          deviceId: 'd',
          nowMs: 3,
        });
        await vault.txEvaluate('t', 'd', 4);
        await expect(vault.txApprove('t', 'wrong', 'd', 5)).rejects.toThrow();
        const signed = await vault.txApprove('t', pass, 'd', 5);
        const wire = Buffer.from(signed.rawSignedHex!.slice(2), 'hex');
        const decoded = getTransactionDecoder().decode(wire);
        expect(new Uint8Array(decoded.messageBytes)).toEqual(nativeTransferMessage(unsigned));
        expect(Object.keys(decoded.signatures)).toEqual([from]);
        expect(base58.encode(wire.subarray(1, 65))).toBe(signed.hash);
        const key = createPublicKey({
          key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            Buffer.from(pub, 'hex'),
          ]),
          format: 'der',
          type: 'spki',
        });
        expect(verify(null, wire.subarray(65), key, wire.subarray(1, 65))).toBe(true);
        await vault.txReport('t', 'broadcast', null, 'd', 6);
        await vault.txReport('t', 'pending', null, 'd', 7);
        await vault.txReport('t', 'expired', 'blockhash expired', 'd', 8);
        const history = await vault.ledger();
        const bytes = await vault.toBytes();
        const reopened = await core.openVault(bytes);
        try {
          await reopened.unlock(pass);
          expect(await reopened.ledger()).toEqual(history);
        } finally {
          reopened.free();
        }
      } finally {
        vault.free();
      }
    });
  },
);
