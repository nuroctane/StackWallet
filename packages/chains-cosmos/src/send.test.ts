import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { Secp256k1, Secp256k1Signature } from '@cosmjs/crypto';
import {
  WasmCoreClient,
  type CosmosTx,
  type TxIntent,
  type WasmModule,
} from '@stackwallet/core-client';
import { MsgSend } from 'cosmjs-types/cosmos/bank/v1beta1/tx';
import { AuthInfo, TxBody, TxRaw } from 'cosmjs-types/cosmos/tx/v1beta1/tx';
import { BaseAccount } from 'cosmjs-types/cosmos/auth/v1beta1/auth';
import { Any } from 'cosmjs-types/google/protobuf/any';
import { describe, expect, it } from 'vitest';
import { cosmosAccountBytes, createCosmosAdapter, encodeCosmosAddress } from './cosmos.js';
import {
  broadcastCosmos,
  cosmosApprovalValid,
  cosmosBodyAuth,
  cosmosSignDoc,
  cosmosTransferStatus,
  COSMOS_TESTNET,
  prepareCosmos,
} from './send.js';

const publicKeyHex = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const from = encodeCosmosAddress(
  'osmo',
  cosmosAccountBytes(Buffer.from(publicKeyHex, 'hex'), 'secp256k1'),
);
const to = encodeCosmosAddress('osmo', new Uint8Array(20).fill(8));
const tx: CosmosTx = {
  chainId: COSMOS_TESTNET,
  from,
  to,
  amount: '1000',
  publicKeyHex,
  accountNumber: '42',
  sequence: '0',
  gasLimit: 130000,
  feeAmount: '3250',
  timeoutHeight: 150,
};
const intent: TxIntent = {
  id: 't',
  walletId: 'w',
  accountId: 'a',
  chainId: COSMOS_TESTNET,
  kind: 'transfer',
  to,
  amount: '1000',
  asset: `${COSMOS_TESTNET}:native`,
  createdAtMs: 1,
  proposer: { kind: 'human', deviceId: 'd' },
  usdMicros: null,
  untrustedDestinations: [],
};
const hash = 'A'.repeat(64);

interface Options {
  network?: string;
  height?: string;
  sequence?: string;
  balance?: string;
  gas?: string;
  unprovenHeight?: boolean;
  wrongAccountKey?: boolean;
  unsupportedAccount?: boolean;
  missingAccount?: boolean;
  simulationFailure?: boolean;
  response?: { txhash: string; height: string; code: number; raw_log?: string };
}
function adapter(
  options: Options = {},
  calls: { path: string; method?: string; body?: string; height?: string }[] = [],
) {
  return createCosmosAdapter({
    fetch: async (input, init) => {
      const url = new URL(String(input));
      const path = url.pathname;
      const requested = url.searchParams.get('height');
      calls.push({
        path,
        ...(init?.method ? { method: init.method } : {}),
        ...(init?.body ? { body: String(init.body) } : {}),
        ...(requested ? { height: requested } : {}),
      });
      let result: unknown;
      if (path.endsWith('/node_info'))
        result = { default_node_info: { network: options.network ?? 'osmo-test-5' } };
      else if (path.endsWith('/blocks/latest'))
        result = {
          block: { header: { chain_id: 'osmo-test-5', height: options.height ?? '100' } },
        };
      else if (path.endsWith('/abci_query')) {
        result = {
          code: 0,
          height: options.unprovenHeight ? '1' : requested,
          key: options.wrongAccountKey ? 'AA==' : url.searchParams.get('data'),
          value: base64.encode(
            Any.encode({
              typeUrl: options.unsupportedAccount
                ? '/cosmos.auth.v1beta1.ModuleAccount'
                : '/cosmos.auth.v1beta1.BaseAccount',
              value: BaseAccount.encode(
                BaseAccount.fromPartial({
                  address: from,
                  accountNumber: 42n,
                  sequence: BigInt(options.sequence ?? '0'),
                }),
              ).finish(),
            }).finish(),
          ),
        };
      } else if (path.includes('/accounts/')) {
        if (options.missingAccount) return new Response('{}', { status: 404 });
        result = {
          account: {
            '@type': '/cosmos.auth.v1beta1.BaseAccount',
            address: from,
            account_number: '42',
            sequence: options.sequence ?? '0',
            pub_key: null,
          },
        };
      } else if (path.endsWith('/by_denom'))
        result = { balance: { denom: 'uosmo', amount: options.balance ?? '1000000' } };
      else if (path.endsWith('/simulate')) {
        if (options.simulationFailure) return new Response('{}', { status: 400 });
        result = { gas_info: { gas_used: options.gas ?? '100000' } };
      } else if (init?.method === 'POST')
        result = { tx_response: options.response ?? { txhash: hash, height: '0', code: 0 } };
      else if (options.response) result = { tx_response: options.response };
      else return new Response('{}', { status: 404 });
      return new Response(JSON.stringify(result));
    },
  });
}

describe('Osmosis native transfer lifecycle', () => {
  it('simulates the final fee/gas bytes and encodes exactly one bank transfer', async () => {
    const calls: Parameters<typeof adapter>[1] = [];
    const prepared = await prepareCosmos(adapter({}, calls), intent, from, publicKeyHex);
    expect(prepared.unsigned).toEqual(tx);
    expect(prepared.simulation).toMatchObject({ ok: true, fee: { amount: '3250' } });
    const { bodyBytes, authInfoBytes } = cosmosBodyAuth(tx);
    const body = TxBody.decode(bodyBytes);
    expect(body.messages).toHaveLength(1);
    expect(body.messages[0]!.typeUrl).toBe('/cosmos.bank.v1beta1.MsgSend');
    expect(MsgSend.decode(body.messages[0]!.value)).toEqual({
      fromAddress: from,
      toAddress: to,
      amount: [{ denom: 'uosmo', amount: '1000' }],
    });
    expect(body.timeoutHeight).toBe(150n);
    expect(body.memo).toBe('');
    expect(AuthInfo.decode(authInfoBytes).fee).toMatchObject({
      amount: [{ denom: 'uosmo', amount: '3250' }],
      gasLimit: 130000n,
    });
    const simulations = calls.filter((c) => c.path.endsWith('/simulate'));
    expect(simulations).toHaveLength(2);
    const wire = TxRaw.decode(
      base64.decode((JSON.parse(simulations[1]!.body!) as { tx_bytes: string }).tx_bytes),
    );
    expect(wire.bodyBytes).toEqual(bodyBytes);
    expect(wire.authInfoBytes).toEqual(authInfoBytes);
  });
  it('rejects mismatched chains before preparation and records failed simulations', async () => {
    await expect(
      prepareCosmos(adapter({ network: 'osmosis-1' }), intent, from, publicKeyHex),
    ).rejects.toThrow();
    await expect(
      prepareCosmos(adapter({ missingAccount: true }), intent, from, publicKeyHex),
    ).rejects.toThrow(/not funded/);
    expect(
      (await prepareCosmos(adapter({ balance: '2000' }), intent, from, publicKeyHex)).simulation.ok,
    ).toBe(false);
    expect(
      (await prepareCosmos(adapter({ simulationFailure: true }), intent, from, publicKeyHex))
        .simulation.ok,
    ).toBe(false);
    expect(
      (await prepareCosmos(adapter({ gas: '1000001' }), intent, from, publicKeyHex)).simulation.ok,
    ).toBe(false);
  });
  it('checks timeout and sequence at a height-bound state before approval without CORS metadata', async () => {
    const calls: Parameters<typeof adapter>[1] = [];
    expect(await cosmosApprovalValid(adapter({}, calls), tx)).toBe(true);
    expect(calls.find((c) => c.path.endsWith('/abci_query'))?.height).toBe('100');
    expect(await cosmosApprovalValid(adapter({ height: '151' }), tx)).toBe(false);
    expect(await cosmosApprovalValid(adapter({ sequence: '1' }), tx)).toBe(false);
    await expect(cosmosApprovalValid(adapter({ unprovenHeight: true }), tx)).rejects.toThrow();
    await expect(cosmosApprovalValid(adapter({ wrongAccountKey: true }), tx)).rejects.toThrow();
    await expect(cosmosApprovalValid(adapter({ unsupportedAccount: true }), tx)).rejects.toThrow();
  });
  it('does not mistake an unindexed included transfer for an expired one', async () => {
    expect(await cosmosTransferStatus(adapter({ height: '150' }), tx, hash)).toEqual({
      state: 'unknown',
    });
    expect(await cosmosTransferStatus(adapter({ height: '151' }), tx, hash)).toEqual({
      state: 'expired',
    });
    expect(await cosmosTransferStatus(adapter({ height: '151', sequence: '1' }), tx, hash)).toEqual(
      { state: 'unknown' },
    );
    await expect(
      cosmosTransferStatus(adapter({ height: '151', unprovenHeight: true }), tx, hash),
    ).rejects.toThrow();
    expect(
      await cosmosTransferStatus(
        adapter({ response: { txhash: hash, height: '123', code: 0 } }),
        tx,
        hash,
      ),
    ).toEqual({ state: 'confirmed', blockNumber: 123 });
    expect(
      await cosmosTransferStatus(
        adapter({ response: { txhash: hash, height: '123', code: 5, raw_log: 'failed' } }),
        tx,
        hash,
      ),
    ).toEqual({ state: 'failed', reason: 'failed' });
    await expect(
      cosmosTransferStatus(
        adapter({ response: { txhash: 'B'.repeat(64), height: '123', code: 0 } }),
        tx,
        hash,
      ),
    ).rejects.toThrow(/different/);
  });
  it('broadcasts only core bytes and treats CheckTx rejection as a send failure', async () => {
    const calls: Parameters<typeof adapter>[1] = [];
    expect(await broadcastCosmos(adapter({}, calls), tx, '0x010203')).toBe(hash);
    const sent = JSON.parse(calls.find((c) => c.path.endsWith('/txs'))!.body!) as {
      tx_bytes: string;
      mode: string;
    };
    expect(sent).toEqual({ tx_bytes: 'AQID', mode: 'BROADCAST_MODE_SYNC' });
    await expect(
      broadcastCosmos(
        adapter({ response: { txhash: hash, height: '0', code: 32, raw_log: 'wrong sequence' } }),
        tx,
        '0x01',
      ),
    ).rejects.toThrow(/sequence/);
  });
  it('rejects hidden fields, unsupported assets and non-canonical or oversized values', async () => {
    for (const amount of ['0', '01', '18446744073709551616'])
      expect(() => cosmosBodyAuth({ ...tx, amount })).toThrow();
    expect(() => cosmosBodyAuth({ ...tx, to: from })).toThrow();
    expect(() => cosmosBodyAuth({ ...tx, memo: 'secret extra' } as CosmosTx)).toThrow();
    await expect(
      prepareCosmos(
        adapter(),
        { ...intent, asset: 'cosmos:osmo-test-5:ibc:other' },
        from,
        publicKeyHex,
      ),
    ).rejects.toThrow(/native/);
  });
});

const wasmDir = resolve(import.meta.dirname, '../../../apps/web/public/wasm');
describe.skipIf(!existsSync(resolve(wasmDir, 'stackwallet_wasm_bg.wasm')))(
  'real Cosmos core wire interoperability',
  () => {
    it('SDK decodes and verifies the core signature, preserves the ledger and refuses policy changes', async () => {
      const module = (await import(
        pathToFileURL(resolve(wasmDir, 'stackwallet_wasm.js')).href
      )) as WasmModule;
      await module.default?.({
        module_or_path: readFileSync(resolve(wasmDir, 'stackwallet_wasm_bg.wasm')),
      });
      const core = new WasmCoreClient(module);
      const pass = 'disposable Cosmos interoperability fixture';
      const vault = await core.createVault(pass);
      try {
        await vault.importPhrase(
          'w',
          'test test test test test test test test test test test junk',
          1,
        );
        const path = "m/44'/118'/0'/0/0";
        const pub = await vault.singlePublicKey('w', 'secp256k1', path);
        const from = encodeCosmosAddress(
          'osmo',
          cosmosAccountBytes(Buffer.from(pub, 'hex'), 'secp256k1'),
        );
        const unsigned = { ...tx, from, publicKeyHex: pub };
        const attach = {
          txId: 't',
          signer: { walletId: 'w', path, address: from },
          unsigned,
          simulation: { ok: true },
          simulationOk: true,
          deviceId: 'd',
          nowMs: 3,
        };
        await vault.txPropose(intent, 'd', 2);
        await expect(
          vault.txAttach({ ...attach, unsigned: { ...unsigned, amount: '1001' } }),
        ).rejects.toThrow(/intent/);
        await vault.txAttach(attach);
        await vault.txEvaluate('t', 'd', 4);
        await expect(vault.txApprove('t', 'wrong', 'd', 5)).rejects.toThrow();
        const signed = await vault.txApprove('t', pass, 'd', 5);
        expect(signed.state).toBe('signed');
        const raw = Buffer.from(signed.rawSignedHex!.slice(2), 'hex');
        const decoded = TxRaw.decode(new Uint8Array(raw));
        const expected = cosmosBodyAuth(unsigned);
        expect(decoded.bodyBytes).toEqual(expected.bodyBytes);
        expect(decoded.authInfoBytes).toEqual(expected.authInfoBytes);
        expect(decoded.signatures).toHaveLength(1);
        expect(
          Secp256k1.verifySignature(
            Secp256k1Signature.fromFixedLength(decoded.signatures[0]!),
            sha256(cosmosSignDoc(unsigned)),
            Buffer.from(pub, 'hex'),
          ),
        ).toBe(true);
        expect(Buffer.from(sha256(raw)).toString('hex').toUpperCase()).toBe(signed.hash);
        await vault.txReport('t', 'broadcast', null, 'd', 6);
        await vault.txReport('t', 'pending', null, 'd', 7);
        await vault.txReport('t', 'failed', 'on-chain failure', 'd', 8);
        const second = { ...intent, id: 'policy' };
        await vault.txPropose(second, 'd', 9);
        await vault.txAttach({ ...attach, txId: 'policy', nowMs: 10 });
        await vault.txEvaluate('policy', 'd', 11);
        await vault.setPolicies(
          [
            {
              id: 'deny',
              name: 'Deny',
              mode: 'enforce',
              rules: [{ rule: 'destinationDeny', addresses: [to] }],
            },
          ],
          'd',
          12,
        );
        expect((await vault.txApprove('policy', pass, 'd', 13)).state).toBe('rejected');
        const history = await vault.ledger();
        const reopened = await core.openVault(await vault.toBytes());
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
