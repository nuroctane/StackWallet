import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Transaction, address, networks, script } from 'bitcoinjs-lib';
import { Secp256k1, Secp256k1Signature } from '@cosmjs/crypto';
import {
  WasmCoreClient,
  type BitcoinTx,
  type TxIntent,
  type WasmModule,
} from '@stackwallet/core-client';
import { describe, it, expect } from 'vitest';
import { createBitcoinAdapter, encodeSegwit, hash160 } from './bitcoin.js';
import {
  BITCOIN_SIGNET,
  prepareBitcoin,
  bitcoinInputsUnspent,
  broadcastBitcoin,
  bitcoinTransferStatus,
} from './send.js';

const publicKey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const from = encodeSegwit('tb', 0, hash160(Buffer.from(publicKey, 'hex')));
const to = encodeSegwit('tb', 0, new Uint8Array(20).fill(8));
function funding(sender = from, value = 100000n, marker = 1) {
  const tx = new Transaction();
  tx.version = 2;
  tx.addInput(new Uint8Array(32).fill(marker), 0);
  tx.addOutput(address.toOutputScript(sender, networks.testnet), value);
  return tx;
}
const previous = funding();
const unsigned: BitcoinTx = {
  chainId: BITCOIN_SIGNET,
  from,
  to,
  amount: '50000',
  fee: '142',
  inputs: [{ txid: previous.getId(), vout: 0, previousTxHex: previous.toHex() }],
};
const intent: TxIntent = {
  id: 't',
  walletId: 'w',
  accountId: 'a',
  chainId: BITCOIN_SIGNET,
  kind: 'transfer',
  to,
  amount: '50000',
  asset: `${BITCOIN_SIGNET}:native`,
  createdAtMs: 1,
  proposer: { kind: 'human', deviceId: 'd' },
  usdMicros: null,
  untrustedDestinations: [],
};
const hash = 'a'.repeat(64);
interface Options {
  genesis?: string;
  value?: number;
  spent?: boolean;
  missing?: boolean;
  fee?: number;
  height?: string;
  status?: { confirmed: boolean; block_height?: number };
  raw?: string;
  duplicate?: boolean;
  rejectBroadcast?: boolean;
}
function adapter(
  options: Options = {},
  calls: { path: string; method?: string; body?: string }[] = [],
) {
  return createBitcoinAdapter({
    fetch: async (input, init) => {
      const path = new URL(String(input)).pathname;
      calls.push({
        path,
        ...(init?.method ? { method: init.method } : {}),
        ...(init?.body ? { body: String(init.body) } : {}),
      });
      if (path.endsWith('/block-height/0'))
        return new Response(
          options.genesis ?? '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6',
        );
      if (path.endsWith('/hex')) return new Response(options.raw ?? previous.toHex());
      if (path.endsWith('/blocks/tip/height')) return new Response(options.height ?? '105');
      if (path.endsWith('/tx') && init?.method === 'POST')
        return new Response(options.rejectBroadcast ? 'rejected' : hash, {
          status: options.rejectBroadcast ? 400 : 200,
        });
      let result: unknown;
      if (path.endsWith('/utxo')) {
        const u = {
          txid: previous.getId(),
          vout: 0,
          value: options.value ?? 100000,
          status: { confirmed: true, block_height: 80 },
        };
        result = options.duplicate ? [u, u] : [u];
      } else if (path.endsWith('/recommended')) result = { halfHourFee: options.fee ?? 1 };
      else if (path.includes('/outspend/')) result = { spent: options.spent ?? false };
      else if (path.endsWith('/status')) {
        if (options.missing) return new Response('{}', { status: 404 });
        result = options.status ?? { confirmed: true, block_height: 100 };
      } else return new Response('{}', { status: 404 });
      return new Response(JSON.stringify(result));
    },
  });
}
describe('Signet native send boundaries', () => {
  it('verifies funding bytes and previews exact fees without claiming network simulation', async () => {
    const prepared = await prepareBitcoin(adapter(), intent, from);
    expect(prepared.unsigned).toEqual(unsigned);
    expect(prepared.simulation).toMatchObject({
      ok: false,
      fee: { amount: '142' },
      error: 'Bitcoin network simulation is unavailable',
    });
    expect(prepared.simulation.warnings[0]).toMatchObject({
      kind: 'other',
      message: expect.stringContaining('49858 sats change'),
    });
  });
  it('rejects wrong genesis, fabricated amounts, wrong funding, unsafe fees and dust', async () => {
    for (const options of [
      { genesis: '0'.repeat(64) },
      { value: 100001 },
      { raw: funding(to).toHex() },
      { fee: 101 },
      { spent: true },
    ])
      await expect(prepareBitcoin(adapter(options), intent, from)).rejects.toThrow();
    await expect(prepareBitcoin(adapter(), { ...intent, amount: '293' }, from)).rejects.toThrow(
      /dust/,
    );
    await expect(
      prepareBitcoin(adapter(), { ...intent, chainId: 'bip122:mainnet' }, from),
    ).rejects.toThrow(/Signet/);
    await expect(
      prepareBitcoin(
        adapter(),
        { ...intent, to: encodeSegwit('tb', 1, new Uint8Array(32).fill(1)) },
        from,
      ),
    ).rejects.toThrow();
  });
  it('rechecks inputs and refuses unavailable observations before approval', async () => {
    expect(await bitcoinInputsUnspent(adapter(), unsigned)).toBe(true);
    expect(await bitcoinInputsUnspent(adapter({ spent: true }), unsigned)).toBe(false);
    const missing = createBitcoinAdapter({
      fetch: async (input) =>
        String(input).endsWith('/block-height/0')
          ? new Response('00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6')
          : new Response('{}', { status: 404 }),
    });
    await expect(bitcoinInputsUnspent(missing, unsigned)).rejects.toThrow();
  });
  it('broadcasts only core bytes and preserves uncertain status until six confirmations', async () => {
    const calls: Parameters<typeof adapter>[1] = [];
    expect(await broadcastBitcoin(adapter({}, calls), unsigned, '0x0102')).toBe(hash);
    expect(calls.find((c) => c.path.endsWith('/tx'))).toMatchObject({
      method: 'POST',
      body: '0102',
    });
    await expect(
      broadcastBitcoin(adapter({ rejectBroadcast: true }), unsigned, '0x0102'),
    ).rejects.toThrow();
    expect(await bitcoinTransferStatus(adapter({ missing: true }), unsigned, hash)).toEqual({
      state: 'unknown',
    });
    expect(
      await bitcoinTransferStatus(adapter({ status: { confirmed: false } }), unsigned, hash),
    ).toEqual({ state: 'pending' });
    expect(await bitcoinTransferStatus(adapter({ height: '104' }), unsigned, hash)).toEqual({
      state: 'pending',
    });
    expect(await bitcoinTransferStatus(adapter(), unsigned, hash)).toEqual({
      state: 'confirmed',
      blockNumber: 100,
    });
  });
});
const wasmDir = resolve(import.meta.dirname, '../../../apps/web/public/wasm');
describe.skipIf(!existsSync(resolve(wasmDir, 'stackwallet_wasm_bg.wasm')))(
  'core Bitcoin wire interoperability',
  () => {
    it('independently verifies every BIP143 signature, output, policy gate and sealed ledger', async () => {
      const module = (await import(
        pathToFileURL(resolve(wasmDir, 'stackwallet_wasm.js')).href
      )) as WasmModule;
      await module.default?.({
        module_or_path: readFileSync(resolve(wasmDir, 'stackwallet_wasm_bg.wasm')),
      });
      const core = new WasmCoreClient(module);
      const pass = 'disposable Bitcoin interoperability fixture';
      const vault = await core.createVault(pass);
      try {
        await vault.importPhrase(
          'w',
          'test test test test test test test test test test test junk',
          1,
        );
        const path = "m/84'/1'/0'/0/0";
        const pub = await vault.singlePublicKey('w', 'secp256k1', path);
        const sender = encodeSegwit('tb', 0, hash160(Buffer.from(pub, 'hex')));
        const funds = [funding(sender, 60000n, 1), funding(sender, 50000n, 2)];
        const tx = {
          ...unsigned,
          from: sender,
          amount: '80000',
          fee: '500',
          inputs: funds.map((f) => ({ txid: f.getId(), vout: 0, previousTxHex: f.toHex() })),
        };
        const proposal = { ...intent, amount: tx.amount };
        await vault.txPropose(proposal, 'd', 2);
        const attach = {
          txId: 't',
          signer: { walletId: 'w', path, address: sender },
          unsigned: tx,
          simulation: { ok: false },
          simulationOk: false,
          deviceId: 'd',
          nowMs: 3,
        };
        await expect(
          vault.txAttach({ ...attach, unsigned: { ...tx, amount: '80001' } }),
        ).rejects.toThrow(/intent/);
        await vault.txAttach(attach);
        await vault.txEvaluate('t', 'd', 4);
        await vault.txPropose({ ...proposal, id: 'conflict' }, 'd', 5);
        await expect(vault.txAttach({ ...attach, txId: 'conflict', nowMs: 6 })).rejects.toThrow(
          /reserved/,
        );
        await expect(vault.txApprove('t', 'wrong', 'd', 7)).rejects.toThrow();
        await vault.setPolicies(
          [
            {
              id: 'simulation',
              name: 'Require network simulation',
              mode: 'enforce',
              rules: [{ rule: 'requireSimulationPass' }],
            },
          ],
          'd',
          8,
        );
        expect((await vault.txApprove('t', pass, 'd', 9)).state).toBe('rejected');
        await vault.setPolicies([], 'd', 10);
        await vault.txPropose({ ...proposal, id: 'signed' }, 'd', 11);
        await vault.txAttach({ ...attach, txId: 'signed', nowMs: 12 });
        await vault.txEvaluate('signed', 'd', 13);
        const signed = await vault.txApprove('signed', pass, 'd', 14);
        const decoded = Transaction.fromHex(signed.rawSignedHex!.slice(2));
        expect(decoded.getId()).toBe(signed.hash);
        expect(decoded.version).toBe(2);
        expect(decoded.locktime).toBe(0);
        expect(decoded.outs).toEqual([
          { script: address.toOutputScript(to, networks.testnet), value: 80000n },
          { script: address.toOutputScript(sender, networks.testnet), value: 29500n },
        ]);
        expect(decoded.ins).toHaveLength(2);
        const h = hash160(Buffer.from(pub, 'hex'));
        const scriptCode = script.compile([
          script.OPS.OP_DUP!,
          script.OPS.OP_HASH160!,
          h,
          script.OPS.OP_EQUALVERIFY!,
          script.OPS.OP_CHECKSIG!,
        ]);
        for (let i = 0; i < decoded.ins.length; i++) {
          const input = decoded.ins[i]!;
          expect(input.sequence).toBe(0xfffffffd);
          expect(input.script).toHaveLength(0);
          expect(input.witness).toHaveLength(2);
          expect(Buffer.from(input.witness[1]!).toString('hex')).toBe(pub);
          const sig = script.signature.decode(input.witness[0]!);
          expect(sig.hashType).toBe(Transaction.SIGHASH_ALL);
          expect(
            Secp256k1.verifySignature(
              Secp256k1Signature.fromFixedLength(sig.signature),
              decoded.hashForWitnessV0(i, scriptCode, funds[i]!.outs[0]!.value, sig.hashType),
              Buffer.from(pub, 'hex'),
            ),
          ).toBe(true);
        }
        await vault.txReport('signed', 'broadcast', null, 'd', 15);
        await vault.txReport('signed', 'pending', null, 'd', 16);
        await expect(vault.txReport('signed', 'expired', null, 'd', 17)).rejects.toThrow();
        await vault.txReport('signed', 'confirmed', null, 'd', 18);
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
