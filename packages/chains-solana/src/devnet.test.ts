import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { base58 } from '@scure/base';
import { WasmCoreClient, type TxIntent, type WasmModule } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { createSolanaAdapter } from './solana.js';
import {
  broadcastSolana,
  prepareSolana,
  SOLANA_DEVNET,
  solanaBlockhashValid,
  solanaTransferStatus,
} from './send.js';

// Opt-in network check uses only faucet SOL and a disposable, core-generated wallet.
describe.skipIf(process.env.STACKWALLET_DEVNET_SMOKE !== '1')('live Devnet native transfer', () => {
  it('simulates, signs, broadcasts and confirms through the audited core ledger', async () => {
    const wasmDir = resolve(import.meta.dirname, '../../../apps/web/public/wasm');
    const module = (await import(
      pathToFileURL(resolve(wasmDir, 'stackwallet_wasm.js')).href
    )) as WasmModule;
    await module.default?.({
      module_or_path: readFileSync(resolve(wasmDir, 'stackwallet_wasm_bg.wasm')),
    });
    const core = new WasmCoreClient(module);
    const pass = 'disposable Devnet smoke fixture';
    const vault = await core.createVault(pass);
    try {
      await vault.createSingle('sender', Date.now());
      await vault.createSingle('recipient', Date.now());
      const path = "m/44'/501'/0'/0'";
      const from = base58.encode(
        Buffer.from(await vault.singlePublicKey('sender', 'ed25519', path), 'hex'),
      );
      const to = base58.encode(
        Buffer.from(await vault.singlePublicKey('recipient', 'ed25519', path), 'hex'),
      );
      const adapter = createSolanaAdapter();
      const airdrop = await adapter.clusterCall(
        SOLANA_DEVNET,
        'requestAirdrop',
        [from, 1_000_000_000, { commitment: 'confirmed' }],
        z.string().max(88),
      );
      console.info('Devnet faucet signature', airdrop);
      for (let i = 0; i < 30; i++) {
        const balance = await adapter.clusterCall(
          SOLANA_DEVNET,
          'getBalance',
          [from, { commitment: 'confirmed' }],
          z.object({ value: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) }),
        );
        if (balance.value >= 1_000_000_000) break;
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
      const intent: TxIntent = {
        id: crypto.randomUUID(),
        walletId: 'sender',
        accountId: 'a',
        chainId: SOLANA_DEVNET,
        kind: 'transfer',
        to,
        asset: `${SOLANA_DEVNET}:native`,
        amount: '1000000',
        proposer: { kind: 'human', deviceId: 'smoke' },
        createdAtMs: Date.now(),
        usdMicros: null,
        untrustedDestinations: [],
      };
      await vault.txPropose(intent, 'smoke', Date.now());
      const prepared = await prepareSolana(adapter, intent, from);
      expect(prepared.simulation.ok).toBe(true);
      await vault.txAttach({
        txId: intent.id,
        signer: { walletId: 'sender', path, address: from },
        ...prepared,
        simulationOk: prepared.simulation.ok,
        deviceId: 'smoke',
        nowMs: Date.now(),
      });
      await vault.txEvaluate(intent.id, 'smoke', Date.now());
      expect(await solanaBlockhashValid(adapter, prepared.unsigned)).toBe(true);
      const signed = await vault.txApprove(intent.id, pass, 'smoke', Date.now());
      await vault.txReport(intent.id, 'broadcast', null, 'smoke', Date.now());
      const hash = await broadcastSolana(adapter, SOLANA_DEVNET, signed.rawSignedHex!);
      expect(hash).toBe(signed.hash);
      await vault.txReport(intent.id, 'pending', null, 'smoke', Date.now());
      for (let i = 0; i < 40; i++) {
        const status = await solanaTransferStatus(adapter, prepared.unsigned, hash);
        if (status.state === 'confirmed') {
          await vault.txReport(
            intent.id,
            'confirmed',
            `slot ${status.blockNumber}`,
            'smoke',
            Date.now(),
          );
          console.info('Confirmed Devnet core-signed transfer', hash, 'slot', status.blockNumber);
          expect((await vault.ledger()).txs[0]?.state).toBe('confirmed');
          return;
        }
        if (status.state === 'failed' || status.state === 'expired')
          throw new Error(JSON.stringify(status));
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
      throw new Error('Devnet finality was not observed');
    } finally {
      vault.free();
    }
  }, 150_000);
});
