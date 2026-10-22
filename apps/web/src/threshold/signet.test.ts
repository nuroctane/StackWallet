/**
 * Opt-in funded check of a shared (2-of-2 FROST secp256k1-tr) wallet on
 * Signet: real UTXOs, a real ceremony between two browser cores, and a real
 * node accepting the Taproot spend. Signet has no scriptable faucet, so it
 * runs in two steps that keep their vaults under `.nur/signet-smoke/`:
 *
 *   1. `STACKWALLET_SIGNET_SMOKE=1 pnpm --filter @stackwallet/web exec vitest run signet`
 *      creates the wallet and prints its `tb1p…` address; fund it from a faucet.
 *   2. Run the same command again once the funding has a confirmation: it
 *      prepares, co-signs, verifies and broadcasts a spend to a second address
 *      held in the same vault, and waits for the node to report it.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  BITCOIN_SIGNET,
  bitcoinInputsUnspent,
  bitcoinTransferStatus,
  broadcastBitcoin,
  createBitcoinAdapter,
  encodeSegwit,
  hash160,
  prepareBitcoin,
  readBitcoinCoins,
  verifyTaprootSpend,
} from '@stackwallet/chains-bitcoin';
import type { TxIntent } from '@stackwallet/core-client';

import { browser, shareKey, signTogether, type Browser } from './testkit.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir =
  process.env.STACKWALLET_SIGNET_SMOKE_DIR ??
  join(here, '..', '..', '..', '..', '.nur', 'signet-smoke');
const files = { laptop: join(dir, 'laptop.vault'), phone: join(dir, 'phone.vault') };
const SEND_SATS = '5000';

async function save(a: Browser, b: Browser) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(files.laptop, await a.vault.toBytes());
  writeFileSync(files.phone, await b.vault.toBytes());
}

describe.skipIf(process.env.STACKWALLET_SIGNET_SMOKE !== '1')('live Signet shared wallet', () => {
  it('co-signs and broadcasts a Taproot spend from a funded 2-of-2 wallet', async () => {
    if (!existsSync(files.laptop) || !existsSync(files.phone)) {
      const [a, b] = [await browser('laptop'), await browser('phone')];
      await a.vault.setDevices([b.device]);
      await b.vault.setDevices([a.device]);
      const [acc] = await shareKey(a, [b], 'secp256k1-tr');
      // The spend goes to a single-key address the laptop also holds.
      await a.vault.createSingle('return', Date.now());
      await save(a, b);
      console.info(
        `Fund ${acc.address} with at least 20000 signet sats, wait for one confirmation, and run again.`,
      );
      return;
    }
    const a = await browser('laptop', readFileSync(files.laptop));
    const b = await browser('phone', readFileSync(files.phone));
    try {
      const [acc] = await a.vault.thresholdList();
      if (!acc) throw new Error('the saved laptop vault holds no shared wallet');
      const adapter = createBitcoinAdapter();
      const coins = (await readBitcoinCoins(adapter, acc.address)).filter(
        (c) => c.status.confirmed,
      );
      if (coins.length === 0) {
        console.info(`No confirmed coins at ${acc.address} yet; fund it and run again.`);
        return;
      }
      const returnKey = await a.vault.singlePublicKey('return', 'secp256k1', "m/84'/1'/0'/0/0");
      const to = encodeSegwit('tb', 0, hash160(Buffer.from(returnKey, 'hex')));
      const intent: TxIntent = {
        id: crypto.randomUUID(),
        walletId: 'w',
        accountId: 'shared',
        chainId: BITCOIN_SIGNET,
        kind: 'transfer',
        to,
        asset: `${BITCOIN_SIGNET}:native`,
        amount: SEND_SATS,
        proposer: { kind: 'human', deviceId: a.local.id },
        createdAtMs: Date.now(),
        usdMicros: null,
        untrustedDestinations: [],
      };
      await a.vault.txPropose(intent, a.local.id, Date.now());
      const prepared = await prepareBitcoin(adapter, intent, acc.address);
      await a.vault.txAttach({
        txId: intent.id,
        signer: { walletId: 'w', path: 'tss', address: acc.address },
        unsigned: prepared.unsigned,
        simulation: prepared.simulation,
        simulationOk: prepared.simulation.ok,
        deviceId: a.local.id,
        nowMs: Date.now(),
      });
      await a.vault.txEvaluate(intent.id, a.local.id, Date.now());
      expect(await bitcoinInputsUnspent(adapter, prepared.unsigned)).toBe(true);
      const [signed] = await signTogether(a, [b], intent.id);
      expect(signed.state).toBe('signed');
      verifyTaprootSpend(prepared.unsigned, signed.rawSignedHex!);
      await a.vault.txReport(intent.id, 'broadcast', null, a.local.id, Date.now());
      const hash = await broadcastBitcoin(adapter, prepared.unsigned, signed.rawSignedHex!);
      expect(hash).toBe(signed.hash);
      await a.vault.txReport(intent.id, 'pending', null, a.local.id, Date.now());
      console.info('Signet node accepted the shared-wallet Taproot spend', hash);
      for (let i = 0; i < 20; i++) {
        const status = await bitcoinTransferStatus(adapter, prepared.unsigned, hash);
        if (status.state !== 'unknown') {
          console.info('Indexed as', status.state);
          return;
        }
        await new Promise((r) => setTimeout(r, 3000));
      }
      throw new Error('the endpoint never indexed the broadcast transaction');
    } finally {
      await save(a, b);
    }
  }, 300_000);
});
