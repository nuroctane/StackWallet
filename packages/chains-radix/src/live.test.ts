/**
 * Live Stokenet proof, skipped unless `RADIX_LIVE=1`: funds come from the
 * faucet (`.nur/radix-sdk/faucet2.mjs`), then the package's own encoder signs
 * and broadcasts a real XRD transfer and polls until the gateway commits it.
 */
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { RADIX_STOKENET, RadixAdapter } from './radix.js';
import { broadcastRadix, prepareRadix, radixTransferStatus, signTransfer } from './send.js';

const LIVE = process.env.RADIX_LIVE === '1';
const SEED = new Uint8Array(32).fill(7);
const FROM = 'account_tdx_2_12ynqzf78g3mtyufkch3ccqpmv6ugnawgqqe0hq0tc06y73dr0sf2qk';
const TO = 'account_tdx_2_169qlmuyvq8vcfdtlgmjllvy4ehs2tky7y8ckkmkhpq776j8vec5c2a';
const GATEWAY = 'https://stokenet.radixdlt.com';

const CHAIN: ChainInfo = {
  chainId: RADIX_STOKENET,
  family: 'radix',
  name: 'Radix Stokenet',
  nativeAsset: { ref: `${RADIX_STOKENET}:native`, symbol: 'XRD', decimals: 18 },
  testnet: true,
  defaultRpcs: [GATEWAY],
};

describe.skipIf(!LIVE)('live stokenet', () => {
  it('broadcasts a real XRD transfer that commits', async () => {
    class LiveAdapter extends RadixAdapter {
      override chains(): ChainInfo[] {
        return [CHAIN];
      }
    }
    const adapter = new LiveAdapter({ rpc: new MemoryRpcPool([CHAIN]), timeoutMs: 15_000 });
    const [holding] = await adapter.getBalances(FROM, RADIX_STOKENET);
    console.log('balance attos', holding!.amount);
    expect(BigInt(holding!.amount) > 0n).toBe(true);
    const intent = {
      id: 'live',
      walletId: 'w',
      accountId: 'a',
      chainId: RADIX_STOKENET,
      proposer: { kind: 'human', deviceId: 'd' },
      kind: 'transfer',
      to: TO,
      asset: `${RADIX_STOKENET}:native`,
      amount: '1000000000000000000', // 1 XRD
      untrustedDestinations: [],
      createdAtMs: Date.now(),
    } as unknown as TxIntent;
    const { unsigned, simulation } = await prepareRadix(adapter, intent, FROM);
    console.log('prepared', unsigned, simulation.ok);
    expect(simulation.ok).toBe(true);
    const { wireHex, txid } = signTransfer(unsigned, SEED);
    const submitted = await broadcastRadix(adapter, unsigned, wireHex);
    expect(submitted).toBe(txid);
    console.log('broadcast txid', txid);
    let state = 'unknown';
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 3000));
      const s = await radixTransferStatus(adapter, unsigned, txid);
      state = s.state;
      if (state !== 'unknown' && state !== 'pending') break;
    }
    console.log('final state', state);
    expect(state).toBe('confirmed');
  }, 180_000);
});
