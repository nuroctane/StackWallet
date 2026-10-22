/**
 * Browsers create threshold wallets and sign a Solana Devnet transfer and
 * Bitcoin Signet Taproot spends with them, each holding only its own share,
 * over real Noise sessions on an in-memory carrier. Skipped when the wasm
 * bundle has not been built.
 */
import { describe, expect, it } from 'vitest';
import { BITCOIN_SIGNET, verifyTaprootSpend } from '@stackwallet/chains-bitcoin';
import type { BitcoinTx } from '@stackwallet/core-client';

import { joinRefresh, proposeRefresh, readProposal } from './ceremony.js';
import {
  browsers,
  built,
  DEVNET,
  fundingTx,
  link,
  links,
  opsFor,
  proof,
  shareKey,
  signTogether,
  type Browser,
} from './testkit.js';

describe.skipIf(!built)('threshold wallets across browsers', () => {
  it('generates a 2-of-2 key and signs a Solana transfer only with both shares', async () => {
    const [a, b] = await browsers('laptop', 'phone');
    const now = Date.now();
    const [accA, accB] = await shareKey(a, [b], 'ed25519');
    expect(accA.address).toBe(accB.address);

    const to = '11111111111111111111111111111112';
    await a.vault.txPropose(
      {
        id: 't1',
        walletId: 'w',
        accountId: 'acc',
        chainId: DEVNET,
        proposer: { kind: 'human', deviceId: a.local.id },
        kind: 'transfer',
        to,
        asset: `${DEVNET}:native`,
        amount: '1000',
        usdMicros: null,
        untrustedDestinations: [],
        createdAtMs: now,
      },
      a.local.id,
      now,
    );
    await a.vault.txAttach({
      txId: 't1',
      signer: { walletId: 'w', path: 'tss', address: accA.address },
      unsigned: {
        chainId: DEVNET,
        from: accA.address,
        to,
        lamports: '1000',
        recentBlockhash: '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi',
        lastValidBlockHeight: 100,
      },
      simulation: { ok: true },
      simulationOk: true,
      deviceId: a.local.id,
      nowMs: now,
    });
    await a.vault.txEvaluate('t1', a.local.id, now);

    const [signed, [review]] = await signTogether(a, [b], 't1');
    expect(review).toMatchObject({ to, amount: '1000', decision: { decision: 'allow' } });
    expect(signed.state).toBe('signed');
    expect(signed.rawSignedHex?.length).toBeGreaterThan(2 + 2 * 64);
  }, 60_000);

  it('spends a Taproot output with a Signet key split between the two browsers', async () => {
    const [a, b] = await browsers('laptop', 'phone');
    const now = Date.now();
    const [accA, accB] = await shareKey(a, [b], 'secp256k1-tr');
    expect(accA).toMatchObject({ curve: 'secp256k1-tr', chainId: BITCOIN_SIGNET });
    expect(accA.address).toBe(accB.address);
    expect(accA.address).toMatch(/^tb1p/);

    const to = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
    await a.vault.txPropose(
      {
        id: 'b1',
        walletId: 'w',
        accountId: 'acc',
        chainId: BITCOIN_SIGNET,
        proposer: { kind: 'human', deviceId: a.local.id },
        kind: 'transfer',
        to,
        asset: `${BITCOIN_SIGNET}:native`,
        amount: '50000',
        usdMicros: null,
        untrustedDestinations: [],
        createdAtMs: now,
      },
      a.local.id,
      now,
    );
    const unsigned: BitcoinTx = {
      chainId: BITCOIN_SIGNET,
      from: accA.address,
      to,
      amount: '50000',
      fee: '600',
      // Two inputs, so the ceremony signs two distinct sighashes.
      inputs: [fundingTx(accA.publicKeyHex, 30_000n), fundingTx(accA.publicKeyHex, 40_000n)],
    };
    await a.vault.txAttach({
      txId: 'b1',
      signer: { walletId: 'w', path: 'tss', address: accA.address },
      unsigned,
      simulation: { ok: true },
      simulationOk: true,
      deviceId: a.local.id,
      nowMs: now,
    });
    await a.vault.txEvaluate('b1', a.local.id, now);

    const [signed, [review]] = await signTogether(a, [b], 'b1');
    expect(review).toMatchObject({ to, amount: '50000', fee: '600' });
    expect(signed.state).toBe('signed');
    // bitcoinjs computes the sighashes and noble checks every BIP340 signature.
    expect(() => verifyTaprootSpend(unsigned, signed.rawSignedHex!)).not.toThrow();
  }, 60_000);

  it('refreshes both shares, keeps the address, and still signs afterwards', async () => {
    const [a, b] = await browsers('laptop', 'phone');
    const [acc] = await shareKey(a, [b], 'secp256k1-tr');
    const before = await a.vault.thresholdShareFingerprint('w');
    const ceremony = await a.vault.thresholdRefreshSession('w', 'rf-1', Date.now());
    const [la, lb] = await link(a, b);
    const [mine, theirs] = await Promise.all([
      proposeRefresh({
        ops: opsFor(a.vault, a.local.id),
        links: [la],
        localId: a.local.id,
        walletId: 'w',
        ceremony,
        session: proof,
      }),
      (async () => {
        const p = readProposal(await lb.next());
        if (p.kind !== 'refresh') throw new Error('expected refresh');
        return joinRefresh({
          ops: opsFor(b.vault, b.local.id),
          link: lb,
          localId: b.local.id,
          walletId: 'w',
          proposal: p,
          session: proof,
        });
      })(),
    ]);
    expect([mine, theirs]).toEqual(['committed', 'committed']);
    const [fa, fb] = [
      await a.vault.thresholdShareFingerprint('w'),
      await b.vault.thresholdShareFingerprint('w'),
    ];
    expect(fa).toEqual(fb);
    expect(fa.previous).toBeNull();
    expect(fa.current).not.toBe(before.current);
    const [after] = await a.vault.thresholdList();
    expect(after?.address).toBe(acc.address);

    const now = Date.now();
    const to = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
    await a.vault.txPropose(
      {
        id: 'b2',
        walletId: 'w',
        accountId: 'acc',
        chainId: BITCOIN_SIGNET,
        proposer: { kind: 'human', deviceId: a.local.id },
        kind: 'transfer',
        to,
        asset: `${BITCOIN_SIGNET}:native`,
        amount: '50000',
        usdMicros: null,
        untrustedDestinations: [],
        createdAtMs: now,
      },
      a.local.id,
      now,
    );
    const unsigned: BitcoinTx = {
      chainId: BITCOIN_SIGNET,
      from: acc.address,
      to,
      amount: '50000',
      fee: '600',
      inputs: [fundingTx(acc.publicKeyHex, 80_000n)],
    };
    await a.vault.txAttach({
      txId: 'b2',
      signer: { walletId: 'w', path: 'tss', address: acc.address },
      unsigned,
      simulation: { ok: true },
      simulationOk: true,
      deviceId: a.local.id,
      nowMs: now,
    });
    await a.vault.txEvaluate('b2', a.local.id, now);
    const [signed] = await signTogether(a, [b], 'b2');
    expect(signed.state).toBe('signed');
    expect(() => verifyTaprootSpend(unsigned, signed.rawSignedHex!)).not.toThrow();
  }, 60_000);

  it('runs a 2-of-3 wallet through a hub: any two sign, all three refresh', async () => {
    const [a, b, c] = await browsers('laptop', 'phone', 'desk');
    const accs = await shareKey(a, [b, c], 'secp256k1-tr', 2);
    expect(new Set(accs.map((x) => x.address)).size).toBe(1);
    expect(accs[0]!.group.threshold).toBe(2);
    const acc = accs[0]!;

    /** Propose a Taproot spend from `from`'s ledger, ready for approval. */
    const propose = async (from: Browser, txId: string, marker: bigint) => {
      const now = Date.now();
      const to = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
      await from.vault.txPropose(
        {
          id: txId,
          walletId: 'w',
          accountId: 'acc',
          chainId: BITCOIN_SIGNET,
          proposer: { kind: 'human', deviceId: from.local.id },
          kind: 'transfer',
          to,
          asset: `${BITCOIN_SIGNET}:native`,
          amount: '50000',
          usdMicros: null,
          untrustedDestinations: [],
          createdAtMs: now,
        },
        from.local.id,
        now,
      );
      const unsigned: BitcoinTx = {
        chainId: BITCOIN_SIGNET,
        from: acc.address,
        to,
        amount: '50000',
        fee: '600',
        inputs: [fundingTx(acc.publicKeyHex, 80_000n + marker)],
      };
      await from.vault.txAttach({
        txId,
        signer: { walletId: 'w', path: 'tss', address: acc.address },
        unsigned,
        simulation: { ok: true },
        simulationOk: true,
        deviceId: from.local.id,
        nowMs: now,
      });
      await from.vault.txEvaluate(txId, from.local.id, now);
      return unsigned;
    };

    // The desk and the laptop sign; the phone is not involved.
    const first = await propose(c, 'b3', 0n);
    const [signed] = await signTogether(c, [a], 'b3');
    expect(signed.state).toBe('signed');
    expect(() => verifyTaprootSpend(first, signed.rawSignedHex!)).not.toThrow();

    // The phone refreshes with both others: round 2 of the refresh crosses the
    // hub sealed, and every device commits once both others report the new share.
    const ceremony = await b.vault.thresholdRefreshSession('w', 'rf-3', Date.now());
    const l = await links(b, [a, c]);
    const outcomes = await Promise.all([
      proposeRefresh({
        ops: opsFor(b.vault, b.local.id),
        links: l.hub,
        localId: b.local.id,
        walletId: 'w',
        ceremony,
        session: proof,
      }),
      ...[a, c].map(async (x, i) => {
        const p = readProposal(await l.peers[i]!.next());
        if (p.kind !== 'refresh') throw new Error('expected refresh');
        return joinRefresh({
          ops: opsFor(x.vault, x.local.id),
          link: l.peers[i]!,
          localId: x.local.id,
          walletId: 'w',
          proposal: p,
          session: proof,
        });
      }),
    ]);
    expect(outcomes).toEqual(['committed', 'committed', 'committed']);

    // A different pair signs with the refreshed shares.
    const second = await propose(a, 'b4', 1n);
    const [again] = await signTogether(a, [b], 'b4');
    expect(again.state).toBe('signed');
    expect(() => verifyTaprootSpend(second, again.rawSignedHex!)).not.toThrow();
  }, 120_000);
});
