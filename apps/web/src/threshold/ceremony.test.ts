/**
 * Browsers create threshold wallets and sign a Solana Devnet transfer and
 * Bitcoin Signet Taproot spends with them, each holding only its own share,
 * over real Noise sessions on an in-memory carrier. Skipped when the wasm
 * bundle has not been built.
 */
import { describe, expect, it } from 'vitest';
import {
  getCompiledTransactionMessageDecoder,
  getPublicKeyFromAddress,
  getTransactionDecoder,
  verifySignature,
  type Address,
} from '@solana/kit';
import { BITCOIN_SIGNET, verifyTaprootSpend } from '@stackwallet/chains-bitcoin';
import type { BitcoinTx, PartyRef, ThresholdAccount } from '@stackwallet/core-client';

import {
  joinReconcile,
  joinRefresh,
  joinReshare,
  proposeReconcile,
  proposeRefresh,
  proposeReshare,
  readProposal,
  type ThresholdOps,
} from './ceremony.js';
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

/** Propose a Taproot spend of wallet `w` from `from`'s ledger, ready for approval. */
async function proposeSpend(from: Browser, acc: ThresholdAccount, txId: string, marker: bigint) {
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
}

/**
 * `hub` replaces `lost` with `fresh`, helped by the other remaining devices;
 * every side's outcome, settled. The newcomer keeps the wallet as `w` too.
 */
async function replace(
  hub: Browser,
  helpers: Browser[],
  fresh: Browser,
  lost: Browser,
  acc: ThresholdAccount,
  opts: { freshOps?: ThresholdOps; onSealed?: (a: ThresholdAccount) => void } = {},
) {
  const newcomer: PartyRef = { deviceId: fresh.local.id, role: 'human' };
  const ceremony = await hub.vault.thresholdReshareSession(
    'w',
    lost.local.id,
    newcomer,
    `rs-${Date.now()}`,
    Date.now(),
  );
  const l = await links(hub, [...helpers, fresh]);
  return Promise.allSettled([
    proposeReshare({
      ops: opsFor(hub.vault, hub.local.id),
      links: l.hub,
      localId: hub.local.id,
      walletId: 'w',
      group: acc.group,
      replaced: lost.local.id,
      newcomer,
      ceremony,
      session: proof,
    }),
    ...[...helpers, fresh].map(async (x, i) => {
      const p = readProposal(await l.peers[i]!.next());
      if (p.kind !== 'reshare') throw new Error('expected reshare');
      const joining = x === fresh;
      return joinReshare({
        ops: joining && opts.freshOps ? opts.freshOps : opsFor(x.vault, x.local.id),
        link: l.peers[i]!,
        localId: x.local.id,
        walletId: 'w',
        proposal: p,
        session: proof,
        ...(joining && opts.onSealed ? { onSealed: opts.onSealed } : {}),
      });
    }),
  ]);
}

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
    // Solana's own decoder and verifier: one signature, by the group address,
    // over a transfer of exactly what was proposed.
    const wire = Uint8Array.from(Buffer.from(signed.rawSignedHex!.slice(2), 'hex'));
    const decoded = getTransactionDecoder().decode(wire);
    expect(Object.keys(decoded.signatures)).toEqual([accA.address]);
    const sig = decoded.signatures[accA.address as Address]!;
    const groupKey = await getPublicKeyFromAddress(accA.address as Address);
    expect(await verifySignature(groupKey, sig, decoded.messageBytes)).toBe(true);
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes);
    expect(message.staticAccounts).toEqual(expect.arrayContaining([accA.address, to]));
    // Any other bytes under the same signature are refused.
    const tampered = Uint8Array.from(decoded.messageBytes);
    tampered[tampered.length - 1] = tampered.at(-1)! ^ 1;
    expect(await verifySignature(groupKey, sig, tampered)).toBe(false);
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

  it('replaces a lost device: the newcomer co-signs for the same address', async () => {
    const [a, b, c, d] = await browsers('laptop', 'phone', 'desk', 'tablet');
    const [acc] = await shareKey(a, [b, c], 'secp256k1-tr', 2);
    // The desk is lost; the tablet takes its place, and the newcomer's group
    // arrives in the proposal, its share repaired across the hub sealed.
    const sealed: ThresholdAccount[] = [];
    const outcomes = await replace(a, [b], d, c, acc, { onSealed: (x) => sealed.push(x) });
    expect(outcomes.map((o) => (o.status === 'fulfilled' ? o.value : String(o.reason)))).toEqual([
      'committed',
      'committed',
      'committed',
    ]);
    expect(sealed[0]?.address).toBe(acc.address);
    expect(sealed[0]?.group.parties.map((p) => p.deviceId).sort()).toEqual(
      [a, b, d].map((x) => x.local.id).sort(),
    );
    const [after] = await a.vault.thresholdList();
    expect(after?.group.parties.some((p) => p.deviceId === c.local.id)).toBe(false);

    const unsigned = await proposeSpend(a, acc, 'b5', 5n);
    const [signed] = await signTogether(a, [d], 'b5');
    expect(signed.state).toBe('signed');
    expect(() => verifyTaprootSpend(unsigned, signed.rawSignedHex!)).not.toThrow();
  }, 120_000);

  it('rolls a replacement back when the newcomer never sealed its share', async () => {
    const [a, b, c, d] = await browsers('laptop', 'phone', 'desk', 'tablet');
    const [acc] = await shareKey(a, [b, c], 'secp256k1-tr', 2);
    const crashing: ThresholdOps = {
      ...opsFor(d.vault, d.local.id),
      thresholdFinishReshare: async () => ({ ok: false, error: 'stopped before sealing' }),
    };
    const first = await replace(a, [b], d, c, acc, { freshOps: crashing });
    expect(first.every((o) => o.status === 'rejected')).toBe(true);
    expect((await a.vault.thresholdShareFingerprint('w')).pending).toBe(true);
    expect((await b.vault.thresholdShareFingerprint('w')).pending).toBe(true);
    expect(await d.vault.thresholdList()).toEqual([]);

    // Comparing shares: the tablet says it holds none, so the others go back.
    const ceremony = await a.vault.thresholdRefreshSession('w', 'rc-1', Date.now());
    const l = await links(a, [b, d]);
    const settled = await Promise.all([
      proposeReconcile({
        ops: opsFor(a.vault, a.local.id),
        links: l.hub,
        localId: a.local.id,
        walletId: 'w',
        ceremony,
        session: proof,
      }),
      ...[b, d].map(async (x, i) => {
        const p = readProposal(await l.peers[i]!.next());
        if (p.kind !== 'reconcile') throw new Error('expected reconcile');
        return joinReconcile({
          ops: opsFor(x.vault, x.local.id),
          link: l.peers[i]!,
          localId: x.local.id,
          walletId: x === d ? null : 'w',
          proposal: p,
          session: proof,
        });
      }),
    ]);
    expect(settled).toEqual(['rolledBack', 'rolledBack', 'dropped']);
    const [back] = await a.vault.thresholdList();
    expect(back?.group.parties.some((p) => p.deviceId === c.local.id)).toBe(true);

    // Nothing was lost: the original pair still signs.
    const unsigned = await proposeSpend(a, acc, 'b7', 7n);
    const [signed] = await signTogether(a, [b], 'b7');
    expect(signed.state).toBe('signed');
    expect(() => verifyTaprootSpend(unsigned, signed.rawSignedHex!)).not.toThrow();
  }, 120_000);
});
