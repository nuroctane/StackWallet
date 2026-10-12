import type { ChainRegistry } from '@stackwallet/chains';
import type { Account, SolanaTx, TxRecord } from '@stackwallet/core-client';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  txPropose: vi.fn(),
  txAttach: vi.fn(),
  txEvaluate: vi.fn(),
  txApprove: vi.fn(),
  txReport: vi.fn(),
  prepareSolana: vi.fn(),
  broadcastSolana: vi.fn(),
  solanaBlockhashValid: vi.fn(),
  solanaTransferStatus: vi.fn(),
  broadcastEvm: vi.fn(),
  prepareEvm: vi.fn(),
  prepareCosmos: vi.fn(),
  broadcastCosmos: vi.fn(),
  cosmosApprovalValid: vi.fn(),
  cosmosTransferStatus: vi.fn(),
  prepareBitcoin: vi.fn(),
  bitcoinInputsUnspent: vi.fn(),
  broadcastBitcoin: vi.fn(),
  bitcoinTransferStatus: vi.fn(),
}));
vi.mock('../core/bridge.js', () => ({ vault: mocks }));
vi.mock('@stackwallet/chains-solana', () => mocks);
vi.mock('@stackwallet/chains-cosmos', () => mocks);
vi.mock('@stackwallet/chains-bitcoin', () => mocks);
vi.mock('@stackwallet/chains-evm', async (original) => ({
  ...(await original<typeof import('@stackwallet/chains-evm')>()),
  broadcastEvm: mocks.broadcastEvm,
  prepareEvm: mocks.prepareEvm,
}));
import { approveAndSend, pollPending, proposeSend } from './txs.js';

const chainId = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
const unsigned: SolanaTx = {
  chainId,
  from: 'from',
  to: 'to',
  lamports: '1000',
  recentBlockhash: 'hash',
  lastValidBlockHeight: 100,
};
const tx: TxRecord = {
  id: 't',
  state: 'awaiting',
  intent: {
    id: 't',
    walletId: 'w',
    accountId: 'a',
    chainId,
    kind: 'transfer',
    to: 'to',
    asset: `${chainId}:native`,
    amount: '1000',
    usdMicros: null,
    untrustedDestinations: [],
    createdAtMs: 1,
    proposer: { kind: 'human', deviceId: 'd' },
  },
  signer: { walletId: 'w', path: "m/44'/501'/0'/0'", address: 'from' },
  unsigned,
  simulation: null,
  simulationOk: true,
  decision: null,
  rawSignedHex: null,
  hash: null,
  error: null,
  createdAtMs: 1,
  updatedAtMs: 1,
};
const signed = {
  ...tx,
  state: 'signed' as const,
  rawSignedHex: '0x0102',
  hash: 'CaseSensitiveSignature',
};
const registry = { adapterFor: () => ({ family: 'solana' }) } as unknown as ChainRegistry;

beforeEach(() => {
  vi.resetAllMocks();
  mocks.solanaBlockhashValid.mockResolvedValue(true);
  mocks.txApprove.mockResolvedValue({ ok: true, value: signed });
  mocks.txReport.mockImplementation(
    async (_id: string, state: TxRecord['state'], error: string | null) => ({
      ok: true,
      value: { ...signed, state, error },
    }),
  );
  mocks.broadcastSolana.mockResolvedValue(signed.hash);
  mocks.cosmosApprovalValid.mockResolvedValue(true);
  mocks.bitcoinInputsUnspent.mockResolvedValue(true);
});

describe('Bitcoin core lifecycle orchestration', () => {
  const chainId = 'bip122:00000008819873e925422c1ff0f99f7c';
  const bitcoinTx: TxRecord = {
    ...tx,
    intent: { ...tx.intent, chainId },
    unsigned: {
      chainId,
      from: 'from',
      to: 'to',
      amount: '1000',
      fee: '200',
      inputs: [{ txid: 'a'.repeat(64), vout: 0, previousTxHex: '00' }],
    },
  };
  const bitcoinRegistry = { adapterFor: () => ({ family: 'bitcoin' }) } as unknown as ChainRegistry;
  it('preserves exact coin control through preparation and core attachment', async () => {
    mocks.txPropose.mockResolvedValue({ ok: true, value: bitcoinTx });
    mocks.prepareBitcoin.mockResolvedValue({
      unsigned: bitcoinTx.unsigned,
      simulation: { ok: false },
    });
    mocks.txAttach.mockResolvedValue({ ok: true, value: bitcoinTx });
    mocks.txEvaluate.mockResolvedValue({ ok: true, value: bitcoinTx });
    const bitcoin = { inputs: [{ txid: 'a'.repeat(64), vout: 0 }], feeRate: 3 };
    const account = {
      id: 'a',
      walletId: 'w',
      family: 'bitcoin',
      chainId,
      address: 'from',
      derivationPath: "m/84'/1'/0'/0/0",
    } as Account;
    expect(
      (
        await proposeSend(bitcoinRegistry, {
          account,
          to: 'to',
          asset: `${chainId}:native`,
          amount: '1000',
          bitcoin,
        })
      ).ok,
    ).toBe(true);
    expect(mocks.prepareBitcoin.mock.calls[0]!.slice(2)).toEqual(['from', bitcoin]);
    expect(mocks.txAttach).toHaveBeenCalledWith(
      expect.objectContaining({ unsigned: bitcoinTx.unsigned, simulationOk: false }),
    );
    expect(mocks.txApprove).not.toHaveBeenCalled();
  });
  it('refuses spent or unavailable inputs before invoking the core signer', async () => {
    mocks.bitcoinInputsUnspent.mockResolvedValue(false);
    expect((await approveAndSend(bitcoinRegistry, bitcoinTx, 'pw')).ok).toBe(false);
    expect(mocks.txApprove).not.toHaveBeenCalled();
    mocks.bitcoinInputsUnspent.mockRejectedValue(new Error('offline'));
    expect((await approveAndSend(bitcoinRegistry, bitcoinTx, 'pw')).ok).toBe(false);
    expect(mocks.txApprove).not.toHaveBeenCalled();
  });
  it('tracks the core txid after an ambiguous broadcast and a restart without resending', async () => {
    mocks.broadcastBitcoin.mockRejectedValue(new Error('timeout'));
    expect(await approveAndSend(bitcoinRegistry, bitcoinTx, 'pw')).toMatchObject({
      ok: true,
      value: { state: 'pending' },
    });
    expect(mocks.txReport).toHaveBeenLastCalledWith(
      't',
      'pending',
      expect.stringContaining('uncertain'),
    );
    mocks.txReport.mockClear();
    mocks.broadcastBitcoin.mockClear();
    mocks.bitcoinTransferStatus.mockResolvedValue({ state: 'unknown' });
    await pollPending(bitcoinRegistry, [{ ...bitcoinTx, state: 'signed', hash: 'a'.repeat(64) }]);
    expect(mocks.txReport).toHaveBeenLastCalledWith(
      't',
      'pending',
      expect.stringContaining('unknown'),
    );
    expect(mocks.broadcastBitcoin).not.toHaveBeenCalled();
    mocks.bitcoinTransferStatus.mockResolvedValue({ state: 'confirmed', blockNumber: 100 });
    await pollPending(bitcoinRegistry, [{ ...bitcoinTx, state: 'pending', hash: 'a'.repeat(64) }]);
    expect(mocks.txReport).toHaveBeenLastCalledWith('t', 'confirmed', 'block 100');
  });
});

describe('Cosmos core lifecycle orchestration', () => {
  const chainId = 'cosmos:osmo-test-5';
  const cosmosTx: TxRecord = {
    ...tx,
    intent: { ...tx.intent, chainId },
    unsigned: {
      chainId,
      from: 'from',
      to: 'to',
      amount: '1000',
      publicKeyHex: 'public',
      accountNumber: '42',
      sequence: '0',
      gasLimit: 130000,
      feeAmount: '3250',
      timeoutHeight: 150,
    },
  };
  const cosmosSigned = {
    ...cosmosTx,
    state: 'signed' as const,
    rawSignedHex: '0x0102',
    hash: 'A'.repeat(64),
  };
  const registry = { adapterFor: () => ({ family: 'cosmos' }) } as unknown as ChainRegistry;
  it('prepares from the account public key and rejects a stale sequence before signing', async () => {
    mocks.txPropose.mockResolvedValue({ ok: true, value: cosmosTx });
    mocks.prepareCosmos.mockResolvedValue({
      unsigned: cosmosTx.unsigned,
      simulation: { ok: true },
    });
    mocks.txAttach.mockResolvedValue({ ok: true, value: cosmosTx });
    mocks.txEvaluate.mockResolvedValue({ ok: true, value: cosmosTx });
    const account = {
      id: 'a',
      walletId: 'w',
      family: 'cosmos',
      chainId,
      address: 'from',
      publicKeyHex: 'public',
      derivationPath: "m/44'/118'/0'/0/0",
    } as Account;
    await proposeSend(registry, { account, to: 'to', asset: `${chainId}:native`, amount: '1000' });
    expect(mocks.prepareCosmos.mock.calls[0]!.slice(2)).toEqual(['from', 'public']);
    mocks.cosmosApprovalValid.mockResolvedValue(false);
    await approveAndSend(registry, cosmosTx, 'pw');
    expect(mocks.txReport).toHaveBeenCalledWith(
      't',
      'expired',
      expect.stringContaining('sequence'),
    );
    expect(mocks.txApprove).not.toHaveBeenCalled();
  });
  it('keeps an ambiguous send pending and polls under the core-known hash', async () => {
    mocks.txApprove.mockResolvedValue({ ok: true, value: cosmosSigned });
    mocks.broadcastCosmos.mockRejectedValue(new Error('timeout'));
    await approveAndSend(registry, cosmosTx, 'pw');
    expect(mocks.txReport.mock.calls.map((args) => args[1])).toEqual(['broadcast', 'pending']);
    mocks.txReport.mockClear();
    mocks.cosmosTransferStatus.mockResolvedValue({ state: 'unknown' });
    await pollPending(registry, [{ ...cosmosSigned, state: 'pending' }]);
    expect(mocks.cosmosTransferStatus).toHaveBeenCalledWith(
      expect.anything(),
      cosmosTx.unsigned,
      cosmosSigned.hash,
    );
    expect(mocks.txReport).not.toHaveBeenCalled();
    mocks.cosmosTransferStatus.mockResolvedValue({ state: 'confirmed', blockNumber: 123 });
    await pollPending(registry, [{ ...cosmosSigned, state: 'pending' }]);
    expect(mocks.txReport).toHaveBeenCalledWith('t', 'confirmed', 'block 123');
  });
});

describe('SOL core lifecycle orchestration', () => {
  it('prepares native SOL with no EVM adapter and attaches the checked signer', async () => {
    mocks.txPropose.mockImplementation(async (intent) => ({ ok: true, value: { ...tx, intent } }));
    mocks.prepareSolana.mockResolvedValue({ unsigned, simulation: { ok: true } });
    mocks.txAttach.mockResolvedValue({ ok: true, value: { ...tx, state: 'simulated' } });
    mocks.txEvaluate.mockResolvedValue({ ok: true, value: tx });
    const account = {
      id: 'a',
      walletId: 'w',
      chainId,
      family: 'solana',
      address: 'from',
      derivationPath: tx.signer!.path,
    } as Account;
    expect(
      await proposeSend(registry, {
        account,
        to: 'to',
        asset: `${chainId}:native`,
        amount: '1000',
      }),
    ).toMatchObject({ ok: true });
    expect(mocks.prepareEvm).not.toHaveBeenCalled();
    expect(mocks.txAttach.mock.calls[0]![0]).toMatchObject({
      signer: tx.signer,
      unsigned,
      simulationOk: true,
    });
  });

  it('expires an approval before signing, and does not sign when expiry cannot be checked', async () => {
    mocks.solanaBlockhashValid.mockResolvedValue(false);
    expect(await approveAndSend(registry, tx, 'pw')).toMatchObject({
      ok: true,
      value: { state: 'expired' },
    });
    expect(mocks.txApprove).not.toHaveBeenCalled();
    expect(mocks.broadcastSolana).not.toHaveBeenCalled();
    mocks.solanaBlockhashValid.mockRejectedValue(new Error('offline'));
    expect(await approveAndSend(registry, tx, 'pw')).toEqual({
      ok: false,
      error: 'Could not check blockhash: offline',
    });
    expect(mocks.txApprove).not.toHaveBeenCalled();
  });

  it('tracks core signatures through an ambiguous broadcast and compares base58 case exactly', async () => {
    mocks.broadcastSolana.mockRejectedValue(new Error('response timed out'));
    expect(await approveAndSend(registry, tx, 'pw')).toMatchObject({
      ok: true,
      value: { state: 'pending', hash: signed.hash },
    });
    expect(mocks.txReport.mock.calls.map((args) => args[1])).toEqual(['broadcast', 'pending']);
    mocks.txReport.mockClear();
    mocks.broadcastSolana.mockResolvedValue(signed.hash!.toLowerCase());
    expect(await approveAndSend(registry, tx, 'pw')).toMatchObject({
      ok: true,
      value: { state: 'pending' },
    });
    expect(mocks.txReport.mock.calls[1]![2]).toContain('tracking the core signature');
  });

  it('honors signing-time policy rejection without broadcasting', async () => {
    mocks.txApprove.mockResolvedValue({ ok: true, value: { ...tx, state: 'rejected' } });
    expect(await approveAndSend(registry, tx, 'pw')).toMatchObject({
      ok: true,
      value: { state: 'rejected' },
    });
    expect(mocks.broadcastSolana).not.toHaveBeenCalled();
    expect(mocks.txReport).not.toHaveBeenCalled();
  });

  it('resumes crash-interrupted signed transactions, then records expiry or finalized failure', async () => {
    mocks.solanaTransferStatus.mockResolvedValue({ state: 'expired' });
    await pollPending(registry, [signed]);
    expect(mocks.txReport.mock.calls.map((args) => args[1])).toEqual([
      'broadcast',
      'pending',
      'expired',
    ]);
    expect(mocks.broadcastSolana).not.toHaveBeenCalled();
    mocks.txReport.mockClear();
    mocks.solanaTransferStatus.mockResolvedValue({ state: 'failed', reason: 'instruction failed' });
    await pollPending(registry, [{ ...signed, state: 'pending' }]);
    expect(mocks.txReport).toHaveBeenCalledWith('t', 'failed', 'instruction failed');
  });

  it('does not let a polling tick advance an active send, and deduplicates approvals', async () => {
    let finish!: (value: unknown) => void;
    mocks.txApprove.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const first = approveAndSend(registry, tx, 'pw');
    await vi.waitFor(() => expect(mocks.txApprove).toHaveBeenCalled());
    await pollPending(registry, [signed]);
    expect(mocks.txReport).not.toHaveBeenCalled();
    expect(await approveAndSend(registry, tx, 'pw')).toMatchObject({ ok: false });
    finish({ ok: true, value: signed });
    await first;
    expect(mocks.txReport.mock.calls.map((args) => args[1])).toEqual(['broadcast', 'pending']);
  });
});
