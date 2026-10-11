import type { ChainRegistry } from '@stackwallet/chains';
import { broadcastEvm, nodeMessage, prepareEvm, type EvmAdapter } from '@stackwallet/chains-evm';
import type { Account, TxIntent, TxRecord } from '@stackwallet/core-client';

import { vault } from '../core/bridge.js';

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

function evmAdapter(registry: ChainRegistry, chainId: string): EvmAdapter {
  const a = registry.adapterFor(chainId);
  if (a.family !== 'evm') throw new Error(`${chainId} is not an EVM chain`);
  return a as unknown as EvmAdapter;
}

export interface SendRequest {
  account: Account;
  to: string;
  /** `${chainId}:native` or `${chainId}:erc20:0x…` */
  asset: string;
  /** Base units. */
  amount: string;
}

/**
 * Propose a transfer: the core records the intent, the adapter prepares the
 * unsigned transaction and simulation, the core checks it against the intent
 * and the signer against the account, then runs the policies. The result is
 * either queued for approval or denied with reasons.
 */
export async function proposeSend(
  registry: ChainRegistry,
  req: SendRequest,
): Promise<Result<TxRecord>> {
  const { account } = req;
  if (!account.derivationPath) return { ok: false, error: 'This account has no key in the vault' };
  const id = crypto.randomUUID();
  const intent = {
    id,
    walletId: account.walletId,
    accountId: account.id,
    chainId: account.chainId,
    kind: 'transfer',
    to: req.to,
    asset: req.asset,
    amount: req.amount,
    usdMicros: null,
    untrustedDestinations: [],
  } as Omit<TxIntent, 'proposer' | 'createdAtMs'>;
  const proposed = await vault.txPropose(intent);
  if (!proposed.ok) return proposed;
  let prepared;
  try {
    prepared = await prepareEvm(
      evmAdapter(registry, account.chainId),
      proposed.value.intent,
      account.address,
    );
  } catch (err) {
    return {
      ok: false,
      error: `Could not prepare: ${nodeMessage(err)}`,
    };
  }
  const attached = await vault.txAttach({
    txId: id,
    signer: { walletId: account.walletId, path: account.derivationPath, address: account.address },
    unsigned: prepared.unsigned,
    simulation: prepared.simulation,
    simulationOk: prepared.simulation.ok,
  });
  if (!attached.ok) return attached;
  return vault.txEvaluate(id);
}

/**
 * Approve in the core (which signs), then hand the bytes to the network. The
 * ledger records Broadcast before the send and Pending or Failed after it.
 */
export async function approveAndSend(
  registry: ChainRegistry,
  tx: TxRecord,
  passphrase: string,
): Promise<Result<TxRecord>> {
  const signed = await vault.txApprove(tx.id, passphrase);
  if (!signed.ok) return signed;
  if (signed.value.state !== 'signed' || !signed.value.rawSignedHex) return signed;
  const b = await vault.txReport(tx.id, 'broadcast', null);
  if (!b.ok) return b;
  try {
    const hash = await broadcastEvm(
      evmAdapter(registry, tx.intent.chainId),
      tx.intent.chainId,
      signed.value.rawSignedHex,
    );
    const note =
      hash.toLowerCase() === signed.value.hash?.toLowerCase() ? null : `node reported ${hash}`;
    return vault.txReport(tx.id, 'pending', note);
  } catch (err) {
    return vault.txReport(tx.id, 'failed', `network refused it: ${nodeMessage(err)}`);
  }
}

/** Ask the chain about every pending transaction and record final outcomes. */
export async function pollPending(
  registry: ChainRegistry,
  txs: readonly TxRecord[],
): Promise<void> {
  for (const t of txs) {
    if (t.state !== 'pending' || !t.hash) continue;
    try {
      const status = await registry.adapterFor(t.intent.chainId).status(t.hash, t.intent.chainId);
      if (status.state === 'confirmed') {
        await vault.txReport(t.id, 'confirmed', `block ${status.blockNumber}`);
      } else if (status.state === 'failed') {
        await vault.txReport(t.id, 'failed', status.reason ?? 'reverted');
      }
    } catch {
      // Endpoints come and go; the next poll asks again.
    }
  }
}
