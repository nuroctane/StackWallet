import type { ChainRegistry } from '@stackwallet/chains';
import {
  prepareBitcoin,
  bitcoinInputsUnspent,
  broadcastBitcoin,
  bitcoinTransferStatus,
  type BitcoinAdapter,
} from '@stackwallet/chains-bitcoin';
import { broadcastEvm, nodeMessage, prepareEvm, type EvmAdapter } from '@stackwallet/chains-evm';
import {
  broadcastSolana,
  prepareSolana,
  solanaBlockhashValid,
  solanaTransferStatus,
  type SolanaAdapter,
} from '@stackwallet/chains-solana';
import type { Account, TxIntent, TxRecord } from '@stackwallet/core-client';
import {
  broadcastCosmos,
  prepareCosmos,
  cosmosApprovalValid,
  cosmosTransferStatus,
  type CosmosAdapter,
} from '@stackwallet/chains-cosmos';

import { vault } from '../core/bridge.js';

type Result<T> = { ok: true; value: T } | { ok: false; error: string };
const activeSends = new Set<string>();
let polling = false;

function evmAdapter(registry: ChainRegistry, chainId: string): EvmAdapter {
  const a = registry.adapterFor(chainId);
  if (a.family !== 'evm') throw new Error(`${chainId} is not an EVM chain`);
  return a as unknown as EvmAdapter;
}

function solanaAdapter(registry: ChainRegistry, chainId: string): SolanaAdapter {
  const a = registry.adapterFor(chainId);
  if (a.family !== 'solana') throw new Error(`${chainId} is not a Solana cluster`);
  return a as unknown as SolanaAdapter;
}

export interface SendRequest {
  account: Account;
  to: string;
  /** `${chainId}:native` or `${chainId}:erc20:0x…` */
  asset: string;
  /** Base units. */
  amount: string;
}
function cosmosAdapter(registry: ChainRegistry, chainId: string): CosmosAdapter {
  const a = registry.adapterFor(chainId);
  if (a.family !== 'cosmos') throw new Error(`${chainId} is not a Cosmos chain`);
  return a as unknown as CosmosAdapter;
}
function bitcoinAdapter(registry: ChainRegistry, chainId: string): BitcoinAdapter {
  const a = registry.adapterFor(chainId);
  if (a.family !== 'bitcoin') throw new Error('Not a Bitcoin chain');
  return a as unknown as BitcoinAdapter;
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
    prepared =
      account.family === 'bitcoin'
        ? await prepareBitcoin(
            bitcoinAdapter(registry, account.chainId),
            proposed.value.intent,
            account.address,
          )
        : account.family === 'solana'
          ? await prepareSolana(
              solanaAdapter(registry, account.chainId),
              proposed.value.intent,
              account.address,
            )
          : account.family === 'cosmos'
            ? await prepareCosmos(
                cosmosAdapter(registry, account.chainId),
                proposed.value.intent,
                account.address,
                account.publicKeyHex,
              )
            : await prepareEvm(
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
  if (activeSends.has(tx.id))
    return { ok: false, error: 'This transfer is already being approved' };
  activeSends.add(tx.id);
  try {
    return await approveAndBroadcast(registry, tx, passphrase);
  } finally {
    activeSends.delete(tx.id);
  }
}

async function approveAndBroadcast(
  registry: ChainRegistry,
  tx: TxRecord,
  passphrase: string,
): Promise<Result<TxRecord>> {
  const solana = tx.unsigned && 'recentBlockhash' in tx.unsigned ? tx.unsigned : null;
  const cosmos = tx.unsigned && 'timeoutHeight' in tx.unsigned ? tx.unsigned : null;
  const bitcoin = tx.unsigned && 'inputs' in tx.unsigned ? tx.unsigned : null;
  if (bitcoin) {
    try {
      if (!(await bitcoinInputsUnspent(bitcoinAdapter(registry, tx.intent.chainId), bitcoin)))
        return {
          ok: false,
          error:
            'A selected input has been spent. Reject this proposal and prepare a fresh transfer.',
        };
    } catch (err) {
      return { ok: false, error: `Could not verify inputs: ${nodeMessage(err)}` };
    }
  }
  if (solana) {
    try {
      if (!(await solanaBlockhashValid(solanaAdapter(registry, tx.intent.chainId), solana)))
        return vault.txReport(
          tx.id,
          'expired',
          'Blockhash expired; propose and approve a fresh transfer',
        );
    } catch (err) {
      return { ok: false, error: `Could not check blockhash: ${nodeMessage(err)}` };
    }
  }
  if (cosmos) {
    try {
      if (!(await cosmosApprovalValid(cosmosAdapter(registry, tx.intent.chainId), cosmos)))
        return vault.txReport(
          tx.id,
          'expired',
          'Timeout or account sequence changed; propose and approve a fresh transfer',
        );
    } catch (err) {
      return { ok: false, error: `Could not check account and timeout: ${nodeMessage(err)}` };
    }
  }
  const signed = await vault.txApprove(tx.id, passphrase);
  if (!signed.ok) return signed;
  if (signed.value.state !== 'signed' || !signed.value.rawSignedHex) return signed;
  const b = await vault.txReport(tx.id, 'broadcast', null);
  if (!b.ok) return b;
  try {
    const hash = bitcoin
      ? await broadcastBitcoin(
          bitcoinAdapter(registry, tx.intent.chainId),
          bitcoin,
          signed.value.rawSignedHex,
        )
      : solana
        ? await broadcastSolana(
            solanaAdapter(registry, tx.intent.chainId),
            tx.intent.chainId,
            signed.value.rawSignedHex,
          )
        : cosmos
          ? await broadcastCosmos(
              cosmosAdapter(registry, tx.intent.chainId),
              cosmos,
              signed.value.rawSignedHex,
            )
          : await broadcastEvm(
              evmAdapter(registry, tx.intent.chainId),
              tx.intent.chainId,
              signed.value.rawSignedHex,
            );
    const note = (
      solana ? hash === signed.value.hash : hash.toLowerCase() === signed.value.hash?.toLowerCase()
    )
      ? null
      : `node reported ${hash}; tracking the core signature`;
    return vault.txReport(tx.id, 'pending', note);
  } catch (err) {
    if (solana || cosmos || bitcoin)
      return vault.txReport(
        tx.id,
        'pending',
        `Broadcast response uncertain: ${nodeMessage(err)}; tracking the core signature`,
      );
    return vault.txReport(tx.id, 'failed', `network refused it: ${nodeMessage(err)}`);
  }
}

/** Ask the chain about every pending transaction and record final outcomes. */
export async function pollPending(
  registry: ChainRegistry,
  txs: readonly TxRecord[],
): Promise<void> {
  if (polling) return;
  polling = true;
  try {
    for (const t of txs) {
      if (activeSends.has(t.id)) continue;
      if (!['signed', 'broadcast', 'pending'].includes(t.state) || !t.hash) continue;
      try {
        const solana = t.unsigned && 'recentBlockhash' in t.unsigned ? t.unsigned : null;
        const cosmos = t.unsigned && 'timeoutHeight' in t.unsigned ? t.unsigned : null;
        const bitcoin = t.unsigned && 'inputs' in t.unsigned ? t.unsigned : null;
        // Resume tracking after a crash between signing, broadcast and the saved response.
        if (t.state !== 'pending') {
          if (!solana && !cosmos && !bitcoin) continue;
          if (t.state === 'signed') {
            const resumed = await vault.txReport(
              t.id,
              'broadcast',
              'Resuming signature tracking after restart',
            );
            if (!resumed.ok) continue;
          }
          const resumed = await vault.txReport(
            t.id,
            'pending',
            'Broadcast outcome unknown; tracking the core signature',
          );
          if (!resumed.ok) continue;
        }
        const status = bitcoin
          ? await bitcoinTransferStatus(bitcoinAdapter(registry, t.intent.chainId), bitcoin, t.hash)
          : solana
            ? await solanaTransferStatus(solanaAdapter(registry, t.intent.chainId), solana, t.hash)
            : cosmos
              ? await cosmosTransferStatus(
                  cosmosAdapter(registry, t.intent.chainId),
                  cosmos,
                  t.hash,
                )
              : await registry.adapterFor(t.intent.chainId).status(t.hash, t.intent.chainId);
        if (status.state === 'confirmed') {
          await vault.txReport(t.id, 'confirmed', `block ${status.blockNumber}`);
        } else if (status.state === 'failed') {
          await vault.txReport(t.id, 'failed', status.reason ?? 'reverted');
        } else if (status.state === 'expired') {
          await vault.txReport(
            t.id,
            'expired',
            cosmos
              ? 'Timeout passed without a transfer; propose again'
              : 'Blockhash expired without a finalized transfer; propose again',
          );
        }
      } catch {
        // Endpoints come and go; the next poll asks again.
      }
    }
  } finally {
    polling = false;
  }
}
