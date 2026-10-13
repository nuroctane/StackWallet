import type { ChainRegistry } from '@stackwallet/chains';
import {
  prepareBitcoin,
  bitcoinInputsUnspent,
  broadcastBitcoin,
  bitcoinTransferStatus,
  type BitcoinAdapter,
  type BitcoinPrepareOptions,
} from '@stackwallet/chains-bitcoin';
import {
  broadcastEvm,
  nodeMessage,
  prepareEvm,
  type EvmAdapter,
  type ReplaceOptions,
} from '@stackwallet/chains-evm';
import {
  broadcastSolana,
  prepareSolana,
  solanaBlockhashValid,
  solanaTransferStatus,
  type SolanaAdapter,
  type SolanaPrepareOptions,
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
import type { ProposedBy } from '../core/vault.js';
import type { SessionProof } from '@stackwallet/core-client';

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
  /** Set when an agent or automation proposed it; the approval card shows who and why. */
  by?: ProposedBy;
  /** Destinations that came from model output rather than the user. */
  untrustedDestinations?: string[];
  /** EVM only: replace the stuck transaction with this nonce and fees. */
  replace?: ReplaceOptions;
  to: string;
  /** `${chainId}:native` or `${chainId}:erc20:0x…` */
  asset: string;
  /** Base units. */
  amount: string;
  bitcoin?: BitcoinPrepareOptions;
  solana?: SolanaPrepareOptions;
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
  return proposeIntent(registry, req, {
    kind: 'transfer',
    to: req.to,
    asset: req.asset,
    amount: req.amount,
  });
}

/**
 * Propose an EVM contract call (a revoke, an NFT transfer). The core checks
 * the unsigned transaction's destination, value and calldata byte for byte.
 */
export async function proposeContractCall(
  registry: ChainRegistry,
  req: {
    account: Account;
    to: string;
    dataHex: string;
    value?: string;
    replace?: ReplaceOptions;
    untrustedDestinations?: string[];
  },
): Promise<Result<TxRecord>> {
  if (req.account.family !== 'evm') return { ok: false, error: 'Contract calls are EVM only' };
  return proposeIntent(
    registry,
    {
      account: req.account,
      ...(req.replace ? { replace: req.replace } : {}),
      ...(req.untrustedDestinations ? { untrustedDestinations: req.untrustedDestinations } : {}),
    },
    { kind: 'contractCall', to: req.to, dataHex: req.dataHex, value: req.value ?? '0' },
  );
}

type IntentShape =
  | { kind: 'transfer'; to: string; asset: string; amount: string }
  | { kind: 'contractCall'; to: string; dataHex: string; value: string }
  | {
      kind: 'swap';
      sell: string;
      sellAmount: string;
      buy: string;
      minBuyAmount: string;
      maxSlippageBps: number;
      aggregator: string;
    }
  | { kind: 'stake' | 'unstake'; validator: string; asset: string; amount: string }
  | { kind: 'claim'; validator: string };

/**
 * Propose a single-pool swap on a chain the core knows a router for. The core
 * decodes the calldata and refuses any other router, recipient, amount or floor.
 */
export async function proposeSwap(
  registry: ChainRegistry,
  req: {
    account: Account;
    sell: string;
    sellAmount: string;
    buy: string;
    minBuyAmount: string;
    maxSlippageBps: number;
    aggregator: string;
  },
): Promise<Result<TxRecord>> {
  if (req.account.family !== 'evm') return { ok: false, error: 'Swaps are EVM only' };
  const { account, ...swap } = req;
  return proposeIntent(registry, { account }, { kind: 'swap', ...swap });
}

/** Delegate, undelegate or claim on Osmosis Testnet; the core builds the staking message. */
export async function proposeStaking(
  registry: ChainRegistry,
  req: { account: Account } & (
    | { kind: 'stake' | 'unstake'; validator: string; amount: string }
    | { kind: 'claim'; validator: string }
  ),
): Promise<Result<TxRecord>> {
  if (req.account.family !== 'cosmos') return { ok: false, error: 'Staking is Cosmos only' };
  const asset = `${req.account.chainId}:native`;
  return proposeIntent(
    registry,
    { account: req.account },
    req.kind === 'claim'
      ? { kind: 'claim', validator: req.validator }
      : { kind: req.kind, validator: req.validator, asset, amount: req.amount },
  );
}

async function proposeIntent(
  registry: ChainRegistry,
  req: Pick<
    SendRequest,
    'account' | 'bitcoin' | 'solana' | 'replace' | 'by' | 'untrustedDestinations'
  >,
  kind: IntentShape,
): Promise<Result<TxRecord>> {
  const { account } = req;
  if (!account.derivationPath) return { ok: false, error: 'This account has no key in the vault' };
  const id = crypto.randomUUID();
  const intent = {
    id,
    walletId: account.walletId,
    accountId: account.id,
    chainId: account.chainId,
    ...kind,
    usdMicros: null,
    untrustedDestinations: req.untrustedDestinations ?? [],
  } as Omit<TxIntent, 'proposer' | 'createdAtMs'>;
  const proposed = await vault.txPropose(intent, req.by);
  if (!proposed.ok) return proposed;
  let prepared;
  try {
    prepared =
      account.family === 'bitcoin'
        ? await prepareBitcoin(
            bitcoinAdapter(registry, account.chainId),
            proposed.value.intent,
            account.address,
            req.bitcoin,
          )
        : account.family === 'solana'
          ? await prepareSolana(
              solanaAdapter(registry, account.chainId),
              proposed.value.intent,
              account.address,
              req.solana,
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
                req.replace,
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
 * Approve a hardware wallet's proposal: the core makes the signing-time
 * checks and hands over the exact payload, the device signs it, and the core
 * accepts the signature only if it recovers to the registered address.
 */
export async function approveWithDevice(
  registry: ChainRegistry,
  tx: TxRecord,
  session: SessionProof,
  device: {
    signTransaction(path: string, payloadHex: string): Promise<{ v: number; r: string; s: string }>;
  },
): Promise<Result<TxRecord>> {
  if (activeSends.has(tx.id))
    return { ok: false, error: 'This transfer is already being approved' };
  if (!tx.signer) return { ok: false, error: 'No signer recorded' };
  activeSends.add(tx.id);
  try {
    const begun = await vault.txBeginExternal(tx.id, session);
    if (!begun.ok) return begun;
    if (begun.value.record.state !== 'signing') return { ok: true, value: begun.value.record };
    let sig;
    try {
      sig = await device.signTransaction(tx.signer.path, begun.value.payloadHex);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      await vault.txAbortExternal(tx.id, `device: ${reason}`);
      return { ok: false, error: reason };
    }
    const signed = await vault.txCompleteExternal(tx.id, sig);
    if (!signed.ok) return signed;
    if (signed.value.state !== 'signed' || !signed.value.rawSignedHex) return signed;
    return broadcastSaved(registry, signed.value);
  } finally {
    activeSends.delete(tx.id);
  }
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
  return broadcastSaved(registry, signed.value);
}

/** The core authorizes the saved record; callers cannot supply replacement bytes or a new intent. */
export async function retryBroadcast(
  registry: ChainRegistry,
  txId: string,
  passphrase: string,
): Promise<Result<TxRecord>> {
  if (activeSends.has(txId)) return { ok: false, error: 'This transfer is already being sent' };
  activeSends.add(txId);
  try {
    const authorized = await vault.txRetryBroadcast(txId, passphrase);
    if (!authorized.ok) return authorized;
    return await broadcastSaved(registry, authorized.value);
  } finally {
    activeSends.delete(txId);
  }
}

async function broadcastSaved(
  registry: ChainRegistry,
  signed: TxRecord,
): Promise<Result<TxRecord>> {
  if (
    !['signed', 'broadcast', 'pending'].includes(signed.state) ||
    !signed.rawSignedHex ||
    !signed.hash ||
    !signed.unsigned
  )
    return { ok: false, error: 'No unresolved signed transaction is available to broadcast' };
  const tx = signed;
  const solana = tx.unsigned && 'recentBlockhash' in tx.unsigned ? tx.unsigned : null;
  const cosmos = tx.unsigned && 'timeoutHeight' in tx.unsigned ? tx.unsigned : null;
  const bitcoin = tx.unsigned && 'inputs' in tx.unsigned ? tx.unsigned : null;
  const raw = signed.rawSignedHex;
  if (signed.state === 'signed') {
    const b = await vault.txReport(tx.id, 'broadcast', null);
    if (!b.ok) return b;
  }
  try {
    const hash = bitcoin
      ? await broadcastBitcoin(bitcoinAdapter(registry, tx.intent.chainId), bitcoin, raw)
      : solana
        ? await broadcastSolana(solanaAdapter(registry, tx.intent.chainId), tx.intent.chainId, raw)
        : cosmos
          ? await broadcastCosmos(cosmosAdapter(registry, tx.intent.chainId), cosmos, raw)
          : await broadcastEvm(evmAdapter(registry, tx.intent.chainId), tx.intent.chainId, raw);
    const note = (solana ? hash === signed.hash : hash.toLowerCase() === signed.hash?.toLowerCase())
      ? null
      : `node reported ${hash}; tracking the core signature`;
    if (signed.state === 'pending')
      return note ? { ok: false, error: note } : { ok: true, value: signed };
    return vault.txReport(tx.id, 'pending', note);
  } catch (err) {
    const note = `Broadcast response uncertain: ${nodeMessage(err)}; tracking the core signature`;
    if (signed.state === 'pending') return { ok: false, error: note };
    return vault.txReport(tx.id, 'pending', note);
  }
}

function evmUnsigned(t: TxRecord) {
  const u = t.unsigned;
  return u && 'maxFeePerGas' in u && 'nonce' in u ? u : null;
}

/**
 * Replace a stuck EVM transaction: the same intent with higher fees (speed
 * up), or a zero-value transfer to the sender itself (cancel). Either is a new
 * proposal at the same nonce, checked by the core and approved like any other;
 * whichever the chain includes first settles both.
 */
export async function proposeReplacement(
  registry: ChainRegistry,
  tx: TxRecord,
  account: Account,
  mode: 'speedUp' | 'cancel',
): Promise<Result<TxRecord>> {
  const u = evmUnsigned(tx);
  if (!u || account.family !== 'evm')
    return { ok: false, error: 'Only EVM transactions can be replaced' };
  if (!['broadcast', 'pending'].includes(tx.state))
    return { ok: false, error: 'Only a sent, unconfirmed transaction can be replaced' };
  const replace = {
    nonce: u.nonce,
    maxFeePerGas: BigInt(u.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(u.maxPriorityFeePerGas),
  };
  const i = tx.intent;
  if (mode === 'cancel')
    return proposeIntent(
      registry,
      { account, replace },
      {
        kind: 'transfer',
        to: account.address,
        asset: `${i.chainId}:native`,
        amount: '0',
      },
    );
  if (i.kind === 'transfer')
    return proposeIntent(
      registry,
      { account, replace },
      {
        kind: 'transfer',
        to: i.to,
        asset: i.asset,
        amount: i.amount,
      },
    );
  if (i.kind === 'contractCall')
    return proposeIntent(
      registry,
      { account, replace },
      {
        kind: 'contractCall',
        to: i.to,
        dataHex: i.dataHex,
        value: i.value,
      },
    );
  return { ok: false, error: 'This transaction kind cannot be sped up' };
}

/**
 * Once one EVM transaction at a nonce confirms, every other one from the
 * same account at that nonce can never land: earlier ones were replaced,
 * later replacements were dropped.
 */
async function settleNonceSiblings(confirmed: TxRecord, txs: readonly TxRecord[]): Promise<void> {
  const u = evmUnsigned(confirmed);
  if (!u) return;
  for (const t of txs) {
    const o = evmUnsigned(t);
    if (
      t.id === confirmed.id ||
      !o ||
      o.nonce !== u.nonce ||
      t.intent.accountId !== confirmed.intent.accountId ||
      t.intent.chainId !== confirmed.intent.chainId ||
      t.state !== 'pending'
    )
      continue;
    await vault.txReport(
      t.id,
      t.createdAtMs < confirmed.createdAtMs ? 'replaced' : 'dropped',
      `nonce ${u.nonce} was used by ${confirmed.hash ?? confirmed.id}`,
    );
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
          const done = await vault.txReport(t.id, 'confirmed', `block ${status.blockNumber}`);
          if (done.ok) await settleNonceSiblings(done.value, txs);
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
