import { useState, type ReactNode } from 'react';
import type { Simulation } from '@stackwallet/chains';
import { erc20Of } from '@stackwallet/chains-evm';
import type { TxRecord, TxState } from '@stackwallet/core-client';
import { Badge, Button, EmptyState, Input, LoadingWord, Panel, StatusDot } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { findChain } from '../lib/chains.js';
import { decodeCalldata, isUnlimitedApproval, type DecodedCall } from '../lib/decode.js';
import { formatUnits, relativeTime } from '../lib/format.js';
import { useRegistry } from '../store/RegistryContext.js';
import { approveAndSend } from '../store/txs.js';
import { tokenStore, useTokens } from '../store/tokens.js';
import { AddressLabel, useLabeler } from './AddressLabel.js';
import { useShell } from './ShellContext.js';

export function ApprovalRail() {
  const { ledger } = useVaultView(vault);
  const pending = ledger?.txs.filter((t) => t.state === 'awaiting').length ?? 0;
  return (
    <Panel as="aside" title="Approvals" meta={`${pending} pending`} className="sw-enter min-w-0">
      <ApprovalRailBody />
    </Panel>
  );
}

const STATE_TONE: Partial<Record<TxState, string>> = {
  confirmed: 'text-ok',
  failed: 'text-danger',
  denied: 'text-danger',
  rejected: 'text-faint',
  pending: 'text-warm',
  broadcast: 'text-warm',
  signed: 'text-warm',
  awaiting: 'text-warm',
  expired: 'text-faint',
};

export function StateChip({ state }: { state: TxState }) {
  return (
    <span
      className={`inline-flex h-4 items-center rounded-sw-sm border border-edge px-1 text-[10px] lowercase ${STATE_TONE[state] ?? 'text-muted'}`}
    >
      {state}
    </span>
  );
}

/** One-line description of what a transaction does, in assets rather than bytes. */
export function useHeadline(): (tx: TxRecord) => string {
  useTokens();
  const registry = useRegistry();
  const labeler = useLabeler();
  return (tx: TxRecord) => {
    const i = tx.intent;
    const chain = findChain(registry, i.chainId);
    if (i.kind === 'transfer') {
      const token = erc20Of(i.asset, i.chainId);
      if (!token) {
        if (!chain) return `Send ${i.amount} base units of ${i.asset}`;
        const sym = chain.nativeAsset.symbol;
        const decimals = chain.nativeAsset.decimals;
        return `Send ${formatUnits(i.amount, decimals, decimals)} ${sym}`;
      }
      const name = labeler(token, i.chainId).label ?? `token ${token.slice(0, 6)}…`;
      const metadata = tokenStore.find(i.asset);
      if (metadata)
        return `Send ${formatUnits(i.amount, metadata.decimals, metadata.decimals)} ${metadata.symbol} · ${token.slice(0, 6)}…`;
      return `Send ${i.amount} base units of ${name}`;
    }
    if (i.kind === 'contractCall') {
      const call = decodeCalldata(i.dataHex);
      return call.kind === 'call' ? `Call ${call.function}` : 'Call an unknown function';
    }
    return i.kind;
  };
}

function DecodedLine({ call, chainId }: { call: DecodedCall; chainId: string }) {
  if (call.kind === 'none') return null;
  if (call.kind === 'unknown') {
    return (
      <p className="text-[11px] text-danger">
        Undecodable call ({call.selector}, {call.bytes} bytes). Nobody here can tell you what it
        does.
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-0.5 text-[11px]">
      <span className="font-mono text-muted">{call.function}(</span>
      {call.args.map((a) => (
        <span key={a.name} className="flex gap-2 pl-3">
          <span className="w-[64px] shrink-0 text-faint">{a.name}</span>
          {a.type === 'address' ? (
            <AddressLabel address={a.value} chainId={chainId} />
          ) : (
            <span className="font-mono text-ink">{a.value}</span>
          )}
        </span>
      ))}
      <span className="font-mono text-muted">)</span>
      {isUnlimitedApproval(call) && (
        <span className="text-danger">Grants unlimited access to these assets.</span>
      )}
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 text-[12px]">
      <span className="w-[64px] shrink-0 pt-px text-[10px] tracking-[0.08em] text-faint uppercase">
        {label}
      </span>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

function ApprovalCard({ tx }: { tx: TxRecord }) {
  const registry = useRegistry();
  const view = useVaultView(vault);
  const headline = useHeadline()(tx);
  const labeler = useLabeler();
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const i = tx.intent;
  const chain = findChain(registry, i.chainId);
  const sim = (tx.simulation ?? null) as Simulation | null;
  const recipient = i.kind === 'transfer' || i.kind === 'contractCall' ? i.to : null;
  const unknownRecipient = recipient ? labeler(recipient, i.chainId).source === 'none' : false;
  const evm = tx.unsigned && 'dataHex' in tx.unsigned ? tx.unsigned : null;
  const solana = tx.unsigned && 'recentBlockhash' in tx.unsigned ? tx.unsigned : null;
  const cosmos = tx.unsigned && 'timeoutHeight' in tx.unsigned ? tx.unsigned : null;
  const bitcoin = tx.unsigned && 'inputs' in tx.unsigned ? tx.unsigned : null;
  const call = decodeCalldata(evm?.dataHex ?? '');
  const native = chain?.nativeAsset;
  const maxFee = evm ? BigInt(evm.maxFeePerGas) * BigInt(evm.gasLimit) : undefined;

  const approve = async () => {
    setWorking(true);
    setError(null);
    const r = await approveAndSend(registry, tx, passphrase);
    setPassphrase('');
    setWorking(false);
    if (!r.ok) setError(r.error);
    else if (r.value.state === 'rejected' || r.value.state === 'failed') {
      setError(r.value.error ?? 'The core refused to sign under the current policy.');
    }
  };

  return (
    <li className="flex flex-col gap-2 border-b border-edge p-3">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-ink">{headline}</span>
        <span className="ml-auto text-[10px] text-faint">
          {relativeTime(tx.createdAtMs, Date.now())} ago
        </span>
      </div>
      <Row label="network">
        <span className="text-muted">{chain?.name ?? i.chainId}</span>
        {chain?.testnet && <Badge className="ml-1">testnet</Badge>}
      </Row>
      {tx.signer && (
        <Row label="from">
          <AddressLabel address={tx.signer.address} chainId={i.chainId} />
        </Row>
      )}
      {recipient && (
        <Row label="to">
          <AddressLabel address={recipient} chainId={i.chainId} full />
        </Row>
      )}
      <DecodedLine call={call} chainId={i.chainId} />
      {bitcoin && (
        <p className="text-[11px] text-muted">
          {bitcoin.inputs.length} confirmed input(s) · change returns to the sender. RBF signaled;
          replacement is not implemented. Confirmation waits for six blocks; unknown outcomes stay
          pending.
        </p>
      )}
      {bitcoin && native && (
        <Row label="fee">
          <span className="font-mono">
            {formatUnits(bitcoin.fee, native.decimals, native.decimals)} {native.symbol}
          </span>
        </Row>
      )}
      {bitcoin && (
        <details className="text-[11px] text-muted">
          <summary className="min-h-11 cursor-pointer py-3">Review exact Bitcoin inputs</summary>
          <ul className="space-y-2">
            {bitcoin.inputs.map((input) => (
              <li key={`${input.txid}:${input.vout}`} className="break-all font-mono">
                {input.txid}:{input.vout}
              </li>
            ))}
          </ul>
        </details>
      )}
      {cosmos && (
        <p className="text-[11px] text-muted">
          One native bank transfer · expires after block {cosmos.timeoutHeight}. If the sequence
          changes, propose again.
        </p>
      )}
      {cosmos && native && (
        <Row label="fee">
          <span className="font-mono text-[11px] text-muted">
            {formatUnits(cosmos.feeAmount, native.decimals, native.decimals)} {native.symbol}
          </span>
        </Row>
      )}
      {solana && (
        <p className="text-[11px] text-muted">
          One System Program transfer · valid through block height {solana.lastValidBlockHeight}. If
          expired, propose again.
        </p>
      )}
      {solana && sim && native && (
        <Row label="fee">
          <span className="font-mono text-[11px] text-muted">
            {formatUnits(sim.fee.amount, native.decimals, native.decimals)} {native.symbol}{' '}
            estimated
          </span>
        </Row>
      )}
      {sim && (
        <Row label="changes">
          <ul className="flex flex-col font-mono text-[11px]">
            {sim.assetDeltas.map((d, n) => (
              <li key={n} className={d.amount.startsWith('-') ? 'text-ink' : 'text-ok'}>
                {d.assetRef === `${i.chainId}:native` && native
                  ? `${d.amount.startsWith('-') ? '−' : '+'}${formatUnits(d.amount.replace('-', ''), native.decimals, native.decimals)} ${native.symbol}`
                  : tokenStore.find(d.assetRef)
                    ? `${formatUnits(d.amount, tokenStore.find(d.assetRef)!.decimals, tokenStore.find(d.assetRef)!.decimals)} ${tokenStore.find(d.assetRef)!.symbol}`
                    : `${d.amount} · ${d.assetRef.split(':').slice(-1)[0]}`}
              </li>
            ))}
          </ul>
        </Row>
      )}
      {maxFee !== undefined && native && (
        <Row label="fee cap">
          <span className="font-mono text-[11px] text-muted">
            {formatUnits(String(maxFee), native.decimals, native.decimals)} {native.symbol} at most
          </span>
        </Row>
      )}
      {tx.simulationOk === false && (
        <p className="text-[11px] text-danger">Simulation failed: {sim?.error ?? 'unknown'}</p>
      )}
      {sim?.warnings.map((w, n) => (
        <p key={n} className="text-[11px] text-warm">
          {w.kind === 'destinationIsContract' ? 'The recipient is a contract.' : w.kind}
        </p>
      ))}
      {tx.decision?.decision === 'allow' && tx.decision.auditNotes.length > 0 && (
        <p className="text-[11px] text-faint">
          Audit-only policy notes: {tx.decision.auditNotes.join('; ')}
        </p>
      )}
      <Row label="proposer">
        <span className="text-muted">
          {i.proposer.kind === 'human'
            ? 'you, on this device'
            : i.proposer.kind === 'agent'
              ? `agent: ${i.proposer.rationale}`
              : 'automation'}
        </span>
      </Row>
      <form
        className="flex gap-1.5 pt-1"
        onSubmit={(e) => {
          e.preventDefault();
          void approve();
        }}
      >
        <Input
          type="password"
          autoComplete="current-password"
          placeholder="vault passphrase"
          aria-label="vault passphrase to approve"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="h-7 min-w-0 flex-1 text-[12px]"
        />
        <Button
          type="submit"
          size="sm"
          variant={unknownRecipient || tx.simulationOk === false ? 'danger' : 'primary'}
          disabled={!passphrase || working || view.busy}
          title={
            tx.simulationOk === false
              ? 'The simulation failed; this is likely to fail on chain'
              : unknownRecipient
                ? 'First payment to this address'
                : undefined
          }
        >
          {working ? <LoadingWord label="signing" /> : 'Approve'}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={working || view.busy}
          onClick={() => void vault.txReject(tx.id)}
        >
          Reject
        </Button>
      </form>
      {error && <p className="text-[11px] text-danger">{error}</p>}
    </li>
  );
}

/** Rail content without the panel chrome, so a workspace pane can host it. */
export function ApprovalRailBody() {
  const view = useVaultView(vault);
  const shell = useShell();
  const headline = useHeadline();
  const ledger = view.ledger;
  const awaiting = ledger?.txs.filter((t) => t.state === 'awaiting') ?? [];
  const recent = (ledger?.txs ?? [])
    .filter((t) => t.state !== 'awaiting')
    .sort((a, b) => b.updatedAtMs - a.updatedAtMs)
    .slice(0, 8);
  const policies = ledger?.policies.length ?? 0;

  return (
    <div className="flex h-full flex-col">
      {view.ledgerError && (
        <p className="border-b border-danger/60 bg-danger-soft p-3 text-[12px] text-ink">
          The transaction ledger failed its integrity check: {view.ledgerError}
        </p>
      )}
      <div className="min-h-0 flex-1 overflow-auto">
        {view.status.kind !== 'unlocked' ? (
          <EmptyState
            title="Vault locked"
            description="Pending signatures live in the vault; unlock it to see and approve them."
          />
        ) : awaiting.length === 0 ? (
          <EmptyState
            title="Nothing to approve"
            description="Every signature request from any wallet, agent session or automation lands here before anything is signed."
          />
        ) : (
          <ul>
            {awaiting.map((t) => (
              <ApprovalCard key={t.id} tx={t} />
            ))}
          </ul>
        )}
        {recent.length > 0 && (
          <div className="flex flex-col gap-1 p-3">
            <div className="text-[10px] tracking-[0.08em] text-faint uppercase">recent</div>
            {recent.map((t) => (
              <div key={t.id} className="flex items-center gap-2 text-[11px]">
                <StateChip state={t.state} />
                <span className="truncate text-muted">{headline(t)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="flex flex-col gap-3 border-t border-edge p-3">
        <div className="flex items-center justify-between gap-2">
          <StatusDot state="online" label="this device" />
          <Button size="sm" variant="ghost" onClick={() => shell.openDialog({ kind: 'send' })}>
            Send…
          </Button>
        </div>
        <p className="text-[11px] text-faint">
          {policies === 0
            ? 'No policies yet: the core still checks every transaction against its intent and needs your passphrase to sign.'
            : `${policies} polic${policies === 1 ? 'y' : 'ies'} evaluated by the core at proposal and again at signing.`}
        </p>
        <Button size="sm" variant="ghost" onClick={() => shell.openDialog({ kind: 'policies' })}>
          Edit policies…
        </Button>
      </div>
    </div>
  );
}
