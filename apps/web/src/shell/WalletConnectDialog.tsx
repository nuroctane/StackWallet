import { useEffect, useId, useRef, useState } from 'react';
import { Button, Dialog, Field, Input, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView, type SessionChoice } from '../core/vault.js';
import { useDirectory } from '../store/persist.js';
import {
  useWalletConnect,
  walletConnect,
  type Dapp,
  type PendingRequest,
} from '../walletconnect/client.js';
import { AddressLabel } from './AddressLabel.js';
import { SessionField, sessionReady } from './ExportGateFields.js';
import { typedSummary } from './SignMessageDialog.js';

/**
 * Connect dapps over WalletConnect. Off by default; the user brings their own
 * Reown project id. Every request a dapp sends lands here and becomes either
 * a proposal in the approval queue or a message signature asked for in full.
 */
export function WalletConnectDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const wc = useWalletConnect();
  return (
    <Dialog open={open} onClose={onClose} title="WalletConnect" meta="dapps · opt-in">
      <div className="flex flex-col gap-4 p-4 text-[12px]">
        <Setup />
        {wc.status === 'ready' && (
          <>
            <Pair />
            {wc.proposals.map((p) => (
              <ProposalCard key={p.id} id={p.id} dapp={p.dapp} required={p.requiredChains} />
            ))}
            {wc.requests.map((r) => (
              <RequestCard key={r.id} request={r} />
            ))}
            <Sessions />
          </>
        )}
      </div>
    </Dialog>
  );
}

function DappLine({ dapp }: { dapp: Dapp }) {
  return (
    <p className="text-muted">
      <span className="text-ink">{dapp.name}</span> · {dapp.url || 'no URL'} ·{' '}
      <span
        className={
          dapp.verified === 'valid'
            ? 'text-muted'
            : dapp.verified === 'unknown'
              ? 'text-faint'
              : 'text-danger'
        }
      >
        {dapp.verified === 'valid'
          ? 'domain verified'
          : dapp.verified === 'scam'
            ? 'flagged as a scam'
            : dapp.verified === 'invalid'
              ? 'domain mismatch'
              : 'domain unverified'}
      </span>
    </p>
  );
}

function Setup() {
  const wc = useWalletConnect();
  const toasts = useToasts();
  const id = useId();
  const [draft, setDraft] = useState('');
  if (wc.projectId)
    return (
      <div className="flex items-center justify-between gap-2">
        <span className="text-muted">
          {wc.status === 'starting' ? (
            <LoadingWord label="connecting to the relay" />
          ) : wc.status === 'error' ? (
            <span className="text-danger">{wc.error}</span>
          ) : (
            'On. Messages pass through the WalletConnect relay, end-to-end encrypted.'
          )}
        </span>
        <Button
          size="sm"
          variant="ghost"
          onClick={() =>
            void walletConnect.configure(null).then(() => toasts.push('WalletConnect off'))
          }
        >
          Turn off
        </Button>
      </div>
    );
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        void walletConnect
          .configure(draft)
          .then(() => setDraft(''))
          .catch((err: unknown) =>
            toasts.push(err instanceof Error ? err.message : String(err), 'danger'),
          );
      }}
    >
      <p className="text-muted">
        WalletConnect needs a relay run by Reown and a project id from your own Reown account.
        StackWallet sends nothing until you add one, and turns the SDK&apos;s telemetry off.
      </p>
      <Field label="Reown project id" htmlFor={id}>
        <Input
          id={id}
          value={draft}
          spellCheck={false}
          autoComplete="off"
          placeholder="32 hex characters"
          onChange={(e) => setDraft(e.target.value)}
        />
      </Field>
      <div className="flex justify-end">
        <Button type="submit" variant="primary" disabled={!/^[0-9a-fA-F]{32}$/.test(draft.trim())}>
          Turn on
        </Button>
      </div>
    </form>
  );
}

function Pair() {
  const toasts = useToasts();
  const id = useId();
  const [uri, setUri] = useState('');
  const [working, setWorking] = useState(false);
  return (
    <form
      className="flex items-end gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        setWorking(true);
        void walletConnect
          .pair(uri)
          .then(() => setUri(''))
          .catch((err: unknown) =>
            toasts.push(err instanceof Error ? err.message : String(err), 'danger'),
          )
          .finally(() => setWorking(false));
      }}
    >
      <Field label="Connection link from the dapp" htmlFor={id}>
        <Input
          id={id}
          value={uri}
          placeholder="wc:…"
          spellCheck={false}
          onChange={(e) => setUri(e.target.value)}
        />
      </Field>
      <Button type="submit" disabled={!uri.trim().startsWith('wc:') || working}>
        {working ? <LoadingWord label="pairing" /> : 'Pair'}
      </Button>
    </form>
  );
}

function ProposalCard({ id, dapp, required }: { id: number; dapp: Dapp; required: string[] }) {
  const { wallets } = useDirectory();
  const toasts = useToasts();
  const field = useId();
  const keyed = wallets.filter((w) => w.kind === 'single' || w.kind === 'hardware');
  const [walletId, setWalletId] = useState(keyed[0]?.id ?? '');
  return (
    <div className="flex flex-col gap-2 rounded-sw-sm border border-edge p-3">
      <p className="text-[10px] tracking-[0.08em] text-faint uppercase">connection request</p>
      <DappLine dapp={dapp} />
      {required.length > 0 && <p className="text-faint">requires {required.join(', ')}</p>}
      <Field label="Answer as" htmlFor={field}>
        <Select id={field} value={walletId} onChange={(e) => setWalletId(e.target.value)}>
          {keyed.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </Select>
      </Field>
      <p className="text-faint">
        The dapp sees this wallet&apos;s EVM testnet addresses and can ask for transactions and
        signatures. It cannot move anything without your approval.
      </p>
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={() => void walletConnect.rejectProposal(id)}>
          Reject
        </Button>
        <Button
          size="sm"
          variant="primary"
          disabled={!walletId}
          onClick={() =>
            void walletConnect
              .approveProposal(id, walletId)
              .catch((err: unknown) =>
                toasts.push(err instanceof Error ? err.message : String(err), 'danger'),
              )
          }
        >
          Connect
        </Button>
      </div>
    </div>
  );
}

function RequestCard({ request: r }: { request: PendingRequest }) {
  const view = useVaultView(vault);
  const [session, setSession] = useState<SessionChoice>({ kind: 'passphrase', passphrase: '' });
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const a = r.action;
  if (a.kind === 'refuse') return null;

  const sign = async () => {
    if (a.kind !== 'sign') return;
    setWorking(true);
    setError(null);
    try {
      const proof = await vault.proveSession(session);
      const out = await vault.signMessage({
        walletId: r.walletId,
        path: a.account.derivationPath!,
        address: a.account.address,
        session: proof,
        kind: a.messageKind,
        payload: a.payload,
      });
      if (!out.ok) setError(out.error);
      else await walletConnect.answerSignature(r.id, out.value.signatureHex);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (session.kind === 'passphrase') setSession({ kind: 'passphrase', passphrase: '' });
      setWorking(false);
    }
  };

  const propose = async () => {
    setWorking(true);
    setError(null);
    const out = await walletConnect.propose(r.id);
    setWorking(false);
    if (!out.ok) setError(out.error);
  };

  return (
    <div className="flex flex-col gap-2 rounded-sw-sm border border-edge p-3">
      <p className="text-[10px] tracking-[0.08em] text-faint uppercase">
        {r.method} · {r.chainId}
      </p>
      <DappLine dapp={r.dapp} />
      {a.kind === 'send' ? (
        <>
          <p className="text-muted">
            {a.dataHex ? 'Call' : 'Send to'} <AddressLabel address={a.to} chainId={r.chainId} /> ·{' '}
            {a.value} wei{a.dataHex ? ` · ${a.dataHex.length / 2} bytes of calldata` : ''}
          </p>
          {r.txId ? (
            <p className="text-faint">
              In the approval queue. The dapp gets the transaction hash once you approve it there.
            </p>
          ) : (
            <p className="text-faint">
              Proposing runs the core&apos;s checks and your policies; the destination is marked as
              coming from the dapp.
            </p>
          )}
        </>
      ) : (
        <>
          {a.messageKind === 'typedData' && (
            <p className="text-ink">
              {typedSummary(a.payload) ?? 'typed data that does not parse'}
            </p>
          )}
          <pre className="max-h-32 overflow-auto rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[11px] whitespace-pre-wrap text-ink">
            {a.payload.slice(0, 4000)}
          </pre>
          <SessionField
            value={session}
            onChange={setSession}
            hint="asked again for every signature"
          />
        </>
      )}
      {error && <p className="text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={() => void walletConnect.decline(r.id)}>
          Decline
        </Button>
        {a.kind === 'send' && !r.txId && (
          <Button size="sm" variant="primary" disabled={working} onClick={() => void propose()}>
            {working ? <LoadingWord label="preparing" /> : 'Propose'}
          </Button>
        )}
        {a.kind === 'sign' && (
          <Button
            size="sm"
            variant="primary"
            disabled={working || !sessionReady(session) || view.busy}
            onClick={() => void sign()}
          >
            {working ? <LoadingWord label="signing" /> : 'Sign'}
          </Button>
        )}
      </div>
    </div>
  );
}

function Sessions() {
  const wc = useWalletConnect();
  const { wallets } = useDirectory();
  if (wc.sessions.length === 0) return <p className="text-faint">No dapps connected.</p>;
  return (
    <ul className="flex flex-col gap-1">
      {wc.sessions.map((s) => (
        <li key={s.topic} className="flex items-center justify-between gap-2">
          <span className="min-w-0 truncate">
            <span className="text-ink">{s.dapp.name}</span>{' '}
            <span className="text-faint">
              {s.dapp.url} · as{' '}
              {wallets.find((w) => w.id === s.walletId)?.name ?? 'a removed wallet'}
            </span>
          </span>
          <Button size="sm" variant="ghost" onClick={() => void walletConnect.disconnect(s.topic)}>
            Disconnect
          </Button>
        </li>
      ))}
    </ul>
  );
}

/** A dapp's request waits in the dialog; this says so wherever the user is. */
export function WalletConnectNotifier({ onOpen }: { onOpen: () => void }) {
  const wc = useWalletConnect();
  const toasts = useToasts();
  const seen = useRef(new Set<number>());
  useEffect(() => {
    for (const x of [...wc.proposals, ...wc.requests]) {
      if (seen.current.has(x.id)) continue;
      seen.current.add(x.id);
      toasts.push(`${x.dapp.name} is asking for something. Open Dapps… to answer.`);
      onOpen();
    }
  }, [wc.proposals, wc.requests, toasts, onOpen]);
  return null;
}
