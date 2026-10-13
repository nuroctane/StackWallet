import { useEffect, useId, useRef, useState } from 'react';
import type {
  CosignSummary,
  Device,
  IdentityHandle,
  KeyGroup,
  ThresholdAccount,
  ThresholdProposal,
  TxRecord,
} from '@stackwallet/core-client';
import { Button, Dialog, Field, Input, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import type { OfferCarrier } from '../core/carrier.js';
import { deviceOf } from '../core/pairing.js';
import { useVaultView, type SessionChoice } from '../core/vault.js';
import { webRtcCarriers } from '../core/webrtc.js';
import { formatUnits } from '../lib/format.js';
import { activeDevices, devices, useDevices } from '../store/devices.js';
import { directory, useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { approveWithCeremony } from '../store/txs.js';
import {
  joinKeygen,
  joinSign,
  proposeKeygen,
  proposeSign,
  readProposal,
} from '../threshold/ceremony.js';
import { openLink, type CeremonyLink } from '../threshold/link.js';
import { SessionField, sessionReady } from './ExportGateFields.js';
import { QrCode } from './views/QrCode.js';

const DEVNET = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';

export type ThresholdTarget =
  | { mode: 'create'; folderId?: string | undefined }
  | { mode: 'join' }
  | { mode: 'sign'; txId: string };

/**
 * Shared (threshold) wallets between two paired devices. Each device keeps
 * one FROST share sealed in its own vault; neither ever holds the key. The
 * devices meet over a direct WebRTC connection set up by pasting or scanning
 * two codes, and every ceremony message is signed by the device that sent it.
 */
export function ThresholdDialog({
  open,
  target,
  onClose,
}: {
  open: boolean;
  target?: ThresholdTarget | undefined;
  onClose: () => void;
}) {
  const title =
    target?.mode === 'sign'
      ? 'Sign together'
      : target?.mode === 'join'
        ? 'Join a ceremony'
        : 'New shared wallet';
  return (
    <Dialog open={open} onClose={onClose} title={title} meta="2-of-2 · ed25519 · solana devnet">
      {target?.mode === 'create' && <CreateFlow folderId={target.folderId} onClose={onClose} />}
      {target?.mode === 'join' && <JoinFlow onClose={onClose} />}
      {target?.mode === 'sign' && <SignFlow txId={target.txId} onClose={onClose} />}
    </Dialog>
  );
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** One direct connection to a paired device, as either side of the code swap. */
function useConnection() {
  const [code, setCode] = useState<string | null>(null);
  const [link, setLink] = useState<CeremonyLink | null>(null);
  const [error, setError] = useState<string | null>(null);
  const offer = useRef<OfferCarrier | null>(null);
  const identity = useRef<IdentityHandle | null>(null);
  const live = useRef<CeremonyLink | null>(null);
  useEffect(
    () => () => {
      live.current?.close('closed');
      identity.current?.free();
    },
    [],
  );

  const open = async (
    carrier: Parameters<typeof openLink>[0]['carrier'],
    role: Parameters<typeof openLink>[0]['role'],
  ) => {
    const core = vault.core;
    const local = devices.getSnapshot().localDevice;
    if (!core || !local) throw new Error('This device has no identity yet; unlock the vault');
    identity.current ??= await vault.identity();
    openLink({
      core,
      identity: identity.current,
      local: deviceOf(local),
      carrier,
      sign: (m) => vault.signCeremony(m),
      role,
      timeoutMs: 5 * 60_000,
    })
      .then((l) => {
        live.current = l;
        setLink(l);
      })
      .catch((err: unknown) => setError(message(err)));
  };

  return {
    code,
    link,
    error,
    /** Initiator: make the code the other device pastes. */
    async start(peer: Device) {
      setError(null);
      try {
        const o = await webRtcCarriers.offer();
        offer.current = o.carrier;
        setCode(o.text);
        await open(o.carrier, { kind: 'initiator', peer });
      } catch (err) {
        setError(message(err));
      }
    },
    /** Initiator: take the other device's reply. */
    async accept(text: string) {
      setError(null);
      try {
        await offer.current?.acceptAnswer(text.trim());
      } catch (err) {
        setError(message(err));
      }
    },
    /** Responder: answer the initiator's code. */
    async answer(text: string) {
      setError(null);
      try {
        const a = await webRtcCarriers.answer(text.trim());
        setCode(a.text);
        await open(a.carrier, {
          kind: 'responder',
          known: activeDevices(devices.getSnapshot()),
        });
      } catch (err) {
        setError(message(err));
      }
    },
  };
}

function CodeBox({ code, label }: { code: string; label: string }) {
  const toasts = useToasts();
  return (
    <div className="flex flex-col gap-2">
      <p className="text-[10px] tracking-[0.08em] text-faint uppercase">{label}</p>
      <div className="mx-auto w-[180px]">
        <QrCode text={code} />
      </div>
      <div className="flex gap-2">
        <code className="min-w-0 flex-1 truncate rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[11px] text-ink">
          {code}
        </code>
        <Button
          size="sm"
          variant="ghost"
          onClick={() =>
            void navigator.clipboard
              .writeText(code)
              .then(() => toasts.push('Copied'))
              .catch(() => toasts.push('Clipboard unavailable', 'danger'))
          }
        >
          Copy
        </Button>
      </div>
    </div>
  );
}

function Paste({
  label,
  onSubmit,
  button,
}: {
  label: string;
  onSubmit: (text: string) => void;
  button: string;
}) {
  const id = useId();
  const [text, setText] = useState('');
  return (
    <form
      className="flex items-end gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(text);
      }}
    >
      <Field label={label} htmlFor={id}>
        <Input
          id={id}
          value={text}
          spellCheck={false}
          placeholder="stackwallet-rtc:…"
          onChange={(e) => setText(e.target.value)}
        />
      </Field>
      <Button type="submit" disabled={!text.trim().startsWith('stackwallet-rtc:')}>
        {button}
      </Button>
    </form>
  );
}

/** The initiator's half of the code swap. */
function Connect({ conn, peer }: { conn: ReturnType<typeof useConnection>; peer: Device }) {
  const [sent, setSent] = useState(false);
  if (conn.link) return <p className="text-muted">Connected to {conn.link.peer.name}.</p>;
  return (
    <div className="flex flex-col gap-3">
      {!conn.code ? (
        <Button variant="primary" onClick={() => void conn.start(peer)}>
          Connect to {peer.name}
        </Button>
      ) : (
        <>
          <CodeBox
            code={conn.code}
            label={`1 · open “Join a ceremony” on ${peer.name} and give it this`}
          />
          {sent ? (
            <LoadingWord label="connecting" />
          ) : (
            <Paste
              label={`2 · paste the reply ${peer.name} shows`}
              button="Connect"
              onSubmit={(t) => {
                setSent(true);
                void conn.accept(t);
              }}
            />
          )}
        </>
      )}
    </div>
  );
}

function SessionStep({
  label,
  working,
  onRun,
}: {
  label: string;
  working: string | null;
  onRun: (session: SessionChoice) => void;
}) {
  const view = useVaultView(vault);
  const [session, setSession] = useState<SessionChoice>({ kind: 'passphrase', passphrase: '' });
  return (
    <div className="flex flex-col gap-3">
      <SessionField value={session} onChange={setSession} hint="this device's share needs it" />
      <div className="flex justify-end">
        <Button
          variant="primary"
          disabled={!sessionReady(session) || working !== null || view.busy}
          onClick={() => {
            onRun(session);
            if (session.kind === 'passphrase') setSession({ kind: 'passphrase', passphrase: '' });
          }}
        >
          {working ? <LoadingWord label={working} /> : label}
        </Button>
      </div>
    </div>
  );
}

function addWallet(account: ThresholdAccount, name: string, folderId: string) {
  return directory.createKeyedWallet({
    walletId: account.walletId,
    name,
    folderId,
    kind: 'tss',
    keyGroupId: account.group.id,
    accounts: [
      {
        chainId: DEVNET,
        address: account.solanaAddress,
        derivationPath: 'tss',
        publicKeyHex: account.publicKeyHex,
      },
    ],
  });
}

function CreateFlow({ folderId, onClose }: { folderId?: string | undefined; onClose: () => void }) {
  const state = useDirectory();
  const devState = useDevices();
  const toasts = useToasts();
  const ids = { name: useId(), peer: useId() };
  const peers = activeDevices(devState);
  const root = state.folders.find((f) => f.parentId === null)!;
  const [name, setName] = useState('Shared');
  const [peerId, setPeerId] = useState(peers[0]?.id ?? '');
  const [chosen, setChosen] = useState<Device | null>(null);
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const conn = useConnection();
  const local = devState.localDevice;
  if (!local || peers.length === 0)
    return (
      <p className="p-4 text-[12px] text-faint">
        Pair the other device first (Devices). A shared wallet is split between two paired devices.
      </p>
    );

  const run = async (choice: SessionChoice) => {
    if (!conn.link || !chosen) return;
    setWorking('generating');
    setError(null);
    try {
      const proof = await vault.proveSession(choice);
      const group: KeyGroup = {
        id: crypto.randomUUID(),
        threshold: 2,
        parties: [
          { deviceId: local.id, role: 'human' },
          { deviceId: chosen.id, role: 'human' },
        ],
        curves: ['ed25519'],
        publicKeys: [],
      };
      const ceremony = await vault.core!.thresholdKeygenSession(
        group,
        crypto.randomUUID(),
        Date.now(),
      );
      const account = await proposeKeygen({
        ops: vault,
        link: conn.link,
        localId: local.id,
        walletId: crypto.randomUUID(),
        group,
        ceremony,
        session: proof,
      });
      const r = addWallet(account, name, folderId ?? root.id);
      if (!r.ok) throw new Error(r.error);
      toasts.push(`${name} created; ${chosen.name} holds the other share`);
      onClose();
    } catch (err) {
      setError(message(err));
    } finally {
      setWorking(null);
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4 text-[12px]">
      {!chosen ? (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            setChosen(peers.find((p) => p.id === peerId) ?? null);
          }}
        >
          <Field label="Name" htmlFor={ids.name}>
            <Input id={ids.name} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Other share on" htmlFor={ids.peer}>
            <Select id={ids.peer} value={peerId} onChange={(e) => setPeerId(e.target.value)}>
              {peers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </Select>
          </Field>
          <p className="text-faint">
            Both devices must approve every transaction. Neither can sign alone, and no device ever
            holds the whole key.
          </p>
          <div className="flex justify-end">
            <Button type="submit" variant="primary" disabled={!peerId || !name.trim()}>
              Next
            </Button>
          </div>
        </form>
      ) : (
        <>
          <Connect conn={conn} peer={chosen} />
          {conn.link && (
            <SessionStep label="Create shared key" working={working} onRun={(s) => void run(s)} />
          )}
        </>
      )}
      {(error ?? conn.error) && <p className="text-danger">{error ?? conn.error}</p>}
    </div>
  );
}

function JoinFlow({ onClose }: { onClose: () => void }) {
  const state = useDirectory();
  const toasts = useToasts();
  const nameId = useId();
  const conn = useConnection();
  const [proposal, setProposal] = useState<ThresholdProposal | null>(null);
  const [review, setReview] = useState<CosignSummary | null>(null);
  const [name, setName] = useState('Shared');
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const root = state.folders.find((f) => f.parentId === null)!;

  useEffect(() => {
    const link = conn.link;
    if (!link) return;
    let live = true;
    void (async () => {
      try {
        const p = readProposal(await link.next());
        if (!live) return;
        if (p.kind === 'sign') {
          const r = await vault.thresholdReview(p.request, p.session, link.peer.id);
          if (!r.ok) throw new Error(r.error);
          setReview(r.value);
        }
        setProposal(p);
      } catch (err) {
        if (live) setError(message(err));
        link.close('refused');
      }
    })();
    return () => {
      live = false;
    };
  }, [conn.link]);

  const run = async (choice: SessionChoice) => {
    const link = conn.link;
    if (!link || !proposal) return;
    setWorking(proposal.kind === 'sign' ? 'signing' : 'generating');
    setError(null);
    try {
      const session = await vault.proveSession(choice);
      if (proposal.kind === 'keyGen') {
        const account = await joinKeygen({
          ops: vault,
          link,
          proposal,
          walletId: crypto.randomUUID(),
          session,
        });
        const r = addWallet(account, name, root.id);
        if (!r.ok) throw new Error(r.error);
        toasts.push(`${name} created; ${link.peer.name} holds the other share`);
      } else {
        await joinSign({ ops: vault, link, proposal, session });
        toasts.push(`Co-signed with ${link.peer.name}`);
      }
      onClose();
    } catch (err) {
      setError(message(err));
    } finally {
      setWorking(null);
    }
  };

  const denied = review?.decision.decision === 'deny';
  return (
    <div className="flex flex-col gap-4 p-4 text-[12px]">
      {!conn.code ? (
        <Paste
          label="Code from the device that started"
          button="Answer"
          onSubmit={(t) => void conn.answer(t)}
        />
      ) : !conn.link ? (
        <>
          <CodeBox code={conn.code} label="give this reply back to the other device" />
          <LoadingWord label="waiting for the connection" />
        </>
      ) : !proposal ? (
        <LoadingWord label={`connected to ${conn.link.peer.name}; waiting for its proposal`} />
      ) : proposal.kind === 'keyGen' ? (
        <>
          <p className="text-muted">
            <span className="text-ink">{conn.link.peer.name}</span> proposes a shared wallet: both
            devices must approve every transaction ({proposal.group.threshold} of{' '}
            {proposal.group.parties.length}).
          </p>
          <Field label="Name here" htmlFor={nameId}>
            <Input id={nameId} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <SessionStep label="Join" working={working} onRun={(s) => void run(s)} />
        </>
      ) : (
        review && (
          <>
            <p className="text-muted">
              <span className="text-ink">{conn.link.peer.name}</span> asks this device to co-sign:
            </p>
            <p className="text-ink">
              Send {formatUnits(review.lamports, 9)} SOL to{' '}
              <span className="font-mono break-all">{review.to}</span>
            </p>
            <p className="text-faint">
              from <span className="font-mono break-all">{review.from}</span> · decoded by this
              device&apos;s core
            </p>
            {denied ? (
              <p className="text-danger">
                This device&apos;s policies refuse it:{' '}
                {review.decision.decision === 'deny' ? review.decision.reasons.join('; ') : ''}
              </p>
            ) : (
              <SessionStep label="Co-sign" working={working} onRun={(s) => void run(s)} />
            )}
          </>
        )
      )}
      {(error ?? conn.error) && <p className="text-danger">{error ?? conn.error}</p>}
    </div>
  );
}

function SignFlow({ txId, onClose }: { txId: string; onClose: () => void }) {
  const registry = useRegistry();
  const view = useVaultView(vault);
  const devState = useDevices();
  const toasts = useToasts();
  const peerId = useId();
  const conn = useConnection();
  const [accounts, setAccounts] = useState<ThresholdAccount[] | null>(null);
  const [picked, setPicked] = useState('');
  const [chosen, setChosen] = useState<Device | null>(null);
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    void vault.thresholdList().then(setAccounts);
  }, []);
  const tx: TxRecord | undefined = view.ledger?.txs.find((t) => t.id === txId);
  const local = devState.localDevice;
  if (!tx || !local) return <p className="p-4 text-[12px] text-faint">Transaction not found.</p>;
  if (!accounts) return <LoadingWord label="reading shares" />;
  const account = accounts.find((a) => a.walletId === tx.intent.walletId);
  if (!account)
    return <p className="p-4 text-[12px] text-faint">This device holds no share of that wallet.</p>;
  const peers = activeDevices(devState).filter((d) =>
    account.group.parties.some((p) => p.deviceId === d.id && d.id !== local.id),
  );
  if (peers.length === 0)
    return (
      <p className="p-4 text-[12px] text-faint">
        The device with the other share is not paired here (or was revoked).
      </p>
    );

  const run = async (choice: SessionChoice) => {
    const link = conn.link;
    if (!link) return;
    setWorking('signing');
    setError(null);
    const session = await vault.proveSession(choice).catch((err: unknown) => {
      setError(message(err));
      return null;
    });
    if (!session) {
      setWorking(null);
      return;
    }
    const r = await approveWithCeremony(registry, tx, () =>
      proposeSign({
        ops: vault,
        link,
        localId: local.id,
        txId,
        session,
        sessionId: crypto.randomUUID(),
      }),
    );
    setWorking(null);
    if (!r.ok) setError(r.error);
    else if (r.value.state === 'rejected' || r.value.state === 'failed')
      setError(r.value.error ?? 'The core refused to sign under the current policy.');
    else {
      toasts.push('Signed by both devices and sent');
      onClose();
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4 text-[12px]">
      {!chosen ? (
        <form
          className="flex items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setChosen(peers.find((p) => p.id === (picked || peers[0]!.id)) ?? null);
          }}
        >
          <Field label="Co-signer" htmlFor={peerId}>
            <Select
              id={peerId}
              value={picked || peers[0]!.id}
              onChange={(e) => setPicked(e.target.value)}
            >
              {peers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </Select>
          </Field>
          <Button type="submit" variant="primary">
            Next
          </Button>
        </form>
      ) : (
        <>
          <Connect conn={conn} peer={chosen} />
          {conn.link && (
            <SessionStep label="Sign together" working={working} onRun={(s) => void run(s)} />
          )}
        </>
      )}
      {(error ?? conn.error) && <p className="text-danger">{error ?? conn.error}</p>}
    </div>
  );
}
