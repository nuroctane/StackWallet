import { useCallback, useEffect, useId, useRef, useState } from 'react';
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
  joinReconcile,
  joinRefresh,
  joinSign,
  proposeKeygen,
  proposeReconcile,
  proposeRefresh,
  proposeSign,
  readProposal,
  type Reconciled,
} from '../threshold/ceremony.js';
import { openLink, type CeremonyLink } from '../threshold/link.js';
import { SessionField, sessionReady } from './ExportGateFields.js';
import { QrCode } from './views/QrCode.js';

/** What a shared wallet signs on, by the one FROST curve its key lives on. */
const KINDS = {
  ed25519: { label: 'Solana Devnet', chain: 'solana devnet', symbol: 'SOL', decimals: 9 },
  'secp256k1-tr': {
    label: 'Bitcoin Signet (Taproot)',
    chain: 'bitcoin signet',
    symbol: 'sBTC',
    decimals: 8,
  },
} as const;
type SharedCurve = keyof typeof KINDS;
const kindOfChain = (chainId: string) =>
  chainId.startsWith('bip122:') ? KINDS['secp256k1-tr'] : KINDS.ed25519;

/** Shared wallets stay small: every extra party is one more code swap per ceremony. */
const MAX_PARTIES = 5;

export type ThresholdTarget =
  | { mode: 'create'; folderId?: string | undefined }
  | { mode: 'join' }
  | { mode: 'sign'; txId: string }
  | { mode: 'refresh'; walletId: string };

/**
 * Shared (threshold) wallets between paired devices. Each device keeps one
 * FROST share sealed in its own vault; none ever holds the key. The device
 * that starts a ceremony connects to each other device directly over WebRTC
 * (two pasted or scanned codes per device) and relays between them; every
 * message is signed by its author, and messages meant for one device are
 * sealed to it, so the relay can neither forge nor read them.
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
        : target?.mode === 'refresh'
          ? 'Refresh shares'
          : 'New shared wallet';
  return (
    <Dialog open={open} onClose={onClose} title={title} meta="threshold · frost">
      {target?.mode === 'create' && <CreateFlow folderId={target.folderId} onClose={onClose} />}
      {target?.mode === 'join' && <JoinFlow onClose={onClose} />}
      {target?.mode === 'sign' && <SignFlow txId={target.txId} onClose={onClose} />}
      {target?.mode === 'refresh' && <RefreshFlow walletId={target.walletId} onClose={onClose} />}
    </Dialog>
  );
}

const RECONCILED: Record<Reconciled, string> = {
  committed: 'Every device holds the refreshed shares; the old ones are gone',
  inSync: 'Every device already holds the same shares',
  rolledBack: 'Another device kept its old share, so this one went back to it',
};

/** The wallet this device holds a share of in `keyGroupId`, if any. */
async function walletOfGroup(keyGroupId: string): Promise<ThresholdAccount> {
  const account = (await vault.thresholdList()).find((a) => a.group.id === keyGroupId);
  if (!account) throw new Error('This device holds no share of that wallet');
  return account;
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
      open: (m) => vault.openCeremony(m),
      // Only a joiner hears from devices other than its peer, relayed by the hub.
      ...(role.kind === 'responder' ? { admitRelayed: (s) => vault.admitRelayed(s) } : {}),
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

/** The initiator's half of the code swap with one device. */
function PeerConnect({
  peer,
  onLink,
}: {
  peer: Device;
  onLink: (peerId: string, link: CeremonyLink | null) => void;
}) {
  const conn = useConnection();
  const [sent, setSent] = useState(false);
  useEffect(() => {
    onLink(peer.id, conn.link);
  }, [conn.link, peer.id, onLink]);
  return (
    <div className="flex flex-col gap-3 rounded-sw-sm border border-edge p-3">
      {conn.link ? (
        <p className="text-muted">Connected to {conn.link.peer.name}.</p>
      ) : !conn.code ? (
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
      {conn.error && <p className="text-danger">{conn.error}</p>}
    </div>
  );
}

/** One code swap per device; `links` is complete once every device is connected. */
function useLinks(peers: readonly Device[]) {
  const [links, setLinks] = useState<Record<string, CeremonyLink | null>>({});
  const onLink = useCallback(
    (peerId: string, link: CeremonyLink | null) =>
      setLinks((prev) => (prev[peerId] === link ? prev : { ...prev, [peerId]: link })),
    [],
  );
  const ready = peers.length > 0 && peers.every((p) => links[p.id]);
  return {
    ready,
    links: ready ? peers.map((p) => links[p.id]!) : [],
    view: (
      <div className="flex flex-col gap-3">
        {peers.map((p) => (
          <PeerConnect key={p.id} peer={p} onLink={onLink} />
        ))}
      </div>
    ),
  };
}

/** Choose some of `candidates`; exactly `exactly` when set. */
function DevicePicker({
  candidates,
  chosen,
  onChange,
  exactly,
}: {
  candidates: readonly Device[];
  chosen: readonly string[];
  onChange: (ids: string[]) => void;
  exactly?: number;
}) {
  return (
    <div className="flex flex-col gap-1">
      {candidates.map((d) => {
        const on = chosen.includes(d.id);
        const full = exactly !== undefined && chosen.length >= exactly && !on;
        return (
          <label key={d.id} className="flex items-center gap-2 text-ink">
            <input
              type="checkbox"
              checked={on}
              disabled={full}
              onChange={() => onChange(on ? chosen.filter((x) => x !== d.id) : [...chosen, d.id])}
            />
            {d.name}
          </label>
        );
      })}
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
        chainId: account.chainId,
        address: account.address,
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
  const ids = { name: useId(), curve: useId(), threshold: useId() };
  const candidates = activeDevices(devState);
  const root = state.folders.find((f) => f.parentId === null)!;
  const [name, setName] = useState('Shared');
  const [curve, setCurve] = useState<SharedCurve>('ed25519');
  const [picked, setPicked] = useState<string[]>(candidates[0] ? [candidates[0].id] : []);
  const [threshold, setThreshold] = useState(2);
  const [chosen, setChosen] = useState<Device[] | null>(null);
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const conns = useLinks(chosen ?? []);
  const local = devState.localDevice;
  if (!local || candidates.length === 0)
    return (
      <p className="p-4 text-[12px] text-faint">
        Pair the other devices first (Devices). A shared wallet is split between paired devices.
      </p>
    );
  const parties = picked.length + 1;
  const t = Math.min(Math.max(threshold, 2), parties);

  const run = async (choice: SessionChoice) => {
    if (!conns.ready || !chosen) return;
    setWorking('generating');
    setError(null);
    try {
      const proof = await vault.proveSession(choice);
      const group: KeyGroup = {
        id: crypto.randomUUID(),
        threshold: t,
        parties: [
          { deviceId: local.id, role: 'human' },
          ...chosen.map((d) => ({ deviceId: d.id, role: 'human' as const })),
        ],
        curves: [curve],
        publicKeys: [],
      };
      const ceremony = await vault.core!.thresholdKeygenSession(
        group,
        crypto.randomUUID(),
        Date.now(),
      );
      const account = await proposeKeygen({
        ops: vault,
        links: conns.links,
        localId: local.id,
        walletId: crypto.randomUUID(),
        group,
        ceremony,
        session: proof,
      });
      const r = addWallet(account, name, folderId ?? root.id);
      if (!r.ok) throw new Error(r.error);
      toasts.push(`${name} created: ${t} of ${group.parties.length} devices sign`);
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
            setThreshold(t);
            setChosen(candidates.filter((d) => picked.includes(d.id)));
          }}
        >
          <Field label="Name" htmlFor={ids.name}>
            <Input id={ids.name} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Signs on" htmlFor={ids.curve}>
            <Select
              id={ids.curve}
              value={curve}
              onChange={(e) => setCurve(e.target.value as SharedCurve)}
            >
              {(Object.keys(KINDS) as SharedCurve[]).map((c) => (
                <option key={c} value={c}>
                  {KINDS[c].label}
                </option>
              ))}
            </Select>
          </Field>
          <div className="flex flex-col gap-1">
            <p className="text-[10px] tracking-[0.08em] text-faint uppercase">
              Other shares on (this device holds one too)
            </p>
            <DevicePicker
              candidates={candidates}
              chosen={picked}
              onChange={(next) => setPicked(next.slice(0, MAX_PARTIES - 1))}
            />
          </div>
          <Field label="Devices needed to sign" htmlFor={ids.threshold}>
            <Select
              id={ids.threshold}
              value={String(t)}
              onChange={(e) => setThreshold(Number(e.target.value))}
            >
              {Array.from({ length: Math.max(parties - 1, 1) }, (_, i) => i + 2).map((n) => (
                <option key={n} value={n}>
                  {n} of {parties}
                </option>
              ))}
            </Select>
          </Field>
          <p className="text-faint">
            Any {t} of these {parties} devices must approve every transaction. Fewer can never sign,
            and no device ever holds the whole key. Every device must be paired with every other
            one.
          </p>
          <div className="flex justify-end">
            <Button type="submit" variant="primary" disabled={picked.length === 0 || !name.trim()}>
              Next
            </Button>
          </div>
        </form>
      ) : (
        <>
          {conns.view}
          {conns.ready && (
            <SessionStep label="Create shared key" working={working} onRun={(s) => void run(s)} />
          )}
        </>
      )}
      {error && <p className="text-danger">{error}</p>}
    </div>
  );
}

/** Participants of a proposal other than this device and the proposer. */
function thirdParties(p: ThresholdProposal, localId: string, proposerId: string): string[] {
  const ids = p.kind === 'keyGen' ? p.group.parties.map((x) => x.deviceId) : p.session.participants;
  return ids.filter((id) => id !== localId && id !== proposerId);
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
        const local = devices.getSnapshot().localDevice;
        if (!local) throw new Error('This device has no identity yet');
        // Messages from the other parties arrive relayed by the proposer and
        // are checked against this device's own pins, so each must be paired here.
        const known = new Set(activeDevices(devices.getSnapshot()).map((d) => d.id));
        const unpaired = thirdParties(p, local.id, link.peer.id).filter((id) => !known.has(id));
        if (unpaired.length > 0)
          throw new Error(
            `Pair this device with ${unpaired.join(', ')} first; it takes part in this ceremony`,
          );
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
    const local = devices.getSnapshot().localDevice;
    if (!link || !proposal || !local) return;
    setWorking(
      proposal.kind === 'sign'
        ? 'signing'
        : proposal.kind === 'keyGen'
          ? 'generating'
          : proposal.kind === 'refresh'
            ? 'refreshing'
            : 'comparing',
    );
    setError(null);
    try {
      const session = await vault.proveSession(choice);
      if (proposal.kind === 'keyGen') {
        const account = await joinKeygen({
          ops: vault,
          link,
          localId: local.id,
          proposal,
          walletId: crypto.randomUUID(),
          session,
        });
        const r = addWallet(account, name, root.id);
        if (!r.ok) throw new Error(r.error);
        toasts.push(`${name} created; this device holds one share`);
      } else if (proposal.kind === 'sign') {
        await joinSign({ ops: vault, link, localId: local.id, proposal, session });
        toasts.push(`Co-signed with ${link.peer.name}`);
      } else {
        const account = await walletOfGroup(proposal.session.keyGroupId);
        const common = { ops: vault, link, localId: local.id, walletId: account.walletId, session };
        const out =
          proposal.kind === 'refresh'
            ? await joinRefresh({ ...common, proposal })
            : await joinReconcile({ ...common, proposal });
        toasts.push(RECONCILED[out]);
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
        !error && (
          <LoadingWord label={`connected to ${conn.link.peer.name}; waiting for its proposal`} />
        )
      ) : proposal.kind === 'keyGen' ? (
        <>
          <p className="text-muted">
            <span className="text-ink">{conn.link.peer.name}</span> proposes a shared{' '}
            {KINDS[proposal.group.curves[0] as SharedCurve]?.label ?? proposal.group.curves[0]}{' '}
            wallet: any {proposal.group.threshold} of its {proposal.group.parties.length} devices
            must approve every transaction.
          </p>
          <Field label="Name here" htmlFor={nameId}>
            <Input id={nameId} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <SessionStep label="Join" working={working} onRun={(s) => void run(s)} />
        </>
      ) : proposal.kind === 'refresh' || proposal.kind === 'reconcile' ? (
        <>
          <p className="text-muted">
            <span className="text-ink">{conn.link.peer.name}</span>{' '}
            {proposal.kind === 'refresh'
              ? 'proposes replacing every share of a shared wallet with fresh ones. The addresses stay the same; the old shares stop working once every device confirms.'
              : 'asks to compare share generations after an unfinished refresh. This device keeps whichever share the other devices hold.'}
          </p>
          <SessionStep
            label={proposal.kind === 'refresh' ? 'Refresh' : 'Compare'}
            working={working}
            onRun={(s) => void run(s)}
          />
        </>
      ) : (
        review && (
          <>
            <p className="text-muted">
              <span className="text-ink">{conn.link.peer.name}</span> asks this device to co-sign:
            </p>
            <p className="text-ink">
              Send {formatUnits(review.amount, kindOfChain(review.chainId).decimals)}{' '}
              {kindOfChain(review.chainId).symbol} to{' '}
              <span className="font-mono break-all">{review.to}</span>
            </p>
            {review.fee !== null && (
              <p className="text-muted">
                network fee {formatUnits(review.fee, kindOfChain(review.chainId).decimals)}{' '}
                {kindOfChain(review.chainId).symbol}
              </p>
            )}
            <p className="text-faint">
              from <span className="font-mono break-all">{review.from}</span> on{' '}
              {kindOfChain(review.chainId).chain} · decoded by this device&apos;s core
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

/** The other parties of `account`'s group that are paired and active here. */
function otherParties(account: ThresholdAccount, all: readonly Device[], localId: string) {
  return all.filter((d) =>
    account.group.parties.some((p) => p.deviceId === d.id && d.id !== localId),
  );
}

function SignFlow({ txId, onClose }: { txId: string; onClose: () => void }) {
  const registry = useRegistry();
  const view = useVaultView(vault);
  const devState = useDevices();
  const toasts = useToasts();
  const [accounts, setAccounts] = useState<ThresholdAccount[] | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [chosen, setChosen] = useState<Device[] | null>(null);
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const conns = useLinks(chosen ?? []);
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
  const peers = otherParties(account, activeDevices(devState), local.id);
  const needed = account.group.threshold - 1;
  if (peers.length < needed)
    return (
      <p className="p-4 text-[12px] text-faint">
        This wallet needs {needed} other device{needed === 1 ? '' : 's'} to sign, and only{' '}
        {peers.length} of its devices {peers.length === 1 ? 'is' : 'are'} paired here.
      </p>
    );
  const selection = peers.length === needed ? peers.map((p) => p.id) : picked;

  const run = async (choice: SessionChoice) => {
    if (!conns.ready) return;
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
        links: conns.links,
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
      toasts.push(`Signed by ${account.group.threshold} devices and sent`);
      onClose();
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4 text-[12px]">
      {!chosen ? (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            setChosen(peers.filter((p) => selection.includes(p.id)));
          }}
        >
          <p className="text-[10px] tracking-[0.08em] text-faint uppercase">
            Co-signers ({needed} of {peers.length})
          </p>
          <DevicePicker
            candidates={peers}
            chosen={selection}
            onChange={setPicked}
            exactly={needed}
          />
          <div className="flex justify-end">
            <Button type="submit" variant="primary" disabled={selection.length !== needed}>
              Next
            </Button>
          </div>
        </form>
      ) : (
        <>
          {conns.view}
          {conns.ready && (
            <SessionStep label="Sign together" working={working} onRun={(s) => void run(s)} />
          )}
        </>
      )}
      {error && <p className="text-danger">{error}</p>}
    </div>
  );
}

/**
 * Replace this wallet's shares on every device. A refresh some device did not
 * finish leaves the previous share pending; then the same connections compare
 * generations instead, and the core keeps whichever the others hold.
 */
function RefreshFlow({ walletId, onClose }: { walletId: string; onClose: () => void }) {
  const devState = useDevices();
  const toasts = useToasts();
  const [account, setAccount] = useState<ThresholdAccount | null | undefined>(undefined);
  const [pending, setPending] = useState(false);
  const [started, setStarted] = useState(false);
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const local = devState.localDevice;
  const peers = account && local ? otherParties(account, activeDevices(devState), local.id) : [];
  const conns = useLinks(started ? peers : []);
  useEffect(() => {
    void (async () => {
      const found = (await vault.thresholdList()).find((a) => a.walletId === walletId) ?? null;
      setAccount(found);
      if (!found) return;
      const fp = await vault.thresholdShareFingerprint(walletId);
      if (fp.ok) setPending(fp.value.previous !== null);
    })();
  }, [walletId]);
  if (account === undefined) return <LoadingWord label="reading shares" />;
  if (!account || !local)
    return <p className="p-4 text-[12px] text-faint">This device holds no share of that wallet.</p>;
  if (peers.length + 1 < account.group.parties.length)
    return (
      <p className="p-4 text-[12px] text-faint">
        Every device of this wallet takes part in a refresh, and not all of them are paired here (or
        one was revoked).
      </p>
    );

  const run = async (choice: SessionChoice) => {
    if (!conns.ready) return;
    setWorking(pending ? 'comparing' : 'refreshing');
    setError(null);
    try {
      const session = await vault.proveSession(choice);
      const ceremony = await vault.thresholdRefreshSession(walletId);
      if (!ceremony.ok) throw new Error(ceremony.error);
      const common = {
        ops: vault,
        links: conns.links,
        localId: local.id,
        walletId,
        ceremony: ceremony.value,
        session,
      };
      const out = pending ? await proposeReconcile(common) : await proposeRefresh(common);
      toasts.push(RECONCILED[out]);
      onClose();
    } catch (err) {
      setError(message(err));
    } finally {
      setWorking(null);
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4 text-[12px]">
      <p className="text-faint">
        {pending
          ? 'A refresh on this device was not confirmed by every other device. Connect to compare: this device keeps whichever share the others hold. Do not sign until this is settled.'
          : 'Every device gets a fresh share of the same key: the addresses and balances stay, and a copy of an old vault stops being useful. Every device must take part.'}
      </p>
      {!started ? (
        <div className="flex justify-end">
          <Button variant="primary" onClick={() => setStarted(true)}>
            Connect {peers.length === 1 ? peers[0]!.name : `${peers.length} devices`}
          </Button>
        </div>
      ) : (
        <>
          {conns.view}
          {conns.ready && (
            <SessionStep
              label={pending ? 'Compare shares' : 'Refresh shares'}
              working={working}
              onRun={(s) => void run(s)}
            />
          )}
        </>
      )}
      {error && <p className="text-danger">{error}</p>}
    </div>
  );
}
