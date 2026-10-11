import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import {
  decodePairingOffer,
  isPairingOfferExpired,
  PAIRING_OFFER_PREFIX,
  PairingOfferError,
  pairingOfferIdMatches,
  type Device,
  type DeviceKind,
  type PairingOffer,
} from '@stackwallet/core-client';
import {
  Badge,
  Button,
  Dialog,
  EmptyState,
  Field,
  Input,
  Kbd,
  LoadingWord,
  useToasts,
} from '@stackwallet/ui';

import { pairing, vault } from '../../core/bridge.js';
import { usePairing, type ScannerState } from '../../core/pairing.js';
import { useVaultView } from '../../core/vault.js';
import { RTC_PREFIX, splitPairingText } from '../../core/webrtc.js';
import { relativeTime } from '../../lib/format.js';
import {
  DEVICES_READ_ONLY,
  devices,
  sortedDevices,
  useDevices,
  type LocalDevice,
} from '../../store/devices.js';
import { useShell } from '../ShellContext.js';
import { QrCode } from './QrCode.js';

/**
 * The identity lives in the vault, so everything that signs needs it unlocked.
 * The handshake runs over a WebRTC data channel the two devices open by
 * swapping pasted offers; every blocked control says which piece is missing.
 */
const NO_IDENTITY_REASON = 'This browser has no device identity yet. Create a vault to mint one.';
const LOCKED_REASON = "Unlock the vault to use this device's identity.";
const NO_WEBRTC_REASON =
  'This browser has no WebRTC, so it cannot open a direct channel to another device.';
const NO_RTC_IN_CODE_REASON =
  'This code has no connection offer. Ask the other device to show a fresh pairing code and paste the whole thing.';
/** Byte-mode capacity at ECC M; past it the QR encoder refuses and the paste path remains. */
const QR_MAX_CHARS = 2_300;

function hasWebRtc(): boolean {
  return typeof RTCPeerConnection !== 'undefined';
}

const KIND_LABEL: Record<DeviceKind, string> = {
  desktop: 'desktop',
  browser: 'browser',
  cli: 'cli',
  mobile: 'mobile',
};

const CLOCK_MS = 1_000;

function useNow(intervalMs = CLOCK_MS): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

/** `66687aad…5f2925`: enough of both ends to tell two ids apart at a glance. */
export function shortId(id: string): string {
  return id.length <= 14 ? id : `${id.slice(0, 8)}…${id.slice(-6)}`;
}

/** Hex in groups of four, the way two people compare a key fingerprint aloud. */
export function fingerprintGroups(hex: string): string[] {
  return hex.match(/.{1,4}/g) ?? [];
}

export function countdown(deltaMs: number): string {
  const total = Math.max(0, Math.floor(deltaMs / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  if (minutes >= 60) return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
  return `${minutes}m ${seconds.toString().padStart(2, '0')}s`;
}

export function DevicesView() {
  const shell = useShell();
  const state = useDevices();

  return (
    <div className="flex flex-col gap-5 p-5">
      <div className="flex flex-col gap-2">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-[12px] text-faint">
          <button
            type="button"
            onClick={() => shell.navigate({ kind: 'directory' })}
            className="sw-pressable rounded-sw-sm px-1 text-muted"
          >
            Overview
          </button>
          <span aria-hidden>/</span>
          <span className="px-1 text-ink">Devices</span>
        </nav>
        <h1 className="text-[22px] font-semibold tracking-[-0.01em]">Devices</h1>
        <p className="text-[12px] text-faint">
          Every device you pair holds its own keys and is pinned here by its identity and Noise
          static. Unknown devices are refused, never prompted for. Revoking keeps the record so the
          core keeps refusing it.{' '}
          <span className="inline-flex items-center gap-1">
            <Kbd>esc</Kbd> back
          </span>
        </p>
      </div>

      <ThisDeviceSection local={state.localDevice} />
      <PairedDevicesSection list={sortedDevices(state)} />
      <AddDeviceSection local={state.localDevice} />
    </div>
  );
}

function SectionHeader({
  title,
  meta,
  children,
}: {
  title: string;
  meta?: string | undefined;
  children?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-center gap-2 border-b border-edge px-4 py-2.5">
      <h2 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">{title}</h2>
      {meta && <span className="text-[11px] text-faint">{meta}</span>}
      <span className="flex-1" />
      {children}
    </header>
  );
}

function ThisDeviceSection({ local }: { local: LocalDevice | null }) {
  const shell = useShell();
  const { status, busy } = useVaultView(vault);
  const unlocked = status.kind === 'unlocked';

  if (local === null) {
    const absent = status.kind === 'absent' || status.kind === 'corrupt';
    const reason =
      status.kind === 'loading'
        ? 'Loading the core.'
        : status.kind === 'unavailable'
          ? `The core did not load (${status.reason}), so this browser cannot hold an identity.`
          : status.kind === 'locked'
            ? LOCKED_REASON
            : NO_IDENTITY_REASON;
    return (
      <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
        <SectionHeader title="This device" />
        <div className="flex flex-col gap-3 px-4 py-3">
          <p className="text-[12px] text-faint">{reason}</p>
          {(absent || status.kind === 'locked') && (
            <Button
              size="sm"
              variant="primary"
              className="self-start"
              disabled={busy}
              onClick={() => shell.openDialog({ kind: 'vault' })}
            >
              {absent ? 'Create vault' : 'Unlock vault'}
            </Button>
          )}
        </div>
      </section>
    );
  }

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <SectionHeader title="This device" meta={unlocked ? 'vault unlocked' : 'vault locked'}>
        {!unlocked && status.kind === 'locked' && (
          <Button size="sm" variant="ghost" onClick={() => shell.openDialog({ kind: 'vault' })}>
            Unlock
          </Button>
        )}
      </SectionHeader>
      <div className="grid gap-x-6 gap-y-2 px-4 py-3 text-[12px] min-[700px]:grid-cols-[auto_1fr]">
        <span className="text-faint">Name</span>
        <span className="text-ink">{local.name}</span>
        <span className="text-faint">Kind</span>
        <span>
          <Badge>{KIND_LABEL[local.kind]}</Badge>
        </span>
        <span className="text-faint">Device id</span>
        <span className="font-mono text-muted" title={local.id}>
          {shortId(local.id)}
        </span>
        <span className="text-faint">Identity key</span>
        <Fingerprint hex={local.identityPubHex} />
        <span className="text-faint">Noise static</span>
        <Fingerprint hex={local.noiseStaticHex} />
      </div>
      <MyPairingCode unlocked={unlocked} />
    </section>
  );
}

/** One toast per pairing outcome; the toast API is not referentially stable across renders. */
function usePairedToast(peer: Device | null): void {
  const toasts = useToasts();
  const announced = useRef<Device | null>(null);
  useEffect(() => {
    if (peer && announced.current !== peer) {
      announced.current = peer;
      toasts.push(`Paired with ${peer.name}`);
    }
  }, [peer, toasts]);
}

function useCopy(): (text: string, what: string) => Promise<void> {
  const toasts = useToasts();
  return async (text, what) => {
    try {
      await navigator.clipboard.writeText(text);
      toasts.push(`${what} copied`);
    } catch {
      toasts.push('Clipboard unavailable', 'danger');
    }
  };
}

/** A code block plus QR for text one device hands to another. */
function HandoffCode({ text, qrLabel }: { text: string; qrLabel: string }) {
  const tooLong = text.length > QR_MAX_CHARS;
  return (
    <div className="grid gap-4 min-[700px]:grid-cols-[auto_1fr]">
      {tooLong ? (
        <div className="flex w-[min(100%,220px)] items-center justify-center rounded-sw-sm border border-dashed border-edge p-3 text-center text-[11px] text-faint">
          too long for a QR code; copy it instead
        </div>
      ) : (
        <QrCode text={text} className="w-[min(100%,220px)]" />
      )}
      <div className="flex min-w-0 flex-col gap-2">
        <span className="text-[11px] text-faint">{qrLabel}</span>
        <code className="block max-h-32 overflow-auto rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[11px] break-all text-muted select-all">
          {text}
        </code>
      </div>
    </div>
  );
}

/**
 * The code another device pastes to pair with this browser: a signed offer
 * with a one-time secret plus a WebRTC offer, shown as one blob. The other
 * device answers with its own blob, which is pasted back here to open the
 * channel; the core then runs the handshake over it. State lives in the
 * pairing controller so a pane closing mid-handshake does not abandon it.
 */
function MyPairingCode({ unlocked }: { unlocked: boolean }) {
  const toasts = useToasts();
  const copy = useCopy();
  const now = useNow();
  const { issuer } = usePairing(pairing);
  const [answer, setAnswer] = useState('');
  const [answerError, setAnswerError] = useState<string | null>(null);
  usePairedToast(issuer.phase === 'paired' ? issuer.peer : null);

  const canIssue = unlocked && hasWebRtc();
  const issueBlocker = !unlocked ? LOCKED_REASON : !hasWebRtc() ? NO_WEBRTC_REASON : undefined;
  const issue = () => {
    setAnswer('');
    setAnswerError(null);
    void pairing.issue();
  };
  const connect = async () => {
    setAnswerError(null);
    try {
      await pairing.acceptAnswer(answer);
    } catch (err) {
      setAnswerError(err instanceof Error ? err.message : String(err));
    }
  };

  const expired = issuer.phase === 'live' && now >= issuer.offer.expiresAtMs;
  const busy =
    issuer.phase === 'issuing' || issuer.phase === 'connecting' || issuer.phase === 'handshaking';

  return (
    <div className="flex flex-col gap-3 border-t border-edge px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" disabled={!canIssue || busy} title={issueBlocker} onClick={issue}>
          {issuer.phase === 'issuing' ? (
            <LoadingWord label="issuing" />
          ) : issuer.phase === 'idle' ? (
            'Show my pairing code'
          ) : (
            'New pairing code'
          )}
        </Button>
        {(issuer.phase === 'live' || issuer.phase === 'connecting') && (
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => void copy(issuer.text, 'Pairing code')}
            >
              Copy
            </Button>
            <Button size="sm" variant="ghost" onClick={() => pairing.resetIssuer()}>
              Hide
            </Button>
            {expired ? (
              <Badge>expired</Badge>
            ) : (
              <span className="text-[11px] text-faint tabular-nums">
                expires in {countdown(issuer.offer.expiresAtMs - now)}
              </span>
            )}
          </>
        )}
        {issuer.phase === 'connecting' && <LoadingWord label="connecting" />}
        {issuer.phase === 'handshaking' && <LoadingWord label="handshaking" />}
        {issuer.phase === 'paired' && (
          <>
            <Badge tone="ok">paired</Badge>
            <Button size="sm" variant="ghost" onClick={() => pairing.resetIssuer()}>
              Done
            </Button>
          </>
        )}
        {issuer.phase === 'failed' && <Badge tone="danger">failed</Badge>}
      </div>

      {issuer.phase === 'idle' && (
        <span className="text-[11px] text-faint">
          {issueBlocker ??
            'Issues a signed offer with a fresh one-time code and a direct connection offer for another device on this network to paste.'}
        </span>
      )}
      {issuer.phase === 'failed' && <span className="text-[12px] text-danger">{issuer.error}</span>}
      {issuer.phase === 'paired' && (
        <span className="text-[12px] text-muted">
          {issuer.peer.name} verified this device's keys and is now in the table.
        </span>
      )}
      {(issuer.phase === 'live' || issuer.phase === 'connecting') && (
        <>
          <HandoffCode
            text={issuer.text}
            qrLabel="Scan or paste this on the other device. It carries public keys, a one-time secret that only this device can redeem, and a direct connection offer that is only reachable from this network."
          />
          <Field
            label="Answer from the other device"
            htmlFor="pairing-answer"
            hint={
              answerError
                ? undefined
                : 'Once the other device pastes the code above, it shows an answer. Paste it here to open the channel.'
            }
            error={answerError ?? undefined}
          >
            <div className="flex flex-col gap-2">
              <textarea
                id="pairing-answer"
                value={answer}
                onChange={(e) => setAnswer(e.target.value)}
                placeholder={`${RTC_PREFIX}…`}
                rows={3}
                spellCheck={false}
                autoComplete="off"
                disabled={issuer.phase !== 'live' || expired}
                aria-invalid={answerError !== null || undefined}
                className={`w-full resize-y rounded-sw-sm border bg-paper px-3 py-2 font-mono text-[12px] break-all text-ink outline-none placeholder:text-faint focus:border-edge-strong disabled:opacity-60 ${
                  answerError ? 'border-danger/70' : 'border-edge'
                }`}
              />
              <Button
                size="sm"
                variant="primary"
                className="self-start"
                disabled={issuer.phase !== 'live' || expired || answer.trim() === ''}
                title={expired ? 'This code has expired; issue a new one' : undefined}
                onClick={() => void connect()}
              >
                Connect
              </Button>
            </div>
          </Field>
        </>
      )}
      {issuer.phase === 'handshaking' && (
        <span className="text-[12px] text-muted">
          Channel open. The core is verifying the other device's keys and the one-time code.
        </span>
      )}
    </div>
  );
}

function Fingerprint({ hex }: { hex: string }) {
  return (
    <span className="flex flex-wrap gap-x-2 gap-y-0.5 font-mono text-[11px] text-muted" title={hex}>
      {fingerprintGroups(hex).map((g, i) => (
        <span key={i}>{g}</span>
      ))}
    </span>
  );
}

function PairedDevicesSection({ list }: { list: Device[] }) {
  const now = useNow(5_000);
  const [revoking, setRevoking] = useState<Device | null>(null);
  const active = list.filter((d) => d.revokedAtMs === null).length;
  // The table is sealed in the vault; while it is locked the list is a cache.
  const writable = useVaultView(vault).status.kind === 'unlocked';
  const counts = `${active} active · ${list.length - active} revoked`;

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <SectionHeader
        title="Paired devices"
        meta={
          list.length === 0 ? undefined : writable ? counts : `${counts} · read-only while locked`
        }
      />
      {list.length === 0 ? (
        <EmptyState
          title="No paired devices"
          description="Paste a pairing code below to preview a device. Pinning it needs a channel to that device."
        />
      ) : (
        <div className="@container overflow-auto">
          <table className="w-full table-fixed border-collapse text-[12px]">
            <colgroup>
              <col />
              <col className="w-[5.5rem]" />
              <col className="hidden w-[9rem] @min-[700px]:table-column" />
              <col className="hidden w-[11rem] @min-[900px]:table-column" />
              <col className="w-[7.5rem]" />
              <col className="w-[9.5rem]" />
            </colgroup>
            <thead className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
              <tr className="h-9 border-b border-edge">
                <th className="px-4 text-left font-semibold">Name</th>
                <th className="px-3 text-left font-semibold">Kind</th>
                <th className="hidden px-3 text-left font-semibold @min-[700px]:table-cell">Id</th>
                <th className="hidden px-3 text-left font-semibold @min-[900px]:table-cell">
                  Endpoints
                </th>
                <th className="px-3 text-right font-semibold">Seen</th>
                <th className="px-4 text-right font-semibold">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {list.map((d) => (
                <DeviceRow
                  key={d.id}
                  device={d}
                  now={now}
                  writable={writable}
                  onRevoke={() => setRevoking(d)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <RevokeDialog device={revoking} onClose={() => setRevoking(null)} />
    </section>
  );
}

function DeviceRow({
  device,
  now,
  writable,
  onRevoke,
}: {
  device: Device;
  now: number;
  writable: boolean;
  onRevoke: () => void;
}) {
  const toasts = useToasts();
  const [renaming, setRenaming] = useState(false);
  const revoked = device.revokedAtMs !== null;

  const remove = async () => {
    const result = await devices.remove(device.id);
    if (!result.ok) toasts.push(result.error, 'danger');
    else toasts.push(`Removed ${device.name}`);
  };

  const seen =
    device.lastSeenAtMs !== null
      ? `${relativeTime(device.lastSeenAtMs, now)} ago`
      : `paired ${relativeTime(device.pairedAtMs, now)} ago`;

  return (
    <tr className={`h-9 hover:bg-hover ${revoked ? 'text-faint' : ''}`}>
      <td className="w-full max-w-0 px-4">
        {renaming ? (
          <RenameInput
            initial={device.name}
            onDone={async (name) => {
              setRenaming(false);
              if (name === null) return;
              const result = await devices.rename(device.id, name);
              if (!result.ok) toasts.push(result.error, 'danger');
            }}
          />
        ) : (
          <span className="flex min-w-0 items-center gap-2">
            <span className={`min-w-0 truncate ${revoked ? 'line-through' : 'text-ink'}`}>
              {device.name}
            </span>
            {revoked && (
              <Badge tone="danger" className="shrink-0">
                revoked
              </Badge>
            )}
          </span>
        )}
      </td>
      <td className="px-3">
        <Badge>{KIND_LABEL[device.kind]}</Badge>
      </td>
      <td className="hidden px-3 font-mono text-muted @min-[700px]:table-cell" title={device.id}>
        {shortId(device.id)}
      </td>
      <td className="hidden px-3 font-mono text-muted @min-[900px]:table-cell">
        {device.endpoints.length === 0 ? (
          <span className="text-faint">—</span>
        ) : (
          <span className="block truncate" title={device.endpoints.join('\n')}>
            {device.endpoints[0]}
            {device.endpoints.length > 1 && (
              <span className="text-faint"> +{device.endpoints.length - 1}</span>
            )}
          </span>
        )}
      </td>
      <td className="px-3 text-right text-muted whitespace-nowrap tabular-nums" title={seen}>
        {device.revokedAtMs !== null
          ? `revoked ${relativeTime(device.revokedAtMs, now)} ago`
          : seen}
      </td>
      <td className="px-4 text-right whitespace-nowrap">
        {revoked ? (
          <Button
            size="sm"
            variant="ghost"
            aria-label={`Remove ${device.name}`}
            onClick={() => void remove()}
            disabled={!writable}
            title={writable ? undefined : DEVICES_READ_ONLY}
          >
            remove
          </Button>
        ) : (
          <>
            <Button
              size="sm"
              variant="ghost"
              aria-label={`Rename ${device.name}`}
              onClick={() => setRenaming(true)}
              disabled={renaming || !writable}
              title={writable ? undefined : DEVICES_READ_ONLY}
            >
              rename
            </Button>
            <Button
              size="sm"
              variant="ghost"
              aria-label={`Revoke ${device.name}`}
              onClick={onRevoke}
              disabled={!writable}
              title={writable ? undefined : DEVICES_READ_ONLY}
            >
              revoke
            </Button>
          </>
        )}
      </td>
    </tr>
  );
}

function RenameInput({
  initial,
  onDone,
}: {
  initial: string;
  onDone: (name: string | null) => void;
}) {
  const [value, setValue] = useState(initial);
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      onDone(value);
    } else if (e.key === 'Escape') {
      // Keep the shell's Escape (which would leave this view) from firing too.
      e.preventDefault();
      e.stopPropagation();
      onDone(null);
    }
  };
  return (
    <Input
      dense
      autoFocus
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onKeyDown={onKeyDown}
      onBlur={() => onDone(value)}
      aria-label="Device name"
      maxLength={64}
      spellCheck={false}
    />
  );
}

function RevokeDialog({ device, onClose }: { device: Device | null; onClose: () => void }) {
  const toasts = useToasts();
  const [error, setError] = useState<string | null>(null);

  const confirm = async () => {
    if (!device) return;
    const result = await devices.revoke(device.id);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toasts.push(`Revoked ${device.name}`);
    setError(null);
    onClose();
  };
  const close = () => {
    setError(null);
    onClose();
  };

  return (
    <Dialog open={device !== null} onClose={close} title="Revoke device">
      <div className="flex flex-col gap-4 p-4">
        <p className="text-muted">
          Revoke <span className="text-ink">{device?.name}</span>? Its keys stay listed so every
          later connection from them is refused. Shares it holds are not destroyed; re-share the
          affected wallets from the remaining devices.
        </p>
        {error && (
          <div role="alert" className="text-[12px] text-danger">
            {error}
          </div>
        )}
        <div className="flex justify-end gap-2 border-t border-edge pt-3">
          <Button variant="ghost" onClick={close} autoFocus>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => void confirm()}>
            Revoke device
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

type Preview =
  | { kind: 'empty' }
  | { kind: 'error'; message: string }
  | { kind: 'offer'; offer: PairingOffer; text: string };

function previewOf(text: string): Preview {
  if (text.trim() === '') return { kind: 'empty' };
  try {
    return { kind: 'offer', offer: decodePairingOffer(text), text: text.trim() };
  } catch (err) {
    if (err instanceof PairingOfferError) {
      const message: Record<typeof err.code, string> = {
        prefix: `Not a pairing code: it should start with ${PAIRING_OFFER_PREFIX}`,
        base64: 'Not a pairing code: the part after the prefix is not base64url',
        json: 'Not a pairing code: the payload is not JSON',
        version:
          'This code comes from a newer or older StackWallet; both devices need the same version',
        shape: `Pairing code is malformed (${err.message})`,
        deviceId: 'Device id does not match the identity key',
      };
      return { kind: 'error', message: message[err.code] };
    }
    return { kind: 'error', message: 'Could not read this pairing code' };
  }
}

function AddDeviceSection({ local }: { local: LocalDevice | null }) {
  const [text, setText] = useState('');
  const parts = useMemo(() => splitPairingText(text), [text]);
  const preview = useMemo(
    () => previewOf(text.trim() === '' ? '' : (parts.pair ?? text)),
    [text, parts],
  );
  const { scanner } = usePairing(pairing);

  if (scanner.phase !== 'idle') {
    return (
      <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
        <SectionHeader title="Add a device" meta={scannerMeta(scanner)} />
        <ScannerProgress
          state={scanner}
          onDone={() => {
            pairing.resetScanner();
            setText('');
          }}
        />
      </section>
    );
  }

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <SectionHeader title="Add a device" meta="paste the code the other device shows" />
      <div className="grid gap-4 px-4 py-3 min-[900px]:grid-cols-2">
        <Field
          label="Pairing code"
          htmlFor="pairing-code"
          hint={
            preview.kind === 'error'
              ? undefined
              : 'The code is safe to paste: it carries public keys and a one-time secret that only this device can use.'
          }
          error={preview.kind === 'error' ? preview.message : undefined}
        >
          <textarea
            id="pairing-code"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={`${PAIRING_OFFER_PREFIX}…`}
            rows={6}
            spellCheck={false}
            autoComplete="off"
            aria-invalid={preview.kind === 'error' || undefined}
            className={`w-full resize-y rounded-sw-sm border bg-paper px-3 py-2 font-mono text-[12px] break-all text-ink outline-none placeholder:text-faint focus:border-edge-strong ${
              preview.kind === 'error' ? 'border-danger/70' : 'border-edge'
            }`}
          />
        </Field>
        {preview.kind === 'offer' ? (
          <OfferPreview offer={preview.offer} text={preview.text} rtc={parts.rtc} local={local} />
        ) : (
          <div className="flex min-h-[8rem] items-center justify-center rounded-sw-sm border border-dashed border-edge px-4 text-center text-[12px] text-faint">
            {preview.kind === 'empty'
              ? 'A preview of the device appears here once a valid code is pasted.'
              : 'Fix the code to see the device it describes.'}
          </div>
        )}
      </div>
    </section>
  );
}

function scannerMeta(state: ScannerState): string {
  switch (state.phase) {
    case 'answering':
      return `answering ${state.offer.deviceName}`;
    case 'waiting':
      return `waiting for ${state.offer.deviceName}`;
    case 'handshaking':
      return `handshaking with ${state.offer.deviceName}`;
    case 'paired':
      return `paired with ${state.peer.name}`;
    case 'failed':
      return 'failed';
    default:
      return '';
  }
}

/** The scanner's side after "Pin device": answer out, channel up, core handshake, pinned. */
function ScannerProgress({ state, onDone }: { state: ScannerState; onDone: () => void }) {
  const copy = useCopy();
  usePairedToast(state.phase === 'paired' ? state.peer : null);

  return (
    <div className="flex flex-col gap-3 px-4 py-3">
      {state.phase === 'answering' && <LoadingWord label="building the answer" />}
      {state.phase === 'waiting' && (
        <>
          <HandoffCode
            text={state.answerText}
            qrLabel={`Paste this answer on ${state.offer.deviceName}, under its pairing code. The channel opens as soon as it does.`}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="primary"
              onClick={() => void copy(state.answerText, 'Answer')}
            >
              Copy answer
            </Button>
            <LoadingWord label="waiting for the channel" />
            <span className="flex-1" />
            <Button size="sm" variant="ghost" onClick={onDone}>
              Cancel
            </Button>
          </div>
        </>
      )}
      {state.phase === 'handshaking' && (
        <div className="flex flex-wrap items-center gap-2">
          <LoadingWord label="handshaking" />
          <span className="text-[12px] text-muted">
            Channel open. The core is verifying {state.offer.deviceName}'s keys and redeeming the
            one-time code.
          </span>
        </div>
      )}
      {state.phase === 'paired' && (
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="ok">paired</Badge>
          <span className="text-[12px] text-muted">
            {state.peer.name} is pinned by the keys the core verified during the handshake.
          </span>
          <span className="flex-1" />
          <Button size="sm" variant="primary" onClick={onDone}>
            Done
          </Button>
        </div>
      )}
      {state.phase === 'failed' && (
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="danger">failed</Badge>
          <span className="text-[12px] text-danger">{state.error}</span>
          <span className="flex-1" />
          <Button size="sm" variant="ghost" onClick={onDone}>
            Try again
          </Button>
        </div>
      )}
    </div>
  );
}

function OfferPreview({
  offer,
  text,
  rtc,
  local,
}: {
  offer: PairingOffer;
  text: string;
  rtc: string | undefined;
  local: LocalDevice | null;
}) {
  const now = useNow();
  const expired = isPairingOfferExpired(offer, now);
  const unlocked = useVaultView(vault).status.kind === 'unlocked';
  const [idMatches, setIdMatches] = useState<boolean | null>(null);
  const [showQr, setShowQr] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setIdMatches(null);
    pairingOfferIdMatches(offer)
      .then((ok) => {
        if (!cancelled) setIdMatches(ok);
      })
      .catch(() => {
        if (!cancelled) setIdMatches(false);
      });
    return () => {
      cancelled = true;
    };
  }, [offer]);

  const isSelf = local !== null && local.id === offer.deviceId;
  const alreadyPinned = useDevices().devices.some((d) => d.id === offer.deviceId);
  const blocker: string | null = isSelf
    ? 'This code was issued by this device'
    : alreadyPinned
      ? 'This device is already in the table'
      : idMatches === false
        ? 'Device id does not match the identity key; refuse this code'
        : idMatches === null
          ? 'Checking the device id against the identity key'
          : expired
            ? 'This code has expired; ask for a fresh one'
            : local === null
              ? NO_IDENTITY_REASON
              : !unlocked
                ? LOCKED_REASON
                : !hasWebRtc()
                  ? NO_WEBRTC_REASON
                  : rtc === undefined
                    ? NO_RTC_IN_CODE_REASON
                    : null;

  return (
    <div className="flex min-w-0 flex-col gap-3 rounded-sw-sm border border-edge p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 truncate text-ink">{offer.deviceName}</span>
        <Badge>{KIND_LABEL[offer.kind]}</Badge>
        {idMatches === false && <Badge tone="danger">id mismatch</Badge>}
        {expired ? (
          <Badge>expired</Badge>
        ) : (
          <span className="text-[11px] text-faint tabular-nums">
            expires in {countdown(offer.expiresAtMs - now)}
          </span>
        )}
        <span className="flex-1" />
        <Button size="sm" variant="ghost" onClick={() => setShowQr((v) => !v)}>
          {showQr ? 'hide QR' : 'show QR'}
        </Button>
      </div>
      <dl className="grid gap-x-4 gap-y-1.5 text-[12px] min-[560px]:grid-cols-[auto_1fr]">
        <dt className="text-faint">Device id</dt>
        <dd className="font-mono text-muted" title={offer.deviceId}>
          {shortId(offer.deviceId)}
        </dd>
        <dt className="text-faint">Identity key</dt>
        <dd>
          <Fingerprint hex={offer.identityPubHex} />
        </dd>
        <dt className="text-faint">Noise static</dt>
        <dd>
          <Fingerprint hex={offer.noiseStaticHex} />
        </dd>
        <dt className="text-faint">Endpoints</dt>
        <dd className="font-mono text-muted">
          {offer.endpoints.length === 0 ? (
            <span className="text-faint">none advertised</span>
          ) : (
            <ul className="flex flex-col">
              {offer.endpoints.map((e) => (
                <li key={e} className="truncate" title={e}>
                  {e}
                </li>
              ))}
            </ul>
          )}
        </dd>
      </dl>
      {showQr && !expired && (
        <div className="flex justify-center">
          <QrCode text={text} className="w-[min(100%,260px)]" />
        </div>
      )}
      <div className="flex flex-col gap-1 border-t border-edge pt-3">
        <Button
          size="sm"
          variant={blocker === null ? 'primary' : 'default'}
          disabled={blocker !== null}
          className="self-start"
          title={blocker ?? undefined}
          onClick={() => {
            if (rtc !== undefined) void pairing.connect(offer, rtc);
          }}
        >
          Pin device
        </Button>
        <span className="text-[11px] text-faint">
          {blocker ??
            'Opens a direct channel to this device and runs the pairing handshake in the core; it is pinned only if its keys and the one-time code check out.'}
        </span>
      </div>
    </div>
  );
}
