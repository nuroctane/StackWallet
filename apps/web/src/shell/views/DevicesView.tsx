import { useEffect, useMemo, useState, type KeyboardEvent, type ReactNode } from 'react';
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
import { Badge, Button, Dialog, EmptyState, Field, Input, Kbd, useToasts } from '@stackwallet/ui';

import { relativeTime } from '../../lib/format.js';
import { devices, sortedDevices, useDevices, type LocalDevice } from '../../store/devices.js';
import { useShell } from '../ShellContext.js';
import { QrCode } from './QrCode.js';

/**
 * Identity generation and the Noise handshake both run in the wasm core, which
 * this build does not load yet. Every control that would need it says so with
 * the same words rather than pretending to work.
 */
const BRIDGE_REASON =
  'This browser has no device identity yet. Pairing becomes available once the core bridge is loaded.';

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
  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <SectionHeader title="This device" />
      {local === null ? (
        <div className="flex flex-col gap-3 px-4 py-3">
          <p className="text-[12px] text-faint">{BRIDGE_REASON}</p>
          <div className="flex flex-col gap-1">
            <Button size="sm" disabled className="self-start" title={BRIDGE_REASON}>
              Show my pairing code
            </Button>
            <span className="text-[11px] text-faint">
              Needs an identity to sign the offer; nothing to show yet.
            </span>
          </div>
        </div>
      ) : (
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
      )}
    </section>
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

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <SectionHeader
        title="Paired devices"
        meta={list.length === 0 ? undefined : `${active} active · ${list.length - active} revoked`}
      />
      {list.length === 0 ? (
        <EmptyState
          title="No paired devices"
          description="Paste a pairing code below to preview a device. Pinning it needs the core bridge."
        />
      ) : (
        <div className="overflow-auto">
          <table className="w-full table-fixed border-collapse text-[12px]">
            <colgroup>
              <col />
              <col className="w-[5.5rem]" />
              <col className="hidden w-[9rem] min-[700px]:table-column" />
              <col className="hidden w-[11rem] min-[900px]:table-column" />
              <col className="w-[7.5rem]" />
              <col className="w-[9.5rem]" />
            </colgroup>
            <thead className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
              <tr className="h-9 border-b border-edge">
                <th className="px-4 text-left font-semibold">Name</th>
                <th className="px-3 text-left font-semibold">Kind</th>
                <th className="hidden px-3 text-left font-semibold min-[700px]:table-cell">Id</th>
                <th className="hidden px-3 text-left font-semibold min-[900px]:table-cell">
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
                <DeviceRow key={d.id} device={d} now={now} onRevoke={() => setRevoking(d)} />
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
  onRevoke,
}: {
  device: Device;
  now: number;
  onRevoke: () => void;
}) {
  const toasts = useToasts();
  const [renaming, setRenaming] = useState(false);
  const revoked = device.revokedAtMs !== null;

  const remove = () => {
    const result = devices.remove(device.id);
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
            onDone={(name) => {
              setRenaming(false);
              if (name === null) return;
              const result = devices.rename(device.id, name);
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
      <td className="hidden px-3 font-mono text-muted min-[700px]:table-cell" title={device.id}>
        {shortId(device.id)}
      </td>
      <td className="hidden px-3 font-mono text-muted min-[900px]:table-cell">
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
          <Button size="sm" variant="ghost" aria-label={`Remove ${device.name}`} onClick={remove}>
            remove
          </Button>
        ) : (
          <>
            <Button
              size="sm"
              variant="ghost"
              aria-label={`Rename ${device.name}`}
              onClick={() => setRenaming(true)}
              disabled={renaming}
            >
              rename
            </Button>
            <Button
              size="sm"
              variant="ghost"
              aria-label={`Revoke ${device.name}`}
              onClick={onRevoke}
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

  const confirm = () => {
    if (!device) return;
    const result = devices.revoke(device.id);
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
          <Button variant="danger" onClick={confirm}>
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
  const preview = useMemo(() => previewOf(text), [text]);

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
          <OfferPreview offer={preview.offer} text={preview.text} local={local} />
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

function OfferPreview({
  offer,
  text,
  local,
}: {
  offer: PairingOffer;
  text: string;
  local: LocalDevice | null;
}) {
  const now = useNow();
  const expired = isPairingOfferExpired(offer, now);
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
  const blocker = isSelf
    ? 'This code was issued by this device'
    : alreadyPinned
      ? 'This device is already in the table'
      : idMatches === false
        ? 'Device id does not match the identity key; refuse this code'
        : expired
          ? 'This code has expired; ask for a fresh one'
          : local === null
            ? BRIDGE_REASON
            : 'Pinning runs the pairing handshake in the core bridge, which this build has not loaded';

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
        <Button size="sm" disabled className="self-start" title={blocker}>
          Pin device
        </Button>
        <span className="text-[11px] text-faint">{blocker}</span>
      </div>
    </div>
  );
}
