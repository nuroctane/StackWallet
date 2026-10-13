import { useId, useState, type FormEvent, type ReactNode } from 'react';
import type { ImportedSet } from '@stackwallet/core-client';
import { Button, Dialog, Field, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView, type SessionChoice } from '../core/vault.js';
import { activeDevices, useDevices } from '../store/devices.js';
import { remapProps } from '../store/layoutBundle.js';
import { directory, useDirectory } from '../store/persist.js';
import {
  exportPayload,
  exportWalletPayload,
  importPayload,
  importWalletPayload,
  payloadLayouts,
  subtree,
} from '../store/sets.js';
import { defaultContext } from '../store/store.js';
import { associatedLayouts } from '../workspace/layoutTransfer.js';
import { workspace } from '../workspace/persist.js';
import { ExportKeyManager, SessionField, sessionReady, useExportGate } from './ExportGateFields.js';

const MAX_BUNDLE_FILE_BYTES = 8 * 1024 * 1024;

function NeedsUnlock() {
  return (
    <p className="p-4 text-[12px] text-faint">
      Unlock the vault first: moving keys needs the vault open and a fresh sign-in.
    </p>
  );
}

/** Pick the paired device, or explain why there is none. */
function usePeers() {
  const devicesState = useDevices();
  return activeDevices(devicesState).filter((d) => d.id !== devicesState.localDevice?.id);
}

function NoPeers({ what }: { what: string }) {
  return (
    <p className="p-4 text-[12px] text-faint">
      No paired devices. Pair the receiving device in the devices element first; {what} can only be
      opened by a device this vault has pinned.
    </p>
  );
}

/** The sealed bundle, with copy and save. */
function BundleOut({
  bundle,
  fileName,
  children,
  onClose,
}: {
  bundle: string;
  fileName: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const toasts = useToasts();
  const download = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([bundle], { type: 'text/plain' }));
    a.download = `${fileName.replace(/[^\w.-]+/g, '_')}.stackwallet-set`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  return (
    <div className="flex flex-col gap-3 p-4 text-[12px]">
      <p className="text-muted">{children}</p>
      <textarea
        readOnly
        value={bundle}
        aria-label="bundle"
        className="h-24 resize-none rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[10px] break-all text-muted"
        onFocus={(e) => e.target.select()}
      />
      <div className="flex justify-end gap-2">
        <Button
          size="sm"
          onClick={() =>
            void navigator.clipboard
              .writeText(bundle)
              .then(() => toasts.push('Bundle copied'))
              .catch(() => toasts.push('Clipboard unavailable', 'danger'))
          }
        >
          Copy
        </Button>
        <Button size="sm" onClick={download}>
          Save file
        </Button>
        <Button size="sm" variant="primary" onClick={onClose}>
          Done
        </Button>
      </div>
    </div>
  );
}

/**
 * Export a directory: the folder, everything under it, the keys of its
 * single wallets and every layout that shows them, sealed for one paired
 * device. The gate is a fresh sign-in plus the directory's key; every wallet
 * inside is tagged `exported` and the directory `exported set`.
 */
export function TransferSetDialog({
  open,
  folderId,
  onClose,
}: {
  open: boolean;
  folderId?: string | undefined;
  onClose: () => void;
}) {
  const view = useVaultView(vault);
  return (
    <Dialog open={open} onClose={onClose} title="Export directory" meta="to a paired device">
      {!folderId ? null : view.status.kind !== 'unlocked' ? (
        <NeedsUnlock />
      ) : (
        <TransferSetForm folderId={folderId} onClose={onClose} />
      )}
    </Dialog>
  );
}

function TransferSetForm({ folderId, onClose }: { folderId: string; onClose: () => void }) {
  const state = useDirectory();
  const view = useVaultView(vault);
  const peers = usePeers();
  const deviceField = useId();
  const [deviceId, setDeviceId] = useState(peers[0]?.id ?? '');
  const [error, setError] = useState<string | null>(null);
  const [bundle, setBundle] = useState<string | null>(null);
  const folder = state.folders.find((f) => f.id === folderId);
  const gate = useExportGate({ folderId, folderName: folder?.name ?? 'this directory' });

  const ids = new Set(subtree(state, folderId));
  const wallets = state.wallets.filter((w) => ids.has(w.folderId));
  const keyed = wallets.filter((w) => w.kind === 'single').length;
  const layouts = associatedLayouts(workspace, directory, folderId);

  if (!folder) return <p className="p-4 text-[12px] text-faint">Folder not found.</p>;
  if (peers.length === 0) return <NoPeers what="a directory" />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const out = exportPayload(state, folderId, layouts);
    if ('error' in out) {
      setError(out.error);
      return;
    }
    let input;
    try {
      input = await gate.build();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const r = await vault.exportBundle({
      gate: input,
      scope: 'set',
      toDeviceId: deviceId,
      walletIds: out.walletIds,
      directory: out.payload,
    });
    gate.reset();
    if (!r.ok) {
      setError(r.error);
      return;
    }
    setBundle(r.value);
  };

  if (bundle) {
    const peer = peers.find((p) => p.id === deviceId);
    return (
      <BundleOut bundle={bundle} fileName={folder.name} onClose={onClose}>
        Sealed for <span className="text-ink">{peer?.name}</span>. Only that device can open it,
        after its own fresh sign-in. Every wallet in this directory is now tagged{' '}
        <span className="text-accent-3">exported</span>.
      </BundleOut>
    );
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <p className="text-[12px] text-faint">
        <span className="text-ink">{folder.name}</span>, its subfolders, {wallets.length} wallet
        {wallets.length === 1 ? '' : 's'}
        {keyed > 0 ? ` and the keys of ${keyed}` : ''}, and {layouts.length} layout
        {layouts.length === 1 ? '' : 's'} that show them. The receiving device tags everything{' '}
        <span className="text-accent-3">imported</span>; this device tags every wallet in it{' '}
        <span className="text-accent-3">exported</span>. Exposure tags travel with the wallets.
      </p>
      <Field label="Send to" htmlFor={deviceField}>
        <Select id={deviceField} value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          {peers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} · {p.kind} · {p.id.slice(0, 8)}
            </option>
          ))}
        </Select>
      </Field>
      {gate.fields}
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!deviceId || !gate.ready || view.busy}>
          {view.busy ? <LoadingWord label="sealing" /> : 'Seal directory'}
        </Button>
      </div>
    </form>
  );
}

/**
 * Export one wallet on its own, wherever it sits. The gate is a fresh
 * sign-in, the key of the directory it is in and its own wallet key. Only
 * this wallet is tagged; the folder and its other wallets are untouched.
 */
export function TransferWalletDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  const view = useVaultView(vault);
  return (
    <Dialog open={open} onClose={onClose} title="Export wallet" meta="to a paired device">
      {!walletId ? null : view.status.kind !== 'unlocked' ? (
        <NeedsUnlock />
      ) : (
        <TransferWalletForm walletId={walletId} onClose={onClose} />
      )}
    </Dialog>
  );
}

function TransferWalletForm({ walletId, onClose }: { walletId: string; onClose: () => void }) {
  const state = useDirectory();
  const view = useVaultView(vault);
  const peers = usePeers();
  const deviceField = useId();
  const [deviceId, setDeviceId] = useState(peers[0]?.id ?? '');
  const [error, setError] = useState<string | null>(null);
  const [bundle, setBundle] = useState<string | null>(null);
  const wallet = state.wallets.find((w) => w.id === walletId);
  const folder = state.folders.find((f) => f.id === wallet?.folderId);
  const gate = useExportGate({
    folderId: wallet?.folderId ?? '',
    folderName: folder?.name ?? 'its directory',
    walletId,
    walletName: wallet?.name ?? 'this wallet',
  });

  if (!wallet) return <p className="p-4 text-[12px] text-faint">Wallet not found.</p>;
  if (peers.length === 0) return <NoPeers what="a wallet" />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const out = exportWalletPayload(state, walletId);
    if ('error' in out) {
      setError(out.error);
      return;
    }
    let input;
    try {
      input = await gate.build();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const r = await vault.exportBundle({
      gate: input,
      scope: 'wallet',
      toDeviceId: deviceId,
      walletIds: [walletId],
      directory: out.payload,
    });
    gate.reset();
    if (!r.ok) {
      setError(r.error);
      return;
    }
    setBundle(r.value);
  };

  if (bundle) {
    const peer = peers.find((p) => p.id === deviceId);
    return (
      <BundleOut bundle={bundle} fileName={wallet.name} onClose={onClose}>
        Sealed for <span className="text-ink">{peer?.name}</span>.{' '}
        <span className="text-ink">{wallet.name}</span> is now tagged{' '}
        <span className="text-accent-3">exported</span>; the other wallets in{' '}
        {folder?.name ?? 'its directory'} are unchanged.
      </BundleOut>
    );
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <p className="text-[12px] text-faint">
        <span className="text-ink">{wallet.name}</span>
        {wallet.kind === 'single' ? ' and its key' : ''}, sealed for one paired device. Only this
        wallet is tagged <span className="text-accent-3">exported</span>; nothing else in{' '}
        {folder?.name ?? 'its directory'} changes. Its exposure history travels with it.
      </p>
      <Field label="Send to" htmlFor={deviceField}>
        <Select id={deviceField} value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          {peers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} · {p.kind} · {p.id.slice(0, 8)}
            </option>
          ))}
        </Select>
      </Field>
      {gate.fields}
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!deviceId || !gate.ready || view.busy}>
          {view.busy ? <LoadingWord label="sealing" /> : 'Seal wallet'}
        </Button>
      </div>
    </form>
  );
}

/** Set or change the export key of one directory or wallet. */
export function ExportKeyDialog({
  open,
  target,
  onClose,
}: {
  open: boolean;
  target?: { scope: 'folder' | 'wallet'; id: string } | undefined;
  onClose: () => void;
}) {
  const state = useDirectory();
  const name =
    target?.scope === 'folder'
      ? state.folders.find((f) => f.id === target.id)?.name
      : state.wallets.find((w) => w.id === target?.id)?.name;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={target?.scope === 'folder' ? 'Directory key' : 'Wallet key'}
      meta="needed for every export"
    >
      {target && name !== undefined && (
        <ExportKeyManager scope={target.scope} id={target.id} name={name} onDone={onClose} />
      )}
    </Dialog>
  );
}

/** Open a bundle sealed for this device: a whole directory or one wallet. */
export function ImportSetDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const view = useVaultView(vault);
  return (
    <Dialog open={open} onClose={onClose} title="Import" meta="from a paired device">
      {view.status.kind !== 'unlocked' ? <NeedsUnlock /> : <ImportForm onClose={onClose} />}
    </Dialog>
  );
}

function checkArrival(set: ImportedSet): void {
  const state = directory.getSnapshot();
  const checked =
    set.scope === 'wallet'
      ? importWalletPayload(state, set.directory, defaultContext)
      : importPayload(state, set.directory, set.folderId, defaultContext);
  if (!checked.ok) throw new Error(checked.error);
}

function ImportForm({ onClose }: { onClose: () => void }) {
  const view = useVaultView(vault);
  const toasts = useToasts();
  const ids = { bundle: useId(), file: useId() };
  const [text, setText] = useState('');
  const [session, setSession] = useState<SessionChoice>({ kind: 'passphrase', passphrase: '' });
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    let proof;
    try {
      proof = await vault.proveSession(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const r = await vault.importSet(proof, text, checkArrival);
    if (session.kind === 'passphrase') setSession({ kind: 'passphrase', passphrase: '' });
    if (!r.ok) {
      setError(r.error);
      return;
    }
    const got = r.value;
    const merged =
      got.scope === 'wallet'
        ? directory.importWallet(got.directory)
        : directory.importSet(got.directory, got.folderId);
    if (!merged.ok) {
      // The keys are sealed and tagged already; the directory refused the layout.
      setError(`Keys imported, but the directory refused it: ${merged.error}`);
      return;
    }
    // Watch-only stand-ins for the same addresses give way to the keyed wallets.
    const after = directory.getSnapshot();
    const inSet = new Set(got.scope === 'set' ? subtree(after, got.folderId) : []);
    const keyedIds =
      got.scope === 'wallet'
        ? [merged.value]
        : after.wallets.filter((w) => inSet.has(w.folderId)).map((w) => w.id);
    const remap = directory.absorbWatchDuplicates(keyedIds);
    workspace.replaceWalletRefs(remap);
    let layouts = 0;
    if (got.scope === 'set') {
      const state = directory.getSnapshot();
      const known = new Map<string, string>();
      for (const w of state.wallets) known.set(`w:${w.id}`, w.id);
      for (const f of state.folders) known.set(`f:${f.id}`, f.id);
      for (const l of payloadLayouts(got.directory)) {
        const added = workspace.importLayout({
          ...l,
          panes: l.panes.map((p) => ({ ...p, props: remapProps(p.props, known) })),
        });
        if (added.ok) layouts += 1;
      }
    }
    toasts.push(
      `Imported ${got.scope === 'wallet' ? 'a wallet' : 'a directory'} from ${got.fromDeviceName}${
        layouts > 0 ? ` with ${layouts} layout${layouts === 1 ? '' : 's'}` : ''
      }${remap.size > 0 ? `; ${remap.size} watch-only wallet${remap.size === 1 ? '' : 's'} now hold keys` : ''}`,
    );
    onClose();
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <Field label="Bundle" htmlFor={ids.bundle} hint="paste it, or pick the .stackwallet-set file">
        <textarea
          id={ids.bundle}
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          className="h-24 resize-none rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[10px] break-all text-ink outline-none focus:border-edge-strong"
          placeholder="stackwallet-set:…"
        />
      </Field>
      <input
        id={ids.file}
        type="file"
        accept=".stackwallet-set,text/plain"
        className="text-[11px] text-faint"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          if (f.size > MAX_BUNDLE_FILE_BYTES) {
            setError('That file is too large to be a bundle');
            return;
          }
          void f.text().then(setText);
        }}
      />
      <SessionField value={session} onChange={setSession} hint="this device's own sign-in" />
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant="primary"
          disabled={!text.trim() || !sessionReady(session) || view.busy}
        >
          {view.busy ? <LoadingWord label="opening" /> : 'Import'}
        </Button>
      </div>
    </form>
  );
}
