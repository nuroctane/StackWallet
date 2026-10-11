import { useId, useState, type FormEvent } from 'react';
import { Button, Dialog, Field, Input, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { activeDevices, useDevices } from '../store/devices.js';
import { directory, useDirectory } from '../store/persist.js';
import { exportPayload, subtree } from '../store/sets.js';

const MAX_BUNDLE_FILE_BYTES = 8 * 1024 * 1024;

function NeedsUnlock() {
  return (
    <p className="p-4 text-[12px] text-faint">
      Unlock the vault first: moving a set needs the vault open and its passphrase again.
    </p>
  );
}

/**
 * Seal a folder and everything under it for one paired device. The core asks
 * for the passphrase again, records the transfer (wallets become `copied`)
 * and only then hands back the bundle.
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
    <Dialog open={open} onClose={onClose} title="Transfer set" meta="to a paired device">
      {!folderId ? null : view.status.kind !== 'unlocked' ? (
        <NeedsUnlock />
      ) : (
        <TransferForm folderId={folderId} onClose={onClose} />
      )}
    </Dialog>
  );
}

function TransferForm({ folderId, onClose }: { folderId: string; onClose: () => void }) {
  const state = useDirectory();
  const devicesState = useDevices();
  const view = useVaultView(vault);
  const toasts = useToasts();
  const ids = { device: useId(), pass: useId() };
  const peers = activeDevices(devicesState).filter((d) => d.id !== devicesState.localDevice?.id);
  const [deviceId, setDeviceId] = useState(peers[0]?.id ?? '');
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [bundle, setBundle] = useState<string | null>(null);

  const folder = state.folders.find((f) => f.id === folderId);
  const ids2 = new Set(subtree(state, folderId));
  const wallets = state.wallets.filter((w) => ids2.has(w.folderId));
  const keyed = wallets.filter((w) => w.kind === 'single').length;

  if (!folder) return <p className="p-4 text-[12px] text-faint">Folder not found.</p>;
  if (peers.length === 0) {
    return (
      <p className="p-4 text-[12px] text-faint">
        No paired devices. Pair the receiving device in the devices element first; a set can only be
        opened by a device this vault has pinned.
      </p>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const out = exportPayload(state, folderId);
    if ('error' in out) {
      setError(out.error);
      return;
    }
    const r = await vault.exportSet({
      passphrase,
      toDeviceId: deviceId,
      folderId,
      walletIds: out.walletIds,
      directory: out.payload,
    });
    setPassphrase('');
    if (!r.ok) {
      setError(r.error);
      return;
    }
    setBundle(r.value);
  };

  if (bundle) {
    const peer = peers.find((p) => p.id === deviceId);
    const download = () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([bundle], { type: 'text/plain' }));
      a.download = `${folder.name.replace(/[^\w.-]+/g, '_')}.stackwallet-set`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    };
    return (
      <div className="flex flex-col gap-3 p-4 text-[12px]">
        <p className="text-muted">
          Sealed for <span className="text-ink">{peer?.name}</span>. Only that device can open it,
          and only with its own vault passphrase. Every wallet in this set is now tagged{' '}
          <span className="text-accent-3">copied</span>.
        </p>
        <textarea
          readOnly
          value={bundle}
          aria-label="set bundle"
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

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <p className="text-[12px] text-faint">
        <span className="text-ink">{folder.name}</span>, its subfolders, {wallets.length} wallet
        {wallets.length === 1 ? '' : 's'}
        {keyed > 0 ? ` and the keys of ${keyed}` : ''}. The receiving device tags everything{' '}
        <span className="text-accent-3">imported</span>; this device tags it{' '}
        <span className="text-accent-3">copied</span>. Exposure tags travel with the wallets.
      </p>
      <Field label="Send to" htmlFor={ids.device}>
        <Select id={ids.device} value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          {peers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} · {p.kind} · {p.id.slice(0, 8)}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Vault passphrase" htmlFor={ids.pass} hint="asked again for every transfer">
        <Input
          id={ids.pass}
          type="password"
          autoComplete="current-password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
      </Field>
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!deviceId || !passphrase || view.busy}>
          {view.busy ? <LoadingWord label="sealing" /> : 'Seal set'}
        </Button>
      </div>
    </form>
  );
}

/** Open a bundle sealed for this device and merge its set under the root. */
export function ImportSetDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const view = useVaultView(vault);
  return (
    <Dialog open={open} onClose={onClose} title="Import set" meta="from a paired device">
      {view.status.kind !== 'unlocked' ? <NeedsUnlock /> : <ImportForm onClose={onClose} />}
    </Dialog>
  );
}

function ImportForm({ onClose }: { onClose: () => void }) {
  const view = useVaultView(vault);
  const toasts = useToasts();
  const ids = { bundle: useId(), pass: useId(), file: useId() };
  const [text, setText] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const r = await vault.importSet(passphrase, text);
    setPassphrase('');
    if (!r.ok) {
      setError(r.error);
      return;
    }
    const merged = directory.importSet(r.value.directory, r.value.folderId);
    if (!merged.ok) {
      // The keys are sealed and tagged already; the directory refused the layout.
      setError(`Keys imported, but the directory refused the set: ${merged.error}`);
      return;
    }
    toasts.push(`Imported a set from ${r.value.fromDeviceName}`);
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
            setError('That file is too large to be a set bundle');
            return;
          }
          void f.text().then(setText);
        }}
      />
      <Field label="Vault passphrase" htmlFor={ids.pass} hint="this device's passphrase">
        <Input
          id={ids.pass}
          type="password"
          autoComplete="current-password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
      </Field>
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!text.trim() || !passphrase || view.busy}>
          {view.busy ? <LoadingWord label="opening" /> : 'Import'}
        </Button>
      </div>
    </form>
  );
}
