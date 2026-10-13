import { useId, useState, type FormEvent } from 'react';
import { Button, Dialog, Field, Input, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView, type SessionChoice } from '../core/vault.js';
import { LedgerEth } from '../hardware/ledger.js';
import { EVM_SIGNING_CHAINS, listChains } from '../lib/chains.js';
import { directory, useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { SessionField, sessionReady } from './ExportGateFields.js';

/**
 * Add a Ledger as a wallet. The key never leaves the device: StackWallet
 * reads the address for one path, the user checks it on the device's own
 * screen, and the core registers that address so it can later refuse any
 * signature that does not recover to it.
 */
export function HardwareWalletDialog({
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
    <Dialog open={open} onClose={onClose} title="Connect Ledger" meta="Ethereum app · WebHID">
      {view.status.kind !== 'unlocked' ? (
        <p className="p-4 text-[12px] text-faint">Unlock the vault first.</p>
      ) : !LedgerEth.supported() ? (
        <p className="p-4 text-[12px] text-faint">
          This browser has no WebHID. Use a Chromium-based browser or the desktop app.
        </p>
      ) : (
        <HardwareForm folderId={folderId} onClose={onClose} />
      )}
    </Dialog>
  );
}

function HardwareForm({
  folderId,
  onClose,
}: {
  folderId?: string | undefined;
  onClose: () => void;
}) {
  const state = useDirectory();
  const registry = useRegistry();
  const view = useVaultView(vault);
  const toasts = useToasts();
  const ids = { name: useId(), index: useId(), folder: useId() };
  const root = state.folders.find((f) => f.parentId === null)!;
  const [folder, setFolder] = useState(folderId ?? root.id);
  const [name, setName] = useState('Ledger');
  const [index, setIndex] = useState('0');
  const [found, setFound] = useState<{
    address: string;
    publicKeyHex: string;
    path: string;
  } | null>(null);
  const [verified, setVerified] = useState(false);
  const [session, setSession] = useState<SessionChoice>({ kind: 'passphrase', passphrase: '' });
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const path = `m/44'/60'/0'/0/${Number.isInteger(Number(index)) && Number(index) >= 0 ? Number(index) : 0}`;
  const chains = listChains(registry).filter(
    (c) => c.family === 'evm' && EVM_SIGNING_CHAINS.has(c.chainId),
  );

  const withDevice = async (label: string, op: (d: LedgerEth) => Promise<void>) => {
    setBusy(label);
    setError(null);
    let device: LedgerEth | null = null;
    try {
      device = await LedgerEth.request();
      await op(device);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
      void device?.close().catch(() => undefined);
    }
  };

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!found || !verified) return;
    setError(null);
    let proof;
    try {
      proof = await vault.proveSession(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const walletId = crypto.randomUUID();
    const reg = await vault.hardwareRegister({
      session: proof,
      walletId,
      path: found.path,
      address: found.address,
    });
    if (!reg.ok) {
      setError(reg.error);
      return;
    }
    const r = directory.createKeyedWallet({
      walletId,
      name,
      folderId: folder,
      kind: 'hardware',
      accounts: chains.map((c) => ({
        chainId: c.chainId,
        address: found.address,
        derivationPath: found.path,
        publicKeyHex: found.publicKeyHex,
      })),
    });
    if (!r.ok) {
      setError(r.error);
      return;
    }
    toasts.push(`Added ${name}: signatures happen on the device`);
    onClose();
  };

  return (
    <form onSubmit={(e) => void save(e)} className="flex flex-col gap-4 p-4 text-[12px]">
      <p className="text-faint">
        Connect the Ledger, unlock it and open the Ethereum app. StackWallet reads one address; the
        key stays on the device. Signing works on the EVM testnets the core signs on.
      </p>
      <Field label="Account index" htmlFor={ids.index} hint={path}>
        <Input
          id={ids.index}
          value={index}
          inputMode="numeric"
          onChange={(e) => {
            setIndex(e.target.value.replace(/\D/g, ''));
            setFound(null);
            setVerified(false);
          }}
        />
      </Field>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          size="sm"
          disabled={busy !== null}
          onClick={() =>
            void withDevice('reading', async (d) => {
              const a = await d.getAddress(path);
              setFound({ ...a, path });
              setVerified(false);
            })
          }
        >
          {busy === 'reading' ? <LoadingWord label="reading" /> : 'Read address'}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={!found || busy !== null}
          onClick={() =>
            void withDevice('verify', async (d) => {
              const a = await d.getAddress(path, true);
              if (a.address.toLowerCase() !== found?.address.toLowerCase())
                throw new Error('The device showed a different address');
              setVerified(true);
            })
          }
        >
          {busy === 'verify' ? <LoadingWord label="confirm on the device" /> : 'Verify on device'}
        </Button>
      </div>
      {found && (
        <p className="font-mono break-all text-ink">
          {found.address} {verified ? <span className="text-ok">· verified on device</span> : null}
        </p>
      )}
      <Field label="Name" htmlFor={ids.name}>
        <Input
          id={ids.name}
          value={name}
          maxLength={80}
          onChange={(e) => setName(e.target.value)}
        />
      </Field>
      <Field label="Folder" htmlFor={ids.folder}>
        <Select id={ids.folder} value={folder} onChange={(e) => setFolder(e.target.value)}>
          {state.folders.map((f) => (
            <option key={f.id} value={f.id}>
              {f.name}
            </option>
          ))}
        </Select>
      </Field>
      <SessionField
        value={session}
        onChange={setSession}
        hint="registers the device address in this vault"
      />
      {error && <p className="text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant="primary"
          disabled={!found || !verified || !sessionReady(session) || view.busy}
        >
          Add wallet
        </Button>
      </div>
    </form>
  );
}
