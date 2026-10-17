import { useEffect, useId, useState, type FormEvent } from 'react';
import type { Account, ExposureChannel, Revealed } from '@stackwallet/core-client';
import { Button, Dialog, Field, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { findChain } from '../lib/chains.js';
import { standardPath } from '../lib/keys.js';
import { formatPrivateKey, privateKeyFormat } from '../lib/secretFormat.js';
import { useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { accountsOf } from '../store/selectors.js';
import { useExportGate } from './ExportGateFields.js';

/** Clipboard copies are wiped after this long if the clipboard still holds them. */
const CLIPBOARD_CLEAR_MS = 30_000;

export function RevealDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="Export key" meta="marks the wallet exposed">
      {walletId && <RevealForm walletId={walletId} onClose={onClose} />}
    </Dialog>
  );
}

function RevealForm({ walletId, onClose }: { walletId: string; onClose: () => void }) {
  const state = useDirectory();
  const registry = useRegistry();
  const view = useVaultView(vault);
  const toasts = useToasts();
  const ids = { what: useId(), channel: useId() };
  const wallet = state.wallets.find((w) => w.id === walletId);
  const folder = state.folders.find((f) => f.id === wallet?.folderId);
  const gate = useExportGate({
    folderId: wallet?.folderId ?? '',
    folderName: folder?.name ?? 'its folder',
    walletId,
    walletName: wallet?.name ?? 'this wallet',
  });
  const accounts = wallet ? accountsOf(state, walletId).filter((a) => a.derivationPath) : [];

  const [target, setTarget] = useState<'phrase' | string>('phrase');
  const [channel, setChannel] = useState<ExposureChannel>('screen');
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState<{ text: string; format: string | null } | null>(null);

  // A shown secret disappears with the dialog; nothing keeps it around.
  useEffect(() => () => setShown(null), []);

  if (!wallet || wallet.kind !== 'single') {
    return (
      <p className="p-4 text-[12px] text-faint">Only single-key wallets have a key to export.</p>
    );
  }
  if (view.status.kind !== 'unlocked') {
    return <p className="p-4 text-[12px] text-faint">Unlock the vault to export a key.</p>;
  }

  const account: Account | undefined = accounts.find((a) => a.id === target);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ack || !gate.ready) return;
    setError(null);
    let what: Revealed;
    const chain = account ? findChain(registry, account.chainId) : undefined;
    if (target === 'phrase') {
      what = { kind: 'mnemonic' };
    } else {
      const sp = chain ? standardPath(chain) : null;
      if (!account || !chain || !sp || !account.derivationPath) {
        setError('This account has no derivation path');
        return;
      }
      what = { kind: 'privateKey', curve: sp.curve, path: account.derivationPath };
    }
    let input;
    try {
      input = await gate.build();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const r = await vault.reveal(walletId, input, what, channel);
    gate.reset();
    if (!r.ok) {
      setError(r.error);
      return;
    }
    const text =
      what.kind === 'mnemonic' || !chain
        ? r.value.secret
        : formatPrivateKey(chain, r.value.secret, r.value.publicHex ?? '');
    const format = what.kind === 'mnemonic' || !chain ? null : privateKeyFormat(chain);
    if (channel === 'screen') {
      setShown({ text, format });
    } else if (channel === 'clipboard') {
      try {
        await navigator.clipboard.writeText(text);
        setTimeout(() => {
          void navigator.clipboard
            .readText()
            .then((cur) => (cur === text ? navigator.clipboard.writeText('') : undefined))
            .catch(() => undefined);
        }, CLIPBOARD_CLEAR_MS);
        toasts.push('Copied; the clipboard is cleared in 30s if unchanged', 'danger');
        onClose();
      } catch {
        // The exposure is already recorded; fall back to showing it.
        setShown({ text, format });
      }
    } else {
      const blob = new Blob([`${text}\n`], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${wallet.name.replace(/[^\w.-]+/g, '_')}-${target === 'phrase' ? 'phrase' : 'key'}.txt`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      toasts.push('Saved to a file', 'danger');
      onClose();
    }
  };

  if (shown !== null) {
    return (
      <div className="flex flex-col gap-3 p-4">
        <p className="text-[12px] text-danger">
          This wallet is now permanently tagged exposed. Anyone who sees this can move its funds.
        </p>
        <pre className="rounded-sw-sm border border-danger/60 bg-paper p-3 font-mono text-[13px] break-words whitespace-pre-wrap text-ink select-all">
          {shown.text}
        </pre>
        {shown.format && <p className="text-[11px] text-faint">{shown.format}</p>}
        <div className="flex justify-end">
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <p className="rounded-sw-sm border border-danger/60 bg-danger-soft p-3 text-[12px] text-ink">
        Exporting takes the key out of the vault. <strong>{wallet.name}</strong> will carry a red{' '}
        <span className="font-semibold">exposed</span> tag on every device from now on, even if you
        never use what you export. This cannot be undone.
      </p>
      <Field label="What" htmlFor={ids.what}>
        <Select id={ids.what} value={target} onChange={(e) => setTarget(e.target.value)}>
          <option value="phrase">Recovery phrase (every account)</option>
          {accounts.map((a) => (
            <option key={a.id} value={a.id}>
              Private key · {findChain(registry, a.chainId)?.name ?? a.chainId}
            </option>
          ))}
        </Select>
        {account && (
          <p className="mt-1 text-[11px] text-faint">
            {(() => {
              const c = findChain(registry, account.chainId);
              return c ? privateKeyFormat(c) : null;
            })()}
          </p>
        )}
      </Field>
      <Field label="Where" htmlFor={ids.channel}>
        <Select
          id={ids.channel}
          value={channel}
          onChange={(e) => setChannel(e.target.value as ExposureChannel)}
        >
          <option value="screen">Show on screen</option>
          <option value="clipboard">Copy to clipboard</option>
          <option value="file">Save to a file</option>
        </Select>
      </Field>
      {gate.fields}
      <p className="text-[11px] text-faint">
        Only this wallet is tagged. Other wallets in {folder?.name ?? 'its folder'} stay unexported
        and untagged.
      </p>
      <label className="flex items-start gap-2 text-[12px] text-muted">
        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />I
        understand this wallet will be tagged exposed permanently.
      </label>
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="danger" disabled={!ack || !gate.ready || view.busy}>
          {view.busy ? <LoadingWord label="checking" /> : 'Export'}
        </Button>
      </div>
    </form>
  );
}
