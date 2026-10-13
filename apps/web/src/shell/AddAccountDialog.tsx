import { useEffect, useId, useMemo, useState, type FormEvent } from 'react';
import { Button, Dialog, Field, Input, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { adapterOrNull, listChains } from '../lib/chains.js';
import { accountPath, nextAccountIndex } from '../lib/keys.js';
import { directory, useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { accountsOf } from '../store/selectors.js';

/**
 * Derive another account from a single-key wallet's phrase: the next free
 * index on one chain, on the same path other wallets use for that index.
 * Only the public key leaves the core.
 */
export function AddAccountDialog({
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
    <Dialog open={open} onClose={onClose} title="Add account" meta="same phrase, next index">
      {!walletId ? null : view.status.kind !== 'unlocked' ? (
        <p className="p-4 text-[12px] text-faint">Unlock the vault to derive an account.</p>
      ) : (
        <AddAccountForm walletId={walletId} onClose={onClose} />
      )}
    </Dialog>
  );
}

function AddAccountForm({ walletId, onClose }: { walletId: string; onClose: () => void }) {
  const state = useDirectory();
  const registry = useRegistry();
  const toasts = useToasts();
  const ids = { chain: useId(), label: useId() };
  const existing = accountsOf(state, walletId);
  const chains = useMemo(
    () => listChains(registry).filter((c) => accountPath(c, 0) !== null),
    [registry],
  );
  const [chainId, setChainId] = useState(existing[0]?.chainId ?? chains[0]?.chainId ?? '');
  const [label, setLabel] = useState('');
  const [preview, setPreview] = useState<{ address: string; hex: string; path: string } | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const chain = chains.find((c) => c.chainId === chainId);
  const index = chain
    ? nextAccountIndex(
        chain,
        existing.filter((a) => a.chainId === chainId).map((a) => a.derivationPath),
      )
    : 0;

  useEffect(() => {
    let live = true;
    setPreview(null);
    setError(null);
    const sp = chain ? accountPath(chain, index) : null;
    const adapter = chain ? adapterOrNull(registry, chain.chainId) : null;
    if (!chain || !sp || !adapter) return;
    vault
      .publicKey(walletId, sp.curve, sp.path)
      .then((hex) => {
        if (!live) return;
        setPreview({
          hex,
          path: sp.path,
          address: adapter.deriveAddress({ curve: sp.curve, hex }, chain.chainId),
        });
      })
      .catch((err: unknown) => live && setError(err instanceof Error ? err.message : String(err)));
    return () => {
      live = false;
    };
  }, [chain, index, registry, walletId]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!preview || !chain) return;
    const r = directory.addKeyedAccount({
      walletId,
      chainId: chain.chainId,
      address: preview.address,
      derivationPath: preview.path,
      publicKeyHex: preview.hex,
      label: label.trim() || `account ${index + 1}`,
    });
    if (!r.ok) {
      setError(r.error);
      return;
    }
    toasts.push(`Added ${chain.name} account ${index + 1}`);
    onClose();
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-4 p-4">
      <Field label="Chain" htmlFor={ids.chain}>
        <Select id={ids.chain} value={chainId} onChange={(e) => setChainId(e.target.value)}>
          {chains.map((c) => (
            <option key={c.chainId} value={c.chainId}>
              {c.name}
              {c.testnet ? ' · testnet' : ''}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Label" htmlFor={ids.label} hint="optional">
        <Input
          id={ids.label}
          value={label}
          maxLength={40}
          placeholder={`account ${index + 1}`}
          onChange={(e) => setLabel(e.target.value)}
        />
      </Field>
      <div className="rounded-sw-sm border border-edge p-3 text-[12px]">
        {preview ? (
          <>
            <p className="text-faint">
              index {index} · <span className="font-mono">{preview.path}</span>
            </p>
            <p className="mt-1 font-mono break-all text-ink">{preview.address}</p>
          </>
        ) : error ? (
          <p className="text-danger">{error}</p>
        ) : (
          <LoadingWord label="deriving" />
        )}
      </div>
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!preview}>
          Add account
        </Button>
      </div>
    </form>
  );
}
