import { useId, useMemo, useState, type FormEvent } from 'react';
import { Button, Chip, Dialog, Field, Input, Select, useToasts } from '@stackwallet/ui';

import { adapterOrNull, listChains, POPULAR_EVM } from '../lib/chains.js';
import { AddressAvatar } from './AddressAvatar.js';
import { ChainSelect, groupChains } from './ChainSelect.js';
import { directory, useDirectory } from '../store/persist.js';
import { rootOf } from '../store/reducers.js';
import { useRegistry } from '../store/RegistryContext.js';
import { FolderOptions } from './FolderOptions.js';

export function AddWatchWalletDialog({
  open,
  folderId,
  onClose,
}: {
  open: boolean;
  folderId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="New watch wallet" meta="read-only">
      <AddWatchWalletForm initialFolderId={folderId} onClose={onClose} />
    </Dialog>
  );
}

function AddWatchWalletForm({
  initialFolderId,
  onClose,
}: {
  initialFolderId?: string | undefined;
  onClose: () => void;
}) {
  const state = useDirectory();
  const registry = useRegistry();
  const toasts = useToasts();
  const ids = { name: useId(), folder: useId(), chain: useId(), address: useId() };

  const chains = useMemo(() => listChains(registry), [registry]);
  const groups = useMemo(() => groupChains(chains), [chains]);
  const firstChain =
    chains.find((c) => c.chainId === 'eip155:1')?.chainId ?? groups[0]?.chains[0]?.chainId ?? '';

  const [name, setName] = useState('');
  const [folder, setFolder] = useState(initialFolderId ?? rootOf(state).id);
  const [chainId, setChainId] = useState(firstChain);
  const [address, setAddress] = useState('');
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [extra, setExtra] = useState<string[]>([]);
  const primary = chains.find((c) => c.chainId === chainId);
  const trimmedAddress = address.trim();
  const adapter = chainId ? adapterOrNull(registry, chainId) : null;
  const addressState: 'empty' | 'valid' | 'invalid' | 'no-adapter' =
    trimmedAddress === ''
      ? 'empty'
      : !adapter
        ? 'no-adapter'
        : safeValidate(adapter.validateAddress.bind(adapter), trimmedAddress, chainId)
          ? 'valid'
          : 'invalid';
  // Other networks of the same family where this exact string is the same
  // owner: the curated EVM list, or any sibling chain whose adapter accepts
  // the address (Sui/IOTA, Aptos/Movement, SS58 prefixes shared by testnets).
  // A watch wallet has no public key, so other families cannot be derived.
  const siblings = useMemo(() => {
    if (!primary) return [];
    if (primary.family === 'evm') {
      return POPULAR_EVM.flatMap((id) => {
        const c = chains.find((x) => x.chainId === id);
        return c && c.chainId !== chainId && c.testnet === primary.testnet ? [c] : [];
      });
    }
    if (addressState !== 'valid') return [];
    return chains.filter((c) => {
      if (c.family !== primary.family || c.chainId === chainId || c.testnet !== primary.testnet)
        return false;
      const a = adapterOrNull(registry, c.chainId);
      return !!a && safeValidate(a.validateAddress.bind(a), trimmedAddress, c.chainId);
    });
  }, [primary, chains, chainId, addressState, trimmedAddress, registry]);
  const extraChainIds = extra.filter((id) => siblings.some((c) => c.chainId === id));

  const addressError =
    addressState === 'invalid'
      ? 'Not a valid address for this chain'
      : addressState === 'no-adapter'
        ? 'No adapter can validate addresses for this chain'
        : null;

  const canSubmit = name.trim() !== '' && chainId !== '' && addressState === 'valid';

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    const result = directory.createWatchWallet({
      name,
      folderId: folder,
      chainId,
      address,
      extraChainIds,
    });
    if (!result.ok) {
      setSubmitError(result.error);
      return;
    }
    toasts.push(`Watching "${name.trim()}"`);
    onClose();
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-4 p-4">
      <Field label="Name" htmlFor={ids.name}>
        <Input
          id={ids.name}
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Treasury"
          maxLength={80}
        />
      </Field>
      <Field label="Folder" htmlFor={ids.folder}>
        <Select id={ids.folder} value={folder} onChange={(e) => setFolder(e.target.value)}>
          <FolderOptions state={state} />
        </Select>
      </Field>
      <Field
        label="Chain"
        htmlFor={ids.chain}
        error={chains.length === 0 ? 'No chain adapters loaded' : null}
      >
        <ChainSelect
          id={ids.chain}
          chains={chains}
          value={chainId}
          disabled={chains.length === 0}
          onChange={setChainId}
          leading={chains.length === 0 && <option value="">No chains available</option>}
        />
      </Field>
      <Field
        label="Address"
        htmlFor={ids.address}
        error={addressError ?? submitError}
        hint="Checked locally; nothing is sent until you refresh balances."
      >
        <Input
          id={ids.address}
          value={address}
          invalid={addressState === 'invalid'}
          onChange={(e) => {
            setAddress(e.target.value);
            setSubmitError(null);
          }}
          placeholder="Paste an address"
          spellCheck={false}
          autoComplete="off"
        />
      </Field>
      {addressState === 'valid' && (
        <div className="-mt-2 flex items-center gap-2 text-[11px] text-faint">
          <AddressAvatar address={trimmedAddress} size={16} />
          <span>This mark stands for this address everywhere in StackWallet.</span>
        </div>
      )}
      {siblings.length > 0 && (
        <Field
          label="Also watch on"
          hint={
            primary?.family === 'evm'
              ? 'The same address exists on every EVM network.'
              : 'Networks of the same family where this address is the same account.'
          }
        >
          <div className="flex flex-wrap gap-1.5">
            {siblings.map((c) => {
              const on = extraChainIds.includes(c.chainId);
              return (
                <Chip
                  key={c.chainId}
                  active={on}
                  onClick={() =>
                    setExtra(on ? extra.filter((x) => x !== c.chainId) : [...extra, c.chainId])
                  }
                >
                  {c.name}
                </Chip>
              );
            })}
          </div>
        </Field>
      )}
      <div className="flex justify-end gap-2 border-t border-edge pt-3">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!canSubmit}>
          Add watch wallet
        </Button>
      </div>
    </form>
  );
}

function safeValidate(
  validate: (addr: string, chainId: string) => boolean,
  addr: string,
  chainId: string,
): boolean {
  try {
    return validate(addr, chainId);
  } catch {
    return false;
  }
}
