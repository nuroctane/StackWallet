import { useId, useMemo, useState, type FormEvent } from 'react';
import type { ChainInfo } from '@stackwallet/chains';
import { Button, Chip, Dialog, Field, Input, Select, useToasts } from '@stackwallet/ui';

import {
  adapterOrNull,
  FAMILY_LABEL,
  FAMILY_ORDER,
  listChains,
  POPULAR_EVM,
} from '../lib/chains.js';
import { AddressAvatar } from './AddressAvatar.js';
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

interface ChainGroup {
  label: string;
  chains: ChainInfo[];
}

function groupChains(chains: ChainInfo[]): ChainGroup[] {
  const groups: ChainGroup[] = [];
  for (const testnet of [false, true]) {
    for (const family of FAMILY_ORDER) {
      const list = chains
        .filter((c) => c.family === family && c.testnet === testnet)
        .sort((a, b) => a.name.localeCompare(b.name));
      if (list.length > 0) {
        groups.push({
          label: `${FAMILY_LABEL[family]}${testnet ? ' · testnets' : ''}`,
          chains: list,
        });
      }
    }
  }
  return groups;
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
  const siblings =
    primary?.family === 'evm'
      ? POPULAR_EVM.flatMap((id) => {
          const c = chains.find((x) => x.chainId === id);
          return c && c.chainId !== chainId && c.testnet === primary.testnet ? [c] : [];
        })
      : [];
  const extraChainIds = extra.filter((id) => siblings.some((c) => c.chainId === id));

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
        <Select
          id={ids.chain}
          value={chainId}
          disabled={chains.length === 0}
          onChange={(e) => setChainId(e.target.value)}
        >
          {chains.length === 0 && <option value="">No chains available</option>}
          {groups.map((g) => (
            <optgroup key={g.label} label={g.label}>
              {g.chains.map((c) => (
                <option key={c.chainId} value={c.chainId}>
                  {c.name} · {c.nativeAsset.symbol}
                </option>
              ))}
            </optgroup>
          ))}
        </Select>
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
        <Field label="Also watch on" hint="The same address exists on every EVM network.">
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
