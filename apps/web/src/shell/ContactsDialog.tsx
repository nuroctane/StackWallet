import { useId, useState, type FormEvent } from 'react';
import { Button, Dialog, Field, Input, Select, useToasts } from '@stackwallet/ui';

import { listChains } from '../lib/chains.js';
import { directory, useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';

/**
 * The address book. A contact's name is the user's own word for an address,
 * so it labels that address everywhere (history, approvals, signing screens)
 * right after the user's own wallets, always with the full address beside it.
 */
export function ContactsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose} title="Contacts" meta="your names for addresses">
      <ContactsBody />
    </Dialog>
  );
}

function ContactsBody() {
  const state = useDirectory();
  const registry = useRegistry();
  const toasts = useToasts();
  const ids = { name: useId(), chain: useId(), address: useId(), note: useId() };
  const chains = listChains(registry).filter((c) => c.family !== 'evm');
  const [editing, setEditing] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [chainId, setChainId] = useState('evm');
  const [address, setAddress] = useState('');
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setEditing(null);
    setName('');
    setAddress('');
    setNote('');
    setChainId('evm');
    setError(null);
  };

  const save = (e: FormEvent) => {
    e.preventDefault();
    const r = directory.upsertContact({
      ...(editing ? { id: editing } : {}),
      name,
      chainId: chainId === 'evm' ? null : chainId,
      address,
      note,
    });
    if (!r.ok) {
      setError(r.error);
      return;
    }
    toasts.push(editing ? 'Contact saved' : `Added ${name.trim()}`);
    reset();
  };

  const chainName = (id: string | null) =>
    id === null ? 'every EVM chain' : (registry.chainInfo(id)?.name ?? id);

  return (
    <div className="flex flex-col gap-4 p-4">
      {state.contacts.length === 0 ? (
        <p className="text-[12px] text-faint">No contacts yet.</p>
      ) : (
        <ul className="flex max-h-[40vh] flex-col divide-y divide-edge overflow-auto text-[12px]">
          {state.contacts.map((c) => (
            <li key={c.id} className="flex items-start justify-between gap-3 py-2">
              <span className="flex min-w-0 flex-col">
                <span className="text-ink">{c.name}</span>
                <span className="font-mono text-[11px] break-all text-muted">{c.address}</span>
                <span className="text-[11px] text-faint">
                  {chainName(c.chainId)}
                  {c.note ? ` · ${c.note}` : ''}
                </span>
              </span>
              <span className="flex shrink-0 gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setEditing(c.id);
                    setName(c.name);
                    setAddress(c.address);
                    setNote(c.note ?? '');
                    setChainId(c.chainId ?? 'evm');
                  }}
                >
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    directory.removeContact(c.id);
                    if (editing === c.id) reset();
                  }}
                >
                  Remove
                </Button>
              </span>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={save} className="flex flex-col gap-3 border-t border-edge pt-3">
        <Field label="Name" htmlFor={ids.name}>
          <Input
            id={ids.name}
            value={name}
            maxLength={60}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field label="Network" htmlFor={ids.chain}>
          <Select id={ids.chain} value={chainId} onChange={(e) => setChainId(e.target.value)}>
            <option value="evm">Every EVM chain</option>
            {chains.map((c) => (
              <option key={c.chainId} value={c.chainId}>
                {c.name}
                {c.testnet ? ' · testnet' : ''}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Address" htmlFor={ids.address}>
          <Input
            id={ids.address}
            value={address}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setAddress(e.target.value)}
          />
        </Field>
        <Field label="Note" htmlFor={ids.note} hint="optional">
          <Input
            id={ids.note}
            value={note}
            maxLength={200}
            onChange={(e) => setNote(e.target.value)}
          />
        </Field>
        {error && <p className="text-[12px] text-danger">{error}</p>}
        <div className="flex justify-end gap-2">
          {editing && (
            <Button type="button" variant="ghost" onClick={reset}>
              Cancel edit
            </Button>
          )}
          <Button type="submit" variant="primary" disabled={!name.trim() || !address.trim()}>
            {editing ? 'Save contact' : 'Add contact'}
          </Button>
        </div>
      </form>
    </div>
  );
}
