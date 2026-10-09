import { useId, useState, type FormEvent } from 'react';
import { Button, Dialog, Field, Input, Select, useToasts } from '@stackwallet/ui';

import { directory, useDirectory } from '../store/persist.js';
import { rootOf } from '../store/reducers.js';
import { FolderOptions } from './FolderOptions.js';

export function AddFolderDialog({
  open,
  parentId,
  onClose,
}: {
  open: boolean;
  parentId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="New folder">
      <AddFolderForm initialParentId={parentId} onClose={onClose} />
    </Dialog>
  );
}

function AddFolderForm({
  initialParentId,
  onClose,
}: {
  initialParentId?: string | undefined;
  onClose: () => void;
}) {
  const state = useDirectory();
  const toasts = useToasts();
  const ids = { name: useId(), parent: useId() };
  const [name, setName] = useState('');
  const [parent, setParent] = useState(initialParentId ?? rootOf(state).id);
  const [error, setError] = useState<string | null>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const result = directory.createFolder(name, parent);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toasts.push(`Folder "${name.trim()}" created`);
    onClose();
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-4 p-4">
      <Field label="Name" htmlFor={ids.name} error={error}>
        <Input
          id={ids.name}
          autoFocus
          value={name}
          invalid={error !== null}
          onChange={(e) => {
            setName(e.target.value);
            setError(null);
          }}
          placeholder="Cold storage"
          maxLength={80}
        />
      </Field>
      <Field label="Parent" htmlFor={ids.parent}>
        <Select id={ids.parent} value={parent} onChange={(e) => setParent(e.target.value)}>
          <FolderOptions state={state} />
        </Select>
      </Field>
      <div className="flex justify-end gap-2 border-t border-edge pt-3">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={name.trim() === ''}>
          Create folder
        </Button>
      </div>
    </form>
  );
}
