import { useState } from 'react';
import { Button, Dialog, useToasts } from '@stackwallet/ui';

import { directory, useDirectory } from '../store/persist.js';
import { findNode } from '../store/selectors.js';

export function ConfirmDeleteDialog({
  open,
  target,
  onClose,
}: {
  open: boolean;
  target: { kind: 'wallet' | 'folder'; id: string } | null;
  onClose: () => void;
}) {
  const state = useDirectory();
  const toasts = useToasts();
  const [error, setError] = useState<string | null>(null);
  const node = target ? findNode(state, target.id) : undefined;
  const name = node ? (node.kind === 'folder' ? node.folder.name : node.wallet.name) : '';
  const isWallet = target?.kind === 'wallet';

  const confirm = () => {
    if (!target) return;
    const result = isWallet ? directory.deleteWallet(target.id) : directory.deleteFolder(target.id);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toasts.push(`${isWallet ? 'Wallet' : 'Folder'} "${name}" deleted`);
    setError(null);
    onClose();
  };

  const close = () => {
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={close} title={isWallet ? 'Delete wallet' : 'Delete folder'}>
      <div className="flex flex-col gap-4 p-4">
        <p className="text-muted">
          Delete <span className="text-ink">{name}</span>?{' '}
          {isWallet
            ? 'This removes the entry and its accounts from this device. Nothing on-chain changes.'
            : 'Only empty folders can be deleted.'}
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
            {isWallet ? 'Delete wallet' : 'Delete folder'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
