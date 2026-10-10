import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Button, Dialog, Kbd, useToasts } from '@stackwallet/ui';

import { directory, useDirectory } from '../store/persist.js';
import { descendantWallets } from '../store/selectors.js';
import { flattenFolders } from './FolderOptions.js';

export function MoveWalletDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="Move wallet" aria-label="Move wallet">
      {walletId && <MoveWalletBody walletId={walletId} onClose={onClose} />}
    </Dialog>
  );
}

function MoveWalletBody({ walletId, onClose }: { walletId: string; onClose: () => void }) {
  const state = useDirectory();
  const toasts = useToasts();
  const wallet = state.wallets.find((w) => w.id === walletId);
  const folders = useMemo(() => flattenFolders(state), [state]);
  const listRef = useRef<HTMLDivElement>(null);

  const firstEnabled = folders.findIndex((f) => f.folder.id !== wallet?.folderId);
  const [cursor, setCursor] = useState(Math.max(0, firstEnabled));

  useEffect(() => {
    const el = listRef.current?.children[cursor];
    if (el instanceof HTMLElement) el.scrollIntoView({ block: 'nearest' });
  }, [cursor]);

  if (!wallet) return null;

  const step = (delta: number) => {
    if (folders.length === 0) return;
    let i = cursor;
    for (let n = 0; n < folders.length; n += 1) {
      i = (i + delta + folders.length) % folders.length;
      if (folders[i]?.folder.id !== wallet.folderId) break;
    }
    setCursor(i);
  };

  const confirm = (folderId: string | undefined) => {
    if (!folderId || folderId === wallet.folderId) return;
    const result = directory.moveWallet(wallet.id, folderId);
    if (!result.ok) {
      toasts.push(result.error, 'danger');
      return;
    }
    const target = folders.find((f) => f.folder.id === folderId)?.folder.name ?? 'folder';
    toasts.push(`Moved "${wallet.name}" to ${target}`);
    onClose();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      step(1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      step(-1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      confirm(folders[cursor]?.folder.id);
    }
  };

  const chosen = folders[cursor];
  const canConfirm = chosen !== undefined && chosen.folder.id !== wallet.folderId;

  return (
    <div className="flex flex-col">
      <p className="px-4 pt-3 pb-2 text-[12px] text-faint">
        Move <span className="text-ink">{wallet.name}</span> to:
      </p>
      <div
        ref={listRef}
        role="listbox"
        aria-label="Destination folder"
        aria-activedescendant={chosen ? `move-opt-${chosen.folder.id}` : undefined}
        tabIndex={0}
        autoFocus
        onKeyDown={onKeyDown}
        className="max-h-[50vh] min-h-24 overflow-auto px-2 pb-2 outline-none"
      >
        {folders.map(({ folder, depth }, i) => {
          const current = folder.id === wallet.folderId;
          const count = descendantWallets(state, folder.id).length;
          return (
            <div
              key={folder.id}
              id={`move-opt-${folder.id}`}
              role="option"
              aria-selected={i === cursor}
              aria-disabled={current || undefined}
              onMouseEnter={() => {
                if (!current) setCursor(i);
              }}
              onClick={() => confirm(current ? undefined : folder.id)}
              onDoubleClick={() => confirm(current ? undefined : folder.id)}
              style={{ paddingLeft: `${8 + depth * 14}px` }}
              className={`sw-pressable flex h-8 items-center gap-2 rounded-sw-sm pr-2 ${
                current ? 'cursor-not-allowed opacity-40' : 'cursor-pointer'
              } ${i === cursor && !current ? 'bg-hover' : ''}`}
            >
              <span className="flex-1 truncate text-ink">{folder.name}</span>
              {current && <span className="text-[11px] text-faint">current</span>}
              {!current && count > 0 && <span className="text-[11px] text-faint">{count}</span>}
            </div>
          );
        })}
      </div>
      <div className="flex items-center justify-between gap-2 border-t border-edge px-4 py-3">
        <span className="flex items-center gap-1 text-[11px] text-faint">
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd> choose <Kbd>↵</Kbd> move
        </span>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={!canConfirm}
            onClick={() => confirm(chosen?.folder.id)}
          >
            Move here
          </Button>
        </div>
      </div>
    </div>
  );
}
