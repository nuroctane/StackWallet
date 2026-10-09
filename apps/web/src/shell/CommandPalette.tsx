import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Badge, Dialog, Input, Kbd } from '@stackwallet/ui';

import { fuzzyMatch } from '../lib/format.js';
import { directory, useDirectory } from '../store/persist.js';
import { kindLabel, pathTo } from '../store/selectors.js';
import { useShell } from './ShellContext.js';

interface Item {
  id: string;
  group: 'actions' | 'folders' | 'wallets';
  label: string;
  hint?: string;
  badge?: string;
  run: () => void;
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      width="w-[min(92vw,560px)]"
      className="mt-[12vh] mb-auto"
      aria-label="Command palette"
    >
      <PaletteBody onClose={onClose} />
    </Dialog>
  );
}

function PaletteBody({ onClose }: { onClose: () => void }) {
  const state = useDirectory();
  const shell = useShell();
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);

  const items = useMemo<Item[]>(() => {
    const actions: Item[] = [
      {
        id: 'action:new-folder',
        group: 'actions',
        label: 'New folder',
        run: () => shell.openDialog({ kind: 'folder' }),
      },
      {
        id: 'action:new-watch',
        group: 'actions',
        label: 'New watch wallet',
        run: () => shell.openDialog({ kind: 'watch' }),
      },
      {
        id: 'action:refresh',
        group: 'actions',
        label: 'Refresh balances',
        run: () => shell.refreshBalances(),
      },
      {
        id: 'action:rail',
        group: 'actions',
        label: shell.railOpen ? 'Hide approvals rail' : 'Show approvals rail',
        hint: 'Ctrl .',
        run: () => shell.toggleRail(),
      },
    ];
    const folders: Item[] = state.folders
      .filter((f) => f.parentId !== null)
      .map((f) => ({
        id: f.id,
        group: 'folders' as const,
        label: f.name,
        hint: pathTo(state, f.id)
          .slice(0, -1)
          .map((p) => p.name)
          .join(' / '),
        run: () => directory.reveal(f.id),
      }));
    const wallets: Item[] = state.wallets.map((w) => ({
      id: w.id,
      group: 'wallets' as const,
      label: w.name,
      hint: pathTo(state, w.id)
        .map((p) => p.name)
        .join(' / '),
      badge: kindLabel(w),
      run: () => directory.reveal(w.id),
    }));
    return [...actions, ...folders, ...wallets];
  }, [state, shell]);

  const visible = useMemo(
    () => items.filter((i) => fuzzyMatch(query, i.label) || (i.hint && fuzzyMatch(query, i.hint))),
    [items, query],
  );
  const clamped = Math.min(cursor, Math.max(0, visible.length - 1));

  useEffect(() => {
    const el = listRef.current?.children[clamped];
    if (el instanceof HTMLElement) el.scrollIntoView({ block: 'nearest' });
  }, [clamped]);

  const choose = (item: Item | undefined) => {
    if (!item) return;
    onClose();
    // Let the dialog close before any follow-up dialog opens; two modals cannot share the top layer cleanly.
    setTimeout(item.run, 0);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setCursor(Math.min(visible.length - 1, clamped + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setCursor(Math.max(0, clamped - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(visible[clamped]);
    }
  };

  let lastGroup: Item['group'] | null = null;

  return (
    <div className="flex max-h-[60vh] flex-col">
      <div className="flex items-center gap-2 border-b border-edge p-2">
        <Input
          autoFocus
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setCursor(0);
          }}
          onKeyDown={onKeyDown}
          placeholder="Jump to a wallet or folder, or run an action"
          aria-label="Command palette"
          spellCheck={false}
          autoComplete="off"
          role="combobox"
          aria-expanded
          aria-controls="palette-list"
        />
      </div>
      <ul
        id="palette-list"
        ref={listRef}
        role="listbox"
        className="min-h-0 flex-1 overflow-auto p-1"
      >
        {visible.length === 0 && (
          <li className="px-3 py-6 text-center text-[12px] text-faint">No matches</li>
        )}
        {visible.map((item, i) => {
          const header = item.group !== lastGroup ? item.group : null;
          lastGroup = item.group;
          return (
            <li
              key={item.id}
              role="option"
              aria-selected={i === clamped}
              onMouseEnter={() => setCursor(i)}
              onClick={() => choose(item)}
              className={`cursor-pointer rounded-sw-sm ${i === clamped ? 'bg-hover' : ''}`}
            >
              {header && (
                <div className="px-2 pt-2 pb-1 text-[10px] font-semibold tracking-[0.12em] text-faint uppercase">
                  {header}
                </div>
              )}
              <div className="flex h-8 items-center gap-2 px-2">
                <span className="flex-1 truncate text-ink">{item.label}</span>
                {item.badge && <Badge>{item.badge}</Badge>}
                {item.hint && <span className="truncate text-[11px] text-faint">{item.hint}</span>}
              </div>
            </li>
          );
        })}
      </ul>
      <div className="flex items-center gap-3 border-t border-edge px-3 py-1.5 text-[11px] text-faint">
        <span className="flex items-center gap-1">
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd> move
        </span>
        <span className="flex items-center gap-1">
          <Kbd>↵</Kbd> open
        </span>
        <span className="flex items-center gap-1">
          <Kbd>esc</Kbd> close
        </span>
      </div>
    </div>
  );
}
