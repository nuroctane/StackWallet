import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Badge, Button, EmptyState, Input, Panel, useToasts } from '@stackwallet/ui';

import { FAMILY_LABEL } from '../lib/chains.js';
import { directory, useDirectory } from '../store/persist.js';
import type { DirectoryState } from '../store/schema.js';
import { flattenTree, kindLabel, walletFamilies, type TreeRow } from '../store/selectors.js';
import { useShell } from './ShellContext.js';

export function DirectoryTree() {
  const state = useDirectory();
  const shell = useShell();
  const toasts = useToasts();
  const [filter, setFilter] = useState('');
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const treeRef = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => flattenTree(state, filter), [state, filter]);
  const onlyRoot = state.folders.length === 1 && state.wallets.length === 0;
  const filtering = filter.trim() !== '';

  const activeId = rows.some((r) => r.id === focusedId)
    ? focusedId
    : rows.some((r) => r.id === state.ui.selectedId)
      ? state.ui.selectedId
      : (rows[0]?.id ?? null);

  useEffect(() => {
    if (!activeId || !treeRef.current) return;
    const el = treeRef.current.querySelector<HTMLElement>(`[data-row-id="${cssEscape(activeId)}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [activeId]);

  const move = (delta: number) => {
    if (rows.length === 0) return;
    const idx = rows.findIndex((r) => r.id === activeId);
    const next = rows[Math.min(rows.length - 1, Math.max(0, (idx < 0 ? 0 : idx) + delta))];
    if (next) setFocusedId(next.id);
  };

  const requestDelete = (row: TreeRow) => {
    shell.openDialog(
      row.kind === 'wallet'
        ? { kind: 'deleteWallet', walletId: row.id }
        : { kind: 'deleteFolder', folderId: row.id },
    );
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (renamingId) return;
    const row = rows.find((r) => r.id === activeId);
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        move(1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        move(-1);
        break;
      case 'Home':
        e.preventDefault();
        if (rows[0]) setFocusedId(rows[0].id);
        break;
      case 'End':
        e.preventDefault();
        if (rows.length) setFocusedId(rows[rows.length - 1]!.id);
        break;
      case 'ArrowRight':
        if (!row) break;
        e.preventDefault();
        if (row.kind === 'folder' && !filtering) {
          if (!row.expanded) directory.setFolderExpanded(row.id, true);
          else move(1);
        } else {
          directory.select(row.id);
        }
        break;
      case 'ArrowLeft': {
        if (!row) break;
        e.preventDefault();
        if (row.kind === 'folder' && row.expanded && !filtering) {
          directory.setFolderExpanded(row.id, false);
        } else if (row.parentId && rows.some((r) => r.id === row.parentId)) {
          setFocusedId(row.parentId);
        }
        break;
      }
      case 'Enter':
      case ' ':
        if (!row) break;
        e.preventDefault();
        directory.select(row.id);
        break;
      case 'F2':
        if (!row) break;
        e.preventDefault();
        setRenamingId(row.id);
        break;
      case 'Delete':
      case 'Backspace':
        if (!row) break;
        e.preventDefault();
        requestDelete(row);
        break;
      default:
        break;
    }
  };

  const commitRename = (id: string, name: string) => {
    setRenamingId(null);
    const current = rows.find((r) => r.id === id)?.name;
    if (name.trim() === '' || name.trim() === current) return;
    const result = directory.renameNode(id, name);
    if (!result.ok) toasts.push(result.error, 'danger');
    treeRef.current?.focus();
  };

  return (
    <Panel
      as="nav"
      title="Directory"
      meta={
        <div className="flex gap-1">
          <Button size="sm" variant="ghost" onClick={() => shell.openDialog({ kind: 'folder' })}>
            + folder
          </Button>
          <Button size="sm" variant="ghost" onClick={() => shell.openDialog({ kind: 'watch' })}>
            + watch
          </Button>
        </div>
      }
      className="sw-enter"
    >
      <div className="flex h-full flex-col">
        {!onlyRoot && (
          <div className="sticky top-0 z-10 border-b border-edge bg-surface p-2">
            <Input
              dense
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by name or address"
              aria-label="Filter directory"
              spellCheck={false}
            />
          </div>
        )}
        {onlyRoot ? (
          <EmptyState
            title="No wallets yet"
            description="Start with a watch-only address, or make a folder to organize what comes next."
            action={
              <>
                <Button size="sm" onClick={() => shell.openDialog({ kind: 'watch' })}>
                  Add watch wallet
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => shell.openDialog({ kind: 'folder' })}
                >
                  New folder
                </Button>
              </>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState title="No matches" description={`Nothing matches "${filter.trim()}".`} />
        ) : (
          <div
            ref={treeRef}
            role="tree"
            aria-label="Wallet directory"
            tabIndex={0}
            aria-activedescendant={activeId ? rowDomId(activeId) : undefined}
            onKeyDown={onKeyDown}
            className="flex flex-col gap-0.5 p-2 outline-none"
          >
            {rows.map((row) => (
              <Row
                key={row.id}
                row={row}
                state={state}
                selected={state.ui.selectedId === row.id}
                active={activeId === row.id}
                renaming={renamingId === row.id}
                filtering={filtering}
                onActivate={() => {
                  setFocusedId(row.id);
                  directory.select(row.id);
                }}
                onToggle={() => directory.toggleFolder(row.id)}
                onRename={(name) => commitRename(row.id, name)}
                onCancelRename={() => {
                  setRenamingId(null);
                  treeRef.current?.focus();
                }}
                onStartRename={() => setRenamingId(row.id)}
              />
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}

function rowDomId(id: string): string {
  return `tree-row-${id}`;
}

function cssEscape(value: string): string {
  return typeof CSS !== 'undefined' && 'escape' in CSS ? CSS.escape(value) : value;
}

interface RowProps {
  row: TreeRow;
  state: DirectoryState;
  selected: boolean;
  active: boolean;
  renaming: boolean;
  filtering: boolean;
  onActivate: () => void;
  onToggle: () => void;
  onRename: (name: string) => void;
  onCancelRename: () => void;
  onStartRename: () => void;
}

function Row({
  row,
  state,
  selected,
  active,
  renaming,
  filtering,
  onActivate,
  onToggle,
  onRename,
  onCancelRename,
  onStartRename,
}: RowProps) {
  const wallet = row.kind === 'wallet' ? state.wallets.find((w) => w.id === row.id) : undefined;
  const families = wallet ? walletFamilies(state, wallet.id) : [];

  return (
    <div
      id={rowDomId(row.id)}
      data-row-id={row.id}
      role="treeitem"
      aria-level={row.depth + 1}
      aria-selected={selected}
      aria-expanded={row.kind === 'folder' && !filtering ? row.expanded : undefined}
      className={`sw-pressable relative flex h-8 w-full items-center gap-1.5 rounded-sw-sm pr-2 text-left ${
        selected
          ? 'bg-hover before:absolute before:inset-y-1.5 before:left-0 before:w-px before:bg-edge-strong'
          : ''
      } ${active && !selected ? 'bg-hover/60' : ''}`}
      style={{ paddingLeft: `${6 + row.depth * 14}px` }}
      onClick={onActivate}
      onDoubleClick={onStartRename}
    >
      {row.kind === 'folder' ? (
        <button
          type="button"
          tabIndex={-1}
          aria-label={row.expanded ? 'Collapse folder' : 'Expand folder'}
          disabled={filtering}
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          className="flex h-5 w-5 shrink-0 items-center justify-center text-muted disabled:opacity-40"
        >
          <svg
            viewBox="0 0 12 12"
            className={`h-3 w-3 transition-transform duration-150 ease-sw ${
              row.expanded && !filtering ? 'rotate-90' : ''
            }`}
            aria-hidden
          >
            <path
              d="M4.5 2.5l3.5 3.5-3.5 3.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.25"
            />
          </svg>
        </button>
      ) : (
        <span aria-hidden className="flex h-5 w-5 shrink-0 items-center justify-center text-faint">
          <span className="h-1 w-1 rounded-full bg-current" />
        </span>
      )}

      {renaming ? (
        <RenameInput initial={row.name} onCommit={onRename} onCancel={onCancelRename} />
      ) : (
        <span className={`flex-1 truncate ${row.kind === 'folder' ? 'text-ink' : 'text-muted'}`}>
          {row.name}
        </span>
      )}

      {wallet && !renaming && (
        <>
          {families.length > 0 && (
            <span className="shrink-0 text-[10px] tracking-[0.06em] text-faint uppercase">
              {families.map((f) => FAMILY_LABEL[f]).join('·')}
            </span>
          )}
          <Badge className="shrink-0">{kindLabel(wallet)}</Badge>
        </>
      )}
    </div>
  );
}

function RenameInput({
  initial,
  onCommit,
  onCancel,
}: {
  initial: string;
  onCommit: (name: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(initial);
  const committed = useRef(false);
  const finish = (commit: boolean) => {
    if (committed.current) return;
    committed.current = true;
    if (commit) onCommit(value);
    else onCancel();
  };
  return (
    <input
      autoFocus
      aria-label="Rename"
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onFocus={(e) => e.target.select()}
      onClick={(e) => e.stopPropagation()}
      onDoubleClick={(e) => e.stopPropagation()}
      onBlur={() => finish(true)}
      onKeyDown={(e) => {
        e.stopPropagation();
        if (e.key === 'Enter') finish(true);
        else if (e.key === 'Escape') finish(false);
      }}
      className="h-6 min-w-0 flex-1 rounded-sw-sm border border-edge-strong bg-paper px-1.5 font-mono text-[12px] text-ink outline-none"
      maxLength={80}
    />
  );
}
