import { useCallback, useEffect, useState, type KeyboardEvent } from 'react';

import { Chip, Popover } from '@stackwallet/ui';

import { isTypingTarget } from '../shell/ShellContext.js';
import { useWorkspace, workspace } from './persist.js';

interface Menu {
  id: string;
  anchor: HTMLElement;
}

interface Rename {
  id: string;
  value: string;
}

const menuItem =
  'sw-pressable flex h-6 w-full items-center rounded-[4px] px-2 text-left text-[12px] lowercase text-ink disabled:cursor-not-allowed disabled:opacity-40';

export function LayoutTabs() {
  const { layouts, activeId } = useWorkspace();
  const [menu, setMenu] = useState<Menu | null>(null);
  const [rename, setRename] = useState<Rename | null>(null);

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
      if (e.key < '1' || e.key > '9' || isTypingTarget(e.target)) return;
      const target = workspace.getSnapshot().layouts[Number(e.key) - 1];
      if (!target) return;
      e.preventDefault();
      workspace.setActive(target.id);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const startRename = useCallback((id: string) => {
    const layout = workspace.getSnapshot().layouts.find((l) => l.id === id);
    if (layout) setRename({ id, value: layout.name });
    setMenu(null);
  }, []);

  const commitRename = useCallback(() => {
    if (!rename) return;
    workspace.renameLayout(rename.id, rename.value);
    setRename(null);
  }, [rename]);

  const onRenameKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') commitRename();
    else if (e.key === 'Escape') {
      e.stopPropagation();
      setRename(null);
    }
  };

  const exportLayout = (id: string) => {
    const data = workspace.exportLayout(id);
    if (data && typeof navigator !== 'undefined' && navigator.clipboard) {
      void navigator.clipboard.writeText(JSON.stringify(data, null, 2)).catch(() => undefined);
    }
    setMenu(null);
  };

  return (
    <div
      role="tablist"
      aria-label="layouts"
      className="sw-tabs flex h-6 flex-none items-center gap-1 border-b border-edge bg-paper px-2 font-mono"
    >
      {layouts.map((layout, i) => {
        const active = layout.id === activeId;
        return (
          <span
            key={layout.id}
            className="inline-flex flex-none items-center"
            onDoubleClick={() => startRename(layout.id)}
          >
            {rename?.id === layout.id ? (
              <input
                autoFocus
                value={rename.value}
                aria-label="layout name"
                maxLength={60}
                size={Math.max(4, rename.value.length)}
                onChange={(e) => setRename({ id: layout.id, value: e.target.value })}
                onKeyDown={onRenameKey}
                onBlur={commitRename}
                className="h-5 rounded-sw-sm border border-edge-strong bg-elevated px-1.5 text-[11px] text-ink outline-none"
              />
            ) : (
              <Chip
                active={active}
                onClick={() => workspace.setActive(layout.id)}
                title={i < 9 ? `${layout.name} (ctrl+${i + 1})` : layout.name}
                role="tab"
                aria-selected={active}
              >
                {layout.name}
              </Chip>
            )}
            <button
              type="button"
              className="sw-pressable inline-flex h-5 w-4 items-center justify-center rounded-[3px] text-[11px] text-faint hover:text-ink"
              aria-label={`${layout.name} menu`}
              aria-haspopup="dialog"
              aria-expanded={menu?.id === layout.id}
              onClick={(e) =>
                setMenu(menu?.id === layout.id ? null : { id: layout.id, anchor: e.currentTarget })
              }
            >
              ⋮
            </button>
          </span>
        );
      })}

      <button
        type="button"
        className="sw-pressable inline-flex h-5 w-5 flex-none items-center justify-center rounded-sw-sm border border-edge text-[12px] text-muted hover:text-ink"
        aria-label="new layout"
        title="new layout"
        onClick={() => workspace.addLayout(`layout ${layouts.length + 1}`)}
      >
        +
      </button>

      <Popover
        anchor={menu?.anchor ?? null}
        open={menu !== null}
        onClose={() => setMenu(null)}
        label="layout menu"
        width="w-[150px]"
      >
        {menu && (
          <div className="flex flex-col">
            <button type="button" className={menuItem} onClick={() => startRename(menu.id)}>
              rename
            </button>
            <button
              type="button"
              className={menuItem}
              onClick={() => {
                workspace.duplicateLayout(menu.id);
                setMenu(null);
              }}
            >
              duplicate
            </button>
            <button type="button" className={menuItem} onClick={() => exportLayout(menu.id)}>
              export
            </button>
            <button
              type="button"
              className={`${menuItem} text-danger`}
              disabled={layouts.length <= 1}
              onClick={() => {
                workspace.removeLayout(menu.id);
                setMenu(null);
              }}
            >
              delete
            </button>
          </div>
        )}
      </Popover>
    </div>
  );
}
