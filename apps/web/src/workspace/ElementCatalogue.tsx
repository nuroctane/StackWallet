import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Input, Popover } from '@stackwallet/ui';

import { fuzzyMatch } from '../lib/format.js';
import { ELEMENT_KINDS, registry } from './elements/registry.js';
import { workspace } from './persist.js';
import type { ElementKind } from './schema.js';
import type { Rect } from './store.js';

/** Searchable `> name  hint` list; Enter or click adds the element to the active layout. */
export function ElementCatalogue({
  anchor,
  open,
  onClose,
  viewport,
  at,
}: {
  anchor: HTMLElement | null;
  open: boolean;
  onClose: () => void;
  viewport: () => Rect;
  /** Canvas point to place the new pane at (double-click), else auto-placed. */
  at?: { x: number; y: number } | null;
}) {
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const listId = useId();
  const list = useRef<HTMLUListElement>(null);
  const items = useMemo(
    () =>
      ELEMENT_KINDS.map((k) => registry[k])
        .filter((d) => fuzzyMatch(query, d.title) || fuzzyMatch(query, d.hint))
        .sort((a, b) => Number(!fuzzyMatch(query, a.title)) - Number(!fuzzyMatch(query, b.title))),
    [query],
  );
  const clamped = Math.min(cursor, Math.max(0, items.length - 1));
  useEffect(() => {
    list.current?.children[clamped]?.scrollIntoView({ block: 'nearest' });
  }, [clamped, query]);

  const add = (kind: ElementKind) => {
    const d = registry[kind];
    workspace.addPane(
      { kind, props: { ...(d.defaultProps ?? {}) }, w: d.defaultSize.w, h: d.defaultSize.h },
      viewport(),
      at ?? undefined,
    );
    onClose();
    setQuery('');
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setCursor(Math.min(items.length - 1, clamped + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setCursor(Math.max(0, clamped - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const d = items[clamped];
      if (d) add(d.kind);
    }
  };

  return (
    <Popover
      anchor={anchor}
      open={open}
      onClose={onClose}
      align="start"
      label="Elements"
      width="w-[760px] max-w-[calc(100vw-16px)]"
    >
      <div className="flex flex-col">
        <div className="border-b border-edge p-1.5">
          <Input
            autoFocus
            dense
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setCursor(0);
            }}
            onKeyDown={onKeyDown}
            placeholder="search elements"
            aria-label="Search elements"
            role="combobox"
            aria-expanded={open}
            aria-controls={listId}
            aria-activedescendant={items[clamped] ? listId + '-' + items[clamped]!.kind : undefined}
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        <ul
          ref={list}
          id={listId}
          role="listbox"
          aria-label="Elements"
          className="max-h-[min(480px,60dvh)] overflow-auto p-1"
        >
          {items.length === 0 && (
            <li className="px-3 py-4 text-center text-[12px] text-faint">no matches</li>
          )}
          {items.map((d, i) => (
            <li
              key={d.kind}
              id={listId + '-' + d.kind}
              role="option"
              aria-selected={i === clamped}
              onMouseEnter={() => setCursor(i)}
              onClick={() => add(d.kind)}
              className={`flex min-h-11 cursor-pointer items-start gap-2 rounded-sw-sm px-2 py-2 text-[12px] ${
                i === clamped ? 'bg-hover' : ''
              }`}
            >
              <span className="w-3 shrink-0 text-faint">{'>'}</span>
              <span className="min-w-0 flex-1">
                <span className="block text-ink">{d.title}</span>
                <span className="block text-[11px] leading-relaxed break-words text-faint">
                  {d.hint}
                </span>
              </span>
              <span className="shrink-0 text-[10px] text-faint">
                {d.defaultSize.w}×{d.defaultSize.h}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </Popover>
  );
}
