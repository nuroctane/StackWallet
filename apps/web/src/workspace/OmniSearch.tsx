import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Chip, Dialog, Input, Kbd } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { useNames, walletLabel } from '../store/names.js';
import { presetsFor, themeStore, useThemeState } from '../store/theme.js';
import { fuzzyMatch } from '../lib/format.js';
import { listChains } from '../lib/chains.js';
import { activeDevices, useDevices } from '../store/devices.js';
import { directory, useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { kindLabel, pathTo } from '../store/selectors.js';
import { useShell } from '../shell/ShellContext.js';
import { ELEMENT_KINDS, registry } from './elements/registry.js';
import { workspace, useWorkspace } from './persist.js';
import type { ElementKind } from './schema.js';

export type ResultType = 'action' | 'element' | 'layout' | 'wallet' | 'folder' | 'device' | 'chain';

export interface SearchResult {
  id: string;
  type: ResultType;
  label: string;
  /** Dimmed suffix after the label: path, dimensions, hint. */
  dim?: string;
  run: () => void;
}

const TYPE_ORDER: ResultType[] = [
  'action',
  'wallet',
  'folder',
  'element',
  'layout',
  'device',
  'chain',
];

/** Rank: exact prefix first, then substring, then subsequence; stable within a tier. */
export function rank(query: string, results: readonly SearchResult[]): SearchResult[] {
  const q = query.trim().toLowerCase();
  if (q === '') return results.slice();
  const tier = (r: SearchResult): number => {
    const l = r.label.toLowerCase();
    if (l.startsWith(q)) return 0;
    if (l.includes(q)) return 1;
    if (fuzzyMatch(q, r.label)) return 2;
    if (r.dim && fuzzyMatch(q, r.dim)) return 3;
    return 9;
  };
  return results
    .map((r, i) => ({ r, i, t: tier(r) }))
    .filter((x) => x.t < 9)
    .sort((a, b) => a.t - b.t || a.i - b.i)
    .map((x) => x.r);
}

export function OmniSearch({
  open,
  onClose,
  viewport,
}: {
  open: boolean;
  onClose: () => void;
  viewport: () => { x: number; y: number; w: number; h: number };
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      width="w-[min(92vw,640px)]"
      className="mt-[10vh] mb-auto"
      aria-label="Search"
    >
      {open && <SearchBody onClose={onClose} viewport={viewport} />}
    </Dialog>
  );
}

function SearchBody({
  onClose,
  viewport,
}: {
  onClose: () => void;
  viewport: () => { x: number; y: number; w: number; h: number };
}) {
  const state = useDirectory();
  const ws = useWorkspace();
  const devices = useDevices();
  const registryCtx = useRegistry();
  const shell = useShell();
  const vaultView = useVaultView(vault);
  const theme = useThemeState();
  const names = useNames();
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);

  const addElement = (kind: ElementKind, props: Record<string, string | number | boolean> = {}) => {
    const d = registry[kind];
    workspace.addPane(
      {
        kind,
        props: { ...(d.defaultProps ?? {}), ...props },
        w: d.defaultSize.w,
        h: d.defaultSize.h,
      },
      viewport(),
    );
  };

  const openOrAdd = (
    kind: ElementKind,
    props: Record<string, string | number | boolean>,
    match: (p: Record<string, unknown>) => boolean,
  ) => {
    const existing = workspace.findPane(kind, match);
    if (existing) {
      workspace.raise(existing.id);
      workspace.focus(existing.id);
    } else {
      addElement(kind, props);
    }
  };

  const all = useMemo<SearchResult[]>(() => {
    const out: SearchResult[] = [];
    out.push(
      {
        id: 'a:watch',
        type: 'action',
        label: 'new watch wallet',
        run: () => shell.openDialog({ kind: 'watch' }),
      },
      {
        id: 'a:wallet',
        type: 'action',
        label: 'new wallet',
        dim: 'key sealed in the vault',
        run: () => shell.openDialog({ kind: 'newWallet' }),
      },
      {
        id: 'a:send',
        type: 'action',
        label: 'send',
        dim: 'propose a transfer for approval',
        run: () => shell.openDialog({ kind: 'send' }),
      },
      {
        id: 'a:importset',
        type: 'action',
        label: 'import set',
        dim: 'from a paired device',
        run: () => shell.openDialog({ kind: 'importSet' }),
      },
      {
        id: 'a:folder',
        type: 'action',
        label: 'new folder',
        run: () => shell.openDialog({ kind: 'folder' }),
      },
      {
        id: 'a:refresh',
        type: 'action',
        label: 'refresh balances',
        run: () => shell.refreshBalances(),
      },
      {
        id: 'a:lock',
        type: 'action',
        label: ws.locked ? 'unlock layout' : 'lock layout',
        dim: 'drag and resize',
        run: () => workspace.toggleLock(),
      },
      {
        id: 'a:vault',
        type: 'action',
        label:
          vaultView.status.kind === 'absent'
            ? 'create vault'
            : vaultView.status.kind === 'locked'
              ? 'unlock vault'
              : vaultView.status.kind === 'unlocked'
                ? 'lock vault'
                : 'vault',
        dim: 'device identity',
        run: () => {
          if (vaultView.status.kind === 'unlocked') void vault.lock();
          else shell.openDialog({ kind: 'vault' });
        },
      },
      {
        id: 'a:theme',
        type: 'action',
        label: 'theme studio',
        dim: 'presets and colours',
        run: () => shell.openDialog({ kind: 'theme' }),
      },
      {
        id: 'a:newlayout',
        type: 'action',
        label: 'new layout',
        run: () => workspace.addLayout(`layout ${ws.layouts.length + 1}`),
      },
      {
        id: 'a:export',
        type: 'action',
        label: 'copy layout json',
        dim: 'clipboard',
        run: () => {
          const data = workspace.exportLayout();
          if (data) void navigator.clipboard.writeText(JSON.stringify(data)).catch(() => undefined);
        },
      },
    );
    // Quick switch: a layout with its own theme takes the preset, otherwise the global theme does.
    const themeScope =
      ws.activeId in theme.layouts
        ? { kind: 'layout' as const, id: ws.activeId }
        : { kind: 'global' as const };
    for (const p of presetsFor(theme)) {
      out.push({
        id: `t:${p.id}`,
        type: 'action',
        label: `theme: ${p.name.toLowerCase()}`,
        dim: p.description,
        run: () => themeStore.setPreset(themeScope, p.id),
      });
    }
    for (const kind of ELEMENT_KINDS) {
      const d = registry[kind];
      out.push({
        id: `e:${kind}`,
        type: 'element',
        label: d.title,
        dim: d.hint,
        run: () => addElement(kind),
      });
    }
    for (const l of ws.layouts) {
      out.push({
        id: `l:${l.id}`,
        type: 'layout',
        label: l.name,
        dim: `${l.panes.length} elements`,
        run: () => workspace.setActive(l.id),
      });
    }
    for (const w of state.wallets) {
      out.push({
        id: `w:${w.id}`,
        type: 'wallet',
        // Search matches the resolved name and the user's own tag alike.
        label: walletLabel(names, w, state.accounts).text,
        dim: `${w.name} · ${pathTo(state, w.id)
          .slice(1)
          .map((p) => p.name)
          .join(' / ')} · ${kindLabel(w)}`,
        run: () => {
          directory.reveal(w.id);
          openOrAdd('wallet', { walletId: w.id }, (p) => p['walletId'] === w.id);
        },
      });
    }
    for (const f of state.folders) {
      if (f.parentId === null) continue;
      out.push({
        id: `f:${f.id}`,
        type: 'folder',
        label: f.name,
        dim: pathTo(state, f.id)
          .slice(1, -1)
          .map((p) => p.name)
          .join(' / '),
        run: () => {
          directory.reveal(f.id);
          openOrAdd('folder', { folderId: f.id }, (p) => p['folderId'] === f.id);
        },
      });
    }
    for (const d of activeDevices(devices)) {
      out.push({
        id: `d:${d.id}`,
        type: 'device',
        label: d.name,
        dim: d.kind,
        run: () => openOrAdd('devices', {}, () => true),
      });
    }
    for (const c of listChains(registryCtx)) {
      out.push({
        id: `c:${c.chainId}`,
        type: 'chain',
        label: c.name,
        dim: `${c.family} · ${c.nativeAsset.symbol}`,
        run: () => openOrAdd('holdings', { chainId: c.chainId }, (p) => p['chainId'] === c.chainId),
      });
    }
    return out;
    // `shell` is stable per layout; the lists rebuild when state changes.
  }, [state, ws, devices, registryCtx, shell, vaultView, theme, names]);

  const visible = useMemo(() => {
    const ranked = rank(query, all);
    if (query.trim() !== '') return ranked;
    // Empty query: group by type so the list reads like a catalogue.
    return ranked.slice().sort((a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type));
  }, [all, query]);
  const clamped = Math.min(cursor, Math.max(0, visible.length - 1));

  useEffect(() => {
    const el = listRef.current?.children[clamped];
    if (el instanceof HTMLElement) el.scrollIntoView({ block: 'nearest' });
  }, [clamped]);

  const choose = (item: SearchResult | undefined) => {
    if (!item) return;
    onClose();
    // Two modals cannot share the top layer; let this one close first.
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

  return (
    <div className="flex max-h-[64vh] flex-col">
      <div className="flex items-center gap-2 border-b border-edge p-2">
        <Input
          autoFocus
          dense
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setCursor(0);
          }}
          onKeyDown={onKeyDown}
          placeholder="search wallets, folders, elements, layouts, devices, chains, actions"
          aria-label="Search"
          spellCheck={false}
          autoComplete="off"
          role="combobox"
          aria-expanded
          aria-controls="omni-list"
        />
      </div>
      <ul id="omni-list" ref={listRef} role="listbox" className="min-h-0 flex-1 overflow-auto p-1">
        {visible.length === 0 && (
          <li className="px-3 py-6 text-center text-[12px] text-faint">no matches</li>
        )}
        {visible.map((item, i) => (
          <li
            key={item.id}
            role="option"
            aria-selected={i === clamped}
            onMouseEnter={() => setCursor(i)}
            onClick={() => choose(item)}
            className={`flex h-7 cursor-pointer items-center gap-2 rounded-sw-sm px-2 text-[12px] ${
              i === clamped ? 'bg-hover' : ''
            }`}
          >
            <span className="w-3 shrink-0 text-faint">{'>'}</span>
            <span className="shrink-0 truncate text-ink">{item.label}</span>
            {item.dim && (
              <span className="min-w-0 flex-1 truncate text-[11px] text-faint">{item.dim}</span>
            )}
            {!item.dim && <span className="flex-1" />}
            <Chip className="shrink-0">{item.type}</Chip>
          </li>
        ))}
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
        <span className="ml-auto">{visible.length} results</span>
      </div>
    </div>
  );
}
