import type {
  Account,
  ChainFamily,
  Folder,
  KeyGroup,
  Wallet,
  WalletKind,
} from '@stackwallet/core-client';

import { fuzzyMatch } from '../lib/format.js';
import type { DirectoryState } from './schema.js';

export type Node = { kind: 'folder'; folder: Folder } | { kind: 'wallet'; wallet: Wallet };

export function findNode(state: DirectoryState, id: string | null): Node | undefined {
  if (!id) return undefined;
  const folder = state.folders.find((f) => f.id === id);
  if (folder) return { kind: 'folder', folder };
  const wallet = state.wallets.find((w) => w.id === id);
  if (wallet) return { kind: 'wallet', wallet };
  return undefined;
}

const byName = <T extends { name: string }>(a: T, b: T) => a.name.localeCompare(b.name);

export function childFolders(state: DirectoryState, parentId: string): Folder[] {
  return state.folders.filter((f) => f.parentId === parentId).sort(byName);
}

export function walletsIn(state: DirectoryState, folderId: string): Wallet[] {
  return state.wallets.filter((w) => w.folderId === folderId).sort(byName);
}

export function accountsOf(state: DirectoryState, walletId: string): Account[] {
  return state.accounts.filter((a) => a.walletId === walletId);
}

/** Folder chain from the root down to (and including) the folder that holds `id`. */
export function pathTo(state: DirectoryState, id: string): Folder[] {
  const node = findNode(state, id);
  if (!node) return [];
  const path: Folder[] = [];
  const seen = new Set<string>();
  let cursor: string | null = node.kind === 'wallet' ? node.wallet.folderId : node.folder.id;
  while (cursor && !seen.has(cursor)) {
    seen.add(cursor);
    const f = state.folders.find((x) => x.id === cursor);
    if (!f) break;
    path.unshift(f);
    cursor = f.parentId;
  }
  return path;
}

export function descendantWallets(state: DirectoryState, folderId: string): Wallet[] {
  const out: Wallet[] = [];
  const stack = [folderId];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const id = stack.pop() as string;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(...walletsIn(state, id));
    for (const f of childFolders(state, id)) stack.push(f.id);
  }
  return out;
}

export function walletFamilies(state: DirectoryState, walletId: string): ChainFamily[] {
  const set = new Set<ChainFamily>();
  for (const a of accountsOf(state, walletId)) set.add(a.family);
  return [...set];
}

export function countByKind(state: DirectoryState): Record<WalletKind, number> {
  const counts: Record<WalletKind, number> = { tss: 0, single: 0, watch: 0, hardware: 0 };
  for (const w of state.wallets) counts[w.kind] += 1;
  return counts;
}

export function chainIdsInUse(state: DirectoryState): string[] {
  return [...new Set(state.accounts.map((a) => a.chainId))].sort();
}

/** Threshold label when the key group is known; otherwise the bare kind. */
export function kindLabel(wallet: Wallet, keyGroup?: KeyGroup): string {
  if (wallet.kind === 'tss' && keyGroup) {
    return `${keyGroup.threshold}-of-${keyGroup.parties.length}`;
  }
  return wallet.kind;
}

export interface TreeRow {
  id: string;
  kind: 'folder' | 'wallet';
  name: string;
  depth: number;
  parentId: string | null;
  expanded: boolean;
  hasChildren: boolean;
}

/**
 * Rows the tree renders, in display order. Without a filter the walk honors
 * expansion state; with one it ignores expansion and flattens every match so a
 * search never hides a hit inside a collapsed folder.
 */
export function flattenTree(state: DirectoryState, filter = ''): TreeRow[] {
  const root = state.folders.find((f) => f.parentId === null);
  if (!root) return [];
  const filtering = filter.trim() !== '';
  const expanded = new Set(state.ui.expandedFolderIds);
  const rows: TreeRow[] = [];
  const seen = new Set<string>();

  const walletMatches = (w: Wallet) =>
    fuzzyMatch(filter, w.name) ||
    accountsOf(state, w.id).some((a) => fuzzyMatch(filter, a.address));

  const visit = (folderId: string, depth: number) => {
    if (seen.has(folderId)) return;
    seen.add(folderId);
    for (const f of childFolders(state, folderId)) {
      const isOpen = expanded.has(f.id);
      const hasChildren =
        state.folders.some((x) => x.parentId === f.id) ||
        state.wallets.some((w) => w.folderId === f.id);
      if (!filtering || fuzzyMatch(filter, f.name)) {
        rows.push({
          id: f.id,
          kind: 'folder',
          name: f.name,
          depth: filtering ? 0 : depth,
          parentId: f.parentId,
          expanded: isOpen,
          hasChildren,
        });
      }
      if (filtering || isOpen) visit(f.id, depth + 1);
    }
    for (const w of walletsIn(state, folderId)) {
      if (filtering && !walletMatches(w)) continue;
      rows.push({
        id: w.id,
        kind: 'wallet',
        name: w.name,
        depth: filtering ? 0 : depth,
        parentId: w.folderId,
        expanded: false,
        hasChildren: false,
      });
    }
  };
  visit(root.id, 0);
  return rows;
}
