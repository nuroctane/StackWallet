/**
 * Which wallets a report covers. Three narrowing steps, in order: what kind
 * of wallet (watched, imported, exported …; any of the chosen kinds), where
 * it lives (any of the chosen directories, subfolders included), then any
 * wallet the user unticks by hand. An empty step does not narrow.
 */

export const SCOPE_TAGS = [
  'watched',
  'imported',
  'exported',
  'local',
  'hardware',
  'shared',
] as const;
export type ScopeTag = (typeof SCOPE_TAGS)[number];

export const SCOPE_TAG_TEXT: Readonly<Record<ScopeTag, string>> = {
  watched: 'watched',
  imported: 'imported',
  exported: 'exported',
  local: 'local keys',
  hardware: 'hardware',
  shared: 'shared',
};

export const SCOPE_TAG_HELP: Readonly<Record<ScopeTag, string>> = {
  watched: 'Watch-only addresses: no key on this device.',
  imported: 'Restored from a phrase, or received from another device, alone or inside a set.',
  exported: 'Sent to another StackWallet device, alone or as part of a directory set.',
  local: 'Single-key wallets whose key never left this vault.',
  hardware: 'Ledger and other hardware signers.',
  shared: 'Threshold wallets shared between devices.',
};

export interface ScopeWallet {
  id: string;
  name: string;
  kind: string;
  folderId: string;
  imported: boolean;
  exported: boolean;
}

export interface ScopeFolder {
  id: string;
  parentId: string | null;
  name: string;
  imported: boolean;
  exported: boolean;
}

export interface ScopeFilter {
  tags: ScopeTag[];
  folderIds: string[];
  excluded: string[];
}

export const EMPTY_SCOPE: ScopeFilter = { tags: [], folderIds: [], excluded: [] };

function ancestors(folders: ReadonlyMap<string, ScopeFolder>, id: string): ScopeFolder[] {
  const out: ScopeFolder[] = [];
  const seen = new Set<string>();
  let cur = folders.get(id);
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id);
    out.push(cur);
    cur = cur.parentId ? folders.get(cur.parentId) : undefined;
  }
  return out;
}

export function walletTagsOf(
  w: ScopeWallet,
  folders: ReadonlyMap<string, ScopeFolder>,
): Set<ScopeTag> {
  const chain = ancestors(folders, w.folderId);
  const tags = new Set<ScopeTag>();
  if (w.kind === 'watch') tags.add('watched');
  if (w.kind === 'hardware') tags.add('hardware');
  if (w.kind === 'tss') tags.add('shared');
  if (w.imported || chain.some((f) => f.imported)) tags.add('imported');
  if (w.exported || chain.some((f) => f.exported)) tags.add('exported');
  if (w.kind === 'single' && !tags.has('imported') && !tags.has('exported')) tags.add('local');
  return tags;
}

export interface ResolvedScope {
  /** Wallets passing the kind and directory steps; the list the user ticks from. */
  candidates: ScopeWallet[];
  included: ScopeWallet[];
}

export function resolveScope(
  filter: ScopeFilter,
  wallets: readonly ScopeWallet[],
  folderList: readonly ScopeFolder[],
): ResolvedScope {
  const folders = new Map(folderList.map((f) => [f.id, f]));
  const candidates = wallets.filter((w) => {
    if (filter.tags.length > 0) {
      const tags = walletTagsOf(w, folders);
      if (!filter.tags.some((t) => tags.has(t))) return false;
    }
    if (filter.folderIds.length > 0) {
      const chain = new Set(ancestors(folders, w.folderId).map((f) => f.id));
      if (!filter.folderIds.some((id) => chain.has(id))) return false;
    }
    return true;
  });
  const excluded = new Set(filter.excluded);
  return { candidates, included: candidates.filter((w) => !excluded.has(w.id)) };
}

export function describeScope(
  filter: ScopeFilter,
  folderList: readonly ScopeFolder[],
  included: number,
  candidates: number,
): string {
  const parts: string[] = [];
  parts.push(
    filter.tags.length === 0
      ? 'all wallets'
      : filter.tags.map((t) => SCOPE_TAG_TEXT[t]).join(' or ') + ' wallets',
  );
  if (filter.folderIds.length > 0) {
    const names = filter.folderIds
      .map((id) => folderList.find((f) => f.id === id)?.name)
      .filter((n): n is string => !!n);
    parts.push('in ' + names.join(', '));
  }
  if (included !== candidates) parts.push(`${included} of ${candidates} selected`);
  return parts.join(' · ');
}
