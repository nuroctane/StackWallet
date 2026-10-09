import type { Folder } from '@stackwallet/core-client';

import type { DirectoryState } from '../store/schema.js';
import { childFolders } from '../store/selectors.js';

interface FlatFolder {
  folder: Folder;
  depth: number;
}

/** Depth-first folder list, root first, for `<select>` menus. */
export function flattenFolders(state: DirectoryState): FlatFolder[] {
  const root = state.folders.find((f) => f.parentId === null);
  if (!root) return [];
  const out: FlatFolder[] = [];
  const seen = new Set<string>();
  const visit = (folder: Folder, depth: number) => {
    if (seen.has(folder.id)) return;
    seen.add(folder.id);
    out.push({ folder, depth });
    for (const child of childFolders(state, folder.id)) visit(child, depth + 1);
  };
  visit(root, 0);
  return out;
}

export function FolderOptions({ state }: { state: DirectoryState }) {
  return (
    <>
      {flattenFolders(state).map(({ folder, depth }) => (
        <option key={folder.id} value={folder.id}>
          {`${'\u00a0\u00a0'.repeat(depth)}${folder.name}`}
        </option>
      ))}
    </>
  );
}
