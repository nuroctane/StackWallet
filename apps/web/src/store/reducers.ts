import {
  ChainId,
  chainFamilyOf,
  type Account,
  type Folder,
  type Wallet,
} from '@stackwallet/core-client';

import type { DirectoryState } from './schema.js';

export const ROOT_FOLDER_NAME = 'Wallets';

export interface ReducerContext {
  now: () => number;
  newId: () => string;
}

export type Failure = { ok: false; error: string };
export type Success<T> = { ok: true; state: DirectoryState; value: T };
export type Outcome<T = undefined> = Success<T> | Failure;

const fail = (error: string): Failure => ({ ok: false, error });
const ok = <T>(state: DirectoryState, value: T): Success<T> => ({ ok: true, state, value });

export function emptyState(ctx: ReducerContext): DirectoryState {
  const t = ctx.now();
  return {
    version: 1,
    folders: [
      {
        id: ctx.newId(),
        parentId: null,
        name: ROOT_FOLDER_NAME,
        tags: [],
        defaultPolicyIds: [],
        createdAtMs: t,
        updatedAtMs: t,
      },
    ],
    wallets: [],
    accounts: [],
    ui: { expandedFolderIds: [], selectedId: null },
  };
}

export function rootOf(state: DirectoryState): Folder {
  const root = state.folders.find((f) => f.parentId === null);
  if (!root) throw new Error('directory has no root folder');
  return root;
}

/**
 * A blob can be schema-valid yet structurally broken (missing root, orphaned
 * nodes, dangling ui references). Repair instead of refusing so the user never
 * loses sight of a wallet because of one bad write.
 */
export function ensureRoot(state: DirectoryState, ctx: ReducerContext): DirectoryState {
  let folders = state.folders;
  let root = folders.find((f) => f.parentId === null);
  if (!root) {
    root = emptyState(ctx).folders[0] as Folder;
    folders = [root, ...folders];
  }
  const rootId = root.id;
  const ids = new Set(folders.map((f) => f.id));
  const repairedFolders = folders.map((f) => {
    if (f.parentId === null) return f.id === rootId ? f : { ...f, parentId: rootId };
    return ids.has(f.parentId) && f.parentId !== f.id ? f : { ...f, parentId: rootId };
  });
  const wallets = state.wallets.map((w) => (ids.has(w.folderId) ? w : { ...w, folderId: rootId }));
  const walletIds = new Set(wallets.map((w) => w.id));
  const accounts = state.accounts.filter((a) => walletIds.has(a.walletId));
  const known = new Set([...ids, ...walletIds]);
  const ui = {
    expandedFolderIds: state.ui.expandedFolderIds.filter((id) => ids.has(id)),
    selectedId: state.ui.selectedId && known.has(state.ui.selectedId) ? state.ui.selectedId : null,
  };
  return { ...state, folders: repairedFolders, wallets, accounts, ui };
}

function folderById(state: DirectoryState, id: string): Folder | undefined {
  return state.folders.find((f) => f.id === id);
}

function walletById(state: DirectoryState, id: string): Wallet | undefined {
  return state.wallets.find((w) => w.id === id);
}

function cleanName(name: string, what: string): string | Failure {
  const trimmed = name.trim();
  if (trimmed === '') return fail(`${what} name is required`);
  if (trimmed.length > 80) return fail(`${what} name is too long`);
  return trimmed;
}

function withExpanded(state: DirectoryState, id: string, expanded: boolean): DirectoryState {
  const has = state.ui.expandedFolderIds.includes(id);
  if (has === expanded) return state;
  return {
    ...state,
    ui: {
      ...state.ui,
      expandedFolderIds: expanded
        ? [...state.ui.expandedFolderIds, id]
        : state.ui.expandedFolderIds.filter((x) => x !== id),
    },
  };
}

export function createFolder(
  state: DirectoryState,
  name: string,
  parentId: string,
  ctx: ReducerContext,
): Outcome<string> {
  const clean = cleanName(name, 'Folder');
  if (typeof clean !== 'string') return clean;
  if (!folderById(state, parentId)) return fail('Parent folder not found');
  const dup = state.folders.some(
    (f) => f.parentId === parentId && f.name.toLowerCase() === clean.toLowerCase(),
  );
  if (dup) return fail('A folder with this name already exists here');
  const t = ctx.now();
  const folder: Folder = {
    id: ctx.newId(),
    parentId,
    name: clean,
    tags: [],
    defaultPolicyIds: [],
    createdAtMs: t,
    updatedAtMs: t,
  };
  let next: DirectoryState = { ...state, folders: [...state.folders, folder] };
  next = withExpanded(next, parentId, true);
  next = { ...next, ui: { ...next.ui, selectedId: folder.id } };
  return ok(next, folder.id);
}

export function renameNode(
  state: DirectoryState,
  id: string,
  name: string,
  ctx: ReducerContext,
): Outcome {
  const folder = folderById(state, id);
  const wallet = walletById(state, id);
  if (!folder && !wallet) return fail('Nothing to rename');
  const clean = cleanName(name, folder ? 'Folder' : 'Wallet');
  if (typeof clean !== 'string') return clean;
  const t = ctx.now();
  if (folder) {
    if (folder.name === clean) return ok(state, undefined);
    return ok(
      {
        ...state,
        folders: state.folders.map((f) =>
          f.id === id ? { ...f, name: clean, updatedAtMs: t } : f,
        ),
      },
      undefined,
    );
  }
  if (wallet?.name === clean) return ok(state, undefined);
  return ok(
    {
      ...state,
      wallets: state.wallets.map((w) => (w.id === id ? { ...w, name: clean, updatedAtMs: t } : w)),
    },
    undefined,
  );
}

function dropFromUi(state: DirectoryState, id: string): DirectoryState {
  return {
    ...state,
    ui: {
      expandedFolderIds: state.ui.expandedFolderIds.filter((x) => x !== id),
      selectedId: state.ui.selectedId === id ? null : state.ui.selectedId,
    },
  };
}

export function deleteFolder(state: DirectoryState, id: string): Outcome {
  const folder = folderById(state, id);
  if (!folder) return fail('Folder not found');
  if (folder.parentId === null) return fail('The root folder cannot be deleted');
  if (state.folders.some((f) => f.parentId === id)) {
    return fail('Folder has subfolders; move or delete them first');
  }
  if (state.wallets.some((w) => w.folderId === id)) {
    return fail('Folder contains wallets; move or delete them first');
  }
  return ok(
    dropFromUi({ ...state, folders: state.folders.filter((f) => f.id !== id) }, id),
    undefined,
  );
}

export function moveWallet(
  state: DirectoryState,
  walletId: string,
  folderId: string,
  ctx: ReducerContext,
): Outcome {
  const wallet = walletById(state, walletId);
  if (!wallet) return fail('Wallet not found');
  if (!folderById(state, folderId)) return fail('Target folder not found');
  if (wallet.folderId === folderId) return ok(state, undefined);
  const t = ctx.now();
  const next: DirectoryState = {
    ...state,
    wallets: state.wallets.map((w) => (w.id === walletId ? { ...w, folderId, updatedAtMs: t } : w)),
  };
  return ok(withExpanded(next, folderId, true), undefined);
}

export const MAX_TAGS = 8;
export const MAX_TAG_LENGTH = 24;
const TAG_PATTERN = /^[a-z0-9-]+$/;

/** Lowercased, trimmed, de-duplicated tags in first-seen order; empty entries drop out. */
export function normalizeTags(tags: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of tags) {
    const tag = raw.trim().toLowerCase();
    if (tag === '' || seen.has(tag)) continue;
    seen.add(tag);
    out.push(tag);
  }
  return out;
}

export function setWalletTags(
  state: DirectoryState,
  walletId: string,
  tags: readonly string[],
  ctx: ReducerContext,
): Outcome {
  const wallet = walletById(state, walletId);
  if (!wallet) return fail('Wallet not found');
  const clean = normalizeTags(tags);
  if (clean.length > MAX_TAGS) return fail(`At most ${MAX_TAGS} tags per wallet`);
  for (const tag of clean) {
    if (tag.length > MAX_TAG_LENGTH) return fail(`Tag "${tag}" is too long`);
    if (!TAG_PATTERN.test(tag)) return fail('Tags may use letters, digits and dashes only');
  }
  if (clean.length === wallet.tags.length && clean.every((t, i) => t === wallet.tags[i])) {
    return ok(state, undefined);
  }
  const t = ctx.now();
  return ok(
    {
      ...state,
      wallets: state.wallets.map((w) =>
        w.id === walletId ? { ...w, tags: clean, updatedAtMs: t } : w,
      ),
    },
    undefined,
  );
}

export interface WatchWalletInput {
  name: string;
  folderId: string;
  chainId: string;
  address: string;
}

export function createWatchWallet(
  state: DirectoryState,
  input: WatchWalletInput,
  ctx: ReducerContext,
): Outcome<string> {
  const clean = cleanName(input.name, 'Wallet');
  if (typeof clean !== 'string') return clean;
  if (!folderById(state, input.folderId)) return fail('Folder not found');
  const chain = ChainId.safeParse(input.chainId);
  if (!chain.success) return fail('Chain id must be CAIP-2 (namespace:reference)');
  const family = chainFamilyOf(chain.data);
  if (!family) return fail('Unsupported chain namespace');
  // Chain-specific validation belongs to the adapter; the store only refuses
  // input no supported address format could ever produce.
  const address = input.address.trim();
  if (address === '') return fail('Address is required');
  if (address.length > 128 || !/^[A-Za-z0-9]+$/.test(address)) {
    return fail('Address contains unexpected characters');
  }

  const t = ctx.now();
  const wallet: Wallet = {
    id: ctx.newId(),
    folderId: input.folderId,
    name: clean,
    kind: 'watch',
    keyGroupId: null,
    tags: [],
    createdAtMs: t,
    updatedAtMs: t,
  };
  const account: Account = {
    id: ctx.newId(),
    walletId: wallet.id,
    family,
    chainId: chain.data,
    address,
    publicKeyHex: '',
    hidden: false,
  };
  let next: DirectoryState = {
    ...state,
    wallets: [...state.wallets, wallet],
    accounts: [...state.accounts, account],
  };
  next = withExpanded(next, input.folderId, true);
  next = { ...next, ui: { ...next.ui, selectedId: wallet.id } };
  return ok(next, wallet.id);
}

export function deleteWallet(state: DirectoryState, walletId: string): Outcome {
  if (!walletById(state, walletId)) return fail('Wallet not found');
  return ok(
    dropFromUi(
      {
        ...state,
        wallets: state.wallets.filter((w) => w.id !== walletId),
        accounts: state.accounts.filter((a) => a.walletId !== walletId),
      },
      walletId,
    ),
    undefined,
  );
}

export function toggleFolder(state: DirectoryState, id: string): DirectoryState {
  if (!folderById(state, id)) return state;
  return withExpanded(state, id, !state.ui.expandedFolderIds.includes(id));
}

export function setFolderExpanded(
  state: DirectoryState,
  id: string,
  expanded: boolean,
): DirectoryState {
  if (!folderById(state, id)) return state;
  return withExpanded(state, id, expanded);
}

export function select(state: DirectoryState, id: string | null): DirectoryState {
  const target = id && (folderById(state, id) || walletById(state, id)) ? id : null;
  if (state.ui.selectedId === target) return state;
  return { ...state, ui: { ...state.ui, selectedId: target } };
}

/** Expands every ancestor folder (excluding the implicit root) so `id` is visible in the tree. */
export function expandTo(state: DirectoryState, id: string): DirectoryState {
  const wallet = walletById(state, id);
  const folder = folderById(state, id);
  let cursor: string | null = wallet ? wallet.folderId : (folder?.parentId ?? null);
  const toExpand: string[] = [];
  const seen = new Set<string>();
  while (cursor && !seen.has(cursor)) {
    seen.add(cursor);
    const f = folderById(state, cursor);
    if (!f || f.parentId === null) break;
    toExpand.push(f.id);
    cursor = f.parentId;
  }
  const missing = toExpand.filter((x) => !state.ui.expandedFolderIds.includes(x));
  if (missing.length === 0) return state;
  return {
    ...state,
    ui: { ...state.ui, expandedFolderIds: [...state.ui.expandedFolderIds, ...missing] },
  };
}
