import { Account, ChainId, chainFamilyOf, Folder, Wallet } from '@stackwallet/core-client';
import { z } from 'zod';

import { rootOf, type Outcome, type ReducerContext } from './reducers.js';
import type { DirectoryState } from './schema.js';

/**
 * The directory half of a set transfer: a folder, its descendants, their
 * wallets and accounts. The core carries this opaquely inside the sealed
 * bundle; it is parsed again here on arrival because a paired device is
 * trusted to be who it is, not to be bug-free.
 */
export const SetPayload = z.object({
  stackwalletSet: z.literal(1),
  folders: Folder.array().min(1).max(10_000),
  wallets: Wallet.array().max(10_000),
  accounts: Account.array().max(50_000),
});
export type SetPayload = z.infer<typeof SetPayload>;

const fail = (error: string) => ({ ok: false as const, error });

/** Ids of `folderId` and every folder beneath it, parent first. */
export function subtree(state: DirectoryState, folderId: string): string[] {
  const out = [folderId];
  for (let i = 0; i < out.length; i++) {
    for (const f of state.folders) if (f.parentId === out[i]) out.push(f.id);
  }
  return out;
}

export function exportPayload(
  state: DirectoryState,
  folderId: string,
): { payload: SetPayload; walletIds: string[] } | { error: string } {
  const folder = state.folders.find((f) => f.id === folderId);
  if (!folder) return { error: 'Folder not found' };
  if (folder.parentId === null) return { error: 'Pick a folder inside the root to transfer' };
  const ids = new Set(subtree(state, folderId));
  const folders = state.folders.filter((f) => ids.has(f.id));
  const wallets = state.wallets.filter((w) => ids.has(w.folderId));
  const walletIds = new Set(wallets.map((w) => w.id));
  const accounts = state.accounts.filter((a) => walletIds.has(a.walletId));
  return {
    payload: { stackwalletSet: 1, folders, wallets, accounts },
    walletIds: [...walletIds],
  };
}

/**
 * Merge an arrived set under the root. Refuses id collisions instead of
 * renaming: a collision means this set (or part of it) is already here, and
 * silently duplicating keys is exactly what provenance exists to prevent.
 */
export function importPayload(
  state: DirectoryState,
  raw: unknown,
  setFolderId: string,
  ctx: ReducerContext,
): Outcome<string> {
  const parsed = SetPayload.safeParse(raw);
  if (!parsed.success) return fail('The set did not match the directory format');
  const p = parsed.data;
  const top = p.folders.find((f) => f.id === setFolderId);
  if (!top) return fail('The set is missing its top folder');

  const folderIds = new Set(p.folders.map((f) => f.id));
  if (folderIds.size !== p.folders.length) return fail('The set repeats a folder');
  for (const f of p.folders) {
    if (f.id !== setFolderId && (f.parentId === null || !folderIds.has(f.parentId))) {
      return fail('The set has a folder outside itself');
    }
  }
  const walletIds = new Set(p.wallets.map((w) => w.id));
  if (walletIds.size !== p.wallets.length) return fail('The set repeats a wallet');
  for (const w of p.wallets) {
    if (!folderIds.has(w.folderId)) return fail('The set has a wallet outside itself');
  }
  for (const a of p.accounts) {
    if (!walletIds.has(a.walletId)) return fail('The set has an account outside itself');
    const chain = ChainId.safeParse(a.chainId);
    if (!chain.success || chainFamilyOf(chain.data) !== a.family) {
      return fail('The set has an account on an unknown chain');
    }
  }
  const taken = new Set([
    ...state.folders.map((f) => f.id),
    ...state.wallets.map((w) => w.id),
    ...state.accounts.map((a) => a.id),
  ]);
  const incoming = [...folderIds, ...walletIds, ...p.accounts.map((a) => a.id)];
  if (incoming.some((id) => taken.has(id))) return fail('Part of this set is already here');

  const t = ctx.now();
  const root = rootOf(state);
  const folders = p.folders.map((f) =>
    f.id === setFolderId ? { ...f, parentId: root.id, updatedAtMs: t } : f,
  );
  return {
    ok: true,
    state: {
      ...state,
      folders: [...state.folders, ...folders],
      wallets: [...state.wallets, ...p.wallets],
      accounts: [...state.accounts, ...p.accounts],
      ui: {
        ...state.ui,
        expandedFolderIds: [...new Set([...state.ui.expandedFolderIds, root.id, setFolderId])],
        selectedId: setFolderId,
      },
    },
    value: setFolderId,
  };
}

export interface KeyedAccountInput {
  chainId: string;
  address: string;
  derivationPath: string;
  publicKeyHex: string;
}

/** A `single` wallet whose key the core already sealed under `walletId`. */
export function createKeyedWallet(
  state: DirectoryState,
  input: { walletId: string; name: string; folderId: string; accounts: KeyedAccountInput[] },
  ctx: ReducerContext,
): Outcome<string> {
  const name = input.name.trim().slice(0, 80) || 'Wallet';
  if (!state.folders.some((f) => f.id === input.folderId)) return fail('Folder not found');
  if (state.wallets.some((w) => w.id === input.walletId)) return fail('Wallet id is taken');
  if (input.accounts.length === 0) return fail('Pick at least one chain');
  const t = ctx.now();
  const accounts: Account[] = [];
  for (const a of input.accounts) {
    const chain = ChainId.safeParse(a.chainId);
    const family = chain.success ? chainFamilyOf(chain.data) : null;
    if (!chain.success || !family) return fail(`Unsupported chain ${a.chainId}`);
    accounts.push({
      id: ctx.newId(),
      walletId: input.walletId,
      family,
      chainId: chain.data,
      address: a.address,
      derivationPath: a.derivationPath,
      publicKeyHex: a.publicKeyHex,
      hidden: false,
    });
  }
  const wallet: Wallet = {
    id: input.walletId,
    folderId: input.folderId,
    name,
    kind: 'single',
    keyGroupId: null,
    tags: [],
    createdAtMs: t,
    updatedAtMs: t,
  };
  return {
    ok: true,
    state: {
      ...state,
      wallets: [...state.wallets, wallet],
      accounts: [...state.accounts, ...accounts],
      ui: {
        ...state.ui,
        expandedFolderIds: [...new Set([...state.ui.expandedFolderIds, input.folderId])],
        selectedId: wallet.id,
      },
    },
    value: wallet.id,
  };
}
