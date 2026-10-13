import { Account, ChainId, chainFamilyOf, Folder, Wallet } from '@stackwallet/core-client';
import { z } from 'zod';

import { MAX_TAGS, normalizeTags, rootOf, type Outcome, type ReducerContext } from './reducers.js';
import type { DirectoryState } from './schema.js';
import { MAX_TAG_DEFS, TagDef, isReservedTagWord, type TagDef as TagDefT } from './tagDefs.js';
import { LayoutExport, MAX_LAYOUTS } from '../workspace/schema.js';

/**
 * The directory half of a set transfer: a folder, its descendants, their
 * wallets and accounts, the looks of their user tags and every layout that
 * shows them. The core carries this opaquely inside the sealed bundle; it is
 * parsed again here on arrival because a paired device is trusted to be who
 * it is, not to be bug-free.
 */
export const SetPayload = z.object({
  stackwalletSet: z.literal(1),
  folders: Folder.array().min(1).max(10_000),
  wallets: Wallet.array().max(10_000),
  accounts: Account.array().max(50_000),
  tagDefs: TagDef.array().max(MAX_TAG_DEFS).default([]),
  layouts: LayoutExport.array().max(MAX_LAYOUTS).default([]),
});
export type SetPayload = z.infer<typeof SetPayload>;

const fail = (error: string) => ({ ok: false as const, error });

/** Ids of `folderId` and every folder beneath it, parent first. */
export function subtree(state: DirectoryState, folderId: string): string[] {
  const out = [folderId];
  const seen = new Set(out);
  const children = new Map<string | null, string[]>();
  for (const f of state.folders) {
    const list = children.get(f.parentId) ?? [];
    list.push(f.id);
    children.set(f.parentId, list);
  }
  for (let i = 0; i < out.length; i++) {
    for (const id of children.get(out[i]!) ?? [])
      if (!seen.has(id)) {
        seen.add(id);
        out.push(id);
      }
  }
  return out;
}

export function exportPayload(
  state: DirectoryState,
  folderId: string,
  layouts: LayoutExport[] = [],
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
    payload: {
      stackwalletSet: 1,
      folders,
      wallets,
      accounts,
      tagDefs: usedTagDefs(state, wallets),
      layouts,
    },
    walletIds: [...walletIds],
  };
}

function usedTagDefs(state: DirectoryState, wallets: readonly { tags: string[] }[]): TagDefT[] {
  const used = new Set(wallets.flatMap((w) => w.tags));
  return state.tagDefs.filter((d) => used.has(d.id));
}

/** Add the sender's tag looks without overriding any this instance already set. */
function mergeTagDefs(state: DirectoryState, incoming: readonly TagDefT[]): DirectoryState {
  const defs = [...state.tagDefs];
  for (const d of incoming)
    if (
      !defs.some((x) => x.id === d.id) &&
      !isReservedTagWord(d.label) &&
      defs.length < MAX_TAG_DEFS
    )
      defs.push(d);
  return defs.length === state.tagDefs.length ? state : { ...state, tagDefs: defs };
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
  if (subtree({ ...state, folders: p.folders }, setFolderId).length !== p.folders.length)
    return fail('The set has cyclic or disconnected folders');
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
  if (new Set(incoming).size !== incoming.length) return fail('The set repeats an entity id');
  if (incoming.some((id) => taken.has(id))) return fail('Part of this set is already here');

  const t = ctx.now();
  const root = rootOf(state);
  const folders = p.folders.map((f) =>
    f.id === setFolderId ? { ...f, parentId: root.id, updatedAtMs: t } : f,
  );
  return {
    ok: true,
    state: mergeTagDefs(
      {
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
      p.tagDefs,
    ),
    value: setFolderId,
  };
}

/** Layouts that arrived with a set; parsed again before the workspace sees them. */
export function payloadLayouts(raw: unknown): LayoutExport[] {
  const parsed = SetPayload.safeParse(raw);
  return parsed.success ? parsed.data.layouts : [];
}

/**
 * One wallet exported on its own: the wallet, its accounts and the looks of
 * its tags. Its folder and the wallets beside it are not part of it.
 */
export const WalletPayload = z.object({
  stackwalletWallet: z.literal(1),
  wallet: Wallet,
  accounts: Account.array().min(1).max(256),
  tagDefs: TagDef.array().max(MAX_TAG_DEFS).default([]),
});
export type WalletPayload = z.infer<typeof WalletPayload>;

export function exportWalletPayload(
  state: DirectoryState,
  walletId: string,
): { payload: WalletPayload; folderId: string } | { error: string } {
  const wallet = state.wallets.find((w) => w.id === walletId);
  if (!wallet) return { error: 'Wallet not found' };
  const accounts = state.accounts.filter((a) => a.walletId === walletId);
  if (accounts.length === 0) return { error: 'This wallet has no accounts to export' };
  return {
    payload: {
      stackwalletWallet: 1,
      wallet,
      accounts,
      tagDefs: usedTagDefs(state, [wallet]),
    },
    folderId: wallet.folderId,
  };
}

/** Place an arrived wallet directly under this instance's root folder. */
export function importWalletPayload(
  state: DirectoryState,
  raw: unknown,
  ctx: ReducerContext,
): Outcome<string> {
  const parsed = WalletPayload.safeParse(raw);
  if (!parsed.success) return fail('The wallet did not match the directory format');
  const { wallet, accounts, tagDefs } = parsed.data;
  if (accounts.some((a) => a.walletId !== wallet.id))
    return fail('The wallet has an account that belongs elsewhere');
  for (const a of accounts) {
    const chain = ChainId.safeParse(a.chainId);
    if (!chain.success || chainFamilyOf(chain.data) !== a.family)
      return fail('The wallet has an account on an unknown chain');
  }
  const taken = new Set([...state.wallets.map((w) => w.id), ...state.accounts.map((a) => a.id)]);
  if (taken.has(wallet.id) || accounts.some((a) => taken.has(a.id)))
    return fail('This wallet is already here');
  const root = rootOf(state).id;
  const t = ctx.now();
  return {
    ok: true,
    state: mergeTagDefs(
      {
        ...state,
        wallets: [...state.wallets, { ...wallet, folderId: root, updatedAtMs: t }],
        accounts: [...state.accounts, ...accounts],
        ui: { ...state.ui, selectedId: wallet.id },
      },
      tagDefs,
    ),
    value: wallet.id,
  };
}

const addrKey = (chainId: string, address: string) =>
  `${chainId}|${chainId.startsWith('eip155:') ? address.toLowerCase() : address}`;

/**
 * Once a wallet's keys are here, a watch-only stand-in for the same addresses
 * (for example one a layout import created) has done its job: it is folded
 * into the keyed wallet, its user tags carried over, and its id returned so
 * layouts can be pointed at the keyed wallet instead.
 */
export function absorbWatchDuplicates(
  state: DirectoryState,
  keyedWalletIds: readonly string[],
): { state: DirectoryState; remap: Map<string, string> } {
  const remap = new Map<string, string>();
  const keyed = new Set(keyedWalletIds);
  const holders = new Map<string, string>();
  for (const a of state.accounts)
    if (keyed.has(a.walletId)) holders.set(addrKey(a.chainId, a.address), a.walletId);
  if (holders.size === 0) return { state, remap };
  const extraTags = new Map<string, string[]>();
  for (const w of state.wallets) {
    if (w.kind !== 'watch' || keyed.has(w.id)) continue;
    const own = state.accounts.filter((a) => a.walletId === w.id);
    if (own.length === 0) continue;
    const targets = new Set(own.map((a) => holders.get(addrKey(a.chainId, a.address))));
    if (targets.size !== 1) continue;
    const target = [...targets][0];
    if (!target) continue;
    remap.set(w.id, target);
    extraTags.set(target, [...(extraTags.get(target) ?? []), ...w.tags]);
  }
  if (remap.size === 0) return { state, remap };
  return {
    state: {
      ...state,
      wallets: state.wallets
        .filter((w) => !remap.has(w.id))
        .map((w) =>
          extraTags.has(w.id)
            ? { ...w, tags: normalizeTags([...w.tags, ...extraTags.get(w.id)!]).slice(0, MAX_TAGS) }
            : w,
        ),
      accounts: state.accounts.filter((a) => !remap.has(a.walletId)),
      ui: {
        ...state.ui,
        selectedId:
          state.ui.selectedId && remap.has(state.ui.selectedId)
            ? remap.get(state.ui.selectedId)!
            : state.ui.selectedId,
      },
    },
    remap,
  };
}

export interface KeyedAccountInput {
  chainId: string;
  address: string;
  derivationPath: string;
  publicKeyHex: string;
}

/** Another account derived from a `single` wallet's sealed key (next index on a chain). */
export function addKeyedAccount(
  state: DirectoryState,
  input: { walletId: string; label?: string } & KeyedAccountInput,
  ctx: ReducerContext,
): Outcome<string> {
  const wallet = state.wallets.find((w) => w.id === input.walletId);
  if (!wallet) return fail('Wallet not found');
  if (wallet.kind !== 'single' && wallet.kind !== 'hardware')
    return fail('Only single-key and hardware wallets derive more accounts');
  const chain = ChainId.safeParse(input.chainId);
  const family = chain.success ? chainFamilyOf(chain.data) : null;
  if (!chain.success || !family) return fail(`Unsupported chain ${input.chainId}`);
  if (
    state.accounts.some(
      (a) =>
        a.walletId === input.walletId &&
        a.chainId === chain.data &&
        (a.derivationPath === input.derivationPath || a.address === input.address),
    )
  )
    return fail('This account is already in the wallet');
  const label = input.label?.trim().slice(0, 40);
  const account: Account = {
    id: ctx.newId(),
    walletId: input.walletId,
    family,
    chainId: chain.data,
    address: input.address,
    derivationPath: input.derivationPath,
    publicKeyHex: input.publicKeyHex,
    ...(label ? { label } : {}),
    hidden: false,
  };
  const t = ctx.now();
  return {
    ok: true,
    state: {
      ...state,
      wallets: state.wallets.map((w) => (w.id === wallet.id ? { ...w, updatedAtMs: t } : w)),
      accounts: [...state.accounts, account],
    },
    value: account.id,
  };
}

/** A `single` wallet whose key the core already sealed under `walletId`. */
export function createKeyedWallet(
  state: DirectoryState,
  input: {
    walletId: string;
    name: string;
    folderId: string;
    accounts: KeyedAccountInput[];
    /** `hardware`: the key is on a device the core registered for these paths. */
    kind?: 'single' | 'hardware' | 'tss';
    /** `tss`: the key group the core sealed this device's share under. */
    keyGroupId?: string;
  },
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
    kind: input.kind ?? 'single',
    keyGroupId: input.kind === 'tss' ? (input.keyGroupId ?? null) : null,
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
