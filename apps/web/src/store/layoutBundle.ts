import { ChainId, chainFamilyOf, type Account, type Wallet } from '@stackwallet/core-client';
import { z } from 'zod';

import { createFolder, rootOf, type Outcome, type ReducerContext } from './reducers.js';
import type { DirectoryState } from './schema.js';
import { subtree } from './sets.js';
import { TAG_ID_PATTERN, TagDef, isReservedTagWord } from './tagDefs.js';
import { MAX_PANES_PER_LAYOUT, type PaneProps } from '../workspace/schema.js';

/**
 * The directory half of a layout export. A layout is shareable with no
 * security and no tagging, so this carries only what anyone could read off
 * a block explorer: folder names, wallet names, user tags and public
 * addresses. No key, no share, no key history, no wallet kind. On the
 * receiving instance every wallet arrives watch-only (or is matched to a
 * wallet already there by address) until its keys come over the secure
 * wallet or directory export, which is where security tags are set.
 */

const MAX_REF = 64;
const Ref = z.string().min(1).max(MAX_REF);

export const LayoutFolder = z.object({
  ref: Ref,
  name: z.string().trim().min(1).max(80),
  /** `null`: directly under the receiving instance's root. */
  parentRef: Ref.nullable(),
});

export const LayoutAccount = z.object({
  chainId: z.string().max(80),
  address: z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9]+$/),
});

export const LayoutWallet = z.object({
  ref: Ref,
  name: z.string().trim().min(1).max(80),
  folderRef: Ref.nullable(),
  tags: z.array(z.string().regex(TAG_ID_PATTERN)).max(8).default([]),
  accounts: LayoutAccount.array().min(1).max(64),
});

export const LayoutDirectory = z.object({
  folders: LayoutFolder.array().max(500),
  wallets: LayoutWallet.array().max(MAX_PANES_PER_LAYOUT * 8),
  tagDefs: TagDef.array().max(128).default([]),
});
export type LayoutDirectory = z.infer<typeof LayoutDirectory>;

const PROP_KEYS = ['walletId', 'folderId'] as const;

/** Wallet and folder ids a set of panes points at. */
export function referencedIds(panes: readonly { props: PaneProps }[]): {
  walletIds: Set<string>;
  folderIds: Set<string>;
} {
  const walletIds = new Set<string>();
  const folderIds = new Set<string>();
  for (const p of panes) {
    const w = p.props['walletId'];
    const f = p.props['folderId'];
    if (typeof w === 'string' && w !== '') walletIds.add(w);
    if (typeof f === 'string' && f !== '') folderIds.add(f);
  }
  return { walletIds, folderIds };
}

/**
 * Watch-only view of everything the panes reference: each wallet named in a
 * pane, every wallet under a folder named in a pane, and the folder path down
 * to each of them (the root itself is the receiver's own).
 */
export function buildLayoutDirectory(
  state: DirectoryState,
  panes: readonly { props: PaneProps }[],
): LayoutDirectory {
  const root = rootOf(state).id;
  const { walletIds, folderIds } = referencedIds(panes);
  const folderSet = new Set<string>();
  const addPath = (folderId: string) => {
    let id: string | null = folderId;
    const guard = new Set<string>();
    while (id && id !== root && !guard.has(id)) {
      guard.add(id);
      folderSet.add(id);
      id = state.folders.find((f) => f.id === id)?.parentId ?? null;
    }
  };
  const wallets = new Set<string>();
  for (const f of folderIds) {
    if (!state.folders.some((x) => x.id === f)) continue;
    for (const id of subtree(state, f)) addPath(id);
    const under = new Set(subtree(state, f));
    for (const w of state.wallets) if (under.has(w.folderId)) wallets.add(w.id);
  }
  for (const id of walletIds) if (state.wallets.some((w) => w.id === id)) wallets.add(id);

  const chosen = state.wallets.filter((w) => wallets.has(w.id));
  for (const w of chosen) addPath(w.folderId);
  const folders = state.folders
    .filter((f) => folderSet.has(f.id))
    .map((f) => ({
      ref: f.id,
      name: f.name,
      parentRef: f.parentId === root || f.parentId === null ? null : f.parentId,
    }));
  const used = new Set(chosen.flatMap((w) => w.tags));
  return {
    folders,
    wallets: chosen
      .map((w) => ({
        ref: w.id,
        name: w.name,
        folderRef: w.folderId === root ? null : w.folderId,
        tags: w.tags.filter((t) => TAG_ID_PATTERN.test(t)),
        accounts: state.accounts
          .filter((a) => a.walletId === w.id && !a.hidden)
          .map((a) => ({ chainId: a.chainId, address: a.address })),
      }))
      .filter((w) => w.accounts.length > 0),
    tagDefs: state.tagDefs.filter((d) => used.has(d.id)),
  };
}

const addrKey = (chainId: string, address: string) =>
  `${chainId}|${chainId.startsWith('eip155:') ? address.toLowerCase() : address}`;

export interface AdoptResult {
  /** Bundle ref -> id on this instance. */
  map: Map<string, string>;
  createdWallets: number;
  matchedWallets: number;
  createdFolders: number;
}

/**
 * Bring a layout's directory into this instance without touching any key:
 * folders are matched by name along the same path or created; a wallet whose
 * address is already here maps to the wallet that holds it (keyed or not);
 * anything else becomes a new watch-only wallet. Nothing here records
 * provenance: watch wallets have no key to have a history.
 */
export function adoptLayoutDirectory(
  state: DirectoryState,
  raw: unknown,
  ctx: ReducerContext,
): Outcome<AdoptResult> {
  const parsed = LayoutDirectory.safeParse(raw);
  if (!parsed.success) return { ok: false, error: 'The layout’s wallet list is not readable' };
  const dir = parsed.data;
  const map = new Map<string, string>();
  let next = state;
  let createdFolders = 0;
  const root = rootOf(state).id;

  const byRef = new Map(dir.folders.map((f) => [f.ref, f]));
  const resolving = new Set<string>();
  const folderFor = (ref: string | null): string | { error: string } => {
    if (ref === null) return root;
    const known = map.get(`f:${ref}`);
    if (known) return known;
    const f = byRef.get(ref);
    if (!f || resolving.has(ref)) return { error: 'The layout has a broken folder path' };
    resolving.add(ref);
    const parent = folderFor(f.parentRef);
    resolving.delete(ref);
    if (typeof parent !== 'string') return parent;
    const existing = next.folders.find((x) => x.parentId === parent && x.name === f.name);
    if (existing) {
      map.set(`f:${ref}`, existing.id);
      return existing.id;
    }
    const made = createFolder(next, f.name, parent, ctx);
    if (!made.ok) return { error: made.error };
    next = made.state;
    createdFolders += 1;
    map.set(`f:${ref}`, made.value);
    return made.value;
  };

  const owned = new Map<string, string>();
  for (const a of next.accounts) owned.set(addrKey(a.chainId, a.address), a.walletId);

  let createdWallets = 0;
  let matchedWallets = 0;
  for (const w of dir.wallets) {
    const accounts: { chainId: ChainId; family: Account['family']; address: string }[] = [];
    for (const a of w.accounts) {
      const chain = ChainId.safeParse(a.chainId);
      const family = chain.success ? chainFamilyOf(chain.data) : null;
      if (!chain.success || !family) continue;
      accounts.push({ chainId: chain.data, family, address: a.address });
    }
    if (accounts.length === 0) continue;
    const already = accounts
      .map((a) => owned.get(addrKey(a.chainId, a.address)))
      .find((id) => id !== undefined);
    if (already) {
      map.set(`w:${w.ref}`, already);
      matchedWallets += 1;
      continue;
    }
    const folderId = folderFor(w.folderRef);
    if (typeof folderId !== 'string') return { ok: false, error: folderId.error };
    const t = ctx.now();
    const wallet: Wallet = {
      id: ctx.newId(),
      folderId,
      name: w.name,
      kind: 'watch',
      keyGroupId: null,
      tags: w.tags.filter((tag) => !isReservedTagWord(tag)),
      createdAtMs: t,
      updatedAtMs: t,
    };
    const rows: Account[] = accounts.map((a) => ({
      id: ctx.newId(),
      walletId: wallet.id,
      family: a.family,
      chainId: a.chainId,
      address: a.address,
      publicKeyHex: '',
      hidden: false,
    }));
    for (const a of rows) owned.set(addrKey(a.chainId, a.address), wallet.id);
    next = { ...next, wallets: [...next.wallets, wallet], accounts: [...next.accounts, ...rows] };
    map.set(`w:${w.ref}`, wallet.id);
    createdWallets += 1;
  }
  // Folders a pane points at directly, even when they hold no wallet.
  for (const f of dir.folders) {
    const id = folderFor(f.ref);
    if (typeof id !== 'string') return { ok: false, error: id.error };
  }

  // The sender's look for its tags, unless this instance already styled the same id.
  const defs = [...next.tagDefs];
  for (const d of dir.tagDefs)
    if (!defs.some((x) => x.id === d.id) && !isReservedTagWord(d.label) && defs.length < 128)
      defs.push(d);
  next = { ...next, tagDefs: defs };

  return { ok: true, state: next, value: { map, createdWallets, matchedWallets, createdFolders } };
}

/** Point pane props at this instance's ids; a reference that did not resolve becomes unset. */
export function remapProps(props: PaneProps, map: ReadonlyMap<string, string>): PaneProps {
  const out: PaneProps = { ...props };
  for (const key of PROP_KEYS) {
    const v = props[key];
    if (typeof v !== 'string' || v === '') continue;
    out[key] = map.get(`${key === 'walletId' ? 'w' : 'f'}:${v}`) ?? '';
  }
  return out;
}
