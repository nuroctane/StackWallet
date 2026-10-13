import * as r from './reducers.js';
import * as sets from './sets.js';
import type { DirectoryState } from './schema.js';
import type { TagDef } from './tagDefs.js';
import { adoptLayoutDirectory, type AdoptResult } from './layoutBundle.js';

export type ActionResult<T = undefined> = { ok: true; value: T } | { ok: false; error: string };

export type Listener = () => void;

export const defaultContext: r.ReducerContext = {
  now: () => Date.now(),
  newId: () => crypto.randomUUID(),
};

/** Minimal external store; React reads it through `useSyncExternalStore`. */
export class DirectoryStore {
  private state: DirectoryState;
  private readonly listeners = new Set<Listener>();
  private readonly ctx: r.ReducerContext;

  constructor(initial: DirectoryState, ctx: r.ReducerContext = defaultContext) {
    this.ctx = ctx;
    this.state = r.ensureRoot(initial, ctx);
  }

  readonly subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  readonly getSnapshot = (): DirectoryState => this.state;

  adoptPersisted(state: DirectoryState): void {
    this.commit(r.ensureRoot(state, this.ctx));
  }

  private commit(next: DirectoryState): void {
    if (next === this.state) return;
    this.state = next;
    for (const l of this.listeners) l();
  }

  private apply<T>(outcome: r.Outcome<T>): ActionResult<T> {
    if (!outcome.ok) return { ok: false, error: outcome.error };
    this.commit(outcome.state);
    return { ok: true, value: outcome.value };
  }

  createFolder(name: string, parentId: string): ActionResult<string> {
    return this.apply(r.createFolder(this.state, name, parentId, this.ctx));
  }

  renameNode(id: string, name: string): ActionResult {
    return this.apply(r.renameNode(this.state, id, name, this.ctx));
  }

  deleteFolder(id: string): ActionResult {
    return this.apply(r.deleteFolder(this.state, id));
  }

  moveWallet(walletId: string, folderId: string): ActionResult {
    return this.apply(r.moveWallet(this.state, walletId, folderId, this.ctx));
  }

  createWatchWallet(input: r.WatchWalletInput): ActionResult<string> {
    return this.apply(r.createWatchWallet(this.state, input, this.ctx));
  }

  /** A `single` wallet whose key the core sealed under `input.walletId` first. */
  createKeyedWallet(input: {
    walletId: string;
    name: string;
    folderId: string;
    accounts: sets.KeyedAccountInput[];
  }): ActionResult<string> {
    return this.apply(sets.createKeyedWallet(this.state, input, this.ctx));
  }

  /** Merge a set that arrived from another device under the root folder. */
  importSet(payload: unknown, setFolderId: string): ActionResult<string> {
    return this.apply(sets.importPayload(this.state, payload, setFolderId, this.ctx));
  }

  /** Watch-only wallets and folders a layout points at; see `layoutBundle.ts`. */
  adoptLayoutDirectory(raw: unknown): ActionResult<AdoptResult> {
    return this.apply(adoptLayoutDirectory(this.state, raw, this.ctx));
  }

  deleteWallet(walletId: string): ActionResult {
    return this.apply(r.deleteWallet(this.state, walletId));
  }

  setWalletTags(walletId: string, tags: readonly string[]): ActionResult {
    return this.apply(r.setWalletTags(this.state, walletId, tags, this.ctx));
  }

  /** Add a tag by id or by any name the user types; new names get their own definition. */
  addTag(walletId: string, typed: string): ActionResult {
    const wallet = this.state.wallets.find((w) => w.id === walletId);
    if (!wallet) return { ok: false, error: 'Wallet not found' };
    const resolved = r.resolveTagInput(this.state, typed, this.ctx);
    if (!resolved.ok) return resolved;
    const tagged = r.setWalletTags(
      resolved.state,
      walletId,
      [...wallet.tags, resolved.value],
      this.ctx,
    );
    return this.apply(tagged);
  }

  upsertTagDef(input: {
    id: string;
    label: string;
    color?: unknown;
    icon?: unknown;
  }): ActionResult<TagDef> {
    return this.apply(r.upsertTagDef(this.state, input, this.ctx));
  }

  resetTagDef(id: string): ActionResult {
    return this.apply(r.resetTagDef(this.state, id));
  }

  removeTag(walletId: string, tag: string): ActionResult {
    const wallet = this.state.wallets.find((w) => w.id === walletId);
    if (!wallet) return { ok: false, error: 'Wallet not found' };
    const target = tag.trim().toLowerCase();
    return this.setWalletTags(
      walletId,
      wallet.tags.filter((t) => t !== target),
    );
  }

  toggleFolder(id: string): void {
    this.commit(r.toggleFolder(this.state, id));
  }

  setFolderExpanded(id: string, expanded: boolean): void {
    this.commit(r.setFolderExpanded(this.state, id, expanded));
  }

  select(id: string | null): void {
    this.commit(r.select(this.state, id));
  }

  expandTo(id: string): void {
    this.commit(r.expandTo(this.state, id));
  }

  /** Expand ancestors and select in one notification. */
  reveal(id: string): void {
    this.commit(r.select(r.expandTo(this.state, id), id));
  }
}
