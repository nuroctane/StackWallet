import * as r from './reducers.js';
import type { DirectoryState } from './schema.js';

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

  deleteWallet(walletId: string): ActionResult {
    return this.apply(r.deleteWallet(this.state, walletId));
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
