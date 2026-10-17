/**
 * Per-account Mixin view-key scan cursors. The kernel has no address index, so
 * a Mixin account's balance is whatever the scan has found: the adapter's UTXO
 * provider is bound here to "advance this address's cursor, then hand back its
 * unspent set". A new address starts at the kernel head (nothing can predate
 * the account), each balance refresh walks a bounded number of pages towards
 * the head, and the cursor persists so no snapshot is read twice. An imported
 * account with older history needs `rewind` to a topology before its first
 * receipt; the scan is hours long from genesis, so that is a deliberate act.
 */
import { useSyncExternalStore } from 'react';
import type { ChainRegistry } from '@stackwallet/chains';
import {
  MIXIN_MAINNET,
  scanMixinOutputs,
  type MixinAdapter,
  type MixinScanCursor,
  type MixinUtxo,
} from '@stackwallet/chains-mixin';
import type { MixinCandidateOutput, MixinOwnedOutput } from '@stackwallet/core-client';
import { z } from 'zod';

import type { StorageLike } from './persist.js';

const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const Utxo = z.object({
  hash: Hash,
  index: z.number().int().min(0).max(1024),
  key: Hash,
  mask: Hash,
  xinat: z.string().regex(/^\d{1,20}$/),
});
const Cursor = z.object({
  topology: z.number().int().nonnegative(),
  utxos: z.array(Utxo).max(10_000),
});
const Cursors = z.record(z.string().regex(/^XIN[1-9A-HJ-NP-Za-km-z]{80,100}$/), Cursor);
type Cursors = z.infer<typeof Cursors>;
const KEY = 'stackwallet.mixin-scan.v1';
/** Pages per balance refresh: 10k snapshots, a few hours of kernel time. */
const PAGES_PER_SYNC = 20;

export interface MixinScanDeps {
  /** The vault account behind `address`, when it has a key here. */
  accountFor(address: string): { walletId: string; derivationPath: string } | undefined;
  /** The core's view-key test; rejects while the vault is locked. */
  owned(
    walletId: string,
    path: string,
    candidates: MixinCandidateOutput[],
  ): Promise<MixinOwnedOutput[]>;
}

export interface MixinScanProgress {
  topology: number;
  head: number;
  reachedHead: boolean;
}

export class MixinScanStore {
  quarantinedKey: string | undefined;
  private cursors: Cursors = {};
  private progress = new Map<string, MixinScanProgress>();
  private running = new Map<string, Promise<MixinUtxo[]>>();
  private listeners = new Set<() => void>();

  constructor(private storage: StorageLike | null) {
    let raw: string | null | undefined;
    try {
      raw = storage?.getItem(KEY);
      if (raw) this.cursors = Cursors.parse(JSON.parse(raw));
    } catch {
      if (raw) {
        try {
          const key = `${KEY}.corrupt-${Date.now()}`;
          storage?.setItem(key, raw);
          storage?.removeItem(KEY);
          this.quarantinedKey = key;
        } catch {
          // Storage may be inaccessible; the unreadable original stays in place.
        }
      }
    }
  }

  getSnapshot = () => this.cursors;
  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  };

  cursor(address: string): MixinScanCursor | undefined {
    return this.cursors[address];
  }

  /** Where the last sync of `address` got to, if one has run this session. */
  progressOf(address: string): MixinScanProgress | undefined {
    return this.progress.get(address);
  }

  /**
   * Restart `address` from `topology`, forgetting what the scan found. For an
   * account that received XIN before it was added here.
   */
  rewind(address: string, topology: number): void {
    const cursor = Cursor.parse({ topology, utxos: [] });
    this.save({ ...this.cursors, [address]: cursor });
  }

  /**
   * Advance the address's cursor towards the head and return its unspent set.
   * Without a vault account (watch-only, or locked) the known set is returned
   * unchanged. Concurrent refreshes share one scan.
   */
  sync(adapter: MixinAdapter, address: string, deps: MixinScanDeps): Promise<MixinUtxo[]> {
    const running = this.running.get(address);
    if (running) return running;
    const run = this.advance(adapter, address, deps).finally(() => {
      this.running.delete(address);
    });
    this.running.set(address, run);
    return run;
  }

  private async advance(
    adapter: MixinAdapter,
    address: string,
    deps: MixinScanDeps,
  ): Promise<MixinUtxo[]> {
    const known = this.cursors[address];
    const account = deps.accountFor(address);
    if (!account) return known?.utxos ?? [];
    const from = known ?? { topology: await this.head(adapter), utxos: [] };
    if (!known) this.save({ ...this.cursors, [address]: Cursor.parse(from) });
    let result;
    try {
      result = await scanMixinOutputs(adapter, MIXIN_MAINNET, {
        from,
        maxPages: PAGES_PER_SYNC,
        matcher: (candidates) => deps.owned(account.walletId, account.derivationPath, candidates),
        onProgress: (cursor) => this.save({ ...this.cursors, [address]: Cursor.parse(cursor) }),
      });
    } catch {
      // A locked vault or an unreachable kernel leaves the cursor where it was.
      return from.utxos;
    }
    this.progress.set(address, {
      topology: result.cursor.topology,
      head: result.head,
      reachedHead: result.reachedHead,
    });
    this.save({ ...this.cursors, [address]: Cursor.parse(result.cursor) });
    return result.cursor.utxos;
  }

  private async head(adapter: MixinAdapter): Promise<number> {
    const info = await adapter.withNode(MIXIN_MAINNET, (url) =>
      adapter.call(
        url,
        'getinfo',
        [],
        z.object({ graph: z.object({ topology: z.number().int().nonnegative() }).loose() }).loose(),
      ),
    );
    if (!info) throw new Error('Kernel reported no topology');
    return info.graph.topology;
  }

  private save(cursors: Cursors) {
    const next = Cursors.parse(cursors);
    this.storage?.setItem(KEY, JSON.stringify(next));
    this.cursors = next;
    for (const fn of this.listeners) fn();
  }

  /** Bind the registry's Mixin adapter to this store's scan. */
  configure(registry: ChainRegistry, deps: MixinScanDeps) {
    const adapter = registry.adapterFor(MIXIN_MAINNET) as unknown as MixinAdapter;
    adapter.setUtxoProvider((address) => this.sync(adapter, address, deps));
    return () => adapter.setUtxoProvider(undefined);
  }
}

function storage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}
export const mixinScanStore = new MixinScanStore(storage());
export function useMixinScan() {
  return useSyncExternalStore(
    mixinScanStore.subscribe,
    mixinScanStore.getSnapshot,
    mixinScanStore.getSnapshot,
  );
}
