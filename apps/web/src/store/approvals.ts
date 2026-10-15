import { useEffect, useSyncExternalStore } from 'react';
import type { ChainRegistry } from '@stackwallet/chains';
import { scanApprovals, type ApprovalScan, type EvmAdapter } from '@stackwallet/chains-evm';
import { BLOCKSCOUT_HOSTS } from '@stackwallet/collectibles';
import type { Account } from '@stackwallet/core-client';
import { z } from 'zod';

import type { StorageLike } from './persist.js';
import { useDirectory } from './persist.js';
import type { ApprovalSummary } from './provenance.js';

/**
 * Open token and collectible approvals per EVM address, across every chain
 * that has a keyless indexer. An EVM address is the same on every chain, so
 * a wallet with only a mainnet account is still scanned on Base, Arbitrum
 * and the rest: an allowance granted there with the same key is just as open.
 *
 * Results are public chain data and are cached locally so the security tag
 * survives a reload and shows while offline; the tag is only ever cleared by
 * a scan that read the contracts, never by a failed one.
 */

export const APPROVALS_STORAGE_KEY = 'stackwallet.approvals.v1';
export const APPROVALS_TTL_MS = 30 * 60 * 1000;
const SCAN_CONCURRENCY = 6;

const Entry = z.object({
  chainId: z.string().max(64),
  owner: z.string().regex(/^0x[0-9a-f]{40}$/),
  open: z
    .array(
      z.object({
        chainId: z.string().max(64),
        kind: z.enum(['erc20', 'nft', 'operator']),
        token: z.string().regex(/^0x[0-9a-f]{40}$/),
        spender: z.string().regex(/^0x[0-9a-f]{40}$/),
        tokenId: z
          .string()
          .regex(/^\d{1,80}$/)
          .optional(),
        granted: z
          .string()
          .regex(/^\d{1,80}$/)
          .optional(),
        amount: z
          .string()
          .regex(/^\d{1,80}$/)
          .optional(),
        unlimited: z.boolean(),
        verified: z.boolean(),
        txHash: z.string().max(80),
        blockNumber: z.number().int().nonnegative(),
      }),
    )
    .max(2000),
  truncated: z.boolean(),
  checkedAtMs: z.number().int(),
});
const Cache = z.record(z.string().max(120), Entry);

export interface ScanStatus {
  scanning: boolean;
  error: string | null;
}

export function approvalKey(chainId: string, owner: string): string {
  return `${chainId}:${owner.toLowerCase()}`;
}

type Scanner = (chainId: string, owner: string) => Promise<ApprovalScan>;

export class ApprovalsStore {
  private cache: Record<string, ApprovalScan> = {};
  private status = new Map<string, ScanStatus>();
  private listeners = new Set<() => void>();
  private version = 0;
  private scanner: Scanner | null = null;
  private chains: string[] = [];

  constructor(
    private readonly storage: StorageLike | null,
    private readonly now: () => number = Date.now,
  ) {
    try {
      const raw = storage?.getItem(APPROVALS_STORAGE_KEY);
      if (raw) this.cache = Cache.parse(JSON.parse(raw)) as Record<string, ApprovalScan>;
    } catch {
      // A cache that does not parse is rebuilt by the next scan.
      this.cache = {};
    }
  }

  readonly subscribe = (l: () => void): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getVersion = (): number => this.version;

  private emit(): void {
    this.version += 1;
    for (const l of this.listeners) l();
  }

  /** Wire the indexer and the contract reads; chains without an indexer are skipped. */
  configure(registry: ChainRegistry): void {
    const evm = (() => {
      try {
        return registry.adapterFor('eip155:1') as unknown as EvmAdapter;
      } catch {
        return null;
      }
    })();
    if (!evm) return;
    // Testnets too: they are where the core can sign a revoke today.
    this.chains = Object.keys(BLOCKSCOUT_HOSTS).filter((id) => registry.chainInfo(id));
    const Hex = z.string().regex(/^0x[0-9a-fA-F]*$/);
    this.setScanner((chainId, owner) =>
      scanApprovals({
        chainId,
        owner,
        indexer: BLOCKSCOUT_HOSTS[chainId]!,
        read: (to, data) => evm.call(chainId, 'eth_call', [{ to, data }, 'latest'], Hex),
        now: this.now,
      }),
    );
  }

  setScanner(scanner: Scanner, chains?: string[]): void {
    this.scanner = scanner;
    if (chains) this.chains = chains;
  }

  /** Chains an address is scanned on. */
  scanChains(): readonly string[] {
    return this.chains;
  }

  get(chainId: string, owner: string): ApprovalScan | undefined {
    return this.cache[approvalKey(chainId, owner)];
  }

  statusOf(chainId: string, owner: string): ScanStatus {
    return this.status.get(approvalKey(chainId, owner)) ?? { scanning: false, error: null };
  }

  /** Every distinct EVM owner address among `accounts`. */
  static owners(accounts: readonly Pick<Account, 'family' | 'address'>[]): string[] {
    return [
      ...new Set(
        accounts
          .filter((a) => a.family === 'evm' && /^0x[0-9a-fA-F]{40}$/.test(a.address))
          .map((a) => a.address.toLowerCase()),
      ),
    ];
  }

  /** Every open approval known for these accounts, on every scanned chain, with its owner. */
  openFor(
    accounts: readonly Pick<Account, 'family' | 'address'>[],
  ): (ApprovalScan['open'][number] & { owner: string })[] {
    const out: (ApprovalScan['open'][number] & { owner: string })[] = [];
    for (const owner of ApprovalsStore.owners(accounts))
      for (const [key, scan] of Object.entries(this.cache))
        if (key.endsWith(`:${owner}`)) out.push(...scan.open.map((o) => ({ ...o, owner })));
    return out;
  }

  summary(accounts: readonly Pick<Account, 'family' | 'address'>[]): ApprovalSummary | null {
    const owners = ApprovalsStore.owners(accounts);
    if (owners.length === 0) return null;
    const open = this.openFor(accounts);
    return {
      tokens: open.filter((o) => o.kind === 'erc20').length,
      collectibles: open.filter((o) => o.kind !== 'erc20').length,
    };
  }

  async scan(owner: string, opts: { force?: boolean } = {}): Promise<void> {
    if (!this.scanner) return;
    const scanner = this.scanner;
    const queue = this.chains.filter((chainId) => {
      const key = approvalKey(chainId, owner);
      const prior = this.cache[key];
      if (this.status.get(key)?.scanning) return false;
      return opts.force || !prior || this.now() - prior.checkedAtMs >= APPROVALS_TTL_MS;
    });
    if (queue.length === 0) return;
    // Queued chains count as scanning so an overlapping call does not queue them twice.
    for (const chainId of queue)
      this.status.set(approvalKey(chainId, owner), { scanning: true, error: null });
    this.emit();
    const scanOne = async (chainId: string) => {
      const key = approvalKey(chainId, owner);
      try {
        const result = await scanner(chainId, owner);
        this.cache[key] = result;
        this.status.set(key, { scanning: false, error: null });
        this.persist();
      } catch (err) {
        // The prior answer stays: a failed scan never clears a security tag.
        this.status.set(key, {
          scanning: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
      this.emit();
    };
    // Dozens of indexed chains: a few at a time keeps the browser's connection pool usable.
    let next = 0;
    const worker = async () => {
      while (next < queue.length) await scanOne(queue[next++]!);
    };
    await Promise.all(Array.from({ length: Math.min(SCAN_CONCURRENCY, queue.length) }, worker));
  }

  private persist(): void {
    try {
      this.storage?.setItem(APPROVALS_STORAGE_KEY, JSON.stringify(this.cache));
    } catch {
      // Kept in memory for this session.
    }
  }
}

function safeStorage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export const approvalsStore = new ApprovalsStore(safeStorage());

export function useApprovalsVersion(): number {
  return useSyncExternalStore(
    approvalsStore.subscribe,
    approvalsStore.getVersion,
    approvalsStore.getVersion,
  );
}

/** The summary behind a wallet's `approvals` tag; `null` for wallets with no EVM address. */
export function useWalletApprovals(walletId: string): ApprovalSummary | null {
  useApprovalsVersion();
  const { accounts } = useDirectory();
  return approvalsStore.summary(accounts.filter((a) => a.walletId === walletId));
}

/** Scan a wallet's EVM addresses when it is opened; cached answers inside the TTL are reused. */
export function useScanApprovals(walletId: string): void {
  const { accounts } = useDirectory();
  const owners = ApprovalsStore.owners(accounts.filter((a) => a.walletId === walletId)).join(',');
  useEffect(() => {
    for (const owner of owners.split(',').filter(Boolean)) void approvalsStore.scan(owner);
  }, [owners]);
}
