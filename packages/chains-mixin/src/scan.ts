/**
 * View-key UTXO discovery over the public kernel. The kernel indexes outputs
 * by ghost key, not by address, so the only self-custodial way to find an
 * account's outputs is to walk `listsnapshots` (500 per page, full
 * transactions when `tx` is true) and ask the core, which holds the private
 * view key, which outputs it recognises. The scan keeps a cursor (topology
 * reached plus the outputs still unspent) so it can resume and never asks the
 * core about an output twice. The main kernel is past 83 million snapshots and
 * grows by roughly one per second, so a scan from genesis is an hours-long job
 * for one public endpoint; resuming from the account's creation topology is a
 * few hundred requests a day.
 */
import type { MixinCandidateOutput, MixinOwnedOutput } from '@stackwallet/core-client';
import { z } from 'zod';

import { XIN_ASSET_ID, type MixinAdapter, type MixinUtxo } from './mixin.js';

/** Largest page `listsnapshots` serves. */
export const SNAPSHOT_PAGE = 500;
/** The one-signer threshold script the core can spend; multisig outputs are not ours to spend alone. */
const SINGLE_SIGNER_SCRIPT = 'fffe01';

const Hash32 = z.string().regex(/^[0-9a-fA-F]{64}$/);
const XinAmount = z.string().regex(/^\d{1,30}(\.\d{1,8})?$/);

const SnapshotOutput = z
  .object({
    type: z.number().int().nonnegative().optional(),
    amount: XinAmount,
    keys: z.array(Hash32).max(16),
    mask: Hash32,
    script: z.string().max(128).optional(),
  })
  .loose();
const SnapshotTransaction = z
  .object({
    hash: Hash32,
    asset: Hash32,
    inputs: z
      .array(
        z
          .object({ hash: Hash32.optional(), index: z.number().int().nonnegative().optional() })
          .loose(),
      )
      .max(256)
      .optional(),
    outputs: z.array(SnapshotOutput).max(256).optional(),
  })
  .loose();
export const SnapshotPage = z
  .array(
    z
      .object({
        topology: z.number().int().nonnegative(),
        transactions: z.array(SnapshotTransaction).max(64).optional(),
      })
      .loose(),
  )
  .max(SNAPSHOT_PAGE);
export type SnapshotPage = z.infer<typeof SnapshotPage>;

/** Where a scan stands: every snapshot below `topology` has been read. */
export interface MixinScanCursor {
  topology: number;
  utxos: MixinUtxo[];
}

/** The core's view-key test (`VaultHandle.mixinOwnedOutputs` bound to one account). */
export type MixinOutputMatcher = (
  candidates: MixinCandidateOutput[],
) => Promise<MixinOwnedOutput[]>;

export interface MixinScanOptions {
  from: MixinScanCursor;
  matcher: MixinOutputMatcher;
  /** Stop after this many pages even if the head is not reached (default 20). */
  maxPages?: number;
  /** Scan no further than this topology; defaults to the node's `getinfo` head. */
  head?: number;
  onProgress?: (cursor: MixinScanCursor, head: number) => void;
  signal?: AbortSignal;
}

/** XIN decimal string (8 places) to integer xinat. */
export function xinToXinat(amount: string): string {
  const [whole, frac = ''] = XinAmount.parse(amount).split('.');
  return (BigInt(whole!) * 100_000_000n + BigInt(frac.padEnd(8, '0'))).toString();
}

/**
 * Advance `from` towards the head. Outputs the account owns are added as they
 * appear; outputs the account spent (any later input referencing them) are
 * dropped, so the cursor's `utxos` stay the unspent set as of `topology`.
 */
export async function scanMixinOutputs(
  adapter: MixinAdapter,
  chainId: string,
  options: MixinScanOptions,
): Promise<{ cursor: MixinScanCursor; head: number; reachedHead: boolean }> {
  const maxPages = options.maxPages ?? 20;
  const utxos = new Map(options.from.utxos.map((u) => [`${u.hash}:${u.index}`, u]));
  let topology = options.from.topology;
  return adapter.withNode(chainId, async (url) => {
    const head =
      options.head ??
      (
        await adapter.call(
          url,
          'getinfo',
          [],
          z
            .object({ graph: z.object({ topology: z.number().int().nonnegative() }).loose() })
            .loose(),
        )
      )?.graph.topology ??
      topology;
    let pages = 0;
    while (topology < head && pages < maxPages) {
      options.signal?.throwIfAborted();
      const page = await adapter.call(
        url,
        'listsnapshots',
        [String(topology), String(SNAPSHOT_PAGE), 'false', 'true'],
        SnapshotPage,
      );
      if (!page || page.length === 0) break;
      const candidates: MixinCandidateOutput[] = [];
      const origins: { hash: string; output: z.infer<typeof SnapshotOutput> }[] = [];
      const spent: string[] = [];
      for (const snapshot of page) {
        for (const tx of snapshot.transactions ?? []) {
          for (const input of tx.inputs ?? []) {
            if (input.hash !== undefined && input.index !== undefined)
              spent.push(`${input.hash.toLowerCase()}:${input.index}`);
          }
          if (tx.asset.toLowerCase() !== XIN_ASSET_ID) continue;
          (tx.outputs ?? []).forEach((output, index) => {
            if ((output.type ?? 0) !== 0 || index > 1024) return;
            if (output.script !== undefined && output.script.toLowerCase() !== SINGLE_SIGNER_SCRIPT)
              return;
            candidates.push({ index, mask: output.mask, keys: output.keys });
            origins.push({ hash: tx.hash.toLowerCase(), output });
          });
        }
      }
      if (candidates.length > 0) {
        for (const owned of await options.matcher(candidates)) {
          const candidate = candidates[owned.position];
          const origin = origins[owned.position];
          const key = candidate?.keys[owned.key];
          if (!candidate || !origin || key === undefined) continue;
          utxos.set(`${origin.hash}:${candidate.index}`, {
            hash: origin.hash,
            index: candidate.index,
            key: key.toLowerCase(),
            mask: candidate.mask.toLowerCase(),
            xinat: xinToXinat(origin.output.amount),
          });
        }
      }
      // An output is always created before it is spent, so within a page the
      // spends apply after the matches.
      for (const ref of spent) utxos.delete(ref);
      const last = page[page.length - 1]!.topology;
      // A page always ends past where it started; a node answering otherwise cannot be walked.
      if (last < topology) throw new Error('Kernel returned snapshots below the requested offset');
      topology = last + 1;
      pages += 1;
      options.onProgress?.({ topology, utxos: [...utxos.values()] }, head);
    }
    return {
      cursor: { topology, utxos: [...utxos.values()] },
      head,
      reachedHead: topology >= head,
    };
  });
}
