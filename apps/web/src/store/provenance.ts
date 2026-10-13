import type { ProvenanceTable, Wallet } from '@stackwallet/core-client';

/**
 * Security tags. Each one is an attestation derived from sealed key history
 * (the core's provenance table) or from the chain (open approvals), never
 * from anything the user typed, and none of them can be renamed, recoloured,
 * hidden or removed. User tags live in `tagDefs.ts` and render apart.
 */
export type TagKind = 'exposed' | 'exported' | 'imported' | 'approvals' | 'local';

export interface ProvenanceTag {
  kind: TagKind;
  label: string;
  detail: string;
}

/** Open spending permissions found on chain for a wallet's addresses. */
export interface ApprovalSummary {
  /** ERC-20 allowances above zero. */
  tokens: number;
  /** NFT single-token approvals plus operator (approve-for-all) grants. */
  collectibles: number;
}

function when(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
}

/**
 * The security tags a wallet always shows. A `single` wallet with none of
 * exposed, imported or exported is local only: safe from copies, and without
 * a backup. Watch wallets hold no key and carry no key tags, but open
 * approvals are a fact about the address and apply to any wallet kind.
 */
export function walletTags(
  table: ProvenanceTable,
  wallet: Pick<Wallet, 'id' | 'kind'>,
  approvals?: ApprovalSummary | null,
): ProvenanceTag[] {
  const p = table.wallets.find((w) => w.walletId === wallet.id);
  const tags: ProvenanceTag[] = [];
  if (p && p.exposures.length > 0) {
    const last = p.exposures[p.exposures.length - 1]!;
    tags.push({
      kind: 'exposed',
      label: 'exposed',
      detail: `A private key or phrase left the vault ${p.exposures.length} time${
        p.exposures.length === 1 ? '' : 's'
      }; last via ${last.channel} at ${when(last.atMs)}. This cannot be undone.`,
    });
  }
  if (p && p.origin.kind === 'importedFromDevice') {
    tags.push({
      kind: 'imported',
      label: 'imported',
      detail: `Transferred from ${p.origin.deviceName} at ${when(p.origin.atMs)}. A copy exists there.`,
    });
  } else if (p && p.origin.kind === 'importedPhrase') {
    tags.push({
      kind: 'imported',
      label: 'imported',
      detail: `Restored from a phrase at ${when(p.origin.atMs)}; the phrase existed before this vault.`,
    });
  }
  if (p && p.transfers.length > 0) {
    const devices = new Set(p.transfers.map((t) => t.toDeviceId)).size;
    tags.push({
      kind: 'exported',
      label: 'exported',
      detail: `Exported to ${devices} other StackWallet device${devices === 1 ? '' : 's'}; last at ${when(
        p.transfers[p.transfers.length - 1]!.atMs,
      )}. A second copy of this wallet exists there.`,
    });
  }
  if (wallet.kind === 'single' && tags.length === 0) {
    tags.push({
      kind: 'local',
      label: 'local · no backup',
      detail:
        'This key has never left this vault: no copy exists anywhere, which also means there is no backup.',
    });
  }
  const open = approvals ? approvals.tokens + approvals.collectibles : 0;
  if (approvals && open > 0) {
    const parts = [
      approvals.tokens > 0
        ? `${approvals.tokens} token allowance${approvals.tokens === 1 ? '' : 's'}`
        : '',
      approvals.collectibles > 0
        ? `${approvals.collectibles} collectible approval${approvals.collectibles === 1 ? '' : 's'}`
        : '',
    ].filter(Boolean);
    tags.push({
      kind: 'approvals',
      label: `approvals ${open}`,
      detail: `${parts.join(' and ')} still open on chain: another contract can move these assets without a new signature. Revoke them to clear this tag.`,
    });
  }
  return tags;
}

/** Tags for a directory set (a folder transferred or received as a whole). */
export function setTags(table: ProvenanceTable, folderId: string): ProvenanceTag[] {
  const s = table.sets.find((x) => x.folderId === folderId);
  if (!s) return [];
  const tags: ProvenanceTag[] = [];
  if (s.origin.kind === 'importedFromDevice') {
    tags.push({
      kind: 'imported',
      label: 'imported set',
      detail: `This set came from ${s.origin.deviceName} at ${when(s.origin.atMs)}.`,
    });
  }
  if (s.transfers.length > 0) {
    tags.push({
      kind: 'exported',
      label: 'exported set',
      detail: `This directory was exported as a whole ${s.transfers.length} time${s.transfers.length === 1 ? '' : 's'}; every wallet in it at the time is tagged exported.`,
    });
  }
  return tags;
}
