import type { ProvenanceTable, Wallet } from '@stackwallet/core-client';

export type TagKind = 'exposed' | 'imported' | 'copied' | 'local';

export interface ProvenanceTag {
  kind: TagKind;
  label: string;
  detail: string;
}

function when(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
}

/**
 * The tags a wallet always shows. A `single` wallet with none of exposed,
 * imported or copied is local only: safe from copies, and without a backup.
 * Watch wallets hold no key and carry no tags.
 */
export function walletTags(
  table: ProvenanceTable,
  wallet: Pick<Wallet, 'id' | 'kind'>,
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
      kind: 'copied',
      label: 'copied',
      detail: `Transferred to ${devices} other device${devices === 1 ? '' : 's'}; last at ${when(
        p.transfers[p.transfers.length - 1]!.atMs,
      )}.`,
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
      kind: 'copied',
      label: 'copied set',
      detail: `This set was transferred ${s.transfers.length} time${s.transfers.length === 1 ? '' : 's'}.`,
    });
  }
  return tags;
}
