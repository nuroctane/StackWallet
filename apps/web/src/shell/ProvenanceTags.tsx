import type { Wallet } from '@stackwallet/core-client';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { setTags, walletTags, type ProvenanceTag, type TagKind } from '../store/provenance.js';

const TONE: Record<TagKind, string> = {
  // Red is reserved for this: a key that has been out in the open.
  exposed: 'border-danger/60 bg-danger-soft text-ink',
  imported: 'border-accent-3/50 text-accent-3',
  copied: 'border-accent-3/50 text-accent-3',
  local: 'border-edge text-faint',
};

export function TagChips({ tags, compact = false }: { tags: ProvenanceTag[]; compact?: boolean }) {
  if (tags.length === 0) return null;
  return (
    <span className="inline-flex shrink-0 flex-wrap items-center gap-1">
      {tags.map((t) => (
        <span
          key={t.kind}
          title={t.detail}
          aria-label={`${t.label}: ${t.detail}`}
          className={`inline-flex h-4 items-center rounded-sw-sm border px-1 text-[10px] leading-none lowercase ${TONE[t.kind]}`}
        >
          {compact && t.kind === 'local' ? 'local' : t.label}
        </span>
      ))}
    </span>
  );
}

export function WalletTags({
  wallet,
  compact,
}: {
  wallet: Pick<Wallet, 'id' | 'kind'>;
  compact?: boolean;
}) {
  const { provenance } = useVaultView(vault);
  return <TagChips tags={walletTags(provenance, wallet)} compact={compact ?? false} />;
}

export function SetTags({ folderId }: { folderId: string }) {
  const { provenance } = useVaultView(vault);
  return <TagChips tags={setTags(provenance, folderId)} compact />;
}
