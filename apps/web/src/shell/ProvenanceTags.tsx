import type { Wallet } from '@stackwallet/core-client';
import { SecurityGlyph, TagIcon, type SecurityGlyphId } from '@stackwallet/ui';
import type { CSSProperties } from 'react';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { useWalletApprovals } from '../store/approvals.js';
import { useDirectory } from '../store/persist.js';
import { setTags, walletTags, type ProvenanceTag, type TagKind } from '../store/provenance.js';
import { resolveTag, tagColorCss, type ResolvedTag } from '../store/tagDefs.js';

/**
 * Security tags share one fixed look: a filled glass chip with a lock, which
 * no user tag can take (user tags are outlined and carry their own icon).
 * Their colours come from fixed theme roles, so a theme edit still cannot
 * make `exposed` look like anything but danger.
 */
const TONE: Record<TagKind, string> = {
  // Red is reserved for this: a key that has been out in the open.
  exposed: 'border-danger/60 bg-danger-soft text-ink',
  approvals: 'border-danger/60 bg-danger-soft text-ink',
  imported: 'border-accent-3/50 bg-hover text-accent-3',
  exported: 'border-accent-3/50 bg-hover text-accent-3',
  local: 'border-edge bg-hover text-faint',
};

const GLYPH: Record<TagKind, SecurityGlyphId> = {
  exposed: 'exposed',
  approvals: 'approvals',
  imported: 'imported',
  exported: 'exported',
  local: 'local',
};

export function TagChips({ tags, compact = false }: { tags: ProvenanceTag[]; compact?: boolean }) {
  if (tags.length === 0) return null;
  return (
    <span className="inline-flex shrink-0 flex-wrap items-center gap-1">
      {tags.map((t) => (
        <span
          key={t.kind}
          title={`${t.detail}\nSecurity tag: set by StackWallet, cannot be edited or removed.`}
          aria-label={`Security tag ${t.label}: ${t.detail}`}
          data-security-tag={t.kind}
          className={`inline-flex h-4 items-center gap-0.5 rounded-sw-sm border px-1 text-[10px] leading-none lowercase ${TONE[t.kind]}`}
        >
          <SecurityGlyph glyph={GLYPH[t.kind]} size={9} />
          {compact && t.kind === 'local' ? 'local' : t.label}
          {!compact && <SecurityGlyph glyph="lock" size={8} className="opacity-60" />}
        </span>
      ))}
    </span>
  );
}

export function userTagStyle(tag: Pick<ResolvedTag, 'color'>): CSSProperties {
  const c = tagColorCss(tag.color);
  return {
    color: c,
    borderColor: `color-mix(in srgb, ${c} 45%, transparent)`,
  };
}

/** One user tag: outlined, never filled, so it cannot pass for a security tag. */
export function UserTagChip({
  tag,
  compact = false,
  className = '',
}: {
  tag: ResolvedTag;
  compact?: boolean;
  className?: string;
}) {
  return (
    <span
      title={tag.custom ? `${tag.label} · your tag (${tag.id})` : `${tag.label} · your tag`}
      style={userTagStyle(tag)}
      className={`inline-flex items-center gap-1 rounded-sw-sm border bg-transparent font-medium tracking-[0.04em] ${
        compact ? 'h-4 px-1 text-[10px]' : 'h-5 px-1.5 text-[10px]'
      } ${className}`}
    >
      {tag.icon && <TagIcon icon={tag.icon} size={compact ? 8 : 9} />}
      <span className="truncate">{tag.label}</span>
    </span>
  );
}

export function UserTags({
  wallet,
  compact = false,
  max,
}: {
  wallet: Pick<Wallet, 'tags'>;
  compact?: boolean;
  max?: number;
}) {
  const { tagDefs } = useDirectory();
  if (wallet.tags.length === 0) return null;
  const shown = max === undefined ? wallet.tags : wallet.tags.slice(0, max);
  const rest = wallet.tags.length - shown.length;
  return (
    <span className="inline-flex min-w-0 shrink items-center gap-1 overflow-hidden">
      {shown.map((id) => {
        const tag = resolveTag(tagDefs, id);
        // The tree is tight: an icon-only chip when the tag has one.
        return compact && tag.icon ? (
          <span
            key={id}
            title={`${tag.label} · your tag`}
            aria-label={`tag ${tag.label}`}
            style={{ color: tagColorCss(tag.color) }}
            className="inline-flex h-4 w-3 shrink-0 items-center justify-center"
          >
            <TagIcon icon={tag.icon} size={9} />
          </span>
        ) : (
          <UserTagChip key={id} tag={tag} compact={compact} className="max-w-[12ch] shrink-0" />
        );
      })}
      {rest > 0 && <span className="text-[10px] text-faint">+{rest}</span>}
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
  const approvals = useWalletApprovals(wallet.id);
  return <TagChips tags={walletTags(provenance, wallet, approvals)} compact={compact ?? false} />;
}

export function SetTags({ folderId }: { folderId: string }) {
  const { provenance } = useVaultView(vault);
  return <TagChips tags={setTags(provenance, folderId)} compact />;
}
