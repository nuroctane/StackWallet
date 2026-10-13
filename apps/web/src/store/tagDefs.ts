import { TAG_ICON_IDS, type TagIconId } from '@stackwallet/ui';
import { z } from 'zod';

/**
 * The user's own tag vocabulary. A wallet stores tag ids (slugs); a `TagDef`
 * gives an id its display name, colour and icon. Ids without a definition
 * render in the default style, so old directories keep working unchanged.
 *
 * Security tags (exposed, exported, imported, open approvals, local, watch)
 * are not in here at all: the core and the chain derive them, they render
 * from `provenance.ts`, and nothing in this module can rename, recolour or
 * hide them. The checks below also stop a user tag from borrowing their
 * names, so a tag reading "exported" is always the real one.
 */

export const MAX_TAG_DEFS = 128;
export const MAX_TAG_LABEL = 24;
export const TAG_ID_PATTERN = /^[a-z0-9-]{1,24}$/;

/**
 * Theme roles a user tag may take. `danger` and `danger-soft` are absent on
 * purpose: red keeps its meaning (exposed keys, destructive actions) whatever
 * hue the theme gives it.
 */
export const TAG_COLOR_ROLES = [
  'ok',
  'ink',
  'muted',
  'faint',
  'warm',
  'accent-2',
  'accent-3',
  'chart-1',
  'chart-2',
  'chart-3',
  'chart-4',
] as const;
export type TagColorRole = (typeof TAG_COLOR_ROLES)[number];

const HEX = /^#[0-9a-f]{6}$/;

export const TagColor = z.union([
  z.enum(TAG_COLOR_ROLES),
  z
    .string()
    .transform((s) => s.trim().toLowerCase())
    .pipe(z.string().regex(HEX, 'expected #rrggbb')),
]);
export type TagColor = z.infer<typeof TagColor>;

export const DEFAULT_TAG_COLOR: TagColor = 'ok';

const printable = (s: string) => !/[\p{C}]/u.test(s);

export const TagDef = z.object({
  id: z.string().regex(TAG_ID_PATTERN),
  label: z.string().trim().min(1).max(MAX_TAG_LABEL).refine(printable, 'no control characters'),
  color: TagColor.default(DEFAULT_TAG_COLOR),
  icon: z
    .enum(TAG_ICON_IDS as [TagIconId, ...TagIconId[]])
    .nullable()
    .default(null),
  updatedAtMs: z.number().int().default(0),
});
export type TagDef = z.infer<typeof TagDef>;

/**
 * Words that belong to security tags. A user tag whose id or name folds to
 * one of these is refused so it cannot impersonate an attestation (or claim
 * the absence of one, which is what "clean" or "safe" would do).
 */
const RESERVED = new Set(
  [
    'exposed',
    'exported',
    'imported',
    'copied',
    'approval',
    'approvals',
    'openapprovals',
    'allowance',
    'allowances',
    'local',
    'localnobackup',
    'nobackup',
    'watch',
    'watchonly',
    'unexposed',
    'notexposed',
    'neverexposed',
    'verified',
    'attested',
    'safe',
    'clean',
    'secure',
  ].map((w) => w.replace(/[^a-z0-9]/g, '')),
);

export function foldTagWord(s: string): string {
  return s
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

export function isReservedTagWord(s: string): boolean {
  return RESERVED.has(foldTagWord(s));
}

/** A free-form name turned into a stable id: lowercase, dashes, 24 chars at most. */
export function slugifyTag(name: string): string {
  return name
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 24)
    .replace(/-+$/g, '');
}

export function findTagDef(defs: readonly TagDef[], id: string): TagDef | undefined {
  return defs.find((d) => d.id === id);
}

/** What a user tag looks like right now, with defaults filled in. */
export interface ResolvedTag {
  id: string;
  label: string;
  color: TagColor;
  icon: TagIconId | null;
  custom: boolean;
}

export function resolveTag(defs: readonly TagDef[], id: string): ResolvedTag {
  const d = findTagDef(defs, id);
  return d
    ? { id, label: d.label, color: d.color, icon: d.icon, custom: true }
    : { id, label: id, color: DEFAULT_TAG_COLOR, icon: null, custom: false };
}

/** CSS colour for a tag: theme roles follow the active theme, hex is literal. */
export function tagColorCss(color: TagColor): string {
  return color.startsWith('#') ? color : `var(--sw-${color})`;
}
