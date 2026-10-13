import { useRef, useState, type KeyboardEvent } from 'react';
import type { Wallet } from '@stackwallet/core-client';
import {
  Button,
  ColorPicker,
  Popover,
  SecurityGlyph,
  TAG_ICON_IDS,
  TagIcon,
  useToasts,
  type TagIconId,
} from '@stackwallet/ui';

import { directory, useDirectory } from '../store/persist.js';
import { MAX_TAGS } from '../store/reducers.js';
import {
  MAX_TAG_LABEL,
  TAG_COLOR_ROLES,
  resolveTag,
  tagColorCss,
  type ResolvedTag,
  type TagColor,
} from '../store/tagDefs.js';
import { userTagStyle } from './ProvenanceTags.js';

/**
 * The user's own tags on one wallet. Each tag opens a customiser (name,
 * colour, icon); the security tags shown beside the wallet name are not
 * here and cannot be reached from here.
 */
export function TagEditor({ wallet }: { wallet: Wallet }) {
  const toasts = useToasts();
  const { tagDefs } = useDirectory();
  const [draft, setDraft] = useState('');
  const [editing, setEditing] = useState<{ id: string; anchor: HTMLElement } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const full = wallet.tags.length >= MAX_TAGS;

  const report = (result: { ok: boolean; error?: string }) => {
    if (!result.ok && result.error) toasts.push(result.error, 'danger');
  };

  const add = () => {
    const tag = draft.trim();
    if (tag === '') return;
    const result = directory.addTag(wallet.id, tag);
    report(result);
    if (result.ok) setDraft('');
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      add();
    } else if (e.key === 'Backspace' && draft === '') {
      const last = wallet.tags[wallet.tags.length - 1];
      if (last) report(directory.removeTag(wallet.id, last));
    } else if (e.key === 'Escape') {
      setDraft('');
    }
  };

  const suggestions = tagDefs.filter((d) => !wallet.tags.includes(d.id)).slice(0, 12);

  return (
    <div
      role="group"
      aria-label="Your tags"
      className="flex min-h-7 flex-wrap items-center gap-1.5"
      onClick={() => inputRef.current?.focus()}
    >
      {wallet.tags.map((id) => {
        const tag = resolveTag(tagDefs, id);
        return (
          <span
            key={id}
            style={userTagStyle(tag)}
            className="inline-flex h-5 items-center rounded-sw-sm border text-[10px] font-medium tracking-[0.04em]"
          >
            <button
              type="button"
              title={`Customise ${tag.label}: name, colour, icon`}
              aria-label={`Customise tag ${tag.label}`}
              onClick={(e) => {
                e.stopPropagation();
                setEditing({ id, anchor: e.currentTarget });
              }}
              className="sw-pressable inline-flex h-5 items-center gap-1 rounded-sw-sm pl-1.5"
            >
              {tag.icon && <TagIcon icon={tag.icon} size={9} />}
              {tag.label}
            </button>
            <button
              type="button"
              aria-label={`Remove tag ${tag.label}`}
              onClick={(e) => {
                e.stopPropagation();
                report(directory.removeTag(wallet.id, id));
              }}
              className="sw-pressable flex h-5 w-5 items-center justify-center rounded-sw-sm text-faint hover:text-ink"
            >
              ×
            </button>
          </span>
        );
      })}
      <input
        ref={inputRef}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={onKeyDown}
        onBlur={add}
        disabled={full}
        maxLength={MAX_TAG_LABEL}
        list={`tag-suggestions-${wallet.id}`}
        placeholder={full ? `${MAX_TAGS} tags max` : wallet.tags.length === 0 ? 'add tag' : '+'}
        aria-label="Add tag"
        spellCheck={false}
        autoComplete="off"
        className="h-5 min-w-[6ch] flex-1 basis-[6ch] bg-transparent px-1 font-mono text-[11px] text-muted outline-none placeholder:text-faint disabled:cursor-not-allowed"
      />
      <datalist id={`tag-suggestions-${wallet.id}`}>
        {suggestions.map((d) => (
          <option key={d.id} value={d.label} />
        ))}
      </datalist>
      {editing && (
        <TagCustomizer
          tag={resolveTag(tagDefs, editing.id)}
          anchor={editing.anchor}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

const ROLE_LABEL: Record<(typeof TAG_COLOR_ROLES)[number], string> = {
  ok: 'ok',
  ink: 'ink',
  muted: 'muted',
  faint: 'faint',
  warm: 'accent',
  'accent-2': 'accent 2',
  'accent-3': 'accent 3',
  'chart-1': 'series 1',
  'chart-2': 'series 2',
  'chart-3': 'series 3',
  'chart-4': 'series 4',
};

export function TagCustomizer({
  tag,
  anchor,
  onClose,
}: {
  tag: ResolvedTag;
  anchor: HTMLElement;
  onClose: () => void;
}) {
  const toasts = useToasts();
  const [label, setLabel] = useState(tag.label);
  const [color, setColor] = useState<TagColor>(tag.color);
  const [icon, setIcon] = useState<TagIconId | null>(tag.icon);
  const [custom, setCustom] = useState(tag.color.startsWith('#'));
  const preview: ResolvedTag = { ...tag, label: label.trim() || tag.id, color, icon };

  const save = () => {
    const result = directory.upsertTagDef({ id: tag.id, label: label.trim(), color, icon });
    if (!result.ok) {
      toasts.push(result.error, 'danger');
      return;
    }
    onClose();
  };

  return (
    <Popover
      anchor={anchor}
      open
      onClose={onClose}
      label={`Customise tag ${tag.label}`}
      width="w-[300px]"
    >
      <div className="flex flex-col gap-3 p-2" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
            Tag
          </span>
          <span
            style={userTagStyle(preview)}
            className="inline-flex h-5 max-w-[60%] items-center gap-1 rounded-sw-sm border px-1.5 text-[10px] font-medium"
          >
            {icon && <TagIcon icon={icon} size={9} />}
            <span className="truncate">{preview.label}</span>
          </span>
        </div>

        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-faint">Name</span>
          <input
            value={label}
            maxLength={MAX_TAG_LABEL}
            autoFocus
            onChange={(e) => setLabel(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') save();
            }}
            className="h-7 rounded-sw-sm border border-edge bg-paper px-2 font-mono text-[12px] text-ink outline-none focus:border-edge-strong"
          />
          <span className="text-[10px] text-faint">
            id {tag.id} · renaming keeps it on every wallet
          </span>
        </label>

        <div className="flex flex-col gap-1.5">
          <span className="text-[11px] text-faint">Colour</span>
          <div role="radiogroup" aria-label="Tag colour" className="flex flex-wrap gap-1.5">
            {TAG_COLOR_ROLES.map((role) => (
              <button
                key={role}
                type="button"
                role="radio"
                aria-checked={!custom && color === role}
                aria-label={ROLE_LABEL[role]}
                title={`${ROLE_LABEL[role]} · follows the theme`}
                onClick={() => {
                  setCustom(false);
                  setColor(role);
                }}
                className={`sw-pressable h-5 w-5 rounded-full border ${
                  !custom && color === role ? 'border-edge-strong' : 'border-edge'
                }`}
                style={{ backgroundColor: tagColorCss(role) }}
              />
            ))}
            <button
              type="button"
              role="radio"
              aria-checked={custom}
              onClick={() => {
                setCustom(true);
                if (!color.startsWith('#')) setColor('#d8d8d8');
              }}
              className={`sw-pressable h-5 rounded-sw-sm border px-1.5 text-[10px] ${
                custom ? 'border-edge-strong text-ink' : 'border-edge text-faint'
              }`}
            >
              custom
            </button>
          </div>
          {custom && (
            <ColorPicker
              value={color.startsWith('#') ? color : '#d8d8d8'}
              alpha={false}
              onChange={(hex) => setColor(hex.slice(0, 7).toLowerCase())}
              label="Custom tag colour"
            />
          )}
          <span className="text-[10px] text-faint">
            Red stays reserved for security tags; pick any other colour.
          </span>
        </div>

        <div className="flex flex-col gap-1.5">
          <span className="text-[11px] text-faint">Icon</span>
          <div role="radiogroup" aria-label="Tag icon" className="grid grid-cols-8 gap-1">
            <button
              type="button"
              role="radio"
              aria-checked={icon === null}
              aria-label="No icon"
              title="No icon"
              onClick={() => setIcon(null)}
              className={`sw-pressable flex h-6 items-center justify-center rounded-sw-sm border text-[10px] ${
                icon === null ? 'border-edge-strong text-ink' : 'border-edge text-faint'
              }`}
            >
              –
            </button>
            {TAG_ICON_IDS.map((id) => (
              <button
                key={id}
                type="button"
                role="radio"
                aria-checked={icon === id}
                aria-label={id}
                title={id}
                onClick={() => setIcon(id)}
                className={`sw-pressable flex h-6 items-center justify-center rounded-sw-sm border ${
                  icon === id
                    ? 'border-edge-strong text-ink'
                    : 'border-edge text-muted hover:text-ink'
                }`}
              >
                <TagIcon icon={id} size={11} />
              </button>
            ))}
          </div>
        </div>

        <p className="flex items-start gap-1.5 text-[10px] text-faint">
          <SecurityGlyph glyph="lock" size={9} className="mt-px shrink-0" />
          Security tags (exposed, exported, imported, approvals, local) are set by StackWallet from
          key and chain history and cannot be customised or removed.
        </p>

        <div className="flex items-center justify-between gap-2">
          <Button
            size="sm"
            variant="ghost"
            disabled={!tag.custom}
            title="Back to the default look; wallets keep the tag"
            onClick={() => {
              directory.resetTagDef(tag.id);
              onClose();
            }}
          >
            Reset
          </Button>
          <span className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button size="sm" onClick={save}>
              Save
            </Button>
          </span>
        </div>
      </div>
    </Popover>
  );
}
