import { useMemo, useState, type ReactNode } from 'react';
import {
  Button,
  ColorPicker,
  contrastRatio,
  Sheet,
  TOKEN_GROUPS,
  TOKEN_META,
  useToasts,
  type ThemePreset,
  type ThemeToken,
  type ThemeTokens,
} from '@stackwallet/ui';

import {
  presetsFor,
  resolveSpec,
  specFor,
  themeStore,
  useThemeState,
  type ThemeScope,
} from '../store/theme.js';
import { useActiveLayout } from '../workspace/persist.js';

/**
 * Pairs that must stay legible whatever the user picks. Text needs 4.5:1,
 * labels and signals 3:1 (WCAG AA for UI components).
 */
const CONTRAST_CHECKS: readonly { fg: ThemeToken; bg: ThemeToken; min: number; what: string }[] = [
  { fg: 'ink', bg: 'paper', min: 4.5, what: 'text on paper' },
  { fg: 'ink', bg: 'surface', min: 4.5, what: 'text on panels' },
  { fg: 'muted', bg: 'surface', min: 4.5, what: 'secondary text' },
  { fg: 'faint', bg: 'surface', min: 3, what: 'labels' },
  { fg: 'danger', bg: 'surface', min: 3, what: 'danger signal' },
  { fg: 'warm', bg: 'surface', min: 3, what: 'accent' },
];

type Section = 'presets' | 'colours';

export function ThemeStudio({ open, onClose }: { open: boolean; onClose: () => void }) {
  const state = useThemeState();
  const layout = useActiveLayout();
  const toasts = useToasts();
  const [scopeKind, setScopeKind] = useState<'global' | 'layout'>('global');
  const [section, setSection] = useState<Section>('presets');
  const [filter, setFilter] = useState('');
  const [editing, setEditing] = useState<ThemeToken | null>(null);
  const [saveName, setSaveName] = useState('');
  const [importText, setImportText] = useState<string | null>(null);

  const scope: ThemeScope =
    scopeKind === 'global' ? { kind: 'global' } : { kind: 'layout', id: layout.id };
  const ownLayout = layout.id in state.layouts;
  const editable = scope.kind === 'global' || ownLayout;
  const spec = specFor(state, scope);
  const tokens = resolveSpec(state, spec);
  const presets = useMemo(() => presetsFor(state), [state]);
  const q = filter.trim().toLowerCase();
  const shown = q
    ? presets.filter((p) => `${p.name} ${p.description} ${p.id}`.toLowerCase().includes(q))
    : presets;

  const ensureEditable = () => {
    if (scope.kind === 'layout' && !ownLayout) themeStore.detachLayout(layout.id);
  };

  const pickPreset = (id: string) => {
    ensureEditable();
    themeStore.setPreset(scope, id);
  };

  const copyExport = async () => {
    const name = saveName.trim() || (presets.find((p) => p.id === spec.preset)?.name ?? 'theme');
    const text = themeStore.exportScope(scope, name);
    try {
      await navigator.clipboard.writeText(text);
      toasts.push('Theme copied as JSON');
    } catch {
      setImportText(text);
      toasts.push('Clipboard blocked; the JSON is in the box below');
    }
  };

  return (
    <Sheet
      open={open}
      onClose={onClose}
      side="right"
      label="theme studio"
      width="w-[min(96vw,400px)]"
      className="sw-sheet-clear"
    >
      <header className="flex h-10 flex-none items-center gap-2 border-b border-edge px-3 text-[12px] lowercase">
        <span className="text-faint">{'>'}</span>
        <span className="font-semibold text-ink">theme</span>
        <span className="truncate text-faint">
          {presets.find((p) => p.id === spec.preset)?.name ?? 'night glass'}
          {Object.keys(spec.overrides).length > 0 &&
            ` · ${Object.keys(spec.overrides).length} edited`}
        </span>
        <button
          type="button"
          className="sw-pressable ml-auto inline-flex h-6 w-6 items-center justify-center rounded-sw-sm text-muted"
          aria-label="close theme studio"
          onClick={onClose}
        >
          ×
        </button>
      </header>

      <div className="flex flex-none flex-col gap-2 border-b border-edge p-3 text-[12px] lowercase">
        <div className="flex gap-1" role="radiogroup" aria-label="theme scope">
          <ScopeButton active={scopeKind === 'global'} onClick={() => setScopeKind('global')}>
            all layouts
          </ScopeButton>
          <ScopeButton active={scopeKind === 'layout'} onClick={() => setScopeKind('layout')}>
            layout · {layout.name}
          </ScopeButton>
        </div>
        {scope.kind === 'layout' && !ownLayout && (
          <p className="text-faint">
            this layout follows the global theme. picking a preset or colour gives it its own.
          </p>
        )}
        {scope.kind === 'layout' && ownLayout && (
          <p className="flex items-center gap-2 text-faint">
            this layout has its own theme.
            <button
              type="button"
              className="sw-pressable text-muted underline decoration-dotted"
              onClick={() => themeStore.resetScope(scope)}
            >
              follow global
            </button>
          </p>
        )}
        <div className="flex gap-1" role="tablist" aria-label="theme sections">
          {(['presets', 'colours'] as const).map((s) => (
            <button
              key={s}
              type="button"
              role="tab"
              aria-selected={section === s}
              className={`sw-pressable h-6 rounded-sw-sm px-2 ${section === s ? 'bg-elevated text-ink' : 'text-faint'}`}
              onClick={() => setSection(s)}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {section === 'presets' ? (
          <div className="flex flex-col gap-3 p-3">
            <input
              className="h-7 rounded-sw-sm border border-edge bg-paper px-2 text-[12px] text-ink outline-none placeholder:text-faint focus:border-edge-strong"
              placeholder={`filter ${presets.length} themes`}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              aria-label="filter themes"
            />
            {(['stackwallet', 'nur', 'custom'] as const).map((family) => {
              const list = shown.filter((p) => p.family === family);
              if (list.length === 0) return null;
              return (
                <section key={family} className="flex flex-col gap-1.5">
                  <h3 className="text-[10px] tracking-[0.08em] text-faint uppercase">
                    {family === 'nur' ? 'nur studies' : family === 'custom' ? 'yours' : 'house'}
                  </h3>
                  <div className="grid grid-cols-2 gap-1.5">
                    {list.map((p) => (
                      <PresetCard
                        key={p.id}
                        preset={p}
                        selected={spec.preset === p.id}
                        onPick={() => pickPreset(p.id)}
                        onDelete={
                          p.family === 'custom' ? () => themeStore.deleteCustom(p.id) : undefined
                        }
                      />
                    ))}
                  </div>
                </section>
              );
            })}
          </div>
        ) : (
          <div className="flex flex-col">
            <Contrast tokens={tokens} />
            {TOKEN_GROUPS.map((g) => (
              <section key={g.name} className="border-b border-edge py-1">
                <h3 className="px-3 pt-1.5 pb-1 text-[10px] tracking-[0.08em] text-faint uppercase">
                  {g.name}
                </h3>
                {g.tokens.map((t) => (
                  <TokenRow
                    key={t}
                    token={t}
                    value={tokens[t]}
                    overridden={editable && t in spec.overrides}
                    open={editing === t}
                    onToggle={() => setEditing((cur) => (cur === t ? null : t))}
                    onChange={(hex) => {
                      ensureEditable();
                      themeStore.setToken(scope, t, hex);
                    }}
                    onCommit={(hex) => themeStore.pushRecent(hex)}
                    onReset={() => themeStore.resetToken(scope, t)}
                    swatches={[...state.recent, ...Object.values(tokens)]}
                  />
                ))}
              </section>
            ))}
          </div>
        )}
      </div>

      <footer className="flex flex-none flex-col gap-2 border-t border-edge p-3 text-[12px] lowercase">
        <form
          className="flex gap-1.5"
          onSubmit={(e) => {
            e.preventDefault();
            ensureEditable();
            const id = themeStore.saveCustom(scope, saveName);
            if (id) {
              toasts.push(`Saved theme “${saveName.trim()}”`);
              setSaveName('');
            }
          }}
        >
          <input
            className="h-7 min-w-0 flex-1 rounded-sw-sm border border-edge bg-paper px-2 text-ink outline-none placeholder:text-faint focus:border-edge-strong"
            placeholder="name this theme"
            maxLength={40}
            value={saveName}
            onChange={(e) => setSaveName(e.target.value)}
            aria-label="theme name"
          />
          <Button size="sm" type="submit" disabled={saveName.trim() === ''}>
            save
          </Button>
        </form>
        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" variant="ghost" onClick={() => void copyExport()}>
            copy json
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setImportText((v) => (v === null ? '' : null))}
          >
            paste json
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="ml-auto"
            onClick={() => themeStore.resetScope(scope)}
          >
            {scope.kind === 'global' ? 'reset to night glass' : 'follow global'}
          </Button>
        </div>
        {importText !== null && (
          <div className="flex flex-col gap-1.5">
            <textarea
              className="h-20 resize-none rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[11px] text-ink outline-none focus:border-edge-strong"
              value={importText}
              spellCheck={false}
              aria-label="theme json"
              placeholder='{"stackwalletTheme":1,"name":"…","tokens":{…}}'
              onChange={(e) => setImportText(e.target.value)}
            />
            <Button
              size="sm"
              disabled={importText.trim() === ''}
              onClick={() => {
                ensureEditable();
                const r = themeStore.importTheme(scope, importText);
                if (r.ok) {
                  toasts.push(`Imported “${r.name}”`);
                  setImportText(null);
                } else toasts.push(`Import refused: ${r.error}`, 'danger');
              }}
            >
              import
            </Button>
          </div>
        )}
      </footer>
    </Sheet>
  );
}

function ScopeButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      className={`sw-pressable h-7 max-w-[60%] truncate rounded-sw-sm border px-2 ${active ? 'border-edge-strong text-ink' : 'border-edge text-faint'}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function PresetCard({
  preset,
  selected,
  onPick,
  onDelete,
}: {
  preset: ThemePreset;
  selected: boolean;
  onPick: () => void;
  onDelete?: (() => void) | undefined;
}) {
  const t = preset.tokens;
  return (
    <div className="group relative">
      <button
        type="button"
        aria-pressed={selected}
        title={preset.description || preset.name}
        onClick={onPick}
        className={`sw-pressable flex w-full flex-col overflow-hidden rounded-sw-sm border text-left ${selected ? 'border-edge-strong ring-1 ring-warm' : 'border-edge'}`}
        style={{ background: t.paper }}
      >
        <span
          className="m-1.5 mb-1 flex items-center gap-1 rounded-[4px] px-1.5 py-1"
          style={{ background: t.surface, color: t.ink, border: `1px solid ${t.edge}` }}
        >
          <span className="text-[11px] font-semibold">Aa</span>
          <span className="ml-auto flex gap-0.5">
            {[t.warm, t['accent-2'], t['accent-3'], t.danger].map((c, i) => (
              <span key={i} className="h-2 w-2 rounded-full" style={{ background: c }} />
            ))}
          </span>
        </span>
        <span className="truncate px-1.5 pb-1.5 text-[11px]" style={{ color: t.muted }}>
          {preset.name.toLowerCase()}
        </span>
      </button>
      {onDelete && (
        <button
          type="button"
          aria-label={`delete ${preset.name}`}
          title="delete this theme"
          className="sw-pressable absolute top-1 right-1 hidden h-4 w-4 items-center justify-center rounded-full bg-elevated text-[10px] text-muted group-hover:inline-flex focus:inline-flex"
          onClick={onDelete}
        >
          ×
        </button>
      )}
    </div>
  );
}

function TokenRow({
  token,
  value,
  overridden,
  open,
  onToggle,
  onChange,
  onCommit,
  onReset,
  swatches,
}: {
  token: ThemeToken;
  value: string;
  overridden: boolean;
  open: boolean;
  onToggle: () => void;
  onChange: (hex: string) => void;
  onCommit: (hex: string) => void;
  onReset: () => void;
  swatches: readonly string[];
}) {
  const meta = TOKEN_META[token];
  const unique = [...new Set(swatches)].slice(0, 24);
  return (
    <div className={open ? 'bg-hover' : ''}>
      <div className="flex h-8 items-center gap-2 px-3 text-[12px]">
        <button
          type="button"
          aria-expanded={open}
          aria-label={`edit ${meta.label}`}
          className="sw-checker sw-pressable h-5 w-5 flex-none rounded-[4px] border border-edge-strong"
          style={{ ['--swatch' as string]: value }}
          onClick={onToggle}
        />
        <button
          type="button"
          className="flex min-w-0 flex-1 items-baseline gap-2 text-left"
          title={meta.hint}
          onClick={onToggle}
        >
          <span className="w-[84px] flex-none truncate text-ink lowercase">{meta.label}</span>
          <span className="min-w-0 truncate text-[10px] text-faint">{meta.hint}</span>
        </button>
        <code className="w-[68px] flex-none text-right text-[11px] text-muted">{value}</code>
        <button
          type="button"
          className={`sw-pressable h-5 w-5 flex-none rounded-sw-sm text-[11px] ${overridden ? 'text-warm' : 'invisible'}`}
          aria-label={`reset ${meta.label}`}
          title="reset to preset"
          onClick={onReset}
        >
          ↺
        </button>
      </div>
      {open && (
        <div
          className="flex justify-center pb-2"
          onPointerUp={() => onCommit(value)}
          onKeyUp={(e) => {
            if (e.key.startsWith('Arrow')) onCommit(value);
          }}
        >
          <ColorPicker value={value} onChange={onChange} swatches={unique} label={meta.label} />
        </div>
      )}
    </div>
  );
}

function Contrast({ tokens }: { tokens: ThemeTokens }) {
  const rows = CONTRAST_CHECKS.map((c) => {
    const ratio = contrastRatio(tokens[c.fg], tokens[c.bg]);
    return { ...c, ratio, ok: ratio >= c.min };
  });
  const failing = rows.filter((r) => !r.ok);
  return (
    <section className="border-b border-edge px-3 py-2 text-[11px]" aria-label="contrast checks">
      <h3 className="pb-1 text-[10px] tracking-[0.08em] text-faint uppercase">legibility</h3>
      <ul className="grid grid-cols-2 gap-x-3 gap-y-0.5">
        {rows.map((r) => (
          <li key={r.what} className="flex justify-between gap-2">
            <span className="truncate text-faint">{r.what}</span>
            <span className={r.ok ? 'text-muted' : 'text-danger'}>
              {r.ratio.toFixed(1)}:1{r.ok ? '' : ` < ${r.min}`}
            </span>
          </li>
        ))}
      </ul>
      {failing.length > 0 && (
        <p className="pt-1 text-faint">
          some pairs are below the legibility floor; signing screens may be hard to read.
        </p>
      )}
    </section>
  );
}
