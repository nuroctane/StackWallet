import { Popover, Select } from '@stackwallet/ui';

import type { SettingField } from './elements/types.js';
import { registry } from './elements/registry.js';
import { usePane, workspace } from './persist.js';

/**
 * Parsec-style `label ⓘ: [control]` rows for one pane. Values write straight
 * into `pane.props`; the element re-renders from the store, so there is no
 * local form state to desynchronise.
 */
export function SettingsPopover({
  paneId,
  anchor,
  onClose,
}: {
  paneId: string | null;
  anchor: HTMLElement | null;
  onClose: () => void;
}) {
  const pane = usePane(paneId ?? '');
  const def = pane ? registry[pane.kind] : undefined;
  const fields = def?.settings ?? [];
  return (
    <Popover
      anchor={anchor}
      open={paneId !== null && pane !== undefined}
      onClose={onClose}
      align="end"
      label={`${def?.title ?? 'element'} settings`}
      width="w-[320px]"
    >
      {pane && def && (
        <div className="flex flex-col">
          <div className="flex h-7 items-center justify-between border-b border-edge px-3 text-[11px] text-faint">
            <span>{def.title} settings</span>
            <button
              type="button"
              aria-label="Close settings"
              onClick={onClose}
              className="sw-pressable -mr-1 h-5 w-5 rounded-sw-sm text-muted"
            >
              ×
            </button>
          </div>
          {fields.length === 0 && (
            <p className="px-3 py-3 text-[12px] text-faint">nothing to configure</p>
          )}
          {fields.map((f) => (
            <Row key={f.key} field={f} value={pane.props[f.key]} paneId={pane.id} />
          ))}
          <div className="flex h-8 items-center justify-between border-t border-edge px-3 text-[11px] text-faint">
            <span>copy element config</span>
            <button
              type="button"
              onClick={() => {
                const cfg = { kind: pane.kind, props: pane.props, w: pane.w, h: pane.h };
                void navigator.clipboard.writeText(JSON.stringify(cfg)).catch(() => undefined);
              }}
              className="sw-pressable -mr-1 rounded-sw-sm px-1 text-muted"
              aria-label="Copy element config to clipboard"
            >
              ⧉
            </button>
          </div>
        </div>
      )}
    </Popover>
  );
}

function Row({
  field,
  value,
  paneId,
}: {
  field: SettingField;
  value: string | number | boolean | undefined;
  paneId: string;
}) {
  const id = `set-${paneId}-${field.key}`;
  return (
    <div className="flex min-h-[34px] items-center gap-3 border-b border-edge/60 px-3 py-1 text-[12px] last:border-b-0">
      <label htmlFor={id} className="flex min-w-0 flex-1 items-center gap-1 text-muted">
        <span className="truncate">{field.label}</span>
        {field.help && (
          <span title={field.help} aria-label={field.help} className="cursor-help text-faint">
            ⓘ
          </span>
        )}
      </label>
      <div className="w-[150px] shrink-0">
        {field.kind === 'toggle' && (
          <input
            id={id}
            type="checkbox"
            checked={value === true}
            onChange={(e) => workspace.setProps(paneId, { [field.key]: e.target.checked })}
            className="h-3.5 w-3.5 accent-[var(--sw-warm)]"
          />
        )}
        {field.kind === 'number' && (
          <input
            id={id}
            type="number"
            value={typeof value === 'number' ? value : ''}
            min={field.min}
            max={field.max}
            step={field.step ?? 1}
            onChange={(e) => {
              const n = Number(e.target.value);
              if (Number.isFinite(n)) workspace.setProps(paneId, { [field.key]: n });
            }}
            className="h-7 w-full rounded-sw-sm border border-edge bg-paper px-2 font-mono text-[12px] text-ink outline-none focus:border-edge-strong"
          />
        )}
        {field.kind === 'select' && (
          <Select
            id={id}
            value={typeof value === 'string' ? value : ''}
            onChange={(e) => workspace.setProps(paneId, { [field.key]: e.target.value })}
            className="[&>select]:h-7 [&>select]:text-[12px]"
          >
            {(typeof field.options === 'function' ? field.options() : field.options).map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        )}
      </div>
    </div>
  );
}
