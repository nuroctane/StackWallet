import { createElement, memo, useCallback } from 'react';

import { Chip } from '@stackwallet/ui';

import type { ElementDefinition } from './elements/types.js';
import { useWorkspace, workspace } from './persist.js';
import type { Layout, Pane, PaneProps } from './schema.js';
import { useElementSize } from './useElementSize.js';
import { useWorkspaceApi } from './WorkspaceContext.js';

/**
 * Narrow-viewport fallback: the active layout as one scrolling column. Front-most panes come
 * first because that is what the user was looking at on the canvas.
 */
export function StackMode() {
  const api = useWorkspaceApi();
  const state = useWorkspace();
  const layout = state.layouts.find((l) => l.id === state.activeId) ?? (state.layouts[0] as Layout);
  const panes = layout.panes.slice().sort((a, b) => b.z - a.z);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto bg-paper p-2">
      {panes.length === 0 && (
        <div className="flex flex-1 items-center justify-center text-[12px] text-faint">
          no elements · press /
        </div>
      )}
      {panes.map((pane) => (
        <StackPane key={pane.id} pane={pane} def={api.registry[pane.kind]} />
      ))}
    </div>
  );
}

interface StackPaneProps {
  pane: Pane;
  def: ElementDefinition;
}

const StackPane = memo(function StackPane({ pane, def }: StackPaneProps) {
  const [bodyRef, size] = useElementSize<HTMLDivElement>();
  const setProps = useCallback((props: PaneProps) => workspace.setProps(pane.id, props), [pane.id]);
  const title = def.titleFor?.(pane) ?? def.title;
  const scope = def.scope?.(pane) ?? [];

  return (
    <section
      aria-label={title}
      className="sw-pane sw-pane-stacked sw-pane-enter flex-none"
      style={{ height: Math.max(260, pane.h) + 28 }}
    >
      <div className="sw-pane-title">
        <span aria-hidden className="text-faint">
          &gt;
        </span>
        <span className="sw-pane-title-text">{title}</span>
        {scope.slice(0, 2).map((s, i) => (
          <Chip key={`${s.label}-${i}`} tone={s.tone ?? 'default'}>
            {s.label}
          </Chip>
        ))}
        <button
          type="button"
          className="sw-pressable sw-pane-icon-btn ml-auto"
          aria-label="close"
          title="close"
          onClick={() => workspace.removePane(pane.id)}
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 12 12"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.2"
            strokeLinecap="round"
            aria-hidden
          >
            <path d="M2.5 2.5l7 7M9.5 2.5l-7 7" />
          </svg>
        </button>
      </div>
      <div ref={bodyRef} className="sw-pane-body min-h-[260px]">
        {createElement(def.body, { pane, width: size.width, height: size.height, setProps })}
      </div>
    </section>
  );
});
