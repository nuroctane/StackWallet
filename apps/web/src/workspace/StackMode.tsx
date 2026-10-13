import { createElement, memo, useCallback } from 'react';

import { Chip } from '@stackwallet/ui';
import { isTypingTarget } from '../shell/ShellContext.js';

import type { ElementDefinition } from './elements/types.js';
import { useWorkspace, workspace } from './persist.js';
import { PaneCollapseToggle, PaneControls } from './PaneControls.js';
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
  const fullscreen = panes.find((pane) => pane.fullscreen);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto bg-paper p-2">
      {panes.length === 0 && (
        <div className="flex flex-1 items-center justify-center text-[12px] text-faint">
          no elements · press /
        </div>
      )}
      {(fullscreen ? [fullscreen] : panes).map((pane) => (
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
  const api = useWorkspaceApi();
  const [bodyRef, size] = useElementSize<HTMLDivElement>();
  const setProps = useCallback((props: PaneProps) => workspace.setProps(pane.id, props), [pane.id]);
  const title = def.titleFor?.(pane) ?? def.title;
  const scope = def.scope?.(pane) ?? [];

  return (
    <section
      aria-label={title}
      tabIndex={-1}
      onKeyDown={(e) => {
        if (isTypingTarget(e.target) || e.ctrlKey || e.metaKey || e.altKey) return;
        const target = e.target as HTMLElement;
        if (target !== e.currentTarget && !target.closest('.sw-pane-title')) return;
        if (e.key.toLowerCase() === 'c') {
          e.preventDefault();
          workspace.toggleCollapsed(pane.id);
        } else if (e.key.toLowerCase() === 'f' || (e.key === 'Escape' && pane.fullscreen)) {
          e.preventDefault();
          workspace.toggleFullscreen(pane.id);
        }
      }}
      className="sw-pane sw-pane-stacked sw-pane-enter flex-none"
      data-collapsed={pane.collapsed ? '' : undefined}
      data-fullscreen={pane.fullscreen ? '' : undefined}
      style={
        pane.fullscreen
          ? { height: '100%', minHeight: 0, flex: '1 1 0' }
          : { height: Math.max(260, pane.h) + 44 }
      }
    >
      <div className="sw-pane-title">
        <PaneCollapseToggle pane={pane} />
        <span className="sw-pane-title-text">{title}</span>
        {scope.slice(0, 2).map((s, i) => (
          <Chip key={`${s.label}-${i}`} tone={s.tone ?? 'default'}>
            {s.label}
          </Chip>
        ))}
        {(def.settings?.length ?? 0) > 0 && (
          <button
            type="button"
            className="sw-pressable sw-pane-icon-btn"
            aria-label="settings"
            onClick={(e) => api.openSettings(pane.id, e.currentTarget)}
          >
            <svg
              width="12"
              height="12"
              viewBox="0 0 12 12"
              fill="none"
              stroke="currentColor"
              aria-hidden
            >
              <circle cx="6" cy="6" r="4" strokeDasharray="2 1.2" />
              <circle cx="6" cy="6" r="1.5" />
            </svg>
          </button>
        )}
        <PaneControls pane={pane} />
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
      <div ref={bodyRef} className="sw-pane-body" hidden={pane.collapsed}>
        {!pane.collapsed &&
          createElement(def.body, { pane, width: size.width, height: size.height, setProps })}
      </div>
    </section>
  );
});
