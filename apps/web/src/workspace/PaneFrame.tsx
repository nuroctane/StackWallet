import {
  memo,
  useCallback,
  useContext,
  useMemo,
  useRef,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent,
} from 'react';

import { Chip, OverflowChip } from '@stackwallet/ui';

import { isTypingTarget } from '../shell/ShellContext.js';
import type { ElementDefinition, RenderElement } from './elements/types.js';
import { workspace } from './persist.js';
import type { Pane, PaneProps } from './schema.js';
import type { Rect } from './store.js';
import { useElementSize } from './useElementSize.js';
import { clampToCanvas, usePaneGesture, type Handle } from './usePaneGesture.js';
import { CanvasHostContext, useWorkspaceApi } from './WorkspaceContext.js';

export interface PaneFrameProps {
  pane: Pane;
  focused: boolean;
  locked: boolean;
  def: ElementDefinition;
  setProps: (props: PaneProps) => void;
  /** Visible canvas region in canvas coordinates; only read while the pane is fullscreen. */
  viewport?: Rect | undefined;
  /** Renders the body for the measured size; kept stable by the caller so moves do not re-render it. */
  children: RenderElement;
}

const HANDLES: readonly Handle[] = ['n', 's', 'e', 'w', 'ne', 'nw', 'se', 'sw'];
const MAX_SCOPE_CHIPS = 3;
const NUDGE = 8;
const NUDGE_FAST = 80;
const FULLSCREEN_Z = 100_000;
const FOCUSABLE = 'button,a,input,select,textarea,[contenteditable],[tabindex]';
const ARROWS: Record<string, readonly [number, number]> = {
  ArrowLeft: [-1, 0],
  ArrowRight: [1, 0],
  ArrowUp: [0, -1],
  ArrowDown: [0, 1],
};

const EMPTY_SCOPE: readonly { label: string; tone?: 'warm' | 'default' }[] = [];

function PaneFrameImpl({
  pane,
  focused,
  locked,
  def,
  setProps,
  viewport,
  children,
}: PaneFrameProps) {
  const api = useWorkspaceApi();
  const host = useContext(CanvasHostContext);
  const frameRef = useRef<HTMLDivElement | null>(null);
  const [bodyRef, size] = useElementSize<HTMLDivElement>();
  const fullscreen = pane.fullscreen === true;
  const frozen = locked || fullscreen;

  const others = useCallback(
    (): readonly Rect[] => host.panesRef.current.filter((p) => p.id !== pane.id && !p.fullscreen),
    [host, pane.id],
  );
  const canvasScroll = useCallback(() => host.scrollRef.current, [host]);
  const onCommit = useCallback((rect: Rect) => workspace.setRect(pane.id, rect), [pane.id]);

  const gesture = usePaneGesture({
    pane,
    others,
    locked: frozen,
    onCommit,
    frameRef,
    canvasScroll,
    minSize: def.minSize,
  });

  const onPointerDownCapture = useCallback(
    (e: PointerEvent<HTMLDivElement>) => {
      workspace.focus(pane.id);
      workspace.raise(pane.id);
      // The title row and handles prevent default to stop text selection, which also
      // suppresses the browser's own focus move; do it by hand unless a control was hit.
      const target = e.target as HTMLElement;
      const focusable = target.closest<HTMLElement>(FOCUSABLE);
      if (!focusable || focusable === frameRef.current) {
        frameRef.current?.focus({ preventScroll: true });
      }
    },
    [pane.id],
  );

  const onKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (isTypingTarget(e.target)) return;
      const target = e.target as HTMLElement;
      // Keys from controls inside the body belong to the element, not the frame.
      if (target !== e.currentTarget && !target.closest('.sw-pane-title')) return;
      if (e.ctrlKey || e.metaKey) return;

      const arrow = ARROWS[e.key];
      if (arrow) {
        if (frozen) return;
        e.preventDefault();
        const step = e.shiftKey ? NUDGE_FAST : NUDGE;
        const [ax, ay] = arrow;
        const rect: Rect = { x: pane.x, y: pane.y, w: pane.w, h: pane.h };
        if (e.altKey) {
          rect.w = Math.max(def.minSize?.w ?? 0, pane.w + ax * step);
          rect.h = Math.max(def.minSize?.h ?? 0, pane.h + ay * step);
        } else {
          rect.x += ax * step;
          rect.y += ay * step;
        }
        workspace.setRect(pane.id, clampToCanvas(rect));
        return;
      }
      if (e.altKey) return;
      if (e.key === 'Delete' || e.key === 'Backspace') {
        e.preventDefault();
        workspace.removePane(pane.id);
      } else if (e.key === 'f' || e.key === 'F') {
        e.preventDefault();
        workspace.toggleFullscreen(pane.id);
      } else if (e.key === 'Escape' && fullscreen) {
        e.preventDefault();
        workspace.toggleFullscreen(pane.id);
      }
    },
    [pane, def.minSize, frozen, fullscreen],
  );

  const title = def.titleFor?.(pane) ?? def.title;
  const scope = def.scope?.(pane) ?? EMPTY_SCOPE;
  const Toolbar = def.toolbar;
  const hasSettings = (def.settings?.length ?? 0) > 0;

  const body = useMemo(() => children(pane, size), [children, pane, size]);

  const style: CSSProperties = fullscreen
    ? {
        transform: viewport ? `translate3d(${viewport.x}px, ${viewport.y}px, 0)` : 'none',
        width: viewport ? viewport.w : '100%',
        height: viewport ? viewport.h : '100%',
        zIndex: FULLSCREEN_Z,
      }
    : {
        transform: `translate3d(${pane.x}px, ${pane.y}px, 0)`,
        width: pane.w,
        height: pane.h,
        zIndex: pane.z,
        containIntrinsicSize: `${pane.w}px ${pane.h}px`,
      };

  return (
    <div
      ref={frameRef}
      role="group"
      aria-label={title}
      tabIndex={-1}
      className="sw-pane sw-pane-enter"
      style={style}
      data-pane-id={pane.id}
      data-focused={focused ? '' : undefined}
      data-locked={locked ? '' : undefined}
      data-fullscreen={fullscreen ? '' : undefined}
      onPointerDownCapture={onPointerDownCapture}
      onKeyDown={onKeyDown}
    >
      <div className="sw-pane-title" onPointerDown={gesture.onTitlePointerDown}>
        <span aria-hidden className="text-faint">
          &gt;
        </span>
        <span className="sw-pane-title-text">{title}</span>
        {scope.slice(0, MAX_SCOPE_CHIPS).map((s, i) => (
          <Chip key={`${s.label}-${i}`} tone={s.tone ?? 'default'} title={s.label}>
            {s.label}
          </Chip>
        ))}
        {scope.length > MAX_SCOPE_CHIPS && (
          <OverflowChip
            count={scope.length - MAX_SCOPE_CHIPS}
            title={scope
              .slice(MAX_SCOPE_CHIPS)
              .map((s) => s.label)
              .join(', ')}
          />
        )}
        {Toolbar && (
          <Toolbar pane={pane} width={size.width} height={size.height} setProps={setProps} />
        )}
        <span className="ml-auto flex items-center gap-0.5">
          {hasSettings && (
            <button
              type="button"
              className="sw-pressable sw-pane-icon-btn"
              aria-label="settings"
              title="settings"
              onClick={(e) => api.openSettings(pane.id, e.currentTarget)}
            >
              <GearIcon />
            </button>
          )}
          <button
            type="button"
            className="sw-pressable sw-pane-icon-btn"
            aria-label={fullscreen ? 'exit fullscreen' : 'fullscreen'}
            aria-pressed={fullscreen || undefined}
            title={fullscreen ? 'exit fullscreen (f)' : 'fullscreen (f)'}
            onClick={() => workspace.toggleFullscreen(pane.id)}
          >
            <ExpandIcon exit={fullscreen} />
          </button>
          <button
            type="button"
            className="sw-pressable sw-pane-icon-btn"
            aria-label="close"
            title="close (delete)"
            onClick={() => workspace.removePane(pane.id)}
          >
            <CloseIcon />
          </button>
        </span>
      </div>
      <div ref={bodyRef} className="sw-pane-body">
        {body}
      </div>
      {!frozen &&
        HANDLES.map((h) => (
          <div
            key={h}
            aria-hidden
            className={`sw-handle sw-handle-${h}`}
            onPointerDown={(e) => gesture.onHandlePointerDown(e, h)}
          />
        ))}
    </div>
  );
}

export const PaneFrame = memo(PaneFrameImpl);

const ICON = {
  width: 12,
  height: 12,
  viewBox: '0 0 12 12',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.2,
  strokeLinecap: 'round' as const,
  'aria-hidden': true,
};

function GearIcon() {
  return (
    <svg {...ICON}>
      <circle cx="6" cy="6" r="4" strokeDasharray="2 1.2" />
      <circle cx="6" cy="6" r="1.5" />
    </svg>
  );
}

function ExpandIcon({ exit }: { exit: boolean }) {
  return (
    <svg {...ICON}>
      <path d={exit ? 'M4 1v3H1M8 1v3h3M11 8H8v3M1 8h3v3' : 'M1 4V1h3M8 1h3v3M11 8v3H8M4 11H1V8'} />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg {...ICON}>
      <path d="M2.5 2.5l7 7M9.5 2.5l-7 7" />
    </svg>
  );
}
