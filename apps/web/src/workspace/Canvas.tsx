import './workspace.css';

import {
  createElement,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  type MouseEvent,
  type PointerEvent,
  type UIEvent,
} from 'react';

import type { RenderElement } from './elements/types.js';
import { PaneFrame } from './PaneFrame.js';
import { useWorkspace, workspace } from './persist.js';
import type { Layout, Pane, PaneProps } from './schema.js';
import type { Rect } from './store.js';
import { useElementSize } from './useElementSize.js';
import {
  CanvasHostContext,
  canvasElementRef,
  canvasPointRef,
  useWorkspaceApi,
  type CanvasHost,
} from './WorkspaceContext.js';

/** Room kept beyond the furthest pane so there is always somewhere to drag to. */
const MARGIN = 240;
const SCROLL_SAVE_MS = 200;

export function Canvas() {
  const api = useWorkspaceApi();
  const state = useWorkspace();
  const layout = state.layouts.find((l) => l.id === state.activeId) ?? (state.layouts[0] as Layout);
  const panes = layout.panes;

  const canvasRef = useRef<HTMLDivElement | null>(null);
  const sizerRef = useRef<HTMLDivElement | null>(null);
  const [sizeRef, viewportSize] = useElementSize<HTMLDivElement>();
  const setCanvas = useCallback(
    (node: HTMLDivElement | null) => {
      canvasRef.current = node;
      canvasElementRef.current = node;
      sizeRef(node);
    },
    [sizeRef],
  );

  const panesRef = useRef<readonly Pane[]>(panes);
  const scrollRef = useRef({ x: layout.scrollX, y: layout.scrollY });
  const host = useMemo<CanvasHost>(() => ({ panesRef, scrollRef }), []);
  const registryRef = useRef(api.registry);
  useLayoutEffect(() => {
    panesRef.current = panes;
    registryRef.current = api.registry;
  });

  // One stable setter per pane so a body's props do not change identity on every move.
  const setters = useRef(new Map<string, (props: PaneProps) => void>());
  const setPropsFor = useCallback((id: string) => {
    let fn = setters.current.get(id);
    if (!fn) {
      fn = (props: PaneProps) => workspace.setProps(id, props);
      setters.current.set(id, fn);
    }
    return fn;
  }, []);
  useEffect(() => {
    const live = new Set(panes.map((p) => p.id));
    for (const id of setters.current.keys()) if (!live.has(id)) setters.current.delete(id);
  }, [panes]);

  const renderBody = useCallback<RenderElement>(
    (pane, size) => {
      const def = registryRef.current[pane.kind];
      return createElement(def.body, {
        pane,
        width: size.width,
        height: size.height,
        setProps: setPropsFor(pane.id),
      });
    },
    [setPropsFor],
  );

  const saveTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const onScroll = useCallback((e: UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    scrollRef.current = { x: el.scrollLeft, y: el.scrollTop };
    if (saveTimer.current !== undefined) clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      saveTimer.current = undefined;
      workspace.setScroll(scrollRef.current.x, scrollRef.current.y);
    }, SCROLL_SAVE_MS);
  }, []);
  useEffect(
    () => () => {
      if (saveTimer.current !== undefined) {
        clearTimeout(saveTimer.current);
        workspace.setScroll(scrollRef.current.x, scrollRef.current.y);
      }
    },
    [],
  );

  useLayoutEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const active = workspace.active;
    el.scrollLeft = active.scrollX;
    el.scrollTop = active.scrollY;
    scrollRef.current = { x: el.scrollLeft, y: el.scrollTop };
  }, [layout.id]);

  const isEmptySpot = useCallback(
    (target: EventTarget) => target === canvasRef.current || target === sizerRef.current,
    [],
  );

  const onPointerDown = useCallback(
    (e: PointerEvent<HTMLDivElement>) => {
      if (isEmptySpot(e.target)) workspace.focus(null);
    },
    [isEmptySpot],
  );

  const onDoubleClick = useCallback(
    (e: MouseEvent<HTMLDivElement>) => {
      const el = canvasRef.current;
      if (!el || !isEmptySpot(e.target)) return;
      const r = el.getBoundingClientRect();
      canvasPointRef.current = {
        x: e.clientX - r.left + el.scrollLeft,
        y: e.clientY - r.top + el.scrollTop,
      };
      api.openCatalogue(el);
    },
    [api, isEmptySpot],
  );

  let maxRight = 0;
  let maxBottom = 0;
  let fullscreen = false;
  for (const p of panes) {
    if (p.fullscreen) fullscreen = true;
    maxRight = Math.max(maxRight, p.x + p.w);
    maxBottom = Math.max(maxBottom, p.y + p.h);
  }
  const sizerStyle = { width: maxRight + MARGIN, height: maxBottom + MARGIN };
  const viewportRect: Rect | undefined = fullscreen
    ? {
        x: scrollRef.current.x,
        y: scrollRef.current.y,
        w: viewportSize.width,
        h: viewportSize.height,
      }
    : undefined;

  return (
    <div
      ref={setCanvas}
      className="sw-canvas"
      data-fullscreen={fullscreen ? '' : undefined}
      onScroll={onScroll}
      onPointerDown={onPointerDown}
      onDoubleClick={onDoubleClick}
    >
      <CanvasHostContext.Provider value={host}>
        <div ref={sizerRef} className="sw-canvas-sizer" style={sizerStyle}>
          {panes.map((pane) => (
            <PaneFrame
              key={pane.id}
              pane={pane}
              focused={state.focusedPaneId === pane.id}
              locked={state.locked}
              def={api.registry[pane.kind]}
              setProps={setPropsFor(pane.id)}
              viewport={pane.fullscreen ? viewportRect : undefined}
            >
              {renderBody}
            </PaneFrame>
          ))}
        </div>
      </CanvasHostContext.Provider>
      {panes.length === 0 && (
        <div className="sw-canvas-empty" aria-live="polite">
          no elements · press / or double-click
        </div>
      )}
    </div>
  );
}
