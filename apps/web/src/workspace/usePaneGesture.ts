import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
  type RefObject,
} from 'react';

import { PANE_MIN_H, PANE_MIN_W, type Pane } from './schema.js';
import { GRID, SNAP_TOLERANCE, clampRect, snap, snapRect, type Rect } from './store.js';

export type Handle = 'n' | 's' | 'e' | 'w' | 'ne' | 'nw' | 'se' | 'sw';
export type GestureMode = Handle | 'move';

export interface MinSize {
  w: number;
  h: number;
}

export const DEFAULT_MIN: MinSize = { w: PANE_MIN_W, h: PANE_MIN_H };

/**
 * Rect after moving the pointer by (dx, dy) from the gesture start. Edges opposite the
 * handle stay fixed; a shrink below the minimum pins the dragged edge instead of flipping.
 */
export function applyGesture(
  start: Rect,
  handle: GestureMode,
  dx: number,
  dy: number,
  min: MinSize = DEFAULT_MIN,
): Rect {
  if (handle === 'move') return { x: start.x + dx, y: start.y + dy, w: start.w, h: start.h };
  let { x, y, w, h } = start;
  if (handle.includes('e')) w = Math.max(min.w, start.w + dx);
  if (handle.includes('w')) {
    const right = start.x + start.w;
    x = Math.min(start.x + dx, right - min.w);
    w = right - x;
  }
  if (handle.includes('s')) h = Math.max(min.h, start.h + dy);
  if (handle.includes('n')) {
    const bottom = start.y + start.h;
    y = Math.min(start.y + dy, bottom - min.h);
    h = bottom - y;
  }
  return { x, y, w, h };
}

function snapEdge(value: number, targets: readonly number[]): number {
  let best = snap(value);
  let bestD = SNAP_TOLERANCE + 1;
  for (const t of targets) {
    const d = Math.abs(value - t);
    if (d < bestD) {
      bestD = d;
      best = t;
    }
  }
  return best;
}

/**
 * Snap the live rect against the grid and neighbouring pane edges. Moves use the store's
 * `snapRect`; resizes snap only the edges the handle drags, so the opposite edge never
 * creeps and a left/top drag snaps as well as a right/bottom one.
 */
export function snapGesture(
  live: Rect,
  others: readonly Rect[],
  handle: GestureMode,
  min: MinSize = DEFAULT_MIN,
): Rect {
  if (handle === 'move') return snapRect(live, others, 'move');
  const xs: number[] = [];
  const ys: number[] = [];
  for (const o of others) {
    xs.push(o.x, o.x + o.w, o.x - GRID, o.x + o.w + GRID);
    ys.push(o.y, o.y + o.h, o.y - GRID, o.y + o.h + GRID);
  }
  let { x, y, w, h } = live;
  const right = x + w;
  const bottom = y + h;
  if (handle.includes('e')) w = Math.max(min.w, snapEdge(right, xs) - x);
  if (handle.includes('w')) {
    const nx = snapEdge(x, xs);
    if (right - nx >= min.w) {
      x = nx;
      w = right - nx;
    }
  }
  if (handle.includes('s')) h = Math.max(min.h, snapEdge(bottom, ys) - y);
  if (handle.includes('n')) {
    const ny = snapEdge(y, ys);
    if (bottom - ny >= min.h) {
      y = ny;
      h = bottom - ny;
    }
  }
  return { x, y, w, h };
}

/** The canvas only extends right and down, so nothing may end up above or left of the origin. */
export function clampToCanvas(r: Rect): Rect {
  const x = Math.max(0, r.x);
  const y = Math.max(0, r.y);
  return clampRect({ x, y, w: r.w - (x - r.x), h: r.h - (y - r.y) });
}

export interface PaneGestureOptions {
  pane: Pane;
  /** Rects of the other panes, read once per gesture. */
  others: () => readonly Rect[];
  locked: boolean;
  onCommit: (rect: Rect) => void;
  onStart?: (() => void) | undefined;
  frameRef: RefObject<HTMLElement | null>;
  canvasScroll: () => { x: number; y: number };
  minSize?: MinSize | undefined;
}

export interface PaneGesture {
  onTitlePointerDown(e: ReactPointerEvent<HTMLElement>): void;
  onHandlePointerDown(e: ReactPointerEvent<HTMLElement>, handle: Handle): void;
  dragging: boolean;
}

interface Session {
  mode: GestureMode;
  start: Rect;
  live: Rect;
  min: MinSize;
  others: readonly Rect[];
  pointerId: number;
  startClient: { x: number; y: number };
  startScroll: { x: number; y: number };
  lastClient: { x: number; y: number };
  shift: boolean;
  raf: number;
  dispose: () => void;
}

const INTERACTIVE = 'button,a,input,select,textarea,[contenteditable],[data-no-drag]';

function writeRect(el: HTMLElement, r: Rect): void {
  el.style.transform = `translate3d(${r.x}px, ${r.y}px, 0)`;
  el.style.width = `${r.w}px`;
  el.style.height = `${r.h}px`;
}

/**
 * Pointer-capture drag and resize for one pane. The React tree is untouched for the whole
 * gesture: pointer samples are coalesced into one animation frame that writes transform and
 * size straight onto the frame element, and the store hears about the rect once, on release.
 */
export function usePaneGesture(options: PaneGestureOptions): PaneGesture {
  const latest = useRef(options);
  latest.current = options;
  const session = useRef<Session | null>(null);
  const [dragging, setDragging] = useState(false);

  const applyFrame = useCallback((s: Session) => {
    const frame = latest.current.frameRef.current;
    const scroll = latest.current.canvasScroll();
    const dx = s.lastClient.x - s.startClient.x + (scroll.x - s.startScroll.x);
    const dy = s.lastClient.y - s.startClient.y + (scroll.y - s.startScroll.y);
    let live = applyGesture(s.start, s.mode, dx, dy, s.min);
    if (!s.shift) live = snapGesture(live, s.others, s.mode, s.min);
    live = clampToCanvas(live);
    s.live = live;
    if (frame) writeRect(frame, live);
  }, []);

  const finish = useCallback(
    (commit: boolean) => {
      const s = session.current;
      if (!s) return;
      session.current = null;
      if (s.raf !== 0) cancelAnimationFrame(s.raf);
      s.dispose();
      const frame = latest.current.frameRef.current;
      if (commit) {
        applyFrame(s);
        const { start, live } = s;
        const moved =
          start.x !== live.x || start.y !== live.y || start.w !== live.w || start.h !== live.h;
        if (moved) latest.current.onCommit(live);
      } else if (frame) {
        writeRect(frame, s.start);
      }
      if (frame) {
        delete frame.dataset['dragging'];
        frame.style.willChange = '';
      }
      setDragging(false);
    },
    [applyFrame],
  );

  const begin = useCallback(
    (e: ReactPointerEvent<HTMLElement>, mode: GestureMode) => {
      const { locked, pane, frameRef, canvasScroll, others, onStart, minSize } = latest.current;
      if (locked || e.button !== 0 || session.current || !frameRef.current) return;
      if (mode === 'move') {
        const target = e.target as Element | null;
        if (target?.closest(INTERACTIVE)) return;
      }
      e.preventDefault();
      const capture = e.currentTarget;
      const frame = frameRef.current;
      const scroll = canvasScroll();
      const start = { x: pane.x, y: pane.y, w: pane.w, h: pane.h };
      const min = {
        w: Math.max(PANE_MIN_W, minSize?.w ?? 0),
        h: Math.max(PANE_MIN_H, minSize?.h ?? 0),
      };

      const s: Session = {
        mode,
        start,
        live: start,
        min,
        others: others(),
        pointerId: e.pointerId,
        startClient: { x: e.clientX, y: e.clientY },
        startScroll: scroll,
        lastClient: { x: e.clientX, y: e.clientY },
        shift: e.shiftKey,
        raf: 0,
        dispose: () => undefined,
      };

      const schedule = () => {
        if (s.raf !== 0) return;
        s.raf = requestAnimationFrame(() => {
          s.raf = 0;
          if (session.current === s) applyFrame(s);
        });
      };
      const onMove = (ev: PointerEvent) => {
        if (ev.pointerId !== s.pointerId) return;
        s.lastClient = { x: ev.clientX, y: ev.clientY };
        s.shift = ev.shiftKey;
        schedule();
      };
      const onUp = (ev: PointerEvent) => {
        if (ev.pointerId !== s.pointerId) return;
        finish(true);
      };
      const onKey = (ev: KeyboardEvent) => {
        if (ev.key === 'Escape') {
          ev.preventDefault();
          ev.stopPropagation();
          finish(false);
        } else if (ev.key === 'Shift') {
          s.shift = ev.type === 'keydown';
          schedule();
        }
      };

      capture.addEventListener('pointermove', onMove);
      capture.addEventListener('pointerup', onUp);
      capture.addEventListener('pointercancel', onUp);
      capture.addEventListener('lostpointercapture', onUp);
      window.addEventListener('keydown', onKey, true);
      window.addEventListener('keyup', onKey, true);
      s.dispose = () => {
        capture.removeEventListener('pointermove', onMove);
        capture.removeEventListener('pointerup', onUp);
        capture.removeEventListener('pointercancel', onUp);
        capture.removeEventListener('lostpointercapture', onUp);
        window.removeEventListener('keydown', onKey, true);
        window.removeEventListener('keyup', onKey, true);
        if (capture.hasPointerCapture(s.pointerId)) capture.releasePointerCapture(s.pointerId);
      };
      try {
        capture.setPointerCapture(e.pointerId);
      } catch {
        // Capture can fail if the pointer already left (synthetic events, tests); the
        // listeners on the element still see moves while it is hovered.
      }

      session.current = s;
      frame.dataset['dragging'] = '';
      frame.style.willChange = 'transform';
      setDragging(true);
      onStart?.();
    },
    [applyFrame, finish],
  );

  useEffect(
    () => () => {
      const s = session.current;
      if (!s) return;
      session.current = null;
      if (s.raf !== 0) cancelAnimationFrame(s.raf);
      s.dispose();
    },
    [],
  );

  const onTitlePointerDown = useCallback(
    (e: ReactPointerEvent<HTMLElement>) => begin(e, 'move'),
    [begin],
  );
  const onHandlePointerDown = useCallback(
    (e: ReactPointerEvent<HTMLElement>, handle: Handle) => begin(e, handle),
    [begin],
  );

  return { onTitlePointerDown, onHandlePointerDown, dragging };
}
