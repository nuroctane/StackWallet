import { useEffect, useLayoutEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

export type PopoverAlign = 'start' | 'end';
export type PopoverSide = 'bottom' | 'top';

export interface PopoverRect {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface PopoverViewport {
  width: number;
  height: number;
  scrollX?: number;
  scrollY?: number;
}

export interface PositionOptions {
  align?: PopoverAlign;
  side?: PopoverSide;
  offset?: number;
  /** Minimum gap kept between the popover and the viewport edge. */
  margin?: number;
}

export interface PopoverPosition {
  left: number;
  top: number;
  /** Side actually used after flipping; drives the enter transform origin. */
  side: PopoverSide;
}

/**
 * Places a popover of `pop` size against `anchor` (both in viewport coordinates) and returns
 * document coordinates. Flips to the other side only when that side has more room, then
 * clamps into the viewport so a popover near an edge slides rather than overflows.
 */
export function positionPopover(
  anchor: PopoverRect,
  pop: { width: number; height: number },
  viewport: PopoverViewport,
  { align = 'start', side = 'bottom', offset = 6, margin = 8 }: PositionOptions = {},
): PopoverPosition {
  const roomBelow = viewport.height - margin - (anchor.top + anchor.height + offset);
  const roomAbove = anchor.top - offset - margin;
  let resolved: PopoverSide = side;
  if (side === 'bottom' && pop.height > roomBelow && roomAbove > roomBelow) resolved = 'top';
  else if (side === 'top' && pop.height > roomAbove && roomBelow > roomAbove) resolved = 'bottom';

  let left = align === 'start' ? anchor.left : anchor.left + anchor.width - pop.width;
  let top =
    resolved === 'bottom' ? anchor.top + anchor.height + offset : anchor.top - pop.height - offset;

  left = clamp(left, margin, Math.max(margin, viewport.width - margin - pop.width));
  top = clamp(top, margin, Math.max(margin, viewport.height - margin - pop.height));

  return {
    left: left + (viewport.scrollX ?? 0),
    top: top + (viewport.scrollY ?? 0),
    side: resolved,
  };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

export interface PopoverProps {
  anchor: HTMLElement | null;
  open: boolean;
  onClose: () => void;
  children?: ReactNode;
  align?: PopoverAlign;
  side?: PopoverSide;
  offset?: number;
  /** Accessible name; a popover has no visible title. */
  label: string;
  /** Tailwind width class. */
  width?: string;
  className?: string;
}

/**
 * Anchored, non-modal floating panel rendered into `document.body`. Position is written
 * straight to the element's style inside a layout effect so the first paint is already in
 * place and scroll/resize repositioning never re-renders React.
 */
export function Popover({
  anchor,
  open,
  onClose,
  children,
  align = 'start',
  side = 'bottom',
  offset = 6,
  label,
  width = 'w-[260px]',
  className = '',
}: PopoverProps) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useLayoutEffect(() => {
    if (!open || !anchor) return;
    const el = ref.current;
    if (!el) return;
    let raf = 0;
    const place = () => {
      raf = 0;
      const root = document.documentElement;
      const pos = positionPopover(
        anchor.getBoundingClientRect(),
        { width: el.offsetWidth, height: el.offsetHeight },
        {
          width: root.clientWidth,
          height: root.clientHeight,
          scrollX: window.scrollX,
          scrollY: window.scrollY,
        },
        { align, side, offset },
      );
      el.style.left = `${pos.left}px`;
      el.style.top = `${pos.top}px`;
      el.style.transformOrigin = `${align === 'start' ? 'left' : 'right'} ${
        pos.side === 'bottom' ? 'top' : 'bottom'
      }`;
    };
    const schedule = () => {
      if (raf === 0) raf = requestAnimationFrame(place);
    };
    place();
    const observer = new ResizeObserver(schedule);
    observer.observe(el);
    window.addEventListener('resize', schedule);
    // Capture catches scrolling inside nested panes, not just the window.
    window.addEventListener('scroll', schedule, true);
    return () => {
      if (raf !== 0) cancelAnimationFrame(raf);
      observer.disconnect();
      window.removeEventListener('resize', schedule);
      window.removeEventListener('scroll', schedule, true);
    };
  }, [open, anchor, align, side, offset]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      const t = e.target as Node | null;
      if (ref.current?.contains(t) || anchor?.contains(t)) return;
      closeRef.current();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      closeRef.current();
    };
    document.addEventListener('pointerdown', onDown, true);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDown, true);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, anchor]);

  useEffect(() => {
    if (!open) return;
    const el = ref.current;
    if (!el) return;
    const first = el.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? el).focus({ preventScroll: true });
    return () => {
      // Only pull focus back when the popover owned it; a click elsewhere keeps its target.
      const active = document.activeElement;
      if (anchor && (active === null || active === document.body || el.contains(active))) {
        anchor.focus({ preventScroll: true });
      }
    };
  }, [open, anchor]);

  if (!open || typeof document === 'undefined') return null;

  return createPortal(
    <div
      ref={ref}
      role="dialog"
      aria-label={label}
      tabIndex={-1}
      className={`sw-popover sw-elevated sw-enter absolute top-0 left-0 z-50 max-h-[calc(100dvh-16px)] max-w-[calc(100vw-16px)] overflow-auto p-1 text-[12px] text-ink shadow-[0_12px_40px_rgb(0_0_0/0.6)] outline-none ${width} ${className}`}
    >
      {children}
    </div>,
    document.body,
  );
}
