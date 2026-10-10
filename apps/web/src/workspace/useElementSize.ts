import { useCallback, useEffect, useRef, useState } from 'react';

export interface Size {
  width: number;
  height: number;
}

const ZERO: Size = { width: 0, height: 0 };

/**
 * Content-box size of one element, rounded to whole pixels. Observations are coalesced to
 * one state update per animation frame and skipped entirely when the rounded size is
 * unchanged, so sub-pixel jitter during a resize never re-renders the consumer.
 */
export function useElementSize<T extends HTMLElement>(): [(node: T | null) => void, Size] {
  const [size, setSize] = useState<Size>(ZERO);
  const committed = useRef<Size>(ZERO);
  const pending = useRef<Size>(ZERO);
  const frame = useRef(0);
  const observer = useRef<ResizeObserver | null>(null);

  const ref = useCallback((node: T | null) => {
    observer.current?.disconnect();
    observer.current = null;
    if (frame.current !== 0) {
      cancelAnimationFrame(frame.current);
      frame.current = 0;
    }
    if (!node || typeof ResizeObserver === 'undefined') return;

    const flush = () => {
      frame.current = 0;
      const next = pending.current;
      const prev = committed.current;
      if (next.width === prev.width && next.height === prev.height) return;
      committed.current = next;
      setSize(next);
    };

    const ro = new ResizeObserver((entries) => {
      const entry = entries[entries.length - 1];
      if (!entry) return;
      const box = entry.contentBoxSize?.[0];
      const width = Math.round(box ? box.inlineSize : entry.contentRect.width);
      const height = Math.round(box ? box.blockSize : entry.contentRect.height);
      pending.current = { width, height };
      if (frame.current === 0) frame.current = requestAnimationFrame(flush);
    });
    ro.observe(node);
    observer.current = ro;
  }, []);

  useEffect(
    () => () => {
      observer.current?.disconnect();
      if (frame.current !== 0) cancelAnimationFrame(frame.current);
    },
    [],
  );

  return [ref, size];
}
