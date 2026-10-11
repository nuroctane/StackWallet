import { useEffect, useRef, useState } from 'react';

import { useWorkspace } from './persist.js';
import { canvasElementRef } from './WorkspaceContext.js';

interface Signal {
  n: number;
  locked: boolean;
  rect: { left: number; top: number; width: number; height: number } | null;
}

/**
 * Feedback for a lock toggle from any source (button, `l`, search): a brief
 * ring around the canvas and a notice naming the new state. Renders nothing
 * on first mount, so a reload never announces a state nobody changed.
 */
export function LockSignal() {
  const { locked } = useWorkspace();
  const first = useRef(true);
  const [signal, setSignal] = useState<Signal | null>(null);

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    const el = canvasElementRef.current;
    const r = el?.getBoundingClientRect();
    setSignal((s) => ({
      n: (s?.n ?? 0) + 1,
      locked,
      rect: r ? { left: r.left, top: r.top, width: r.width, height: r.height } : null,
    }));
    const t = setTimeout(() => setSignal(null), 1200);
    return () => clearTimeout(t);
  }, [locked]);

  if (!signal) return null;
  return (
    <>
      {signal.rect && (
        <div
          key={`ring-${signal.n}`}
          aria-hidden
          className="sw-lock-ring"
          style={signal.rect}
          data-locked={signal.locked ? '' : undefined}
        />
      )}
      <div
        key={`notice-${signal.n}`}
        role="status"
        className="sw-lock-notice"
        data-locked={signal.locked ? '' : undefined}
      >
        {signal.locked ? 'layout locked' : 'layout unlocked'}
      </div>
    </>
  );
}
