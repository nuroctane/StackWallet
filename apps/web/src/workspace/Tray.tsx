import { useCallback, useEffect, useState, type ReactNode } from 'react';

import { Chip } from '@stackwallet/ui';

import { isTypingTarget } from '../shell/ShellContext.js';

export interface TrayProps {
  children?: ReactNode;
  /** Pending items; shown as a warm chip on the pill when above zero. */
  count?: number | undefined;
  /** Controlled open state; leave both unset for the tray to own it. */
  open?: boolean | undefined;
  onOpenChange?: ((open: boolean) => void) | undefined;
}

/** Bottom-right persistent activity tray, sitting just above the status bar. */
export function Tray({ children, count = 0, open, onOpenChange }: TrayProps) {
  const [internal, setInternal] = useState(false);
  const isOpen = open ?? internal;

  const setOpen = useCallback(
    (next: boolean) => {
      if (open === undefined) setInternal(next);
      onOpenChange?.(next);
    },
    [open, onOpenChange],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.key !== '.' || isTypingTarget(e.target)) return;
      e.preventDefault();
      setOpen(!isOpen);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, setOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, setOpen]);

  return (
    <div className="fixed right-3 bottom-9 z-40 flex flex-col items-end font-mono">
      {isOpen && (
        <section
          aria-label="activity"
          className="sw-elevated sw-enter sw-tray-panel mb-2 flex h-[240px] w-[320px] flex-col overflow-hidden shadow-[0_12px_40px_rgb(0_0_0/0.55)]"
        >
          <header className="flex h-7 flex-none items-center gap-2 border-b border-edge px-3 text-[11px] lowercase text-muted">
            activity
            {count > 0 && <Chip tone="warm">{count}</Chip>}
          </header>
          <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
        </section>
      )}
      <button
        type="button"
        className="sw-pressable sw-elevated inline-flex h-6 items-center gap-1.5 rounded-full! px-2.5 text-[11px] lowercase text-muted hover:text-ink"
        aria-expanded={isOpen}
        title={isOpen ? 'hide activity (ctrl+.)' : 'show activity (ctrl+.)'}
        onClick={() => setOpen(!isOpen)}
      >
        activity
        {count > 0 && <Chip tone="warm">{count}</Chip>}
        <span aria-hidden className="text-faint">
          {isOpen ? '⌄' : '^'}
        </span>
      </button>
    </div>
  );
}
