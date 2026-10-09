import {
  useEffect,
  useRef,
  type HTMLAttributes,
  type MouseEvent,
  type ReactNode,
  type SyntheticEvent,
} from 'react';

export interface DialogProps extends Omit<HTMLAttributes<HTMLDialogElement>, 'title'> {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  meta?: ReactNode;
  /** Tailwind width class; defaults to a 480px sheet that shrinks on narrow viewports. */
  width?: string;
}

/**
 * Thin wrapper over the native `<dialog>`: the platform supplies the top layer,
 * focus trapping, Escape handling and `inert` on the rest of the page. Children
 * mount only while open so form state resets between uses.
 */
export function Dialog({
  open,
  onClose,
  title,
  meta,
  width = 'w-[min(92vw,480px)]',
  className = '',
  children,
  ...rest
}: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    else if (!open && el.open) el.close();
  }, [open]);

  // The ::backdrop has no DOM node, so a click on it reports the <dialog> as
  // target. Clicks on disabled controls or padding do too; only coordinates
  // outside the dialog's box are a real backdrop click.
  const handleBackdrop = (e: MouseEvent<HTMLDialogElement>) => {
    if (e.target !== e.currentTarget) return;
    const r = e.currentTarget.getBoundingClientRect();
    const outside =
      e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    if (outside) onClose();
  };
  const handleClose = (_e: SyntheticEvent<HTMLDialogElement>) => {
    if (open) onClose();
  };

  return (
    <dialog
      ref={ref}
      onClick={handleBackdrop}
      onClose={handleClose}
      className={`sw-dialog sw-glass m-auto max-h-[85vh] flex-col p-0 text-ink open:flex ${width} ${className}`}
      {...rest}
    >
      {open && (
        <>
          {(title || meta) && (
            <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
              {title && (
                <h2 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
                  {title}
                </h2>
              )}
              {meta && <div className="text-[11px] text-faint">{meta}</div>}
            </header>
          )}
          <div className="min-h-0 flex-1 overflow-auto">{children}</div>
        </>
      )}
    </dialog>
  );
}
