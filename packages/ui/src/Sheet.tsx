import {
  useEffect,
  useRef,
  type HTMLAttributes,
  type MouseEvent,
  type ReactNode,
  type SyntheticEvent,
} from 'react';

export interface SheetProps extends Omit<HTMLAttributes<HTMLDialogElement>, 'title'> {
  open: boolean;
  onClose: () => void;
  side: 'left' | 'right';
  /** Accessible name; sheets have no visible title of their own. */
  label: string;
  /** Tailwind width class; defaults to a 320px panel that shrinks on narrow viewports. */
  width?: string;
  children?: ReactNode;
}

const CLOSE_FALLBACK_MS = 400;

/**
 * Edge-anchored modal built on the native `<dialog>`, which supplies the top
 * layer, the focus trap, `inert` on the rest of the page, Escape handling and
 * focus return to the opener. The exit travel is played before `close()` so the
 * panel slides out instead of vanishing.
 */
export function Sheet({
  open,
  onClose,
  side,
  label,
  width = 'w-[min(88vw,320px)]',
  className = '',
  children,
  ...rest
}: SheetProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open) {
      // Reopening mid-exit must cancel the exit travel even though the dialog
      // is still open, or the panel stays parked off-screen while modal.
      el.removeAttribute('data-closing');
      if (!el.open) el.showModal();
      return;
    }
    if (!el.open) return;
    el.setAttribute('data-closing', '');
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      el.removeAttribute('data-closing');
      if (el.open) el.close();
    };
    // Children animate too; only the panel's own exit animation ends the close.
    const onAnimationEnd = (e: AnimationEvent) => {
      if (e.target === el) finish();
    };
    el.addEventListener('animationend', onAnimationEnd);
    const timer = setTimeout(finish, CLOSE_FALLBACK_MS);
    return () => {
      clearTimeout(timer);
      el.removeEventListener('animationend', onAnimationEnd);
    };
  }, [open]);

  const handleBackdrop = (e: MouseEvent<HTMLDialogElement>) => {
    if (e.target !== e.currentTarget) return;
    const r = e.currentTarget.getBoundingClientRect();
    const outside =
      e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    if (outside) onClose();
  };
  const handleCancel = (e: SyntheticEvent<HTMLDialogElement>) => {
    e.preventDefault();
    if (open) onClose();
  };
  const handleClose = () => {
    if (open) onClose();
  };

  return (
    <dialog
      ref={ref}
      tabIndex={-1}
      aria-label={label}
      data-side={side}
      onClick={handleBackdrop}
      onCancel={handleCancel}
      onClose={handleClose}
      className={`sw-sheet sw-glass h-full max-h-none flex-col p-0 text-ink open:flex ${width} ${className}`}
      {...rest}
    >
      {children}
    </dialog>
  );
}
