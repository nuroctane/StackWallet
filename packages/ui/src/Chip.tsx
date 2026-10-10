import type { CSSProperties, HTMLAttributes, MouseEvent, ReactNode } from 'react';

export type ChipTone = 'default' | 'warm' | 'danger';

export interface ChipProps extends Omit<HTMLAttributes<HTMLElement>, 'onClick' | 'title'> {
  children?: ReactNode;
  tone?: ChipTone;
  /** Selected state; draws the same warm glass as `tone="warm"`. */
  active?: boolean;
  onClick?: (e: MouseEvent<HTMLButtonElement>) => void;
  /** Renders a small `×` inside the chip; the chip itself stays clickable. */
  onRemove?: () => void;
  title?: string;
  className?: string;
}

const base =
  'inline-flex h-5 max-w-full shrink-0 items-center gap-1 rounded-sw-sm border px-1.5 text-[11px] leading-none lowercase whitespace-nowrap';

const toneClass: Record<ChipTone, string> = {
  default: 'border-edge bg-transparent text-muted',
  warm: 'text-ink',
  // Red is a signal: only for denials, failures and destructive filters.
  danger: 'border-danger/60 bg-danger-soft text-ink',
};

// Warm glass is mixed at draw time so it tracks the token without a second colour entry.
const warmStyle: CSSProperties = {
  backgroundColor: 'color-mix(in srgb, var(--sw-warm) 14%, transparent)',
  borderColor: 'color-mix(in srgb, var(--sw-warm) 55%, transparent)',
};

export function Chip({
  children,
  tone = 'default',
  active = false,
  onClick,
  onRemove,
  title,
  className = '',
  style,
  ...rest
}: ChipProps) {
  const warm = active || tone === 'warm';
  const cls = `${base} ${warm ? toneClass.warm : toneClass[tone]} ${className}`;
  const merged: CSSProperties | undefined = warm ? { ...warmStyle, ...style } : style;

  const remove = onRemove && (
    <button
      type="button"
      aria-label="remove"
      onClick={(e) => {
        // The chip may itself be a button; removing must not also toggle it.
        e.stopPropagation();
        onRemove();
      }}
      className="sw-pressable -mr-0.5 inline-flex h-3.5 w-3.5 items-center justify-center rounded-[3px] text-muted hover:text-ink"
    >
      ×
    </button>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        aria-pressed={active || undefined}
        title={title}
        style={merged}
        className={`sw-pressable ${cls}`}
        {...(rest as HTMLAttributes<HTMLButtonElement>)}
      >
        <span className="truncate">{children}</span>
        {remove}
      </button>
    );
  }

  return (
    <span
      title={title}
      style={merged}
      className={cls}
      {...(rest as HTMLAttributes<HTMLSpanElement>)}
    >
      <span className="truncate">{children}</span>
      {remove}
    </span>
  );
}

export interface OverflowChipProps {
  count: number;
  title?: string;
  className?: string;
}

/** Collapsed remainder of a chip row, e.g. `+3`. */
export function OverflowChip({ count, title, className = '' }: OverflowChipProps) {
  return (
    <span className={`${base} border-edge text-faint ${className}`} title={title}>
      +{count}
    </span>
  );
}
