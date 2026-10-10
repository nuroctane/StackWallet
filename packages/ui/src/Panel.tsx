import type { HTMLAttributes, ReactNode } from 'react';

export interface PanelProps extends HTMLAttributes<HTMLElement> {
  title?: string;
  meta?: ReactNode;
  /** Controls rendered before the title, e.g. a drawer toggle on narrow layouts. */
  leading?: ReactNode;
  elevated?: boolean;
  as?: 'section' | 'aside' | 'div' | 'nav';
}

export function Panel({
  title,
  meta,
  leading,
  elevated,
  as = 'section',
  className = '',
  children,
  ...rest
}: PanelProps) {
  const Tag = as;
  return (
    <Tag
      className={`${elevated ? 'sw-elevated' : 'sw-glass'} flex min-h-0 flex-col ${className}`}
      {...rest}
    >
      {(title || meta || leading) && (
        <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
          <div className="flex shrink-0 items-center gap-2">
            {leading}
            {title && (
              <h2 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
                {title}
              </h2>
            )}
          </div>
          {meta && (
            <div className="flex min-w-0 items-center truncate text-[11px] text-faint">{meta}</div>
          )}
        </header>
      )}
      <div className="min-h-0 flex-1 overflow-auto">{children}</div>
    </Tag>
  );
}
