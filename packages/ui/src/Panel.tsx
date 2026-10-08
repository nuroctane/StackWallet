import type { HTMLAttributes, ReactNode } from 'react';

export interface PanelProps extends HTMLAttributes<HTMLElement> {
  title?: string;
  meta?: ReactNode;
  elevated?: boolean;
  as?: 'section' | 'aside' | 'div' | 'nav';
}

export function Panel({
  title,
  meta,
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
      {(title || meta) && (
        <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
          {title && (
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted">
              {title}
            </h2>
          )}
          {meta && <div className="text-[11px] text-faint">{meta}</div>}
        </header>
      )}
      <div className="min-h-0 flex-1 overflow-auto">{children}</div>
    </Tag>
  );
}
