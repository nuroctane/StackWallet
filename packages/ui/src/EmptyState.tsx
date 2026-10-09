import type { ReactNode } from 'react';

export interface EmptyStateProps {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ title, description, action, className = '' }: EmptyStateProps) {
  return (
    <div
      className={`flex flex-col items-center justify-center gap-2 px-6 py-10 text-center ${className}`}
    >
      <div className="text-[13px] font-medium text-muted">{title}</div>
      {description && <div className="max-w-[36ch] text-[12px] text-faint">{description}</div>}
      {action && <div className="mt-2 flex flex-wrap justify-center gap-2">{action}</div>}
    </div>
  );
}
