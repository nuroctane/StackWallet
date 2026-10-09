import type { ReactNode } from 'react';

export interface FieldProps {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  error?: ReactNode;
  className?: string;
  children: ReactNode;
}

export function Field({ label, htmlFor, hint, error, className = '', children }: FieldProps) {
  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      <label
        htmlFor={htmlFor}
        className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase"
      >
        {label}
      </label>
      {children}
      {error ? (
        <div role="alert" className="text-[11px] text-danger">
          {error}
        </div>
      ) : hint ? (
        <div className="text-[11px] text-faint">{hint}</div>
      ) : null}
    </div>
  );
}
