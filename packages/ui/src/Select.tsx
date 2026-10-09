import { forwardRef, type SelectHTMLAttributes } from 'react';

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  invalid?: boolean;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { invalid = false, className = '', children, ...rest },
  ref,
) {
  return (
    <span className={`relative block ${className}`}>
      <select
        ref={ref}
        aria-invalid={invalid || undefined}
        className={`h-9 w-full appearance-none rounded-sw-sm border bg-paper pr-8 pl-3 font-mono text-[13px] text-ink outline-none focus:border-edge-strong disabled:cursor-not-allowed disabled:opacity-50 ${
          invalid ? 'border-danger/70' : 'border-edge'
        }`}
        {...rest}
      >
        {children}
      </select>
      <svg
        aria-hidden
        viewBox="0 0 12 12"
        className="pointer-events-none absolute top-1/2 right-3 h-3 w-3 -translate-y-1/2 text-faint"
      >
        <path d="M3 4.5l3 3 3-3" fill="none" stroke="currentColor" strokeWidth="1.25" />
      </svg>
    </span>
  );
});
