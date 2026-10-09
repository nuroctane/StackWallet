import { forwardRef, type InputHTMLAttributes } from 'react';

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean;
  /** Compact variant for toolbars and filters. */
  dense?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { invalid = false, dense = false, className = '', ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      aria-invalid={invalid || undefined}
      className={`w-full rounded-sw-sm border bg-paper px-3 font-mono text-ink outline-none placeholder:text-faint focus:border-edge-strong disabled:cursor-not-allowed disabled:opacity-50 ${
        dense ? 'h-8 text-[12px]' : 'h-9 text-[13px]'
      } ${invalid ? 'border-danger/70' : 'border-edge'} ${className}`}
      {...rest}
    />
  );
});
