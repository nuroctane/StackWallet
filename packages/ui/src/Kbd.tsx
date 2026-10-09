import type { HTMLAttributes } from 'react';

export type KbdProps = HTMLAttributes<HTMLElement>;

export function Kbd({ className = '', ...rest }: KbdProps) {
  return (
    <kbd
      className={`inline-flex h-5 min-w-5 items-center justify-center rounded-sw-sm border border-edge bg-elevated px-1.5 font-mono text-[10px] text-muted ${className}`}
      {...rest}
    />
  );
}
