import type { ButtonHTMLAttributes } from 'react';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'primary' | 'danger' | 'ghost';
  size?: 'sm' | 'md';
}

const variants: Record<NonNullable<ButtonProps['variant']>, string> = {
  default: 'border border-edge bg-elevated text-ink',
  primary: 'border border-edge-strong bg-ink text-paper',
  // Red is a signal: only for irreversible or denying actions.
  danger: 'border border-danger/60 bg-danger-soft text-ink',
  ghost: 'border border-transparent bg-transparent text-muted',
};

const sizes: Record<NonNullable<ButtonProps['size']>, string> = {
  sm: 'h-7 px-2.5 text-[12px]',
  md: 'h-9 px-3.5 text-[13px]',
};

export function Button({
  variant = 'default',
  size = 'md',
  className = '',
  type = 'button',
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      className={`sw-pressable inline-flex items-center justify-center gap-2 rounded-sw-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${sizes[size]} ${className}`}
      {...rest}
    />
  );
}
