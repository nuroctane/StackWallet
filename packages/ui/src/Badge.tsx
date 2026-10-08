import type { HTMLAttributes } from 'react';

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: 'neutral' | 'warm' | 'danger' | 'ok';
}

const tones: Record<NonNullable<BadgeProps['tone']>, string> = {
  neutral: 'border-edge text-muted',
  warm: 'border-warm/50 text-warm',
  danger: 'border-danger/60 text-danger',
  ok: 'border-edge text-ok',
};

export function Badge({ tone = 'neutral', className = '', ...rest }: BadgeProps) {
  return (
    <span
      className={`inline-flex h-5 items-center rounded-sw-sm border px-1.5 text-[10px] font-medium uppercase tracking-[0.08em] ${tones[tone]} ${className}`}
      {...rest}
    />
  );
}
