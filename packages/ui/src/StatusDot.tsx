export interface StatusDotProps {
  state: 'online' | 'offline' | 'danger';
  label?: string;
}

const colors: Record<StatusDotProps['state'], string> = {
  online: 'bg-ok',
  offline: 'bg-faint',
  danger: 'bg-danger',
};

export function StatusDot({ state, label }: StatusDotProps) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] text-muted">
      <span aria-hidden className={`inline-block h-1.5 w-1.5 rounded-full ${colors[state]}`} />
      {label ?? state}
    </span>
  );
}
