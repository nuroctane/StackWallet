export interface LoadingWordProps {
  label?: string;
  className?: string;
}

/** Quiet loading state: one dimmed word over a 10px ring. */
export function LoadingWord({ label = 'loading', className = '' }: LoadingWordProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={`flex flex-col items-center justify-center gap-2 py-6 text-[11px] text-faint lowercase ${className}`}
    >
      <span>{label}</span>
      <span
        aria-hidden
        className="sw-spin block h-2.5 w-2.5 rounded-full border border-edge-strong border-t-transparent"
      />
    </div>
  );
}

/** Stands in for a number that has not arrived yet, keeping KPI cells the same width. */
export function Placeholder({ className = '' }: { className?: string }) {
  return (
    <span aria-label="loading" className={`text-faint ${className}`}>
      ··
    </span>
  );
}
