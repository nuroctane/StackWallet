import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

export type ToastTone = 'neutral' | 'danger';

export interface ToastItem {
  id: string;
  message: string;
  tone: ToastTone;
}

export interface ToastApi {
  toasts: readonly ToastItem[];
  push: (message: string, tone?: ToastTone) => string;
  dismiss: (id: string) => void;
}

const noop: ToastApi = { toasts: [], push: () => '', dismiss: () => undefined };
const ToastContext = createContext<ToastApi>(noop);

export function useToasts(): ToastApi {
  return useContext(ToastContext);
}

let seq = 0;

export function ToastProvider({
  children,
  durationMs = 4000,
}: {
  children: ReactNode;
  durationMs?: number;
}) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: string) => {
    const t = timers.current.get(id);
    if (t !== undefined) clearTimeout(t);
    timers.current.delete(id);
    setToasts((list) => list.filter((x) => x.id !== id));
  }, []);

  const push = useCallback(
    (message: string, tone: ToastTone = 'neutral') => {
      const id = `toast-${++seq}`;
      setToasts((list) => [...list, { id, message, tone }]);
      timers.current.set(
        id,
        setTimeout(() => dismiss(id), durationMs),
      );
      return id;
    },
    [dismiss, durationMs],
  );

  useEffect(() => {
    const map = timers.current;
    return () => map.forEach((t) => clearTimeout(t));
  }, []);

  const api = useMemo<ToastApi>(() => ({ toasts, push, dismiss }), [toasts, push, dismiss]);

  return (
    <ToastContext value={api}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext>
  );
}

export function ToastViewport({
  toasts,
  onDismiss,
}: {
  toasts: readonly ToastItem[];
  onDismiss: (id: string) => void;
}) {
  if (toasts.length === 0) return null;
  return (
    <div
      aria-live="polite"
      className="pointer-events-none fixed right-4 bottom-10 z-50 flex w-[320px] flex-col items-end gap-2"
    >
      {toasts.map((t) => (
        <Toast key={t.id} toast={t} onDismiss={() => onDismiss(t.id)} />
      ))}
    </div>
  );
}

const tones: Record<ToastTone, string> = {
  neutral: 'border-edge text-ink',
  danger: 'border-danger/60 bg-danger-soft text-ink',
};

export function Toast({ toast, onDismiss }: { toast: ToastItem; onDismiss: () => void }) {
  return (
    <button
      type="button"
      role="status"
      onClick={onDismiss}
      className={`sw-pressable sw-enter pointer-events-auto max-w-full rounded-sw-sm border bg-elevated px-3 py-2 text-left text-[12px] ${tones[toast.tone]}`}
    >
      {toast.message}
    </button>
  );
}
