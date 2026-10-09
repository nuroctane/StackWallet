import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Button } from '@stackwallet/ui';

interface State {
  message: string | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  override state: State = { message: null };

  static getDerivedStateFromError(err: unknown): State {
    return { message: err instanceof Error ? err.message : String(err) };
  }

  override componentDidCatch(_err: unknown, _info: ErrorInfo): void {
    // No telemetry: the message is shown to the user and nowhere else.
  }

  override render(): ReactNode {
    if (this.state.message === null) return this.props.children;
    return (
      <div className="grid h-full place-items-center bg-paper p-5 text-ink">
        <div className="sw-glass flex w-[min(92vw,440px)] flex-col gap-4 p-5">
          <div className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
            Something broke
          </div>
          <p className="text-muted">
            The interface hit an error it could not recover from. Your directory is saved locally
            and will be there after a reload.
          </p>
          <pre className="max-h-32 overflow-auto rounded-sw-sm border border-edge bg-paper p-3 text-[12px] whitespace-pre-wrap text-faint">
            {this.state.message}
          </pre>
          <div>
            <Button variant="primary" onClick={() => window.location.reload()}>
              Reload
            </Button>
          </div>
        </div>
      </div>
    );
  }
}
