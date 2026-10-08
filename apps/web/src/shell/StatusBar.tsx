import { StatusDot } from '@stackwallet/ui';

import type { CoreStatus } from '../App.js';

export function StatusBar({ core }: { core: CoreStatus }) {
  const label =
    core.backend === 'unavailable'
      ? `core unavailable (${core.reason ?? 'unknown'})`
      : `core ${core.version ?? '?'} via ${core.backend}`;
  return (
    <footer className="flex items-center justify-between border-t border-edge px-4 py-1.5 text-[11px] text-faint">
      <StatusDot state={core.backend === 'unavailable' ? 'offline' : 'online'} label={label} />
      <span>local-first · no server · no telemetry</span>
    </footer>
  );
}
