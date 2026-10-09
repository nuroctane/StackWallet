import { Kbd, StatusDot } from '@stackwallet/ui';

import type { CoreStatus } from '../App.js';
import { listChains, listFamilies } from '../lib/chains.js';
import { useRegistry } from '../store/RegistryContext.js';

const MOD_KEY =
  typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘' : 'Ctrl';

export function StatusBar({
  core,
  registryError,
}: {
  core: CoreStatus;
  registryError?: string | undefined;
}) {
  const registry = useRegistry();
  const chains = listChains(registry).length;
  const families = listFamilies(registry).length;
  const label =
    core.backend === 'unavailable'
      ? `core unavailable (${core.reason ?? 'unknown'})`
      : `core ${core.version ?? '?'} via ${core.backend}`;
  const chainLabel = registryError
    ? 'chain adapters failed to load'
    : chains === 0
      ? 'no chain adapters loaded'
      : `${chains} ${chains === 1 ? 'chain' : 'chains'} · ${families} ${families === 1 ? 'family' : 'families'}`;

  return (
    <footer className="flex items-center justify-between gap-4 border-t border-edge px-4 py-1.5 text-[11px] text-faint">
      <div className="flex items-center gap-3">
        <StatusDot state={core.backend === 'unavailable' ? 'offline' : 'online'} label={label} />
        <span title={registryError}>{chainLabel}</span>
      </div>
      <div className="flex items-center gap-3">
        <span>local-first · no server · no telemetry</span>
        <span className="flex items-center gap-1">
          <Kbd>{MOD_KEY}</Kbd>
          <Kbd>K</Kbd>
        </span>
      </div>
    </footer>
  );
}
