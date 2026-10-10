import { Kbd, StatusDot } from '@stackwallet/ui';

import type { CoreStatus } from '../core/bridge.js';
import { listChains, listFamilies } from '../lib/chains.js';
import { activeDevices, useDevices } from '../store/devices.js';
import { useRegistry } from '../store/RegistryContext.js';
import { MOD_KEY, useShell } from './ShellContext.js';

export function StatusBar({
  core,
  registryError,
}: {
  core: CoreStatus;
  registryError?: string | undefined;
}) {
  const registry = useRegistry();
  const shell = useShell();
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
  const onNetwork = shell.route.kind === 'network';
  const onDevices = shell.route.kind === 'devices';
  const paired = activeDevices(useDevices()).length;
  const deviceLabel = `${paired} ${paired === 1 ? 'device' : 'devices'}`;

  return (
    <footer className="flex min-w-0 items-center justify-between gap-4 border-t border-edge px-4 py-1.5 text-[11px] text-faint">
      <div className="flex min-w-0 items-center gap-3">
        <span className="hidden min-[560px]:inline-flex">
          <StatusDot state={core.backend === 'unavailable' ? 'offline' : 'online'} label={label} />
        </span>
        <button
          type="button"
          title={registryError ?? 'RPC endpoints'}
          aria-pressed={onNetwork}
          onClick={() => shell.navigate(onNetwork ? { kind: 'directory' } : { kind: 'network' })}
          className={`sw-pressable -mx-1 truncate rounded-sw-sm px-1 ${onNetwork ? 'text-ink' : ''}`}
        >
          {chainLabel}
        </button>
        <button
          type="button"
          title="Paired devices"
          aria-pressed={onDevices}
          onClick={() => shell.navigate(onDevices ? { kind: 'directory' } : { kind: 'devices' })}
          className={`sw-pressable -mx-1 shrink-0 rounded-sw-sm px-1 ${onDevices ? 'text-ink' : ''}`}
        >
          {deviceLabel}
        </button>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        {shell.layout !== 'three' && (
          <button
            type="button"
            aria-expanded={shell.railOpen}
            onClick={shell.toggleRail}
            className="sw-pressable -mx-1 rounded-sw-sm px-1 text-muted"
          >
            approvals · 0
          </button>
        )}
        <span className="hidden min-[900px]:inline">local-first · no server · no telemetry</span>
        <span className="flex items-center gap-1">
          <Kbd>{MOD_KEY}</Kbd>
          <Kbd>K</Kbd>
        </span>
      </div>
    </footer>
  );
}
