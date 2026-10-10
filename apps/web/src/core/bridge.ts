/**
 * Module-level bootstrap of the core: load the client once, report its status,
 * and hand it to the vault store. Lives outside React so the status is settled
 * for every element that mounts after the first paint.
 */
import { useSyncExternalStore } from 'react';
import { createCoreClient, type CoreClient, type IdentityInfo } from '@stackwallet/core-client';

import { devices } from '../store/devices.js';
import { createVaultStore, describeDevice } from './vault.js';

export interface CoreStatus {
  backend: CoreClient['backend'];
  version?: string;
  reason?: string;
}

let status: CoreStatus = { backend: 'unavailable', reason: 'loading' };
const listeners = new Set<() => void>();

function setStatus(next: CoreStatus): void {
  status = next;
  for (const l of listeners) l();
}

const subscribe = (l: () => void) => {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
};
const getSnapshot = () => status;

export function useCoreStatus(): CoreStatus {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/** Mirror the sealed identity's public half into the device table. */
function onIdentity(info: IdentityInfo | null): void {
  if (!info) {
    devices.setLocal(null);
    return;
  }
  const current = devices.getSnapshot().localDevice;
  devices.setLocal({
    id: info.deviceId,
    name: current && current.id === info.deviceId ? current.name : describeDevice(),
    kind: 'browser',
    identityPubHex: info.publicHex,
    noiseStaticHex: info.noiseStaticHex,
  });
}

export const vault = createVaultStore({ onIdentity });

export const coreReady: Promise<CoreClient> = createCoreClient().then(async (client) => {
  if (client.backend === 'unavailable') {
    setStatus({
      backend: 'unavailable',
      reason: 'reason' in client ? String(client.reason) : 'unknown',
    });
  } else {
    try {
      setStatus({ backend: client.backend, version: await client.coreVersion() });
    } catch (err) {
      setStatus({
        backend: 'unavailable',
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }
  await vault.attach(client);
  return client;
});
