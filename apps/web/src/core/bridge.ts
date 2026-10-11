/**
 * Module-level bootstrap of the core: load the client once, report its status,
 * and hand it to the vault store. Lives outside React so the status is settled
 * for every element that mounts after the first paint.
 */
import { useSyncExternalStore } from 'react';
import {
  createCoreClient,
  type CoreClient,
  type Device,
  type IdentityInfo,
} from '@stackwallet/core-client';

import { devices } from '../store/devices.js';
import { PairingController } from './pairing.js';
import { createVaultStore, describeDevice } from './vault.js';
import { webRtcCarriers } from './webrtc.js';

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

/**
 * The core's sealed table replaces the cache on unlock; on lock the cache
 * stays visible but every mutation is refused until the next unlock.
 */
function onDevices(table: Device[] | null, write: ((d: Device[]) => Promise<void>) | null): void {
  void devices.adopt(table, write ? { write } : null);
}

export const vault = createVaultStore({ onIdentity, onDevices });

/** One pairing controller per page: the handshake outlives whichever pane started it. */
export const pairing = new PairingController({
  core: () => vault.core,
  identity: () => vault.identity(),
  local: () => devices.getSnapshot().localDevice,
  carriers: webRtcCarriers,
  pin: (peer) => devices.pin(peer),
});

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
