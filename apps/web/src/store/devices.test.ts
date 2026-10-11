import { describe, expect, it } from 'vitest';
import type { Device, PairingOffer } from '@stackwallet/core-client';

import {
  activeDevices,
  DEVICES_STORAGE_KEY,
  deviceFromOffer,
  DEVICES_READ_ONLY,
  DevicesState,
  DevicesStore,
  emptyDevicesState,
  loadDevices,
  markSeen,
  pinDevice,
  removeDevice,
  renameDevice,
  revokeDevice,
  revokedDevices,
  setLocalDevice,
  sortedDevices,
  type DevicesOutcome,
} from './devices.js';
import type { StorageLike } from './persist.js';

class MemoryStorage implements StorageLike {
  readonly map = new Map<string, string>();
  getItem(key: string) {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.map.set(key, value);
  }
  removeItem(key: string) {
    this.map.delete(key);
  }
}

function hex(byte: string, bytes: number): string {
  return byte.repeat(bytes);
}

function device(seed: string, name: string, extra: Partial<Device> = {}): Device {
  return {
    id: hex(seed, 16),
    name,
    kind: 'desktop',
    identityPubHex: hex(seed, 32),
    noiseStaticHex: hex(`a${seed.slice(1)}`, 32),
    endpoints: ['tcp://192.168.1.10:4000'],
    pairedAtMs: 1_000,
    lastSeenAtMs: null,
    revokedAtMs: null,
    ...extra,
  };
}

function expectOk<T>(o: DevicesOutcome<T>) {
  if (!o.ok) throw new Error(`expected ok, got: ${o.error}`);
  return o;
}

function expectFail<T>(o: DevicesOutcome<T>): string {
  if (o.ok) throw new Error('expected failure');
  return o.error;
}

const offer: PairingOffer = {
  version: 1,
  deviceId: hex('0c', 16),
  deviceName: 'Study desktop',
  kind: 'desktop',
  identityPubHex: hex('0c', 32),
  noiseStaticHex: hex('1d', 32),
  endpoints: ['tcp://192.168.1.20:4000'],
  oneTimeCodeHex: hex('2e', 32),
  expiresAtMs: 5_000,
};

describe('devices reducers', () => {
  it('pins a device and refuses duplicates', () => {
    const s0 = emptyDevicesState();
    const a = expectOk(pinDevice(s0, device('1a', 'Laptop')));
    expect(a.value).toBe(hex('1a', 16));
    expect(a.state.devices).toHaveLength(1);
    expect(expectFail(pinDevice(a.state, device('1a', 'Laptop again')))).toMatch(/Already paired/);
    expect(DevicesState.safeParse(JSON.parse(JSON.stringify(a.state))).success).toBe(true);
  });

  it('refuses to pin the local device or an invalid record', () => {
    const local = expectOk(
      setLocalDevice(emptyDevicesState(), {
        id: hex('1a', 16),
        name: 'This browser',
        kind: 'browser',
        identityPubHex: hex('1a', 32),
        noiseStaticHex: hex('2b', 32),
      }),
    );
    expect(expectFail(pinDevice(local.state, device('1a', 'Me')))).toMatch(/this device/);
    const bad = { ...device('1b', 'Bad'), identityPubHex: 'nope' };
    expect(expectFail(pinDevice(emptyDevicesState(), bad))).toMatch(/not valid/);
  });

  it('builds the pinned record from an offer without the one-time code', () => {
    const d = deviceFromOffer(offer, 4_000);
    expect(d).toEqual({
      id: offer.deviceId,
      name: offer.deviceName,
      kind: 'desktop',
      identityPubHex: offer.identityPubHex,
      noiseStaticHex: offer.noiseStaticHex,
      endpoints: offer.endpoints,
      pairedAtMs: 4_000,
      lastSeenAtMs: null,
      revokedAtMs: null,
    });
    expect(JSON.stringify(d)).not.toContain(offer.oneTimeCodeHex);
  });

  it('renames with the core name rules', () => {
    const s = expectOk(pinDevice(emptyDevicesState(), device('1a', 'Laptop'))).state;
    const renamed = expectOk(renameDevice(s, hex('1a', 16), '  Study laptop '));
    expect(renamed.state.devices[0]?.name).toBe('Study laptop');
    expect(expectFail(renameDevice(s, hex('1a', 16), '   '))).toMatch(/blank/);
    expect(expectFail(renameDevice(s, hex('1a', 16), '€'.repeat(22)))).toMatch(/64 bytes/);
    expect(expectFail(renameDevice(s, 'missing', 'x'))).toMatch(/not found/);
    expect(renameDevice(s, hex('1a', 16), 'Laptop')).toMatchObject({ ok: true, state: s });
  });

  it('revokes without deleting and only removes revoked records', () => {
    const s = expectOk(pinDevice(emptyDevicesState(), device('1a', 'Laptop'))).state;
    expect(expectFail(removeDevice(s, hex('1a', 16)))).toMatch(/Revoke/);
    const revoked = expectOk(revokeDevice(s, hex('1a', 16), 2_000)).state;
    expect(revoked.devices[0]?.revokedAtMs).toBe(2_000);
    expect(activeDevices(revoked)).toHaveLength(0);
    expect(revokedDevices(revoked)).toHaveLength(1);
    expect(expectFail(revokeDevice(revoked, hex('1a', 16), 3_000))).toMatch(/Already revoked/);
    expect(expectFail(pinDevice(revoked, device('1a', 'Laptop')))).toMatch(/revoked; remove/);
    const removed = expectOk(removeDevice(revoked, hex('1a', 16))).state;
    expect(removed.devices).toHaveLength(0);
  });

  it('tracks last seen and sorts revoked devices last', () => {
    let s = emptyDevicesState();
    s = expectOk(pinDevice(s, device('1a', 'Zed'))).state;
    s = expectOk(pinDevice(s, device('2b', 'Alpha'))).state;
    s = expectOk(pinDevice(s, device('3c', 'Mid'))).state;
    s = expectOk(revokeDevice(s, hex('2b', 16), 2_000)).state;
    s = expectOk(markSeen(s, hex('3c', 16), 2_500)).state;
    expect(sortedDevices(s).map((d) => d.name)).toEqual(['Mid', 'Zed', 'Alpha']);
    expect(s.devices.find((d) => d.id === hex('3c', 16))?.lastSeenAtMs).toBe(2_500);
  });

  it('keeps the local id disjoint from pinned ids', () => {
    const s = expectOk(pinDevice(emptyDevicesState(), device('1a', 'Laptop'))).state;
    expect(
      expectFail(
        setLocalDevice(s, {
          id: hex('1a', 16),
          name: 'Me',
          kind: 'browser',
          identityPubHex: hex('1a', 32),
          noiseStaticHex: hex('2b', 32),
        }),
      ),
    ).toMatch(/paired device/);
    expect(expectOk(setLocalDevice(s, null)).state.localDevice).toBeNull();
  });
});

describe('loadDevices', () => {
  it('starts empty and round-trips', () => {
    expect(loadDevices(null).state).toEqual(emptyDevicesState());
    const storage = new MemoryStorage();
    const s = expectOk(pinDevice(emptyDevicesState(), device('1a', 'Laptop'))).state;
    storage.setItem(DEVICES_STORAGE_KEY, JSON.stringify(s));
    expect(loadDevices(storage).state).toEqual(s);
  });

  it('quarantines a bad blob once and clears the live key', () => {
    for (const bad of ['{nope', JSON.stringify({ version: 2 }), JSON.stringify({ devices: 1 })]) {
      const storage = new MemoryStorage();
      storage.setItem(DEVICES_STORAGE_KEY, bad);
      const loaded = loadDevices(storage, () => 7);
      expect(loaded.state).toEqual(emptyDevicesState());
      expect(loaded.quarantinedKey).toBe(`${DEVICES_STORAGE_KEY}.corrupt-7`);
      expect(storage.getItem(loaded.quarantinedKey!)).toBe(bad);
      expect(storage.getItem(DEVICES_STORAGE_KEY)).toBeNull();
      expect(loadDevices(storage, () => 8).quarantinedKey).toBeUndefined();
    }
  });
});

describe('DevicesStore', () => {
  it('writes every table change through the sink, caches it, and notifies once per change', async () => {
    const storage = new MemoryStorage();
    let t = 1_000;
    const sealed: Device[][] = [];
    const store = new DevicesStore(emptyDevicesState(), storage, () => (t += 1), {
      write: async (d) => {
        sealed.push(d);
      },
    });
    let n = 0;
    store.subscribe(() => (n += 1));

    expect(await store.pin(device('1a', 'Laptop'))).toEqual({ ok: true, value: hex('1a', 16) });
    expect(await store.pin(device('1a', 'Laptop'))).toEqual({ ok: false, error: 'Already paired' });
    expect(await store.rename(hex('1a', 16), 'Laptop')).toEqual({ ok: true, value: undefined });
    expect((await store.revoke(hex('1a', 16))).ok).toBe(true);
    expect(store.getSnapshot().devices[0]?.revokedAtMs).toBe(1_001);
    expect((await store.remove(hex('1a', 16))).ok).toBe(true);
    // pin, revoke, remove changed the table; the no-op rename and the failed pin did not.
    expect(n).toBe(3);
    expect(sealed.map((d) => d.length)).toEqual([1, 1, 0]);
    expect(JSON.parse(storage.getItem(DEVICES_STORAGE_KEY)!)).toEqual(emptyDevicesState());
  });

  it('is read-only without a sink and keeps the cache when a seal fails', async () => {
    const storage = new MemoryStorage();
    const store = new DevicesStore(emptyDevicesState(), storage);
    expect(store.writable).toBe(false);
    expect(await store.pin(device('1a', 'Laptop'))).toEqual({
      ok: false,
      error: DEVICES_READ_ONLY,
    });
    // Local identity is not part of the sealed table, so it stays writable.
    expect(store.setLocal(null).ok).toBe(true);

    await store.adopt([device('1a', 'Laptop')], {
      write: async () => {
        throw new Error('vault refused');
      },
    });
    expect(store.writable).toBe(true);
    expect(store.getSnapshot().devices.map((d) => d.name)).toEqual(['Laptop']);
    expect(await store.rename(hex('1a', 16), 'Desk')).toEqual({
      ok: false,
      error: 'vault refused',
    });
    expect(store.getSnapshot().devices[0]?.name).toBe('Laptop');

    await store.adopt(null, null);
    expect(store.writable).toBe(false);
    expect(store.getSnapshot().devices).toHaveLength(1);
    expect(await store.revoke(hex('1a', 16))).toEqual({ ok: false, error: DEVICES_READ_ONLY });
  });

  it('serializes overlapping mutations so none is computed from a stale table', async () => {
    const store = new DevicesStore(emptyDevicesState(), null, () => 1, {
      write: () => new Promise((r) => setTimeout(r, 2)),
    });
    const results = await Promise.all([
      store.pin(device('1a', 'A')),
      store.pin(device('2b', 'B')),
      store.pin(device('1a', 'A again')),
    ]);
    expect(results.map((r) => r.ok)).toEqual([true, true, false]);
    expect(store.getSnapshot().devices).toHaveLength(2);
  });
});
