import { useSyncExternalStore } from 'react';
import {
  Device,
  DeviceId,
  DeviceKind,
  DeviceName,
  type PairingOffer,
} from '@stackwallet/core-client';
import { z } from 'zod';

import type { StorageLike } from './persist.js';

export const DEVICES_STORAGE_KEY = 'stackwallet.devices.v1';
export const DEVICES_VERSION = 1 as const;
export const MAX_DEVICES = 256;

/**
 * The browser's own entry in the device directory. Public fields only; the
 * identity seed lives in the vault and is never part of this blob. `null`
 * until the core bridge has generated an identity, which is also when pairing
 * becomes possible.
 */
export const LocalDevice = z.object({
  id: DeviceId,
  name: DeviceName,
  kind: DeviceKind,
  identityPubHex: z.string(),
  noiseStaticHex: z.string(),
});
export type LocalDevice = z.infer<typeof LocalDevice>;

/**
 * Pinned peers reuse the core-client `Device` schema verbatim so the same
 * records can be handed to the wasm `Session` lookup or written to the native
 * store later without a translation step.
 *
 * Trust note: the authoritative table is sealed inside the vault and the core
 * re-validates it (ids derived from identity keys, no duplicates, bounds) on
 * every load and save. The localStorage blob is only a cache so the list stays
 * visible while the vault is locked; any script on the origin can rewrite it,
 * so it is replaced by the core's copy on unlock and no session constructor
 * may consume these records without going through the core.
 */
export const DevicesState = z.object({
  version: z.literal(DEVICES_VERSION),
  localDevice: LocalDevice.nullable(),
  devices: Device.array().max(MAX_DEVICES),
});
export type DevicesState = z.infer<typeof DevicesState>;

export function emptyDevicesState(): DevicesState {
  return { version: DEVICES_VERSION, localDevice: null, devices: [] };
}

export type DevicesFailure = { ok: false; error: string };
export type DevicesSuccess<T> = { ok: true; state: DevicesState; value: T };
export type DevicesOutcome<T = undefined> = DevicesSuccess<T> | DevicesFailure;

const fail = (error: string): DevicesFailure => ({ ok: false, error });
const ok = <T>(state: DevicesState, value: T): DevicesSuccess<T> => ({ ok: true, state, value });

export function findDevice(state: DevicesState, id: string): Device | undefined {
  return state.devices.find((d) => d.id === id);
}

export function activeDevices(state: DevicesState): Device[] {
  return state.devices.filter((d) => d.revokedAtMs === null);
}

export function revokedDevices(state: DevicesState): Device[] {
  return state.devices.filter((d) => d.revokedAtMs !== null);
}

/** Active first, then by name; revoked records sink to the bottom so the live set reads as one block. */
export function sortedDevices(state: DevicesState): Device[] {
  return [...state.devices].sort(
    (a, b) =>
      Number(a.revokedAtMs !== null) - Number(b.revokedAtMs !== null) ||
      a.name.localeCompare(b.name) ||
      a.id.localeCompare(b.id),
  );
}

/** The record a pairing offer describes, stamped as pinned at `nowMs`. */
export function deviceFromOffer(offer: PairingOffer, nowMs: number): Device {
  return {
    id: offer.deviceId,
    name: offer.deviceName,
    kind: offer.kind,
    identityPubHex: offer.identityPubHex,
    noiseStaticHex: offer.noiseStaticHex,
    endpoints: offer.endpoints,
    pairedAtMs: nowMs,
    lastSeenAtMs: null,
    revokedAtMs: null,
  };
}

/**
 * Pin a record the core has authenticated (the `paired` session event).
 * Duplicates and the local id are refused so a bad call cannot create a
 * second trust entry for a device that already has one.
 */
export function pinDevice(state: DevicesState, device: Device): DevicesOutcome<string> {
  const parsed = Device.safeParse(device);
  if (!parsed.success) return fail('Device record is not valid');
  if (state.localDevice && state.localDevice.id === parsed.data.id) {
    return fail('That is this device');
  }
  const existing = findDevice(state, parsed.data.id);
  if (existing) {
    return fail(
      existing.revokedAtMs === null
        ? 'Already paired'
        : 'This device was revoked; remove it before pairing again',
    );
  }
  if (state.devices.length >= MAX_DEVICES) return fail(`At most ${MAX_DEVICES} devices`);
  return ok({ ...state, devices: [...state.devices, parsed.data] }, parsed.data.id);
}

export function renameDevice(state: DevicesState, id: string, name: string): DevicesOutcome {
  const device = findDevice(state, id);
  if (!device) return fail('Device not found');
  const trimmed = name.trim();
  const parsed = DeviceName.safeParse(trimmed);
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid name');
  if (trimmed === device.name) return ok(state, undefined);
  return ok(
    {
      ...state,
      devices: state.devices.map((d) => (d.id === id ? { ...d, name: trimmed } : d)),
    },
    undefined,
  );
}

/**
 * Revocation is a tombstone, not a delete: the core must keep refusing this
 * static, and a user must be able to see that a device was ever trusted.
 */
export function revokeDevice(state: DevicesState, id: string, nowMs: number): DevicesOutcome {
  const device = findDevice(state, id);
  if (!device) return fail('Device not found');
  if (device.revokedAtMs !== null) return fail('Already revoked');
  return ok(
    {
      ...state,
      devices: state.devices.map((d) => (d.id === id ? { ...d, revokedAtMs: nowMs } : d)),
    },
    undefined,
  );
}

export function removeDevice(state: DevicesState, id: string): DevicesOutcome {
  const device = findDevice(state, id);
  if (!device) return fail('Device not found');
  if (device.revokedAtMs === null) return fail('Revoke the device before removing it');
  return ok({ ...state, devices: state.devices.filter((d) => d.id !== id) }, undefined);
}

export function markSeen(state: DevicesState, id: string, nowMs: number): DevicesOutcome {
  const device = findDevice(state, id);
  if (!device) return fail('Device not found');
  return ok(
    {
      ...state,
      devices: state.devices.map((d) => (d.id === id ? { ...d, lastSeenAtMs: nowMs } : d)),
    },
    undefined,
  );
}

export function setLocalDevice(state: DevicesState, local: LocalDevice | null): DevicesOutcome {
  if (local === null) return ok({ ...state, localDevice: null }, undefined);
  const parsed = LocalDevice.safeParse(local);
  if (!parsed.success) return fail('Local device record is not valid');
  if (findDevice(state, parsed.data.id)) return fail('That id belongs to a paired device');
  return ok({ ...state, localDevice: parsed.data }, undefined);
}

export interface DevicesLoadResult {
  state: DevicesState;
  quarantinedKey?: string;
}

export function loadDevices(
  storage: StorageLike | null,
  now = () => Date.now(),
): DevicesLoadResult {
  if (!storage) return { state: emptyDevicesState() };
  let raw: string | null = null;
  try {
    raw = storage.getItem(DEVICES_STORAGE_KEY);
  } catch {
    return { state: emptyDevicesState() };
  }
  if (raw === null || raw === '') return { state: emptyDevicesState() };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  const result = parsed === undefined ? undefined : DevicesState.safeParse(parsed);
  if (result?.success) return { state: result.data };
  // A device table is trust state; keep the unreadable blob for inspection
  // and clear the live key so it is not quarantined again on every load.
  const quarantinedKey = `${DEVICES_STORAGE_KEY}.corrupt-${now()}`;
  try {
    storage.setItem(quarantinedKey, raw);
    storage.removeItem(DEVICES_STORAGE_KEY);
  } catch {
    // Storage full or blocked; an empty table is the safe fallback.
  }
  return { state: emptyDevicesState(), quarantinedKey };
}

export function saveDevices(storage: StorageLike, state: DevicesState): boolean {
  try {
    storage.setItem(DEVICES_STORAGE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

export type DevicesListener = () => void;
export type DevicesActionResult<T = undefined> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export const DEVICES_READ_ONLY = 'Unlock the vault to change paired devices';

/**
 * Where the pinned table really lives: the core seals it in the vault and
 * validates it on every read and write. The store's own storage is a cache
 * of the last table the core handed over, kept so the list is visible while
 * the vault is locked.
 */
export interface DeviceTableSink {
  write(devices: Device[]): Promise<void>;
}

export class DevicesStore {
  private state: DevicesState;
  private readonly listeners = new Set<DevicesListener>();
  private sink: DeviceTableSink | null;
  // Mutations are serialized so two writers never seal tables computed from
  // the same base and silently drop one another's change.
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    initial: DevicesState,
    private readonly storage: StorageLike | null,
    private readonly now: () => number = () => Date.now(),
    sink: DeviceTableSink | null = null,
  ) {
    this.state = initial;
    this.sink = sink;
  }

  readonly subscribe = (l: DevicesListener): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getSnapshot = (): DevicesState => this.state;

  /** Whether the table can be changed right now (the core is holding an unlocked vault). */
  get writable(): boolean {
    return this.sink !== null;
  }

  private commit(next: DevicesState): void {
    if (next === this.state) return;
    this.state = next;
    if (this.storage) saveDevices(this.storage, next);
    for (const l of this.listeners) l();
  }

  private serialized<T>(run: () => Promise<T>): Promise<T> {
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => undefined);
    return p;
  }

  /**
   * The core handed over its validated table (unlock) or withdrew (lock).
   * `devices === null` keeps the cached list visible but read-only.
   */
  adopt(devices: Device[] | null, sink: DeviceTableSink | null): Promise<void> {
    return this.serialized(async () => {
      this.sink = sink;
      if (devices === null) return;
      const parsed = DevicesState.safeParse({ ...this.state, devices });
      if (!parsed.success) throw new Error('Device table from the core is not valid');
      this.commit(parsed.data);
    });
  }

  private mutate<T>(
    step: (state: DevicesState) => DevicesOutcome<T>,
  ): Promise<DevicesActionResult<T>> {
    return this.serialized(async () => {
      const outcome = step(this.state);
      if (!outcome.ok) return { ok: false, error: outcome.error };
      if (outcome.state.devices !== this.state.devices) {
        if (!this.sink) return { ok: false, error: DEVICES_READ_ONLY };
        try {
          await this.sink.write(outcome.state.devices);
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
      }
      this.commit(outcome.state);
      return { ok: true, value: outcome.value };
    });
  }

  pin(device: Device): Promise<DevicesActionResult<string>> {
    return this.mutate((s) => pinDevice(s, device));
  }

  rename(id: string, name: string): Promise<DevicesActionResult> {
    return this.mutate((s) => renameDevice(s, id, name));
  }

  revoke(id: string): Promise<DevicesActionResult> {
    return this.mutate((s) => revokeDevice(s, id, this.now()));
  }

  remove(id: string): Promise<DevicesActionResult> {
    return this.mutate((s) => removeDevice(s, id));
  }

  markSeen(id: string): Promise<DevicesActionResult> {
    return this.mutate((s) => markSeen(s, id, this.now()));
  }

  /** The local identity is derived from the vault, not stored in the table; no sink needed. */
  setLocal(local: LocalDevice | null): DevicesActionResult {
    const outcome = setLocalDevice(this.state, local);
    if (!outcome.ok) return { ok: false, error: outcome.error };
    this.commit(outcome.state);
    return { ok: true, value: outcome.value };
  }
}

function safeStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${DEVICES_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

const storage = safeStorage();
const loaded = loadDevices(storage);

export const devices = new DevicesStore(loaded.state, storage);
export const devicesQuarantinedKey: string | undefined = loaded.quarantinedKey;

export function useDevices(): DevicesState {
  return useSyncExternalStore(devices.subscribe, devices.getSnapshot, devices.getSnapshot);
}
