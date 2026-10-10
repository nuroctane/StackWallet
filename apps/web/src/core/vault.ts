/**
 * The browser's vault: ciphertext persisted locally, plaintext only ever inside
 * the wasm core. This store tracks where the vault is in its lifecycle
 * (loading → absent | locked | unlocked) and runs the handful of actions the
 * UI needs. The identity sealed under `IDENTITY_LABEL` is what makes this
 * browser a device; its public half is mirrored into the device table so the
 * Devices element can show it while the vault is locked.
 */
import { useSyncExternalStore } from 'react';
import type {
  CoreClient,
  IdentityHandle,
  IdentityInfo,
  VaultHandle,
  VaultLabel,
} from '@stackwallet/core-client';

import type { StorageLike } from '../store/persist.js';

export const VAULT_STORAGE_KEY = 'stackwallet.vault.v1';
export const IDENTITY_LABEL = 'device-identity';
export const MIN_PASSPHRASE_CHARS = 10;

export type VaultStatus =
  | { kind: 'loading' }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'absent' }
  | { kind: 'locked'; labels: VaultLabel[] }
  | { kind: 'unlocked'; labels: VaultLabel[]; identity: IdentityInfo | null }
  | { kind: 'corrupt'; quarantinedKey: string };

/** True while a passphrase is being stretched; the UI shows the word instead of a spinner. */
export interface VaultView {
  status: VaultStatus;
  busy: boolean;
}

export type VaultResult = { ok: true } | { ok: false; error: string };

export function encodeBytes(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function decodeBytes(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return undefined;
  try {
    return Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
  } catch {
    return undefined;
  }
}

export function passphraseProblem(passphrase: string): string | null {
  if (passphrase.length < MIN_PASSPHRASE_CHARS) {
    return `Use at least ${MIN_PASSPHRASE_CHARS} characters`;
  }
  return null;
}

export function describeDevice(): string {
  const ua = typeof navigator === 'undefined' ? '' : navigator.userAgent;
  const os = /Windows/.test(ua)
    ? 'Windows'
    : /Mac OS X/.test(ua)
      ? 'macOS'
      : /Android/.test(ua)
        ? 'Android'
        : /iPhone|iPad/.test(ua)
          ? 'iOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : null;
  return os ? `Browser on ${os}` : 'Browser';
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export interface VaultStoreDeps {
  storage: StorageLike | null;
  now?: () => number;
  /** Called after the identity is minted or read, so the device table can mirror it. */
  onIdentity?: (info: IdentityInfo | null) => void;
}

export class VaultStore {
  private view: VaultView = { status: { kind: 'loading' }, busy: false };
  private client: CoreClient | null = null;
  private vault: VaultHandle | null = null;
  private readonly listeners = new Set<() => void>();
  private readonly now: () => number;

  constructor(private readonly deps: VaultStoreDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  readonly subscribe = (l: () => void): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  readonly getSnapshot = (): VaultView => this.view;

  private set(next: Partial<VaultView>): void {
    this.view = { ...this.view, ...next };
    for (const l of this.listeners) l();
  }

  /** Bind the core once it has loaded and open whatever ciphertext is stored. */
  async attach(client: CoreClient): Promise<void> {
    this.client = client;
    if (client.backend === 'unavailable') {
      const reason = 'reason' in client ? String(client.reason) : 'unknown';
      this.set({ status: { kind: 'unavailable', reason } });
      return;
    }
    const raw = this.deps.storage?.getItem(VAULT_STORAGE_KEY) ?? null;
    if (raw === null) {
      this.set({ status: { kind: 'absent' } });
      return;
    }
    const bytes = decodeBytes(raw);
    if (!bytes) {
      this.quarantine(raw);
      return;
    }
    try {
      this.vault = await client.openVault(bytes);
      this.set({ status: { kind: 'locked', labels: await this.vault.labels() } });
    } catch {
      this.quarantine(raw);
    }
  }

  private quarantine(raw: string): void {
    const quarantinedKey = `${VAULT_STORAGE_KEY}.corrupt-${this.now()}`;
    try {
      this.deps.storage?.setItem(quarantinedKey, raw);
      this.deps.storage?.removeItem(VAULT_STORAGE_KEY);
    } catch {
      // Nothing more to do; the vault is unreadable either way.
    }
    this.set({ status: { kind: 'corrupt', quarantinedKey } });
  }

  private async persist(): Promise<void> {
    if (!this.vault || !this.deps.storage) return;
    this.deps.storage.setItem(VAULT_STORAGE_KEY, encodeBytes(await this.vault.toBytes()));
  }

  private async refreshUnlocked(): Promise<void> {
    if (!this.vault) return;
    const labels = await this.vault.labels();
    let identity: IdentityInfo | null = null;
    if (labels.some((l) => l.label === IDENTITY_LABEL)) {
      identity = await this.vault.identityInfo(IDENTITY_LABEL);
    }
    this.deps.onIdentity?.(identity);
    this.set({ status: { kind: 'unlocked', labels, identity } });
  }

  private async guarded(op: () => Promise<void>): Promise<VaultResult> {
    if (this.view.busy) return { ok: false, error: 'The vault is busy' };
    this.set({ busy: true });
    try {
      await op();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: message(err) };
    } finally {
      this.set({ busy: false });
    }
  }

  /** New vault with a fresh device identity; replaces nothing (refuses if one exists). */
  create(passphrase: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!this.client) throw new Error('core not loaded');
      if (this.view.status.kind !== 'absent' && this.view.status.kind !== 'corrupt') {
        throw new Error('A vault already exists on this device');
      }
      const problem = passphraseProblem(passphrase);
      if (problem) throw new Error(problem);
      const vault = await this.client.createVault(passphrase);
      await vault.createIdentity(IDENTITY_LABEL);
      this.vault = vault;
      await this.persist();
      await this.refreshUnlocked();
    });
  }

  unlock(passphrase: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!this.vault) throw new Error('No vault to unlock');
      await this.vault.unlock(passphrase);
      await this.refreshUnlocked();
    });
  }

  lock(): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!this.vault) throw new Error('No vault to lock');
      await this.vault.lock();
      this.set({ status: { kind: 'locked', labels: await this.vault.labels() } });
    });
  }

  changePassphrase(current: string, next: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!this.vault) throw new Error('No vault');
      const problem = passphraseProblem(next);
      if (problem) throw new Error(problem);
      await this.vault.changePassphrase(current, next);
      await this.persist();
    });
  }

  /** Live identity for a session; only while unlocked. Caller frees it. */
  async identity(): Promise<IdentityHandle> {
    if (!this.vault || this.view.status.kind !== 'unlocked') {
      throw new Error('Unlock the vault first');
    }
    return this.vault.identity(IDENTITY_LABEL);
  }

  get core(): CoreClient | null {
    return this.client;
  }
}

function safeStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    if (!s) return null;
    const probe = `${VAULT_STORAGE_KEY}.probe`;
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

export function createVaultStore(deps: Partial<VaultStoreDeps> = {}): VaultStore {
  return new VaultStore({ storage: safeStorage(), ...deps });
}

export function useVaultView(store: VaultStore): VaultView {
  return useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
}
