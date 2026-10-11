/**
 * The browser's vault: ciphertext persisted locally, plaintext only ever inside
 * the wasm core. This store tracks where the vault is in its lifecycle
 * (loading → absent | locked | unlocked) and runs the handful of actions the
 * UI needs. The identity sealed under `IDENTITY_LABEL` is what makes this
 * browser a device; its public half is mirrored into the device table so the
 * Devices element can show it while the vault is locked.
 */
import { useSyncExternalStore } from 'react';
import {
  ProvenanceTable,
  type CoreClient,
  type Curve,
  type Device,
  type ExposureChannel,
  type IdentityHandle,
  type IdentityInfo,
  type LedgerUnsignedTx,
  type ImportedSet,
  type Ledger,
  type Policy,
  type Revealed,
  type RevealedSecret,
  type Signer,
  type TxIntent,
  type TxRecord,
  type TxState,
  type VaultHandle,
  type VaultLabel,
} from '@stackwallet/core-client';

import type { StorageLike } from '../store/persist.js';

export const VAULT_STORAGE_KEY = 'stackwallet.vault.v1';
/** Read-only mirror of the sealed provenance table, so tags stay visible while locked. */
export const PROVENANCE_CACHE_KEY = 'stackwallet.provenance.v1';
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
  /**
   * Where every key came from and where it has been. From the core while
   * unlocked; from the local mirror while locked (display only, never trusted
   * for a decision).
   */
  provenance: ProvenanceTable;
  /** Transactions, policies and audit log; `null` while locked (they live sealed in the vault). */
  ledger: Ledger | null;
  /** Set when the sealed ledger failed to load: a broken audit chain is a red banner, not silence. */
  ledgerError: string | null;
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
  /**
   * Called with the core-validated pinned table on unlock and `null` on lock,
   * together with the writer that seals changes (`null` while locked).
   */
  onDevices?: (
    devices: Device[] | null,
    write: ((devices: Device[]) => Promise<void>) | null,
  ) => void;
}

export class VaultStore {
  private view: VaultView = {
    status: { kind: 'loading' },
    busy: false,
    provenance: { wallets: [], sets: [] },
    ledger: null,
    ledgerError: null,
  };
  private client: CoreClient | null = null;
  private vault: VaultHandle | null = null;
  private readonly listeners = new Set<() => void>();
  private readonly now: () => number;

  constructor(private readonly deps: VaultStoreDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.view = { ...this.view, provenance: this.cachedProvenance() };
  }

  private cachedProvenance(): ProvenanceTable {
    try {
      const raw = this.deps.storage?.getItem(PROVENANCE_CACHE_KEY);
      const r = raw ? ProvenanceTable.safeParse(JSON.parse(raw)) : null;
      return r?.success ? r.data : { wallets: [], sets: [] };
    } catch {
      return { wallets: [], sets: [] };
    }
  }

  private async refreshProvenance(): Promise<void> {
    if (!this.vault || this.view.status.kind !== 'unlocked') return;
    const provenance = await this.vault.provenance();
    try {
      this.deps.storage?.setItem(PROVENANCE_CACHE_KEY, JSON.stringify(provenance));
    } catch {
      // The sealed table is the record; the mirror is a convenience.
    }
    this.set({ provenance });
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
    this.deps.onDevices?.(await this.vault.devices(), this.writeDevices);
    this.set({ status: { kind: 'unlocked', labels, identity } });
    await this.refreshProvenance();
    await this.refreshLedger();
  }

  private async refreshLedger(): Promise<void> {
    if (!this.vault || this.view.status.kind !== 'unlocked') return;
    try {
      this.set({ ledger: await this.vault.ledger(), ledgerError: null });
    } catch (err) {
      this.set({ ledger: null, ledgerError: message(err) });
    }
  }

  /** Id the audit log records as the actor; the browser's own device identity. */
  private deviceId(): string {
    const s = this.view.status;
    return s.kind === 'unlocked' && s.identity ? s.identity.deviceId : 'local';
  }

  /** Run one ledger operation, persist the vault and refresh the view. */
  private async ledgerOp(op: (v: VaultHandle, device: string, now: number) => Promise<TxRecord>) {
    return this.guardedValue(async () => {
      const out = await op(this.unlockedVault(), this.deviceId(), this.now());
      await this.persist();
      await this.refreshLedger();
      return out;
    });
  }

  txPropose(intent: Omit<TxIntent, 'proposer' | 'createdAtMs'>) {
    return this.ledgerOp((v, device, now) =>
      v.txPropose(
        { ...intent, proposer: { kind: 'human', deviceId: device }, createdAtMs: now } as TxIntent,
        device,
        now,
      ),
    );
  }

  txAttach(req: {
    txId: string;
    signer: Signer;
    unsigned: LedgerUnsignedTx;
    simulation: unknown;
    simulationOk: boolean;
  }) {
    return this.ledgerOp((v, deviceId, nowMs) => v.txAttach({ ...req, deviceId, nowMs }));
  }

  txEvaluate(txId: string) {
    return this.ledgerOp((v, device, now) => v.txEvaluate(txId, device, now));
  }

  txApprove(txId: string, passphrase: string) {
    return this.ledgerOp((v, device, now) => v.txApprove(txId, passphrase, device, now));
  }

  txReject(txId: string) {
    return this.ledgerOp((v, device, now) => v.txReject(txId, device, now));
  }

  txReport(txId: string, state: TxState, note: string | null) {
    return this.ledgerOp((v, device, now) => v.txReport(txId, state, note, device, now));
  }

  setPolicies(policies: Policy[]): Promise<VaultResult> {
    return this.guarded(async () => {
      await this.unlockedVault().setPolicies(policies, this.deviceId(), this.now());
      await this.persist();
      await this.refreshLedger();
    });
  }

  /** Seal a whole device table and persist the vault; the core validates before writing. */
  private readonly writeDevices = async (devices: Device[]): Promise<void> => {
    if (!this.vault || this.view.status.kind !== 'unlocked')
      throw new Error('Unlock the vault first');
    await this.vault.setDevices(devices);
    await this.persist();
    this.set({ status: { ...this.view.status, labels: await this.vault.labels() } });
  };

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
      this.deps.onDevices?.(null, null);
      this.set({ ledger: null, ledgerError: null });
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

  private unlockedVault(): VaultHandle {
    if (!this.vault || this.view.status.kind !== 'unlocked') {
      throw new Error('Unlock the vault first');
    }
    return this.vault;
  }

  /** Like `guarded`, for operations that hand a value back. */
  private async guardedValue<T>(
    op: () => Promise<T>,
  ): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
    if (this.view.busy) return { ok: false, error: 'The vault is busy' };
    this.set({ busy: true });
    try {
      return { ok: true, value: await op() };
    } catch (err) {
      return { ok: false, error: message(err) };
    } finally {
      this.set({ busy: false });
    }
  }

  /** Seal a key for a new `single` wallet: fresh, or a phrase brought from elsewhere. */
  createSingle(walletId: string, phrase?: string): Promise<VaultResult> {
    return this.guarded(async () => {
      const v = this.unlockedVault();
      if (phrase === undefined) await v.createSingle(walletId, this.now());
      else await v.importPhrase(walletId, phrase, this.now());
      await this.persist();
      await this.refreshProvenance();
    });
  }

  async publicKey(walletId: string, curve: Curve, path: string): Promise<string> {
    return this.unlockedVault().singlePublicKey(walletId, curve, path);
  }

  /**
   * Take a phrase or key out. The core re-checks the passphrase and seals the
   * exposure before it returns anything, so the tag cannot be skipped.
   */
  reveal(
    walletId: string,
    passphrase: string,
    what: Revealed,
    channel: ExposureChannel,
  ): Promise<{ ok: true; value: RevealedSecret } | { ok: false; error: string }> {
    return this.guardedValue(async () => {
      const v = this.unlockedVault();
      const out = await v.reveal(walletId, passphrase, what, channel, this.now());
      await this.persist();
      await this.refreshProvenance();
      return out;
    });
  }

  exportSet(req: {
    passphrase: string;
    toDeviceId: string;
    folderId: string;
    walletIds: string[];
    directory: unknown;
  }): Promise<{ ok: true; value: string } | { ok: false; error: string }> {
    return this.guardedValue(async () => {
      const v = this.unlockedVault();
      const bundle = await v.exportSet({
        identityLabel: IDENTITY_LABEL,
        nowMs: this.now(),
        ...req,
      });
      await this.persist();
      await this.refreshProvenance();
      return bundle;
    });
  }

  importSet(
    passphrase: string,
    bundle: string,
  ): Promise<{ ok: true; value: ImportedSet } | { ok: false; error: string }> {
    return this.guardedValue(async () => {
      const v = this.unlockedVault();
      const got = await v.importSet(IDENTITY_LABEL, passphrase, bundle, this.now());
      await this.persist();
      await this.refreshProvenance();
      return got;
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
