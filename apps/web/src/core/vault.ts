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
  type ExportGateInput,
  type ExportKeyRef,
  type ExportKeyScope,
  type ExposureChannel,
  type IdentityHandle,
  type IdentityInfo,
  type LedgerUnsignedTx,
  type ImportedSet,
  type Ledger,
  type Policy,
  type Revealed,
  type RevealedSecret,
  type SessionProof,
  type SignedMessage,
  type Signer,
  type SlotInfo,
  type TxIntent,
  type TxRecord,
  type TxState,
  type VaultHandle,
  type VaultLabel,
} from '@stackwallet/core-client';

import type { StorageLike } from '../store/persist.js';
import { withStorageWriter } from '../store/storageWriter.js';
import {
  MAX_PIN_FAILURES,
  createDeviceSecret,
  destroyDeviceSecret,
  loadDeviceSecret,
  pinFailures,
  setPinFailures,
} from './deviceSecret.js';
import { createPasskey, passkeySecret } from './passkey.js';

export const VAULT_STORAGE_KEY = 'stackwallet.vault.v1';
/** Read-only mirror of the sealed provenance table, so tags stay visible while locked. */
export const PROVENANCE_CACHE_KEY = 'stackwallet.provenance.v1';
export const IDENTITY_LABEL = 'device-identity';
export const MIN_PASSPHRASE_CHARS = 10;
export const MAX_AGENT_SESSIONS = 50;

class DurabilityError extends Error {}

async function withVaultWriter<T>(storage: StorageLike, op: () => Promise<T>): Promise<T> {
  return withStorageWriter(storage, VAULT_STORAGE_KEY, op);
}

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
  /** This device's PIN and passkey unlock methods; readable while locked. */
  slots: SlotInfo[];
  /** Folders and wallets with an export key; readable while locked. */
  exportKeys: ExportKeyRef[];
}

/** Who other than the person at this device made a proposal. */
export type ProposedBy =
  | { kind: 'agent'; sessionId: string; grantId: string; rationale: string }
  | { kind: 'automation'; automationId: string; runId: string };

/** How the person proves the session for an export: never a PIN. */
export type SessionChoice =
  | { kind: 'passphrase'; passphrase: string }
  | { kind: 'passkey'; slotId: string };

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
    slots: [],
    exportKeys: [],
  };
  private client: CoreClient | null = null;
  private vault: VaultHandle | null = null;
  private committed: string | null = null;
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
  async attach(client: CoreClient, quarantineInvalid = true): Promise<void> {
    this.client = client;
    if (client.backend === 'unavailable') {
      const reason = 'reason' in client ? String(client.reason) : 'unknown';
      this.set({ status: { kind: 'unavailable', reason } });
      return;
    }
    if (!this.deps.storage) {
      this.set({
        status: {
          kind: 'unavailable',
          reason: 'Durable local storage is unavailable. Wallet creation and signing are disabled.',
        },
      });
      return;
    }
    let raw: string | null;
    try {
      raw = this.deps.storage.getItem(VAULT_STORAGE_KEY);
    } catch {
      this.set({ status: { kind: 'unavailable', reason: 'Cannot read durable vault storage' } });
      return;
    }
    this.committed = raw;
    if (raw === null) {
      this.set({ status: { kind: 'absent' } });
      return;
    }
    const bytes = decodeBytes(raw);
    if (!bytes) {
      if (quarantineInvalid) await this.quarantine(raw);
      else this.set({ status: { kind: 'corrupt', quarantinedKey: VAULT_STORAGE_KEY } });
      return;
    }
    try {
      this.vault = await client.openVault(bytes);
      await this.refreshFactors();
      this.set({ status: { kind: 'locked', labels: await this.vault.labels() } });
    } catch {
      if (quarantineInvalid) await this.quarantine(raw);
      else this.set({ status: { kind: 'corrupt', quarantinedKey: VAULT_STORAGE_KEY } });
    }
  }

  private async quarantine(raw: string): Promise<void> {
    const quarantinedKey = `${VAULT_STORAGE_KEY}.corrupt-${this.now()}`;
    let changed = false;
    try {
      if (this.deps.storage)
        await withVaultWriter(this.deps.storage, async () => {
          if (this.deps.storage!.getItem(VAULT_STORAGE_KEY) !== raw) {
            changed = true;
            return;
          }
          this.deps.storage!.setItem(quarantinedKey, raw);
          this.deps.storage!.removeItem(VAULT_STORAGE_KEY);
          this.committed = null;
        });
    } catch {
      // Nothing more to do; the vault is unreadable either way.
    }
    if (changed && this.client) {
      await this.attach(this.client);
      return;
    }
    this.set({ status: { kind: 'corrupt', quarantinedKey } });
  }

  private async persist(): Promise<void> {
    if (!this.vault || !this.deps.storage)
      throw new DurabilityError('Durable vault storage is unavailable');
    const raw = encodeBytes(await this.vault.toBytes());
    try {
      if (this.deps.storage.getItem(VAULT_STORAGE_KEY) !== this.committed)
        throw new Error('The vault changed in another tab. Unlock again before continuing.');
      this.deps.storage.setItem(VAULT_STORAGE_KEY, raw);
      this.committed = raw;
    } catch (err) {
      throw new DurabilityError(`Vault was not saved: ${message(err)}`);
    }
  }

  private async restoreCommitted(): Promise<void> {
    this.vault?.free();
    this.vault = null;
    this.deps.onIdentity?.(null);
    this.deps.onDevices?.(null, null);
    this.set({ ledger: null, ledgerError: null, provenance: this.cachedProvenance() });
    if (this.client) await this.attach(this.client, false);
  }

  private async run<T>(op: () => Promise<T>, mutating: boolean): Promise<T> {
    const execute = async () => {
      if (mutating && this.deps.storage?.getItem(VAULT_STORAGE_KEY) !== this.committed) {
        await this.restoreCommitted();
        throw new Error('The vault changed in another tab. Unlock again before continuing.');
      }
      try {
        return await op();
      } catch (err) {
        if (
          mutating &&
          this.vault &&
          (err instanceof DurabilityError ||
            encodeBytes(await this.vault.toBytes()) !== this.committed)
        )
          await this.restoreCommitted();
        throw err;
      }
    };
    if (!mutating) return execute();
    if (!this.deps.storage) throw new Error('Durable vault storage is unavailable');
    return withVaultWriter(this.deps.storage, execute);
  }

  private async refreshFactors(): Promise<void> {
    if (!this.vault) return;
    this.set({ slots: await this.vault.slots(), exportKeys: await this.vault.exportKeys() });
  }

  private async refreshUnlocked(): Promise<void> {
    if (!this.vault) return;
    await this.refreshFactors();
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

  /** `by` marks a proposal an agent or automation made; approvers see who and why. */
  txPropose(intent: Omit<TxIntent, 'proposer' | 'createdAtMs'>, by?: ProposedBy) {
    return this.ledgerOp((v, device, now) =>
      v.txPropose(
        {
          ...intent,
          proposer: by ?? { kind: 'human', deviceId: device },
          createdAtMs: now,
        } as TxIntent,
        device,
        now,
      ),
    );
  }

  hasProviderKey(provider: string): boolean {
    const s = this.view.status;
    return (
      (s.kind === 'unlocked' || s.kind === 'locked') &&
      s.labels.some((l) => l.label === `provider-key:${provider}`)
    );
  }

  /** Seal a model provider's API key (D4); replaces any earlier one. */
  setProviderKey(provider: string, key: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!/^[a-z-]{1,32}$/.test(provider)) throw new Error('bad provider');
      if (key.trim().length < 8) throw new Error('That does not look like an API key');
      await this.unlockedVault().put(
        `provider-key:${provider}`,
        new TextEncoder().encode(key.trim()),
      );
      await this.persist();
      await this.refreshUnlocked();
    });
  }

  /** Seal one agent session transcript; the newest MAX_AGENT_SESSIONS are kept. */
  saveAgentSession(id: string, json: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!/^[0-9a-f-]{8,64}$/.test(id)) throw new Error('bad session id');
      if (json.length > 256 * 1024) throw new Error('session too large to keep');
      const v = this.unlockedVault();
      await v.put(`agent-session:${id}`, new TextEncoder().encode(json));
      const labels = (await v.labels()).filter((l) => l.label.startsWith('agent-session:'));
      // Oldest first by insertion order; drop beyond the cap.
      for (const l of labels.slice(0, Math.max(0, labels.length - MAX_AGENT_SESSIONS)))
        await v.delete(l.handle);
      await this.persist();
      await this.refreshUnlocked();
    });
  }

  async agentSessions(): Promise<string[]> {
    const v = this.unlockedVault();
    const out: string[] = [];
    for (const l of await v.labels())
      if (l.label.startsWith('agent-session:')) {
        const text = await v.appRecord(l.label);
        if (text) out.push(text);
      }
    return out;
  }

  deleteAgentSession(id: string): Promise<VaultResult> {
    return this.guarded(async () => {
      const v = this.unlockedVault();
      const handle = await v.handleFor(`agent-session:${id}`);
      if (handle) await v.delete(handle);
      await this.persist();
      await this.refreshUnlocked();
    });
  }

  async providerKey(provider: string): Promise<string | null> {
    return this.unlockedVault().providerKey(provider);
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

  hardwareRegister(req: {
    session: SessionProof;
    walletId: string;
    path: string;
    address: string;
  }) {
    return this.guarded(async () => {
      await this.unlockedVault().hardwareRegister(req);
      await this.persist();
      await this.refreshUnlocked();
    });
  }

  /** Hardware approval, first half; returns the bytes the device must sign. */
  txBeginExternal(txId: string, session: SessionProof) {
    return this.guardedValue(async () => {
      const out = await this.unlockedVault().txBeginExternal(
        txId,
        session,
        this.deviceId(),
        this.now(),
      );
      await this.persist();
      await this.refreshLedger();
      return out;
    });
  }

  txCompleteExternal(txId: string, sig: { v: number; r: string; s: string }) {
    return this.ledgerOp((v, deviceId, nowMs) =>
      v.txCompleteExternal({ txId, ...sig, deviceId, nowMs }),
    );
  }

  txAbortExternal(txId: string, reason: string) {
    return this.ledgerOp((v, device, now) => v.txAbortExternal(txId, reason, device, now));
  }

  txReject(txId: string) {
    return this.ledgerOp((v, device, now) => v.txReject(txId, device, now));
  }

  txRetryBroadcast(txId: string, passphrase: string) {
    return this.ledgerOp((v, device, now) => v.txRetryBroadcast(txId, passphrase, device, now));
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
    const result = await this.guarded(async () => {
      await this.unlockedVault().setDevices(devices);
      await this.persist();
      await this.refreshUnlocked();
    });
    if (!result.ok) throw new Error(result.error);
  };

  private async guarded(op: () => Promise<void>, mutating = true): Promise<VaultResult> {
    if (this.view.busy) return { ok: false, error: 'The vault is busy' };
    this.set({ busy: true });
    try {
      await this.run(op, mutating);
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
      this.vault = vault;
      await vault.createIdentity(IDENTITY_LABEL);
      await this.persist();
      await this.refreshUnlocked();
    });
  }

  unlock(passphrase: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (this.deps.storage?.getItem(VAULT_STORAGE_KEY) !== this.committed)
        await this.restoreCommitted();
      if (!this.vault) throw new Error('No vault to unlock');
      await this.vault.unlock(passphrase);
      await this.refreshUnlocked();
    }, false);
  }

  /**
   * Open the session with this device's PIN. Wrong PINs count; at the limit
   * the device secret the PIN is bound to is destroyed, which retires the
   * PIN for good (the passphrase still works and can set a new one).
   */
  unlockWithPin(pin: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (this.deps.storage?.getItem(VAULT_STORAGE_KEY) !== this.committed)
        await this.restoreCommitted();
      if (!this.vault) throw new Error('No vault to unlock');
      const slot = this.view.slots.find((s) => s.kind === 'pin');
      if (!slot) throw new Error('No PIN is set on this device');
      const failures = pinFailures(this.deps.storage);
      if (failures >= MAX_PIN_FAILURES)
        throw new Error('Too many wrong PINs; unlock with the passphrase');
      const device = await loadDeviceSecret().catch(() => null);
      if (!device)
        throw new Error('This device no longer holds its PIN binding; use the passphrase');
      try {
        await this.vault.unlockWithSlot(slot.id, new TextEncoder().encode(pin), device);
      } catch (err) {
        const next = failures + 1;
        setPinFailures(this.deps.storage, next);
        if (next >= MAX_PIN_FAILURES) {
          await destroyDeviceSecret().catch(() => undefined);
          throw new Error(
            'Too many wrong PINs: the PIN is retired on this device. Use the passphrase.',
          );
        }
        throw new Error(
          /6 digits/.test(message(err))
            ? 'A PIN is exactly 6 digits'
            : `Wrong PIN; ${MAX_PIN_FAILURES - next} tries left`,
        );
      }
      setPinFailures(this.deps.storage, 0);
      await this.refreshUnlocked();
    }, false);
  }

  /** Open the session with a passkey (Face ID, Touch ID, Windows Hello, security key). */
  unlockWithPasskey(slotId: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (this.deps.storage?.getItem(VAULT_STORAGE_KEY) !== this.committed)
        await this.restoreCommitted();
      if (!this.vault) throw new Error('No vault to unlock');
      const slot = this.view.slots.find((s) => s.id === slotId && s.kind === 'passkey');
      if (!slot?.credentialId) throw new Error('That passkey is not set on this device');
      await this.vault.unlockWithSlot(slot.id, await passkeySecret(slot.credentialId));
      await this.refreshUnlocked();
    }, false);
  }

  /** Six digits bound to a fresh device secret. Only the passphrase can add one. */
  addPin(passphrase: string, pin: string): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!/^\d{6}$/.test(pin)) throw new Error('A PIN is exactly 6 digits');
      const v = this.unlockedVault();
      const device = await createDeviceSecret();
      await v.addSlot({
        passphrase,
        kind: 'pin',
        label: 'PIN',
        secret: new TextEncoder().encode(pin),
        device,
        nowMs: this.now(),
      });
      setPinFailures(this.deps.storage, 0);
      await this.persist();
      await this.refreshFactors();
    });
  }

  addPasskey(passphrase: string, label: string): Promise<VaultResult> {
    return this.guarded(async () => {
      const v = this.unlockedVault();
      // Check the passphrase before the biometric prompt, so a typo costs no ceremony.
      await v.verifySession({ kind: 'passphrase', passphrase }, false);
      const { credentialId, secret } = await createPasskey(label);
      await v.addSlot({
        passphrase,
        kind: 'passkey',
        label,
        credentialId,
        secret,
        nowMs: this.now(),
      });
      await this.persist();
      await this.refreshFactors();
    });
  }

  removeSlot(id: string): Promise<VaultResult> {
    return this.guarded(async () => {
      const v = this.unlockedVault();
      const slot = this.view.slots.find((s) => s.id === id);
      await v.removeSlot(id);
      if (slot?.kind === 'pin') await destroyDeviceSecret().catch(() => undefined);
      await this.persist();
      await this.refreshFactors();
    });
  }

  /** Turn the person's choice into a proof the core checks; a passkey prompts here. */
  async proveSession(choice: SessionChoice): Promise<SessionProof> {
    if (choice.kind === 'passphrase') return choice;
    const slot = this.view.slots.find((s) => s.id === choice.slotId && s.kind === 'passkey');
    if (!slot?.credentialId) throw new Error('That passkey is not set on this device');
    return { kind: 'slot', slotId: slot.id, secret: await passkeySecret(slot.credentialId) };
  }

  /** Sign a message from a single wallet's EVM key; the core audits it before returning. */
  signMessage(req: {
    walletId: string;
    path: string;
    address: string;
    session: SessionProof;
    kind: 'personal' | 'typedData';
    payload: string;
  }): Promise<{ ok: true; value: SignedMessage } | { ok: false; error: string }> {
    return this.guardedValue(async () => {
      const out = await this.unlockedVault().signMessage({
        ...req,
        deviceId: this.deviceId(),
        nowMs: this.now(),
      });
      await this.persist();
      await this.refreshLedger();
      return out;
    });
  }

  /** Set or change the export key of a directory or a wallet. */
  setExportKey(req: {
    scope: ExportKeyScope;
    id: string;
    session: SessionProof;
    current?: string;
    next: string;
  }): Promise<VaultResult> {
    return this.guarded(async () => {
      await this.unlockedVault().setExportKey(req);
      await this.persist();
      await this.refreshFactors();
    });
  }

  hasExportKey(scope: ExportKeyScope, id: string): boolean {
    return this.view.exportKeys.some((k) => k.scope === scope && k.id === id);
  }

  lock(): Promise<VaultResult> {
    return this.guarded(async () => {
      if (!this.vault) throw new Error('No vault to lock');
      await this.vault.lock();
      this.deps.onDevices?.(null, null);
      this.set({ ledger: null, ledgerError: null });
      this.set({ status: { kind: 'locked', labels: await this.vault.labels() } });
    }, false);
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
      return { ok: true, value: await this.run(op, true) };
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
   * Take a phrase or key out. The core checks the export gate (session,
   * parent directory key, wallet key) and seals the exposure before it
   * returns anything, so the tag cannot be skipped.
   */
  reveal(
    walletId: string,
    gate: ExportGateInput,
    what: Revealed,
    channel: ExposureChannel,
  ): Promise<{ ok: true; value: RevealedSecret } | { ok: false; error: string }> {
    return this.guardedValue(async () => {
      const v = this.unlockedVault();
      const out = await v.reveal(walletId, gate, what, channel, this.now());
      await this.persist();
      await this.refreshProvenance();
      return out;
    });
  }

  /** A directory (`set`) or one wallet (`wallet`), sealed for one paired device. */
  exportBundle(req: {
    gate: ExportGateInput;
    scope: 'set' | 'wallet';
    toDeviceId: string;
    walletIds: string[];
    directory: unknown;
  }): Promise<{ ok: true; value: string } | { ok: false; error: string }> {
    return this.guardedValue(async () => {
      const v = this.unlockedVault();
      const bundle = await v.exportBundle({
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
    session: SessionProof,
    bundle: string,
    validate?: (set: ImportedSet) => void,
  ): Promise<{ ok: true; value: ImportedSet } | { ok: false; error: string }> {
    return this.guardedValue(async () => {
      const v = this.unlockedVault();
      const got = await v.importSet(IDENTITY_LABEL, session, bundle, this.now());
      validate?.(got);
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
