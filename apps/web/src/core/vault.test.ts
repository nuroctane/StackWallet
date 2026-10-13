import { describe, expect, it } from 'vitest';
import type {
  CoreClient,
  Device,
  ExportGateInput,
  ExportKeyRef,
  SessionProof,
  SlotInfo,
  ExposureChannel,
  IdentityHandle,
  IdentityInfo,
  ProvenanceTable,
  Revealed,
  VaultHandle,
  VaultLabel,
} from '@stackwallet/core-client';

import type { StorageLike } from '../store/persist.js';
import {
  decodeBytes,
  encodeBytes,
  IDENTITY_LABEL,
  passphraseProblem,
  PROVENANCE_CACHE_KEY,
  VAULT_STORAGE_KEY,
  VaultStore,
} from './vault.js';

class MemoryStorage implements StorageLike {
  readonly map = new Map<string, string>();
  getItem(k: string) {
    return this.map.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.map.set(k, v);
  }
  removeItem(k: string) {
    this.map.delete(k);
  }
}

const INFO: IdentityInfo = {
  deviceId: '66687aadf862bd776c8fc18b8e9f8e20',
  publicHex: '00'.repeat(32),
  noiseStaticHex: '11'.repeat(32),
};

/**
 * A vault that behaves like the core's without the cryptography: ciphertext is
 * the JSON of its labels plus the passphrase it was created with.
 */
class FakeVault implements VaultHandle {
  unlocked = true;
  constructor(
    private pass: string,
    private readonly labelList: VaultLabel[] = [],
  ) {}
  static open(bytes: Uint8Array): FakeVault {
    const { pass, labels } = JSON.parse(new TextDecoder().decode(bytes)) as {
      pass: string;
      labels: VaultLabel[];
    };
    const v = new FakeVault(pass, labels);
    v.unlocked = false;
    return v;
  }
  async isUnlocked() {
    return this.unlocked;
  }
  async unlock(p: string) {
    if (p !== this.pass) throw new Error('wrong passphrase');
    this.unlocked = true;
  }
  async lock() {
    this.unlocked = false;
  }
  async changePassphrase(current: string, next: string) {
    if (current !== this.pass) throw new Error('wrong passphrase');
    this.pass = next;
  }
  async toBytes() {
    return new TextEncoder().encode(JSON.stringify({ pass: this.pass, labels: this.labelList }));
  }
  async kdfParams() {
    return { mCostKib: 19_456, tCost: 2, pCost: 1 };
  }
  async labels() {
    return this.labelList.slice();
  }
  async handleFor(label: string) {
    return this.labelList.find((l) => l.label === label)?.handle;
  }
  async put(label: string) {
    this.labelList.push({ handle: `h-${label}`, label });
    return `h-${label}`;
  }
  async delete() {}
  async createIdentity(label: string) {
    this.labelList.push({ handle: `h-${label}`, label });
    return INFO;
  }
  async identityInfo() {
    if (!this.unlocked) throw new Error('locked');
    return INFO;
  }
  async identity(): Promise<IdentityHandle> {
    if (!this.unlocked) throw new Error('locked');
    return { info: async () => INFO, free: () => undefined };
  }
  async signCeremonyMessage(): Promise<never> {
    throw new Error('not used');
  }
  table: Device[] = [];
  async devices() {
    if (!this.unlocked) throw new Error('locked');
    return this.table.slice();
  }
  async setDevices(devices: Device[]) {
    if (!this.unlocked) throw new Error('locked');
    this.table = devices.slice();
    if (!this.labelList.some((l) => l.label === 'device-table')) {
      this.labelList.push({ handle: 'h-device-table', label: 'device-table' });
    }
  }
  prov: ProvenanceTable = { wallets: [], sets: [] };
  async createSingle(walletId: string, nowMs: number) {
    if (!this.unlocked) throw new Error('locked');
    this.prov.wallets.push({
      walletId,
      origin: { kind: 'created', atMs: nowMs },
      exposures: [],
      transfers: [],
    });
  }
  async importPhrase(walletId: string, _phrase: string, nowMs: number) {
    this.prov.wallets.push({
      walletId,
      origin: { kind: 'importedPhrase', atMs: nowMs },
      exposures: [],
      transfers: [],
    });
  }
  async hasSingleKey(walletId: string) {
    return this.prov.wallets.some((w) => w.walletId === walletId);
  }
  async singlePublicKey() {
    return '02'.padEnd(66, '1');
  }
  async reveal(
    walletId: string,
    gate: ExportGateInput,
    what: Revealed,
    channel: ExposureChannel,
    nowMs: number,
  ) {
    if (gate.session.kind !== 'passphrase' || gate.session.passphrase !== this.pass)
      throw new Error('wrong passphrase');
    if (gate.folderKey !== 'folder-key' || gate.walletKey !== 'wallet-key')
      throw new Error('wrong export key');
    this.prov.wallets
      .find((w) => w.walletId === walletId)!
      .exposures.push({ atMs: nowMs, channel, what });
    return { what, secret: 'abandon about', publicHex: null };
  }
  async provenance() {
    if (!this.unlocked) throw new Error('locked');
    return structuredClone(this.prov);
  }
  async exportBundle(): Promise<never> {
    throw new Error('not used');
  }
  async importSet(): Promise<never> {
    throw new Error('not used');
  }
  async verifySession(session: SessionProof) {
    if (session.kind !== 'passphrase' || session.passphrase !== this.pass)
      throw new Error('wrong passphrase');
  }
  slotList: SlotInfo[] = [];
  async slots() {
    return this.slotList.slice();
  }
  async addSlot(): Promise<never> {
    throw new Error('not used');
  }
  async removeSlot(): Promise<never> {
    throw new Error('not used');
  }
  async unlockWithSlot(): Promise<never> {
    throw new Error('not used');
  }
  keys: ExportKeyRef[] = [];
  async exportKeys() {
    return this.keys.slice();
  }
  async setExportKey(req: { scope: ExportKeyRef['scope']; id: string; session: SessionProof }) {
    await this.verifySession(req.session);
    this.keys.push({ scope: req.scope, id: req.id });
  }
  async ledger() {
    if (!this.unlocked) throw new Error('locked');
    return { txs: [], audit: [], policies: [] };
  }
  async txPropose(): Promise<never> {
    throw new Error('not used');
  }
  async txAttach(): Promise<never> {
    throw new Error('not used');
  }
  async txEvaluate(): Promise<never> {
    throw new Error('not used');
  }
  async txApprove(): Promise<never> {
    throw new Error('not used');
  }
  async txRetryBroadcast(): Promise<never> {
    throw new Error('not used');
  }
  async txReject(): Promise<never> {
    throw new Error('not used');
  }
  async txReport(): Promise<never> {
    throw new Error('not used');
  }
  async setPolicies() {}
  free() {}
}

function fakeClient(): CoreClient {
  const unsupported = () => Promise.reject(new Error('not used'));
  return {
    backend: 'wasm',
    coreVersion: async () => '0.0.1',
    evaluatePolicy: unsupported,
    validateKeyGroup: unsupported,
    canTransition: unsupported,
    schemaSql: unsupported,
    createVault: async (pass) => new FakeVault(pass),
    openVault: async (bytes) => FakeVault.open(bytes),
    newPairingCodeHex: async () => 'ab'.repeat(32),
    pairAsIssuer: unsupported,
    pairAsScanner: unsupported,
    connectInitiator: unsupported,
    connectResponder: unsupported,
    verifyCeremonyMessage: unsupported,
  };
}

const PASS = 'correct horse battery';

describe('vault helpers', () => {
  it('round-trips bytes through base64 and rejects junk', () => {
    const bytes = Uint8Array.from([0, 1, 2, 250, 255]);
    expect(decodeBytes(encodeBytes(bytes))).toEqual(bytes);
    expect(decodeBytes('not base64!')).toBeUndefined();
  });

  it('enforces a passphrase floor', () => {
    expect(passphraseProblem('short')).toMatch(/at least/);
    expect(passphraseProblem(PASS)).toBeNull();
  });
});

describe('VaultStore', () => {
  it('reports absent when nothing is stored, then creates, persists and mints an identity', async () => {
    const storage = new MemoryStorage();
    const seen: Array<IdentityInfo | null> = [];
    const store = new VaultStore({ storage, onIdentity: (i) => seen.push(i) });
    expect(store.getSnapshot().status.kind).toBe('loading');

    await store.attach(fakeClient());
    expect(store.getSnapshot().status.kind).toBe('absent');

    expect(await store.create('short')).toEqual({
      ok: false,
      error: expect.stringMatching(/at least/),
    });
    expect(await store.create(PASS)).toEqual({ ok: true });
    const status = store.getSnapshot().status;
    expect(status.kind).toBe('unlocked');
    if (status.kind === 'unlocked') {
      expect(status.identity).toEqual(INFO);
      expect(status.labels.map((l) => l.label)).toEqual([IDENTITY_LABEL]);
    }
    expect(seen).toEqual([INFO]);
    expect(storage.getItem(VAULT_STORAGE_KEY)).not.toBeNull();
    expect(await store.create(PASS)).toEqual({
      ok: false,
      error: expect.stringMatching(/already exists/),
    });
  });

  it('opens a stored vault locked, refuses a wrong passphrase and unlocks with the right one', async () => {
    const storage = new MemoryStorage();
    const first = new VaultStore({ storage });
    await first.attach(fakeClient());
    await first.create(PASS);

    const seen: Array<IdentityInfo | null> = [];
    const second = new VaultStore({ storage, onIdentity: (i) => seen.push(i) });
    await second.attach(fakeClient());
    expect(second.getSnapshot().status).toEqual({
      kind: 'locked',
      labels: [{ handle: `h-${IDENTITY_LABEL}`, label: IDENTITY_LABEL }],
    });
    await expect(second.identity()).rejects.toThrow(/Unlock/);

    expect(await second.unlock('nope')).toEqual({ ok: false, error: 'wrong passphrase' });
    expect(second.getSnapshot().status.kind).toBe('locked');
    expect(await second.unlock(PASS)).toEqual({ ok: true });
    expect(second.getSnapshot().status.kind).toBe('unlocked');
    expect(seen).toEqual([INFO]);
    expect(await (await second.identity()).info()).toEqual(INFO);

    expect(await second.lock()).toEqual({ ok: true });
    expect(second.getSnapshot().status.kind).toBe('locked');
  });

  it('hands the sealed device table to the UI on unlock and withdraws the writer on lock', async () => {
    const storage = new MemoryStorage();
    const events: Array<{ table: Device[] | null; writable: boolean }> = [];
    let writer: ((d: Device[]) => Promise<void>) | null = null;
    const store = new VaultStore({
      storage,
      onDevices: (table, write) => {
        events.push({ table, writable: write !== null });
        writer = write;
      },
    });
    await store.attach(fakeClient());
    await store.create(PASS);
    expect(events).toEqual([{ table: [], writable: true }]);

    const peer: Device = {
      id: '66687aadf862bd776c8fc18b8e9f8e20',
      name: 'Laptop',
      kind: 'desktop',
      identityPubHex: '00'.repeat(32),
      noiseStaticHex: '11'.repeat(32),
      endpoints: [],
      pairedAtMs: 1,
      lastSeenAtMs: null,
      revokedAtMs: null,
    };
    const write = writer!;
    await write([peer]);
    const status = store.getSnapshot().status;
    if (status.kind === 'unlocked') {
      expect(status.labels.map((l) => l.label)).toContain('device-table');
    }

    await store.lock();
    expect(events.at(-1)).toEqual({ table: null, writable: false });
    expect(writer).toBeNull();
    await expect(write([peer])).rejects.toThrow(/Unlock/);

    // The ciphertext written after the table change carries the table.
    const reopened = new VaultStore({
      storage,
      onDevices: (table, write) => events.push({ table, writable: write !== null }),
    });
    await reopened.attach(fakeClient());
    await reopened.unlock(PASS);
    expect(events.at(-1)?.writable).toBe(true);
  });

  it('marks a revealed wallet exposed and keeps the tag visible while locked', async () => {
    const storage = new MemoryStorage();
    const store = new VaultStore({ storage, now: () => 42 });
    await store.attach(fakeClient());
    await store.create(PASS);
    expect(await store.createSingle('w1')).toEqual({ ok: true });
    expect(store.getSnapshot().provenance.wallets[0]?.origin).toEqual({
      kind: 'created',
      atMs: 42,
    });

    const gate = (passphrase: string, walletKey = 'wallet-key') => ({
      session: { kind: 'passphrase' as const, passphrase },
      folderId: 'f',
      folderKey: 'folder-key',
      walletKey,
    });
    const wrong = await store.reveal('w1', gate('nope'), { kind: 'mnemonic' }, 'screen');
    expect(wrong.ok).toBe(false);
    const wrongKey = await store.reveal('w1', gate(PASS, 'nope'), { kind: 'mnemonic' }, 'screen');
    expect(wrongKey.ok).toBe(false);
    expect(store.getSnapshot().provenance.wallets[0]?.exposures).toEqual([]);

    expect(
      await store.setExportKey({
        scope: 'wallet',
        id: 'w1',
        session: { kind: 'passphrase', passphrase: PASS },
        next: 'wallet-key',
      }),
    ).toEqual({ ok: true });
    expect(store.hasExportKey('wallet', 'w1')).toBe(true);
    expect(store.hasExportKey('folder', 'w1')).toBe(false);

    const r = await store.reveal('w1', gate(PASS), { kind: 'mnemonic' }, 'clipboard');
    expect(r.ok).toBe(true);
    expect(store.getSnapshot().provenance.wallets[0]?.exposures).toHaveLength(1);

    await store.lock();
    expect(store.getSnapshot().provenance.wallets[0]?.exposures).toHaveLength(1);
    // A fresh page load shows the mirror before any unlock.
    const reloaded = new VaultStore({ storage });
    expect(reloaded.getSnapshot().provenance.wallets[0]?.exposures).toHaveLength(1);
    expect(storage.getItem(PROVENANCE_CACHE_KEY)).toContain('clipboard');
  });

  it('persists a passphrase change', async () => {
    const storage = new MemoryStorage();
    const store = new VaultStore({ storage });
    await store.attach(fakeClient());
    await store.create(PASS);
    expect(await store.changePassphrase('wrong', 'another long passphrase')).toEqual({
      ok: false,
      error: 'wrong passphrase',
    });
    expect(await store.changePassphrase(PASS, 'another long passphrase')).toEqual({ ok: true });

    const reopened = new VaultStore({ storage });
    await reopened.attach(fakeClient());
    expect(await reopened.unlock(PASS)).toEqual({ ok: false, error: 'wrong passphrase' });
    expect(await reopened.unlock('another long passphrase')).toEqual({ ok: true });
  });

  it('quarantines unreadable ciphertext instead of failing to load', async () => {
    const storage = new MemoryStorage();
    storage.setItem(VAULT_STORAGE_KEY, '%%% not base64 %%%');
    const store = new VaultStore({ storage, now: () => 42 });
    await store.attach(fakeClient());
    expect(store.getSnapshot().status).toEqual({
      kind: 'corrupt',
      quarantinedKey: `${VAULT_STORAGE_KEY}.corrupt-42`,
    });
    expect(storage.getItem(`${VAULT_STORAGE_KEY}.corrupt-42`)).toBe('%%% not base64 %%%');
    expect(storage.getItem(VAULT_STORAGE_KEY)).toBeNull();
    // A fresh vault may replace the quarantined one.
    expect(await store.create(PASS)).toEqual({ ok: true });
  });

  it('reports an unavailable core without touching storage', async () => {
    const storage = new MemoryStorage();
    const store = new VaultStore({ storage });
    await store.attach({
      ...fakeClient(),
      backend: 'unavailable',
      reason: 'no wasm',
    } as CoreClient);
    expect(store.getSnapshot().status).toEqual({ kind: 'unavailable', reason: 'no wasm' });
    expect(storage.map.size).toBe(0);
  });
});
