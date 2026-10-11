/**
 * One client API over two backends: the wasm build of the core (browser) and
 * Tauri IPC (desktop). Both return JSON that is Zod-validated here, so UI code
 * never sees an unchecked shape from either side.
 *
 * Stateful objects (vault, identity, session) are opaque handles. The wasm
 * backend keeps their secrets inside linear memory; the Tauri backend will keep
 * them in-process and hand JS an id. Either way, nothing secret crosses here.
 */
import { z } from 'zod';

import {
  CeremonyMessage,
  Curve,
  Decision,
  Device,
  DeviceId,
  EvmTx,
  ExposureChannel,
  Frame,
  ImportedSet,
  Hex32,
  KeyGroup,
  Ledger,
  PairingOffer,
  Policy,
  PolicyContext,
  ProvenanceTable,
  Revealed,
  RevealedSecret,
  SessionEvent,
  SessionStateName,
  SignedCeremonyMessage,
  Signer,
  TxIntent,
  TxRecord,
  TxState,
} from './types.js';

export const KdfParams = z.object({
  mCostKib: z.number().int().positive(),
  tCost: z.number().int().positive(),
  pCost: z.number().int().positive(),
});
export type KdfParams = z.infer<typeof KdfParams>;

export const IdentityInfo = z.object({
  deviceId: DeviceId,
  publicHex: Hex32,
  noiseStaticHex: Hex32,
});
export type IdentityInfo = z.infer<typeof IdentityInfo>;

export const VaultLabel = z.object({ handle: z.string().min(1), label: z.string() });
export type VaultLabel = z.infer<typeof VaultLabel>;

/** Thrown when a backend has no implementation for a call yet. */
export class CoreUnsupportedError extends Error {
  override readonly name = 'CoreUnsupportedError';
  constructor(
    readonly backend: string,
    readonly op: string,
  ) {
    super(`${op} is not available on the ${backend} backend`);
  }
}

/** Opaque long-term identity; `free()` once the session that needed it is over. */
export interface IdentityHandle {
  info(): Promise<IdentityInfo>;
  free(): void;
}

/**
 * The encrypted vault. `toBytes()` is the only thing worth persisting; labels
 * are readable while locked, everything else needs `unlock`.
 */
export interface VaultHandle {
  isUnlocked(): Promise<boolean>;
  unlock(passphrase: string): Promise<void>;
  lock(): Promise<void>;
  changePassphrase(current: string, next: string): Promise<void>;
  toBytes(): Promise<Uint8Array>;
  kdfParams(): Promise<KdfParams>;
  labels(): Promise<VaultLabel[]>;
  handleFor(label: string): Promise<string | undefined>;
  /** Store a secret the UI already holds; returns the handle. */
  put(label: string, secret: Uint8Array): Promise<string>;
  delete(handle: string): Promise<void>;
  /** Mint an identity and seal its seed under `label`. */
  createIdentity(label: string): Promise<IdentityInfo>;
  identityInfo(label: string): Promise<IdentityInfo>;
  identity(label: string): Promise<IdentityHandle>;
  signCeremonyMessage(label: string, msg: CeremonyMessage): Promise<SignedCeremonyMessage>;
  /** The pinned device table sealed in the vault, validated by the core; empty if none. */
  devices(): Promise<Device[]>;
  /** Validate and seal the whole table; the core refuses forged ids and duplicates. */
  setDevices(devices: Device[]): Promise<void>;
  /** Generate and seal a fresh phrase for a new `single` wallet. */
  createSingle(walletId: string, nowMs: number): Promise<void>;
  /** Seal a phrase from elsewhere; the wallet starts `imported`. */
  importPhrase(walletId: string, phrase: string, nowMs: number): Promise<void>;
  hasSingleKey(walletId: string): Promise<boolean>;
  singlePublicKey(walletId: string, curve: Curve, path: string): Promise<string>;
  /** Step-up reveal; the core marks the wallet exposed before returning the secret. */
  reveal(
    walletId: string,
    passphrase: string,
    what: Revealed,
    channel: ExposureChannel,
    nowMs: number,
  ): Promise<RevealedSecret>;
  provenance(): Promise<ProvenanceTable>;
  exportSet(req: {
    identityLabel: string;
    passphrase: string;
    toDeviceId: string;
    folderId: string;
    walletIds: string[];
    directory: unknown;
    nowMs: number;
  }): Promise<string>;
  importSet(
    identityLabel: string,
    passphrase: string,
    bundle: string,
    nowMs: number,
  ): Promise<ImportedSet>;
  /** Transactions, policies and the hash-chained audit log, as the core sealed them. */
  ledger(): Promise<Ledger>;
  txPropose(intent: TxIntent, deviceId: string, nowMs: number): Promise<TxRecord>;
  txAttach(req: {
    txId: string;
    signer: Signer;
    unsigned: EvmTx;
    simulation: unknown;
    simulationOk: boolean;
    deviceId: string;
    nowMs: number;
  }): Promise<TxRecord>;
  txEvaluate(txId: string, deviceId: string, nowMs: number): Promise<TxRecord>;
  /** Step-up approval; the core re-checks policy and signs. */
  txApprove(txId: string, passphrase: string, deviceId: string, nowMs: number): Promise<TxRecord>;
  txReject(txId: string, deviceId: string, nowMs: number): Promise<TxRecord>;
  txReport(
    txId: string,
    state: TxState,
    note: string | null,
    deviceId: string,
    nowMs: number,
  ): Promise<TxRecord>;
  setPolicies(policies: Policy[], deviceId: string, nowMs: number): Promise<void>;
  free(): void;
}

/** One authenticated channel to one peer (`transport::Session`). */
export interface SessionHandle {
  handleIncoming(bytes: Uint8Array): Promise<SessionEvent[]>;
  sendFrame(frame: Frame): Promise<void>;
  takeOutgoing(): Promise<Uint8Array[]>;
  state(): Promise<SessionStateName>;
  isPairing(): Promise<boolean>;
  peer(): Promise<Device | undefined>;
  close(reason: string): Promise<void>;
  free(): void;
}

export interface CoreClient {
  readonly backend: 'wasm' | 'tauri' | 'unavailable';
  coreVersion(): Promise<string>;
  evaluatePolicy(policies: Policy[], intent: TxIntent, ctx: PolicyContext): Promise<Decision>;
  /** `null` when valid, otherwise the violation message. */
  validateKeyGroup(group: KeyGroup): Promise<string | null>;
  canTransition(from: TxState, to: TxState): Promise<boolean>;
  schemaSql(): Promise<string>;

  /** New unlocked vault. Omitted `kdf` means the OWASP minimum. */
  createVault(passphrase: string, kdf?: KdfParams): Promise<VaultHandle>;
  /** Parse a serialized vault; the result is locked. */
  openVault(bytes: Uint8Array): Promise<VaultHandle>;

  newPairingCodeHex(): Promise<Hex32>;
  /** Issuer side of pairing: this device showed the offer. */
  pairAsIssuer(
    identity: IdentityHandle,
    local: Device,
    offer: PairingOffer,
    nowMs: number,
  ): Promise<SessionHandle>;
  /** Scanner side of pairing: this device read the offer. */
  pairAsScanner(
    identity: IdentityHandle,
    local: Device,
    offer: PairingOffer,
    nowMs: number,
  ): Promise<SessionHandle>;
  connectInitiator(
    identity: IdentityHandle,
    local: Device,
    peer: Device,
    nowMs: number,
  ): Promise<SessionHandle>;
  connectResponder(
    identity: IdentityHandle,
    local: Device,
    known: Device[],
    nowMs: number,
  ): Promise<SessionHandle>;
  verifyCeremonyMessage(signed: SignedCeremonyMessage, publicHex: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// wasm backend
// ---------------------------------------------------------------------------

/**
 * Hand-written mirror of the wasm-bindgen glue (`stackwallet_wasm.js`). The
 * bridge test in `apps/web` loads the real binary against this shape, so a
 * drift between the two fails CI rather than a user's first unlock.
 */
export interface WasmIdentityObject {
  public_hex(): string;
  device_id(): string;
  noise_static_public_hex(): string;
  info_json(): string;
  free(): void;
}

export interface WasmVaultObject {
  to_bytes(): Uint8Array;
  is_unlocked(): boolean;
  unlock(passphrase: string): void;
  lock(): void;
  change_passphrase(old: string, next: string): void;
  kdf_params_json(): string;
  labels_json(): string;
  handle_for(label: string): string | undefined;
  put(label: string, secret: Uint8Array): string;
  delete(handle: string): void;
  create_identity(label: string): string;
  identity_info(label: string): string;
  identity(label: string): WasmIdentityObject;
  sign_ceremony_message(label: string, msgJson: string): string;
  devices_json(): string;
  set_devices_json(devicesJson: string): void;
  create_single(walletId: string, nowMs: number): void;
  import_phrase(walletId: string, phrase: string, nowMs: number): void;
  has_single_key(walletId: string): boolean;
  single_public_key(walletId: string, curve: string, path: string): string;
  reveal(
    walletId: string,
    passphrase: string,
    whatJson: string,
    channel: string,
    nowMs: number,
  ): string;
  provenance_json(): string;
  export_set(
    identityLabel: string,
    passphrase: string,
    toDeviceId: string,
    folderId: string,
    walletIdsJson: string,
    directoryJson: string,
    nowMs: number,
  ): string;
  import_set(identityLabel: string, passphrase: string, bundle: string, nowMs: number): string;
  ledger_json(): string;
  tx_propose(intentJson: string, deviceId: string, nowMs: number): string;
  tx_attach(
    txId: string,
    signerJson: string,
    unsignedJson: string,
    simulationJson: string,
    simulationOk: boolean,
    deviceId: string,
    nowMs: number,
  ): string;
  tx_evaluate(txId: string, deviceId: string, nowMs: number): string;
  tx_approve(txId: string, passphrase: string, deviceId: string, nowMs: number): string;
  tx_reject(txId: string, deviceId: string, nowMs: number): string;
  tx_report(
    txId: string,
    state: string,
    note: string | undefined,
    deviceId: string,
    nowMs: number,
  ): string;
  set_policies_json(policiesJson: string, deviceId: string, nowMs: number): void;
  free(): void;
}

export interface WasmSessionObject {
  handle_incoming(bytes: Uint8Array): unknown;
  send_frame(frameJson: string): void;
  take_outgoing(): Uint8Array[];
  state(): string;
  is_pairing(): boolean;
  peer_json(): string | undefined;
  close(reason: string): void;
  free(): void;
}

export interface WasmModule {
  default?: (input?: unknown) => Promise<unknown>;
  core_version(): string;
  evaluate_policy(policies: string, intent: string, ctx: string): string;
  validate_key_group(group: string): string | undefined;
  can_transition(from: string, to: string): boolean;
  schema_sql(): string;
  verify_ceremony_message(signedJson: string, publicHex: string): boolean;
  device_id_from_public_hex(publicHex: string): string;
  pairing_new_code_hex(): string;
  pairing_offer_encode(offerJson: string): string;
  pairing_offer_decode(text: string): unknown;
  WasmVault: {
    new (passphrase: string, kdfJson?: string): WasmVaultObject;
    open(bytes: Uint8Array): WasmVaultObject;
  };
  WasmSession: {
    pair_as_issuer(
      identity: WasmIdentityObject,
      localJson: string,
      offerJson: string,
      nowMs: number,
    ): WasmSessionObject;
    pair_as_scanner(
      identity: WasmIdentityObject,
      localJson: string,
      offerJson: string,
      nowMs: number,
    ): WasmSessionObject;
    connect_initiator(
      identity: WasmIdentityObject,
      localJson: string,
      peerJson: string,
      nowMs: number,
    ): WasmSessionObject;
    connect_responder(
      identity: WasmIdentityObject,
      localJson: string,
      knownJson: string,
      nowMs: number,
    ): WasmSessionObject;
  };
}

class WasmIdentityHandle implements IdentityHandle {
  constructor(readonly raw: WasmIdentityObject) {}
  async info() {
    return IdentityInfo.parse(JSON.parse(this.raw.info_json()));
  }
  free() {
    this.raw.free();
  }
}

/** The only way to get at the raw identity; sessions need it, nothing else does. */
function rawIdentity(identity: IdentityHandle): WasmIdentityObject {
  if (!(identity instanceof WasmIdentityHandle)) {
    throw new TypeError('identity handle does not belong to the wasm backend');
  }
  return identity.raw;
}

class WasmVaultHandle implements VaultHandle {
  constructor(private readonly raw: WasmVaultObject) {}
  async isUnlocked() {
    return this.raw.is_unlocked();
  }
  async unlock(passphrase: string) {
    this.raw.unlock(passphrase);
  }
  async lock() {
    this.raw.lock();
  }
  async changePassphrase(current: string, next: string) {
    this.raw.change_passphrase(current, next);
  }
  async toBytes() {
    return this.raw.to_bytes();
  }
  async kdfParams() {
    return KdfParams.parse(JSON.parse(this.raw.kdf_params_json()));
  }
  async labels() {
    return VaultLabel.array().parse(JSON.parse(this.raw.labels_json()));
  }
  async handleFor(label: string) {
    return this.raw.handle_for(label);
  }
  async put(label: string, secret: Uint8Array) {
    return this.raw.put(label, secret);
  }
  async delete(handle: string) {
    this.raw.delete(handle);
  }
  async createIdentity(label: string) {
    return IdentityInfo.parse(JSON.parse(this.raw.create_identity(label)));
  }
  async identityInfo(label: string) {
    return IdentityInfo.parse(JSON.parse(this.raw.identity_info(label)));
  }
  async identity(label: string): Promise<IdentityHandle> {
    return new WasmIdentityHandle(this.raw.identity(label));
  }
  async signCeremonyMessage(label: string, msg: CeremonyMessage) {
    const out = this.raw.sign_ceremony_message(label, JSON.stringify(CeremonyMessage.parse(msg)));
    return SignedCeremonyMessage.parse(JSON.parse(out));
  }
  async devices() {
    return Device.array().parse(JSON.parse(this.raw.devices_json()));
  }
  async setDevices(devices: Device[]) {
    this.raw.set_devices_json(JSON.stringify(Device.array().parse(devices)));
  }
  async createSingle(walletId: string, nowMs: number) {
    this.raw.create_single(walletId, nowMs);
  }
  async importPhrase(walletId: string, phrase: string, nowMs: number) {
    this.raw.import_phrase(walletId, phrase, nowMs);
  }
  async hasSingleKey(walletId: string) {
    return this.raw.has_single_key(walletId);
  }
  async singlePublicKey(walletId: string, curve: Curve, path: string) {
    return this.raw.single_public_key(walletId, Curve.parse(curve), path);
  }
  async reveal(
    walletId: string,
    passphrase: string,
    what: Revealed,
    channel: ExposureChannel,
    nowMs: number,
  ) {
    const out = this.raw.reveal(
      walletId,
      passphrase,
      JSON.stringify(Revealed.parse(what)),
      ExposureChannel.parse(channel),
      nowMs,
    );
    return RevealedSecret.parse(JSON.parse(out));
  }
  async provenance() {
    return ProvenanceTable.parse(JSON.parse(this.raw.provenance_json()));
  }
  async exportSet(req: {
    identityLabel: string;
    passphrase: string;
    toDeviceId: string;
    folderId: string;
    walletIds: string[];
    directory: unknown;
    nowMs: number;
  }) {
    return this.raw.export_set(
      req.identityLabel,
      req.passphrase,
      req.toDeviceId,
      req.folderId,
      JSON.stringify(req.walletIds),
      JSON.stringify(req.directory),
      req.nowMs,
    );
  }
  async ledger() {
    return Ledger.parse(JSON.parse(this.raw.ledger_json()));
  }
  async txPropose(intent: TxIntent, deviceId: string, nowMs: number) {
    const out = this.raw.tx_propose(JSON.stringify(TxIntent.parse(intent)), deviceId, nowMs);
    return TxRecord.parse(JSON.parse(out));
  }
  async txAttach(req: {
    txId: string;
    signer: Signer;
    unsigned: EvmTx;
    simulation: unknown;
    simulationOk: boolean;
    deviceId: string;
    nowMs: number;
  }) {
    const out = this.raw.tx_attach(
      req.txId,
      JSON.stringify(Signer.parse(req.signer)),
      JSON.stringify(EvmTx.parse(req.unsigned)),
      JSON.stringify(req.simulation ?? null),
      req.simulationOk,
      req.deviceId,
      req.nowMs,
    );
    return TxRecord.parse(JSON.parse(out));
  }
  async txEvaluate(txId: string, deviceId: string, nowMs: number) {
    return TxRecord.parse(JSON.parse(this.raw.tx_evaluate(txId, deviceId, nowMs)));
  }
  async txApprove(txId: string, passphrase: string, deviceId: string, nowMs: number) {
    return TxRecord.parse(JSON.parse(this.raw.tx_approve(txId, passphrase, deviceId, nowMs)));
  }
  async txReject(txId: string, deviceId: string, nowMs: number) {
    return TxRecord.parse(JSON.parse(this.raw.tx_reject(txId, deviceId, nowMs)));
  }
  async txReport(
    txId: string,
    state: TxState,
    note: string | null,
    deviceId: string,
    nowMs: number,
  ) {
    const out = this.raw.tx_report(txId, TxState.parse(state), note ?? undefined, deviceId, nowMs);
    return TxRecord.parse(JSON.parse(out));
  }
  async setPolicies(policies: Policy[], deviceId: string, nowMs: number) {
    this.raw.set_policies_json(JSON.stringify(Policy.array().parse(policies)), deviceId, nowMs);
  }
  async importSet(identityLabel: string, passphrase: string, bundle: string, nowMs: number) {
    return ImportedSet.parse(
      JSON.parse(this.raw.import_set(identityLabel, passphrase, bundle, nowMs)),
    );
  }
  free() {
    this.raw.free();
  }
}

class WasmSessionHandle implements SessionHandle {
  constructor(private readonly raw: WasmSessionObject) {}
  async handleIncoming(bytes: Uint8Array) {
    return SessionEvent.array().parse(this.raw.handle_incoming(bytes));
  }
  async sendFrame(frame: Frame) {
    this.raw.send_frame(JSON.stringify(Frame.parse(frame)));
  }
  async takeOutgoing() {
    return this.raw.take_outgoing();
  }
  async state() {
    return SessionStateName.parse(this.raw.state());
  }
  async isPairing() {
    return this.raw.is_pairing();
  }
  async peer() {
    const json = this.raw.peer_json();
    return json === undefined ? undefined : Device.parse(JSON.parse(json));
  }
  async close(reason: string) {
    this.raw.close(reason);
  }
  free() {
    this.raw.free();
  }
}

export class WasmCoreClient implements CoreClient {
  readonly backend = 'wasm' as const;
  constructor(private readonly m: WasmModule) {}

  async coreVersion() {
    return this.m.core_version();
  }
  async evaluatePolicy(policies: Policy[], intent: TxIntent, ctx: PolicyContext) {
    const out = this.m.evaluate_policy(
      JSON.stringify(policies),
      JSON.stringify(intent),
      JSON.stringify(ctx),
    );
    return Decision.parse(JSON.parse(out));
  }
  async validateKeyGroup(group: KeyGroup) {
    return this.m.validate_key_group(JSON.stringify(group)) ?? null;
  }
  async canTransition(from: TxState, to: TxState) {
    return this.m.can_transition(JSON.stringify(from), JSON.stringify(to));
  }
  async schemaSql() {
    return this.m.schema_sql();
  }

  async createVault(passphrase: string, kdf?: KdfParams): Promise<VaultHandle> {
    const raw = kdf
      ? new this.m.WasmVault(passphrase, JSON.stringify(KdfParams.parse(kdf)))
      : new this.m.WasmVault(passphrase);
    return new WasmVaultHandle(raw);
  }
  async openVault(bytes: Uint8Array): Promise<VaultHandle> {
    return new WasmVaultHandle(this.m.WasmVault.open(bytes));
  }

  async newPairingCodeHex() {
    return Hex32.parse(this.m.pairing_new_code_hex());
  }
  async pairAsIssuer(identity: IdentityHandle, local: Device, offer: PairingOffer, nowMs: number) {
    return new WasmSessionHandle(
      this.m.WasmSession.pair_as_issuer(
        rawIdentity(identity),
        JSON.stringify(Device.parse(local)),
        JSON.stringify(PairingOffer.parse(offer)),
        nowMs,
      ),
    );
  }
  async pairAsScanner(identity: IdentityHandle, local: Device, offer: PairingOffer, nowMs: number) {
    return new WasmSessionHandle(
      this.m.WasmSession.pair_as_scanner(
        rawIdentity(identity),
        JSON.stringify(Device.parse(local)),
        JSON.stringify(PairingOffer.parse(offer)),
        nowMs,
      ),
    );
  }
  async connectInitiator(identity: IdentityHandle, local: Device, peer: Device, nowMs: number) {
    return new WasmSessionHandle(
      this.m.WasmSession.connect_initiator(
        rawIdentity(identity),
        JSON.stringify(Device.parse(local)),
        JSON.stringify(Device.parse(peer)),
        nowMs,
      ),
    );
  }
  async connectResponder(identity: IdentityHandle, local: Device, known: Device[], nowMs: number) {
    return new WasmSessionHandle(
      this.m.WasmSession.connect_responder(
        rawIdentity(identity),
        JSON.stringify(Device.parse(local)),
        JSON.stringify(Device.array().parse(known)),
        nowMs,
      ),
    );
  }
  async verifyCeremonyMessage(signed: SignedCeremonyMessage, publicHex: string) {
    return this.m.verify_ceremony_message(
      JSON.stringify(SignedCeremonyMessage.parse(signed)),
      publicHex,
    );
  }
}

// ---------------------------------------------------------------------------
// Tauri backend
// ---------------------------------------------------------------------------

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export class TauriCoreClient implements CoreClient {
  readonly backend = 'tauri' as const;
  constructor(private readonly invoke: Invoke) {}

  private unsupported(op: string): never {
    throw new CoreUnsupportedError(this.backend, op);
  }

  async coreVersion() {
    return this.invoke<string>('core_version');
  }
  async evaluatePolicy(policies: Policy[], intent: TxIntent, ctx: PolicyContext) {
    return Decision.parse(await this.invoke('evaluate_policy', { policies, intent, ctx }));
  }
  async validateKeyGroup(group: KeyGroup) {
    return (await this.invoke<string | null>('validate_key_group', { group })) ?? null;
  }
  async canTransition(from: TxState, to: TxState) {
    return this.invoke<boolean>('can_transition', { from, to });
  }
  async schemaSql() {
    return this.invoke<string>('schema_sql');
  }

  // The desktop shell keeps its vault natively (OS keychain unlock lands with
  // desktop packaging); until those commands exist the calls fail closed.
  async createVault(): Promise<VaultHandle> {
    this.unsupported('createVault');
  }
  async openVault(): Promise<VaultHandle> {
    this.unsupported('openVault');
  }
  async newPairingCodeHex(): Promise<Hex32> {
    this.unsupported('newPairingCodeHex');
  }
  async pairAsIssuer(): Promise<SessionHandle> {
    this.unsupported('pairAsIssuer');
  }
  async pairAsScanner(): Promise<SessionHandle> {
    this.unsupported('pairAsScanner');
  }
  async connectInitiator(): Promise<SessionHandle> {
    this.unsupported('connectInitiator');
  }
  async connectResponder(): Promise<SessionHandle> {
    this.unsupported('connectResponder');
  }
  async verifyCeremonyMessage(): Promise<boolean> {
    this.unsupported('verifyCeremonyMessage');
  }
}

// ---------------------------------------------------------------------------
// Fallback
// ---------------------------------------------------------------------------

/** Returned when neither backend can be loaded. Every call fails closed. */
export class UnavailableCoreClient implements CoreClient {
  readonly backend = 'unavailable' as const;
  constructor(readonly reason: string) {}

  private fail(): never {
    throw new Error(`core unavailable: ${this.reason}`);
  }
  async coreVersion(): Promise<string> {
    this.fail();
  }
  async evaluatePolicy(): Promise<Decision> {
    this.fail();
  }
  async validateKeyGroup(): Promise<string | null> {
    this.fail();
  }
  async canTransition(): Promise<boolean> {
    this.fail();
  }
  async schemaSql(): Promise<string> {
    this.fail();
  }
  async createVault(): Promise<VaultHandle> {
    this.fail();
  }
  async openVault(): Promise<VaultHandle> {
    this.fail();
  }
  async newPairingCodeHex(): Promise<Hex32> {
    this.fail();
  }
  async pairAsIssuer(): Promise<SessionHandle> {
    this.fail();
  }
  async pairAsScanner(): Promise<SessionHandle> {
    this.fail();
  }
  async connectInitiator(): Promise<SessionHandle> {
    this.fail();
  }
  async connectResponder(): Promise<SessionHandle> {
    this.fail();
  }
  async verifyCeremonyMessage(): Promise<boolean> {
    this.fail();
  }
}

function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

export interface CreateCoreClientOptions {
  /**
   * URL of the wasm-pack glue (`stackwallet_wasm.js`). Defaults to `wasm/`
   * next to the document, which is where the web build copies it.
   */
  wasmUrl?: string;
}

function defaultWasmUrl(): string {
  if (typeof document !== 'undefined' && document.baseURI) {
    return new URL('wasm/stackwallet_wasm.js', document.baseURI).href;
  }
  return '/wasm/stackwallet_wasm.js';
}

export async function createCoreClient(opts: CreateCoreClientOptions = {}): Promise<CoreClient> {
  if (isTauri()) {
    const { invoke } = await import('@tauri-apps/api/core');
    return new TauriCoreClient(invoke as Invoke);
  }
  const url = opts.wasmUrl ?? defaultWasmUrl();
  try {
    // The wasm bundle is produced by `pnpm --filter @stackwallet/web build:wasm`
    // and served as a static asset; it is not part of the Vite module graph.
    const m = (await import(/* @vite-ignore */ url)) as WasmModule;
    if (typeof m.default === 'function') await m.default();
    return new WasmCoreClient(m);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const missing = /fetch dynamically imported module|Failed to fetch|404/i.test(message);
    if (missing) console.warn(`[stackwallet] wasm core not found at ${url}: ${message}`);
    return new UnavailableCoreClient(missing ? 'wasm core not bundled' : message);
  }
}
