/**
 * Zod mirrors of the Rust core's serde types. Field names and tags match the
 * `#[serde(rename_all = "camelCase")]` / `tag = ...` attributes exactly; a
 * mismatch here is a bug on one side or the other, never a feature.
 */
import { z } from 'zod';

export const ChainFamily = z.enum([
  'evm',
  'bitcoin',
  'solana',
  'cosmos',
  'tron',
  'substrate',
  'sui',
  'aptos',
  'stellar',
  'near',
  'ton',
  'xrpl',
  'cardano',
  'algorand',
  'tezos',
  'multiversx',
  'antelope',
  'hyperliquid',
  'stacks',
  'vechain',
  'starknet',
  'icp',
  'waves',
  'neo',
  'ergo',
  'icon',
  'alephium',
  'chia',
  'everscale',
  'radix',
  'aeternity',
  'fuel',
  'aelf',
  'starcoin',
  'obyte',
  'chromia',
  'keeta',
  'btcfork',
  'gala',
  'mixin',
  'qubic',
  'aleo',
  'canton',
  'namada',
]);
export type ChainFamily = z.infer<typeof ChainFamily>;

/** CAIP-2: `namespace:reference`. */
export const ChainId = z
  .string()
  .regex(/^[a-z0-9-]{3,8}:[A-Za-z0-9_-]{1,32}$/, 'chain id must be CAIP-2');
export type ChainId = z.infer<typeof ChainId>;

export function chainFamilyOf(chainId: ChainId): ChainFamily | undefined {
  const ns = chainId.split(':')[0];
  switch (ns) {
    case 'eip155':
      return 'evm';
    case 'bip122':
      return 'bitcoin';
    case 'solana':
      return 'solana';
    case 'cosmos':
      return 'cosmos';
    case 'tron':
      return 'tron';
    case 'algorand':
      return 'algorand';
    case 'antelope':
      return 'antelope';
    case 'aptos':
    case 'movement':
    case 'supra':
      return 'aptos';
    case 'cip34':
      return 'cardano';
    case 'hype':
      return 'hyperliquid';
    case 'mvx':
      return 'multiversx';
    case 'near':
      return 'near';
    case 'polkadot':
      return 'substrate';
    case 'stacks':
      return 'stacks';
    case 'stellar':
      return 'stellar';
    case 'sui':
    case 'iota':
      return 'sui';
    case 'tezos':
      return 'tezos';
    case 'tvm':
      return 'ton';
    case 'vechain':
      return 'vechain';
    case 'starknet':
      return 'starknet';
    case 'icp':
      return 'icp';
    case 'waves':
      return 'waves';
    case 'neo3':
      return 'neo';
    case 'ergo':
      return 'ergo';
    case 'obyte':
      return 'obyte';
    case 'chromia':
      return 'chromia';
    case 'keeta':
      return 'keeta';
    case 'icon':
      return 'icon';
    case 'alph':
    case 'alephium':
      return 'alephium';
    case 'chia':
      return 'chia';
    case 'ever':
    case 'venom':
      return 'everscale';
    case 'radix':
      return 'radix';
    case 'aet':
      return 'aeternity';
    case 'fuel':
      return 'fuel';
    case 'aelf':
      return 'aelf';
    case 'starcoin':
      return 'starcoin';
    case 'obyte':
      return 'obyte';
    case 'chromia':
      return 'chromia';
    case 'keeta':
      return 'keeta';
    case 'chromia':
      return 'chromia';
    case 'keeta':
      return 'keeta';
    case 'keeta':
      return 'keeta';
    case 'btcfork':
      return 'btcfork';
    case 'gala':
      return 'gala';
    case 'mixin':
      return 'mixin';
    case 'qubic':
      return 'qubic';
    case 'aleo':
      return 'aleo';
    case 'canton':
      return 'canton';
    case 'namada':
      return 'namada';
    case 'xrpl':
      return 'xrpl';
    default:
      return undefined;
  }
}

export const AssetRef = z.string().min(1);
export type AssetRef = z.infer<typeof AssetRef>;

export const Curve = z.enum(['secp256k1', 'ed25519', 'secp256k1-tr']);
export type Curve = z.infer<typeof Curve>;

export const PublicKey = z.object({ curve: Curve, hex: z.string().regex(/^[0-9a-f]+$/) });
export type PublicKey = z.infer<typeof PublicKey>;

export const PartyRole = z.enum(['human', 'agent', 'automation']);
export type PartyRole = z.infer<typeof PartyRole>;

export const PartyRef = z.object({ deviceId: z.string(), role: PartyRole });
export type PartyRef = z.infer<typeof PartyRef>;

export const KeyGroup = z.object({
  id: z.string(),
  threshold: z.number().int().min(1).max(255),
  parties: z.array(PartyRef),
  curves: z.array(Curve),
  publicKeys: z.array(PublicKey).default([]),
});
export type KeyGroup = z.infer<typeof KeyGroup>;

/** Base-unit amount as a decimal string. */
export const Amount = z.string().regex(/^[0-9]+$/);
export type Amount = z.infer<typeof Amount>;

export const Proposer = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('human'), deviceId: z.string() }),
  z.object({
    kind: z.literal('agent'),
    sessionId: z.string(),
    grantId: z.string(),
    rationale: z.string(),
  }),
  z.object({ kind: z.literal('automation'), automationId: z.string(), runId: z.string() }),
]);
export type Proposer = z.infer<typeof Proposer>;

const intentBase = {
  id: z.string(),
  walletId: z.string(),
  accountId: z.string(),
  chainId: ChainId,
  proposer: Proposer,
  usdMicros: z.number().int().nonnegative().nullable().optional(),
  untrustedDestinations: z.array(z.string()).default([]),
  createdAtMs: z.number().int(),
};

export const TxIntent = z.discriminatedUnion('kind', [
  z.object({
    ...intentBase,
    kind: z.literal('transfer'),
    to: z.string(),
    asset: AssetRef,
    amount: Amount,
  }),
  z.object({
    ...intentBase,
    kind: z.literal('contractCall'),
    to: z.string(),
    dataHex: z.string(),
    value: Amount,
  }),
  z.object({
    ...intentBase,
    kind: z.literal('swap'),
    sell: AssetRef,
    sellAmount: Amount,
    buy: AssetRef,
    minBuyAmount: Amount,
    maxSlippageBps: z.number().int().nonnegative(),
    aggregator: z.string(),
  }),
  z.object({
    ...intentBase,
    kind: z.literal('stake'),
    validator: z.string(),
    asset: AssetRef,
    amount: Amount,
  }),
  z.object({
    ...intentBase,
    kind: z.literal('unstake'),
    validator: z.string(),
    asset: AssetRef,
    amount: Amount,
  }),
  z.object({ ...intentBase, kind: z.literal('claim'), validator: z.string().nullable() }),
  z.object({
    ...intentBase,
    kind: z.literal('ibcTransfer'),
    to: z.string(),
    asset: AssetRef,
    amount: Amount,
    channel: z.string(),
    destChain: ChainId,
  }),
  z.object({ ...intentBase, kind: z.literal('psbt'), psbtBase64: z.string() }),
]);
export type TxIntent = z.infer<typeof TxIntent>;

export const SignRequest = z.object({
  id: z.string(),
  txId: z.string(),
  keyGroupId: z.string(),
  curve: Curve,
  payloadHashHex: z.string().regex(/^[0-9a-f]{64}$/),
  payloadHex: z.string().regex(/^[0-9a-f]*$/),
});
export type SignRequest = z.infer<typeof SignRequest>;

export const Signature = z.object({
  signRequestId: z.string(),
  curve: Curve,
  signatureHex: z.string(),
  recoveryId: z.number().int().min(0).max(3).nullable().optional(),
});
export type Signature = z.infer<typeof Signature>;

export const Window = z.enum(['tx', '1h', '24h', '7d', '30d']);
export type Window = z.infer<typeof Window>;

export const Rule = z.discriminatedUnion('rule', [
  z.object({
    rule: z.literal('spendCap'),
    window: Window,
    usdMicros: z.number().int().nonnegative(),
  }),
  z.object({ rule: z.literal('destinationAllow'), addresses: z.array(z.string()) }),
  z.object({ rule: z.literal('destinationDeny'), addresses: z.array(z.string()) }),
  z.object({ rule: z.literal('chainAllow'), chainIds: z.array(ChainId) }),
  z.object({ rule: z.literal('assetAllow'), assets: z.array(AssetRef) }),
  z.object({ rule: z.literal('maxSlippageBps'), bps: z.number().int().nonnegative() }),
  z.object({ rule: z.literal('requireSimulationPass') }),
  z.object({
    rule: z.literal('requireApprovers'),
    deviceIds: z.array(z.string()),
    atLeast: z.number().int().min(1),
  }),
  z.object({ rule: z.literal('cooldown'), seconds: z.number().int().nonnegative() }),
  z.object({ rule: z.literal('maxPendingProposals'), count: z.number().int().nonnegative() }),
  z.object({ rule: z.literal('refuseUntrustedDestinations') }),
]);
export type Rule = z.infer<typeof Rule>;

export const PolicyMode = z.enum(['enforce', 'audit']);
export type PolicyMode = z.infer<typeof PolicyMode>;

export const Policy = z.object({
  id: z.string(),
  name: z.string(),
  mode: PolicyMode,
  rules: z.array(Rule),
});
export type Policy = z.infer<typeof Policy>;

export const PolicyContext = z.object({
  nowMs: z.number().int(),
  spentUsdMicros: z.partialRecord(Window, z.number().int().nonnegative()).default({}),
  pendingProposals: z.number().int().nonnegative().default(0),
  lastTxAtMs: z.number().int().nullable().optional(),
  simulationOk: z.boolean().nullable().optional(),
  keyGroup: KeyGroup.nullable().optional(),
});
export type PolicyContext = z.infer<typeof PolicyContext>;

export const ApproverRequirement = z.object({
  deviceIds: z.array(z.string()),
  atLeast: z.number().int().min(1),
});

export const Decision = z.discriminatedUnion('decision', [
  z.object({
    decision: z.literal('allow'),
    requiredApprovers: z.array(ApproverRequirement),
    auditNotes: z.array(z.string()),
  }),
  z.object({
    decision: z.literal('deny'),
    reasons: z.array(z.string()),
    auditNotes: z.array(z.string()),
  }),
]);
export type Decision = z.infer<typeof Decision>;

export const TxState = z.enum([
  'draft',
  'simulated',
  'evaluated',
  'denied',
  'awaiting',
  'signing',
  'signed',
  'broadcast',
  'pending',
  'confirmed',
  'replaced',
  'dropped',
  'expired',
  'rejected',
  'failed',
]);
export type TxState = z.infer<typeof TxState>;

export const WalletKind = z.enum(['tss', 'single', 'watch', 'hardware']);
export type WalletKind = z.infer<typeof WalletKind>;

export const Folder = z.object({
  id: z.string(),
  parentId: z.string().nullable(),
  name: z.string(),
  color: z.string().nullable().optional(),
  tags: z.array(z.string()).default([]),
  defaultPolicyIds: z.array(z.string()).default([]),
  createdAtMs: z.number().int(),
  updatedAtMs: z.number().int(),
});
export type Folder = z.infer<typeof Folder>;

export const Wallet = z.object({
  id: z.string(),
  folderId: z.string(),
  name: z.string(),
  kind: WalletKind,
  keyGroupId: z.string().nullable(),
  tags: z.array(z.string().max(24)).max(8).default([]),
  notes: z.string().nullable().optional(),
  createdAtMs: z.number().int(),
  updatedAtMs: z.number().int(),
});
export type Wallet = z.infer<typeof Wallet>;

export const Account = z.object({
  id: z.string(),
  walletId: z.string(),
  family: ChainFamily,
  chainId: ChainId,
  address: z.string(),
  derivationPath: z.string().nullable().optional(),
  publicKeyHex: z.string(),
  label: z.string().nullable().optional(),
  hidden: z.boolean().default(false),
});
export type Account = z.infer<typeof Account>;

// ---------------------------------------------------------------------------
// Devices and transport (core `store::Device`, `transport::*`)
// ---------------------------------------------------------------------------

/** 32 bytes as lowercase hex: Ed25519 and X25519 public keys, one-time codes. */
export const Hex32 = z.string().regex(/^[0-9a-f]{64}$/, 'expected 32 hex-encoded bytes');
export type Hex32 = z.infer<typeof Hex32>;

/** First 16 bytes of SHA-256(identity key) as hex; see `identity::device_id_for_public_key`. */
export const DeviceId = z.string().regex(/^[0-9a-f]{32}$/, 'expected a 16-byte hex device id');
export type DeviceId = z.infer<typeof DeviceId>;

export const DeviceKind = z.enum(['desktop', 'browser', 'cli', 'mobile']);
export type DeviceKind = z.infer<typeof DeviceKind>;

export const MAX_DEVICE_NAME_BYTES = 64;
export const MAX_ENDPOINTS = 16;
export const MAX_ENDPOINT_LENGTH = 256;

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

/** The core checks byte length, not code units, so a name full of multi-byte glyphs must fail here too. */
export const DeviceName = z
  .string()
  .refine((s) => s.trim().length > 0, 'device name must not be blank')
  .refine((s) => utf8Length(s) <= MAX_DEVICE_NAME_BYTES, 'device name must be 1-64 bytes');

export const EndpointText = z.string().max(MAX_ENDPOINT_LENGTH);
export const Endpoints = z.array(EndpointText).max(MAX_ENDPOINTS);

/** A paired peer as the core stores it. Both keys are learned once at pairing. */
export const Device = z.object({
  id: DeviceId,
  name: DeviceName,
  kind: DeviceKind,
  identityPubHex: Hex32,
  noiseStaticHex: z.string().default(''),
  endpoints: Endpoints.default([]),
  pairedAtMs: z.number().int(),
  lastSeenAtMs: z.number().int().nullable(),
  revokedAtMs: z.number().int().nullable(),
});
export type Device = z.infer<typeof Device>;

/** Mirrors `transport::Endpoint` (`#[serde(tag = "kind")]`). */
export const Endpoint = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('tcp'), addr: z.string().min(1) }),
  z.object({ kind: z.literal('webRtc'), viaDeviceId: DeviceId }),
]);
export type Endpoint = z.infer<typeof Endpoint>;

/** `tcp://host:port` or `webrtc-via://<deviceId>`; anything else is not an endpoint. */
export function parseEndpoint(text: string): Endpoint | undefined {
  if (text.startsWith('tcp://')) {
    const addr = text.slice('tcp://'.length);
    return addr === '' ? undefined : { kind: 'tcp', addr };
  }
  if (text.startsWith('webrtc-via://')) {
    const via = DeviceId.safeParse(text.slice('webrtc-via://'.length));
    return via.success ? { kind: 'webRtc', viaDeviceId: via.data } : undefined;
  }
  return undefined;
}

export function formatEndpoint(endpoint: Endpoint): string {
  return endpoint.kind === 'tcp'
    ? `tcp://${endpoint.addr}`
    : `webrtc-via://${endpoint.viaDeviceId}`;
}

export const TRANSPORT_VERSION = 1 as const;
export const PAIRING_OFFER_PREFIX = 'stackwallet-pair:';

/** Contents of the pairing QR (`transport::pairing::PairingOffer`). */
export const PairingOffer = z.object({
  version: z.literal(TRANSPORT_VERSION),
  deviceId: DeviceId,
  deviceName: DeviceName,
  kind: DeviceKind,
  identityPubHex: Hex32,
  noiseStaticHex: Hex32,
  endpoints: Endpoints,
  oneTimeCodeHex: Hex32,
  expiresAtMs: z.number().int(),
});
export type PairingOffer = z.infer<typeof PairingOffer>;

export type PairingOfferErrorCode = 'prefix' | 'base64' | 'json' | 'version' | 'shape' | 'deviceId';

export class PairingOfferError extends Error {
  override readonly name = 'PairingOfferError';
  constructor(
    readonly code: PairingOfferErrorCode,
    message: string,
  ) {
    super(message);
  }
}

function base64UrlDecode(body: string): Uint8Array | undefined {
  // The core emits and accepts only unpadded base64url; stay strict here so a
  // code that previews as valid cannot fail in the core afterwards.
  if (!/^[A-Za-z0-9_-]*$/.test(body) || body.includes('=')) return undefined;
  const unpadded = body;
  const padded = unpadded
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(unpadded.length / 4) * 4, '=');
  try {
    const bin = atob(padded);
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return undefined;
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Shape-level decode of a pasted or scanned `stackwallet-pair:` string. The
 * core repeats every check (and adds the ones that need key material, such as
 * the device id derivation) before a handshake starts; this exists so the UI
 * can preview an offer and explain a bad paste without the wasm bridge.
 */
export function decodePairingOffer(text: string): PairingOffer {
  const trimmed = text.trim();
  if (!trimmed.startsWith(PAIRING_OFFER_PREFIX)) {
    throw new PairingOfferError('prefix', `missing ${PAIRING_OFFER_PREFIX} prefix`);
  }
  const bytes = base64UrlDecode(trimmed.slice(PAIRING_OFFER_PREFIX.length));
  if (!bytes) throw new PairingOfferError('base64', 'not base64url');
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new PairingOfferError('json', 'malformed');
  }
  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    'version' in parsed &&
    parsed.version !== TRANSPORT_VERSION
  ) {
    throw new PairingOfferError('version', 'unsupported version');
  }
  const result = PairingOffer.safeParse(parsed);
  if (!result.success) {
    const first = result.error.issues[0];
    const where = first?.path.map(String).join('.') ?? '';
    throw new PairingOfferError('shape', where ? `${where}: ${first?.message}` : 'malformed');
  }
  return result.data;
}

export function encodePairingOffer(offer: PairingOffer): string {
  const json = JSON.stringify(PairingOffer.parse(offer));
  return `${PAIRING_OFFER_PREFIX}${base64UrlEncode(new TextEncoder().encode(json))}`;
}

export function isPairingOfferExpired(offer: Pick<PairingOffer, 'expiresAtMs'>, nowMs: number) {
  return nowMs >= offer.expiresAtMs;
}

/**
 * Same derivation as the core (`identity::device_id_from_public_hex`): hex of
 * the first 16 bytes of SHA-256 over the raw key. Async because the browser
 * only exposes SHA-256 through SubtleCrypto. Does not check that the bytes
 * are a valid Ed25519 point; only the core can.
 */
export async function deviceIdFromPublicHex(publicHex: string): Promise<DeviceId> {
  const hex = Hex32.parse(publicHex);
  const key = Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', key));
  return Array.from(digest.subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Checks the one thing `decodePairingOffer` cannot do synchronously. */
export async function pairingOfferIdMatches(offer: PairingOffer): Promise<boolean> {
  return (await deviceIdFromPublicHex(offer.identityPubHex)) === offer.deviceId;
}

/** One ceremony's frame of reference (`tss::CeremonySession`). */
export const CeremonySession = z.object({
  id: z.string().min(1).max(128),
  kind: z.enum(['keyGen', 'refresh', 'reshare', 'sign']),
  keyGroupId: z.string(),
  curve: Curve,
  payloadHashHex: z.string().nullable(),
  participants: z.array(z.string()).min(1).max(16),
  state: z.enum(['proposed', 'collecting', 'rounds', 'complete', 'aborted']),
  createdAtMs: z.number().int(),
  expiresAtMs: z.number().int(),
});
export type CeremonySession = z.infer<typeof CeremonySession>;

/** What a proposer sends before round 1 (`threshold::Proposal`). */
export const ThresholdProposal = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('keyGen'), group: z.lazy(() => KeyGroup), session: CeremonySession }),
  z.object({
    kind: z.literal('sign'),
    request: z.lazy(() => SignRequest),
    session: CeremonySession,
  }),
]);
export type ThresholdProposal = z.infer<typeof ThresholdProposal>;

/** A threshold wallet this vault holds one share of (`threshold::ThresholdAccount`). */
export const ThresholdAccount = z.object({
  walletId: z.string(),
  group: z.lazy(() => KeyGroup),
  deviceId: z.string(),
  publicKeyHex: z.string().regex(/^[0-9a-f]{64}$/),
  solanaAddress: z.string(),
});
export type ThresholdAccount = z.infer<typeof ThresholdAccount>;

/** A co-signer's view of what it is asked to sign, decoded by its own core. */
export const CosignSummary = z.object({
  walletId: z.string(),
  chainId: z.string(),
  from: z.string(),
  to: z.string(),
  lamports: z.string(),
  decision: z.lazy(() => Decision),
});
export type CosignSummary = z.infer<typeof CosignSummary>;

/** The ceremony envelope the transport carries (`tss::CeremonyMessage`). */
export const CeremonyMessage = z.object({
  sessionId: z.string(),
  // Empty only on the round-0 proposal, which carries session parameters
  // instead of a payload binding; protocol rounds always carry the hash.
  payloadHashHex: z.string().regex(/^([0-9a-f]{64})?$/),
  fromDeviceId: z.string(),
  toDeviceId: z.string().nullable(),
  round: z.number().int().min(0).max(255),
  bodyHex: z.string().regex(/^[0-9a-f]*$/),
});
export type CeremonyMessage = z.infer<typeof CeremonyMessage>;

export const SignedCeremonyMessage = z.object({
  msg: CeremonyMessage,
  signatureHex: z.string().regex(/^[0-9a-f]{128}$/),
});
export type SignedCeremonyMessage = z.infer<typeof SignedCeremonyMessage>;

/** First frame after the handshake; `transport::frame::Hello`. */
export const Hello = z.object({
  deviceId: DeviceId,
  deviceName: DeviceName,
  kind: DeviceKind,
  identityPubHex: Hex32,
  handshakeSigHex: z.string().regex(/^[0-9a-f]{128}$/),
  endpoints: Endpoints.default([]),
});
export type Hello = z.infer<typeof Hello>;

/**
 * `transport::frame::Frame` with `#[serde(tag = "type")]`: newtype variants
 * (`hello`, `ceremony`) flatten their struct into the tagged object.
 */
export const Frame = z.discriminatedUnion('type', [
  Hello.extend({ type: z.literal('hello') }),
  SignedCeremonyMessage.extend({ type: z.literal('ceremony') }),
  z.object({
    type: z.literal('signal'),
    toDeviceId: z.string(),
    fromDeviceId: z.string(),
    sdpOrIceJson: z.string(),
  }),
  z.object({ type: z.literal('ping'), nonce: z.number().int().nonnegative() }),
  z.object({ type: z.literal('pong'), nonce: z.number().int().nonnegative() }),
  z.object({ type: z.literal('bye'), reason: z.string() }),
]);
export type Frame = z.infer<typeof Frame>;

export const SessionStateName = z.enum(['handshaking', 'awaitingHello', 'open', 'closed']);
export type SessionStateName = z.infer<typeof SessionStateName>;

/**
 * What `WasmSession.handle_incoming` yields, one object per `SessionEvent`.
 * A `relayed` envelope was forwarded by the peer on another device's behalf;
 * the channel vouches for the relay only, so the caller must verify `signed`
 * against its own pinned record for `msg.fromDeviceId` before using it.
 */
export const SessionEvent = z.discriminatedUnion('type', [
  z.object({ type: z.literal('opened'), peer: Device }),
  z.object({ type: z.literal('paired'), peer: Device }),
  z.object({ type: z.literal('frame'), frame: Frame }),
  z.object({ type: z.literal('relayed'), signed: SignedCeremonyMessage }),
  z.object({ type: z.literal('closed'), reason: z.string() }),
]);
export type SessionEvent = z.infer<typeof SessionEvent>;

// ---------------------------------------------------------------------------
// Provenance and directory-set transfer (core `provenance`, `transfer`)
// ---------------------------------------------------------------------------

export const Origin = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('created'), atMs: z.number().int() }),
  z.object({ kind: z.literal('importedPhrase'), atMs: z.number().int() }),
  z.object({
    kind: z.literal('importedFromDevice'),
    atMs: z.number().int(),
    deviceId: z.string(),
    deviceName: z.string(),
    bundleId: z.string(),
  }),
]);
export type Origin = z.infer<typeof Origin>;

export const ExposureChannel = z.enum(['screen', 'clipboard', 'file']);
export type ExposureChannel = z.infer<typeof ExposureChannel>;

export const Revealed = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('mnemonic') }),
  z.object({ kind: z.literal('privateKey'), curve: Curve, path: z.string() }),
]);
export type Revealed = z.infer<typeof Revealed>;

export const Exposure = z.object({
  atMs: z.number().int(),
  channel: ExposureChannel,
  what: Revealed,
});
export type Exposure = z.infer<typeof Exposure>;

export const Transfer = z.object({
  atMs: z.number().int(),
  toDeviceId: z.string(),
  bundleId: z.string(),
});
export type Transfer = z.infer<typeof Transfer>;

export const WalletProvenance = z.object({
  walletId: z.string(),
  origin: Origin,
  exposures: z.array(Exposure).default([]),
  transfers: z.array(Transfer).default([]),
});
export type WalletProvenance = z.infer<typeof WalletProvenance>;

export const SetProvenance = z.object({
  folderId: z.string(),
  origin: Origin,
  transfers: z.array(Transfer).default([]),
});
export type SetProvenance = z.infer<typeof SetProvenance>;

export const ProvenanceTable = z.object({
  wallets: z.array(WalletProvenance).default([]),
  sets: z.array(SetProvenance).default([]),
});
export type ProvenanceTable = z.infer<typeof ProvenanceTable>;

export const RevealedSecret = z.object({
  what: Revealed,
  secret: z.string().min(1),
  publicHex: z.string().nullable(),
});
export type RevealedSecret = z.infer<typeof RevealedSecret>;

export const ImportedSet = z.object({
  /** `set`: a whole directory. `wallet`: one wallet exported on its own. */
  scope: z.enum(['set', 'wallet']).default('set'),
  bundleId: z.string(),
  folderId: z.string(),
  fromDeviceId: z.string(),
  fromDeviceName: z.string(),
  exportedAtMs: z.number().int(),
  directory: z.unknown(),
  walletsWithKeys: z.array(z.string()),
});
export type ImportedSet = z.infer<typeof ImportedSet>;

// ---------------------------------------------------------------------------
// Session factors and the export gate (core `vault` slots, `export_gate`)
// ---------------------------------------------------------------------------

/** Device-local ways to open the session besides the passphrase. Never exported. */
export const SlotKind = z.enum(['pin', 'passkey']);
export type SlotKind = z.infer<typeof SlotKind>;

export const SlotInfo = z.object({
  id: z.string().regex(/^[0-9a-f]{16}$/),
  kind: SlotKind,
  label: z.string().max(80),
  saltHex: z.string().regex(/^[0-9a-f]{32}$/),
  credentialId: z
    .string()
    .regex(/^[A-Za-z0-9_-]{1,1024}$/)
    .nullable(),
  createdAtMs: z.number().int(),
});
export type SlotInfo = z.infer<typeof SlotInfo>;

/**
 * Proof the person at this device can open the session now. The passphrase,
 * or a slot: PIN digits plus the device secret, or a passkey's PRF output.
 */
export type SessionProof =
  | { kind: 'passphrase'; passphrase: string }
  | { kind: 'slot'; slotId: string; secret: Uint8Array; device?: Uint8Array };

export const MessageKind = z.enum(['personal', 'typedData']);
export type MessageKind = z.infer<typeof MessageKind>;

export const SignedMessage = z.object({
  address: z.string(),
  digestHex: z.string().regex(/^0x[0-9a-f]{64}$/),
  signatureHex: z.string().regex(/^0x[0-9a-f]{130}$/),
});
export type SignedMessage = z.infer<typeof SignedMessage>;

export const ExportKeyScope = z.enum(['folder', 'wallet']);
export type ExportKeyScope = z.infer<typeof ExportKeyScope>;

export const ExportKeyRef = z.object({ scope: ExportKeyScope, id: z.string().max(128) });
export type ExportKeyRef = z.infer<typeof ExportKeyRef>;

/** What every export presents: session, the directory's key, and for one wallet its key. */
export interface ExportGateInput {
  session: SessionProof;
  folderId: string;
  folderKey: string;
  walletKey?: string;
}

// ---------------------------------------------------------------------------
// Transaction ledger (core `evm`, `ledger`, `audit`)
// ---------------------------------------------------------------------------

/** Unsigned EIP-1559 transaction the adapter proposes; amounts in wei as decimals. */
export const EvmTx = z.object({
  chainId: z.number().int().positive(),
  nonce: z.number().int().nonnegative(),
  maxPriorityFeePerGas: Amount,
  maxFeePerGas: Amount,
  gasLimit: z.number().int().positive(),
  to: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  value: Amount,
  dataHex: z
    .string()
    .regex(/^(0x)?[0-9a-fA-F]*$/)
    .default(''),
});
export type EvmTx = z.infer<typeof EvmTx>;

export const SolanaTx = z.strictObject({
  chainId: z.literal('solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'),
  from: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/),
  to: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/),
  lamports: Amount,
  recentBlockhash: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/),
  lastValidBlockHeight: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  messageVersion: z.enum(['legacy', 'v0']).optional(),
});
export type SolanaTx = z.infer<typeof SolanaTx>;
export const CosmosMsg = z.enum(['send', 'delegate', 'undelegate', 'withdrawRewards']);
export type CosmosMsg = z.infer<typeof CosmosMsg>;
export const CosmosTx = z.strictObject({
  /** Absent means a bank send; staking messages name a validator operator in `to`. */
  msg: CosmosMsg.optional(),
  chainId: z.literal('cosmos:osmo-test-5'),
  from: z.string().max(90),
  to: z.string().max(90),
  amount: Amount,
  publicKeyHex: z.string().regex(/^(02|03)[0-9a-f]{64}$/),
  accountNumber: Amount,
  sequence: Amount,
  gasLimit: z.number().int().positive().max(1_000_000),
  feeAmount: Amount,
  timeoutHeight: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type CosmosTx = z.infer<typeof CosmosTx>;
export const BitcoinTx = z.strictObject({
  chainId: z.literal('bip122:00000008819873e925422c1ff0f99f7c'),
  from: z.string().max(90),
  to: z.string().max(90),
  amount: Amount,
  fee: Amount,
  inputs: z
    .array(
      z.strictObject({
        txid: z.string().regex(/^[0-9a-f]{64}$/),
        vout: z.number().int().nonnegative().max(0xffffffff),
        previousTxHex: z
          .string()
          .max(400000)
          .regex(/^(?:[0-9a-f]{2})+$/),
      }),
    )
    .min(1)
    .max(8),
});
export type BitcoinTx = z.infer<typeof BitcoinTx>;
const TronAddress = z.string().regex(/^T[1-9A-HJ-NP-Za-km-z]{33}$/);
export const TronTx = z.strictObject({
  chainId: z.literal('tron:0xcd8690dc'),
  from: TronAddress,
  to: TronAddress,
  sun: Amount,
  refBlockBytes: z.string().regex(/^[0-9a-f]{4}$/),
  refBlockHash: z.string().regex(/^[0-9a-f]{16}$/),
  expiration: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type TronTx = z.infer<typeof TronTx>;
const SubstrateAddress = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{40,50}$/);
const SubstrateU32 = z.number().int().nonnegative().max(0xffffffff);
const SubstrateHash = z.string().regex(/^0x[0-9a-f]{64}$/);
export const SubstrateTx = z.strictObject({
  chainId: z.enum([
    'polkadot:e143f23803ac50e8f6f8e62695d1ce9e',
    'polkadot:67f9723393ef76214df0118c34bbbd3d',
  ]),
  from: SubstrateAddress,
  to: SubstrateAddress,
  planck: z.string().regex(/^(0|[1-9][0-9]{0,38})$/),
  tip: z.string().regex(/^(0|[1-9][0-9]{0,38})$/),
  nonce: SubstrateU32,
  specVersion: SubstrateU32.min(1),
  transactionVersion: SubstrateU32,
  genesisHash: SubstrateHash,
  blockHash: SubstrateHash,
  blockNumber: SubstrateU32,
  eraPeriod: z.number().int().min(4).max(4096),
  metadataHashMode: z.literal(0),
});
export type SubstrateTx = z.infer<typeof SubstrateTx>;
const StellarAddress = z.string().regex(/^G[A-Z2-7]{55}$/);
export const StellarTx = z.strictObject({
  chainId: z.literal('stellar:testnet'),
  from: StellarAddress,
  to: StellarAddress,
  stroops: Amount,
  fee: z.number().int().min(100).max(10_000_000),
  seqNum: z.string().regex(/^[0-9]+$/),
  maxTime: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  builtAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  createAccount: z.boolean(),
});
export type StellarTx = z.infer<typeof StellarTx>;
const Hex32Address = z.string().regex(/^0x[0-9a-f]{64}$/);
export const AptosTx = z.strictObject({
  chainId: z.literal('aptos:2'),
  from: Hex32Address,
  to: Hex32Address,
  octas: Amount,
  sequenceNumber: z.string().regex(/^[0-9]+$/),
  maxGasAmount: z.number().int().min(1).max(20_000),
  gasUnitPrice: z.number().int().min(1).max(10_000),
  expirationTimestampSecs: z.number().int().positive().max(4_102_444_800),
});
export type AptosTx = z.infer<typeof AptosTx>;
const XrplAddress = z.string().regex(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
export const XrplTx = z.strictObject({
  chainId: z.literal('xrpl:1'),
  from: XrplAddress,
  to: XrplAddress,
  drops: Amount,
  fee: z.number().int().min(10).max(1_000_000),
  sequence: z.number().int().min(1).max(0xffff_ffff),
  lastLedgerSequence: z.number().int().min(2).max(0xffff_ffff),
  builtAtLedger: z.number().int().min(1).max(0xffff_ffff),
  destinationTag: z.number().int().min(0).max(0xffff_ffff).optional(),
  publicKeyHex: z.string().regex(/^(02|03)[0-9a-f]{64}$/),
});
export type XrplTx = z.infer<typeof XrplTx>;
export const SuiTx = z.strictObject({
  chainId: z.literal('sui:testnet'),
  from: Hex32Address,
  to: Hex32Address,
  mist: Amount,
  gasPayment: z
    .array(
      z.strictObject({
        objectId: Hex32Address,
        version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        digest: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/),
      }),
    )
    .min(1)
    .max(16),
  gasPrice: z.number().int().min(1).max(100_000),
  gasBudget: z.number().int().positive().max(1_000_000_000),
});
export type SuiTx = z.infer<typeof SuiTx>;
export const NearTx = z.strictObject({
  chainId: z.literal('near:testnet'),
  from: z.string().regex(/^[0-9a-f]{64}$/),
  to: z
    .string()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9._-]+$/),
  yocto: Amount,
  nonce: z.string().regex(/^[0-9]+$/),
  blockHash: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/),
  blockHeight: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type NearTx = z.infer<typeof NearTx>;
const AlgorandAddress = z.string().regex(/^[A-Z2-7]{58}$/);
const AlgorandRound = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
export const AlgorandTx = z.strictObject({
  chainId: z.literal('algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe'),
  from: AlgorandAddress,
  to: AlgorandAddress,
  microalgos: z.string().regex(/^[1-9][0-9]{0,16}$/),
  fee: z.number().int().min(1_000).max(1_000_000),
  firstValid: AlgorandRound,
  lastValid: AlgorandRound,
  genesisID: z.literal('testnet-v1.0'),
  genesisHash: z.literal('SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI='),
});
export type AlgorandTx = z.infer<typeof AlgorandTx>;
export const TonTx = z.strictObject({
  chainId: z.literal('tvm:-3'),
  from: z.string().regex(/^[A-Za-z0-9_-]{48}$/),
  to: z.string().min(48).max(66),
  nanoton: Amount,
  seqno: z.number().int().min(0).max(0xffff_ffff),
  validUntil: z.number().int().positive().max(0xffff_ffff),
  builtAt: z.number().int().positive().max(0xffff_ffff),
  bounce: z.boolean(),
  deploy: z.boolean(),
});
export type TonTx = z.infer<typeof TonTx>;
const CardanoLovelace = z.string().regex(/^[1-9][0-9]{0,16}$/);
const CardanoTestnetAddress = z.string().regex(/^addr_test1[02-9ac-hj-np-z]{50,110}$/);
export const CardanoInput = z.strictObject({
  txHash: z.string().regex(/^[0-9a-f]{64}$/),
  index: z.number().int().min(0).max(0xffffffff),
  lovelace: CardanoLovelace,
});
export type CardanoInput = z.infer<typeof CardanoInput>;
export const CardanoTx = z.strictObject({
  chainId: z.literal('cip34:0-1'),
  from: CardanoTestnetAddress,
  to: CardanoTestnetAddress,
  lovelace: CardanoLovelace,
  inputs: z.array(CardanoInput).min(1).max(40),
  fee: z.number().int().min(1).max(1_000_000),
  ttl: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  builtSlot: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  minFeeA: z.number().int().min(1).max(1_000),
  minFeeB: z.number().int().min(1).max(1_000_000),
  coinsPerUtxoByte: z.number().int().min(1).max(100_000),
});
export type CardanoTx = z.infer<typeof CardanoTx>;
const AntelopeName = z.string().regex(/^[.1-5a-z]{1,12}$/);
export const AntelopeTx = z.strictObject({
  chainId: z.literal('antelope:f16b1833c747c43682f4386fca9cbb32'),
  from: AntelopeName,
  permission: AntelopeName,
  to: AntelopeName,
  antelopeUnits: z.string().regex(/^[1-9][0-9]{0,18}$/),
  symbol: z.literal('WAX'),
  precision: z.literal(8),
  tokenContract: z.literal('eosio.token'),
  memo: z.string().max(256),
  expiration: z.number().int().min(1).max(0xffff_ffff),
  refBlockNum: z.number().int().min(0).max(0xffff),
  refBlockPrefix: z.number().int().min(0).max(0xffff_ffff),
  builtAtSecs: z.number().int().min(1).max(0xffff_ffff),
  publicKey: z.string().regex(/^PUB_K1_[1-9A-HJ-NP-Za-km-z]{48,52}$/),
});
export type AntelopeTx = z.infer<typeof AntelopeTx>;
export const MultiversxTx = z.strictObject({
  chainId: z.literal('mvx:D'),
  from: z.string().regex(/^erd1[02-9ac-hj-np-z]{58}$/),
  to: z.string().regex(/^erd1[02-9ac-hj-np-z]{58}$/),
  attoegld: z.string().regex(/^[1-9][0-9]{0,25}$/),
  nonce: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  gasPrice: z.number().int().min(1_000_000_000).max(100_000_000_000),
  gasLimit: z.number().int().min(50_000).max(1_000_000),
});
export type MultiversxTx = z.infer<typeof MultiversxTx>;
const TezosImplicit = z.string().regex(/^tz[1-4][1-9A-HJ-NP-Za-km-z]{33}$/);
const TezosFee = z.number().int().min(100).max(100_000);
export const TezosTx = z.strictObject({
  chainId: z.literal('tezos:NetXsqzbfFenSTS'),
  from: z.string().regex(/^tz1[1-9A-HJ-NP-Za-km-z]{33}$/),
  to: TezosImplicit,
  mutez: z.string().regex(/^[1-9][0-9]{0,18}$/),
  branch: z.string().regex(/^B[1-9A-HJ-NP-Za-km-z]{50}$/),
  counter: z.number().int().min(1).max(9_007_199_254_740_990),
  fee: TezosFee,
  gasLimit: z.number().int().min(1).max(100_000),
  storageLimit: z.number().int().min(0).max(1_000),
  reveal: z
    .strictObject({ fee: TezosFee, gasLimit: z.number().int().min(1).max(10_000) })
    .optional(),
});
export type TezosTx = z.infer<typeof TezosTx>;
export const StacksTx = z.strictObject({
  chainId: z.literal('stacks:2147483648'),
  from: z.string().max(64),
  to: z.string().max(64),
  microstx: z.string().regex(/^[1-9][0-9]{0,19}$/),
  fee: z.number().int().min(1).max(1_000_000),
  nonce: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
export type StacksTx = z.infer<typeof StacksTx>;
export const VechainTx = z.strictObject({
  chainId: z.literal('vechain:87721b09ed2e15997f466536b20bb127'),
  from: z.string().regex(/^0x[0-9a-f]{40}$/),
  to: z.string().regex(/^0x[0-9a-f]{40}$/),
  vetWei: z.string().regex(/^[1-9][0-9]{0,38}$/),
  blockRef: z.string().regex(/^[0-9a-f]{16}$/),
  expiration: z.number().int().min(1).max(720),
  gasPriceCoef: z.number().int().min(0).max(255),
  gas: z.number().int().min(21_000).max(100_000),
  nonce: z.string().regex(/^[0-9a-f]{16}$/),
});
export type VechainTx = z.infer<typeof VechainTx>;
export const HyperliquidTx = z.strictObject({
  chainId: z.literal('hype:testnet'),
  from: z.string().regex(/^0x[0-9a-f]{40}$/),
  to: z.string().regex(/^0x[0-9a-f]{40}$/),
  hlUsdMicro: z.string().regex(/^[1-9][0-9]{0,15}$/),
  time: z.number().int().min(1_672_531_200_000).max(Number.MAX_SAFE_INTEGER),
  builtAtMs: z.number().int().min(1_672_531_200_000).max(Number.MAX_SAFE_INTEGER),
});
export type HyperliquidTx = z.infer<typeof HyperliquidTx>;
const StarknetAddress = z.string().regex(/^0x[0-9a-f]{64}$/);
const StarknetU128 = z.string().regex(/^(0|[1-9][0-9]{0,38})$/);
export const StarknetTx = z.strictObject({
  chainId: z.literal('starknet:SN_SEPOLIA'),
  from: StarknetAddress,
  to: StarknetAddress,
  fri: z.string().regex(/^[1-9][0-9]{0,38}$/),
  nonce: z
    .number()
    .int()
    .min(1)
    .max(2 ** 53),
  deploy: z.boolean(),
  tip: StarknetU128,
  l1GasMaxAmount: z.number().int().nonnegative().max(1_000_000),
  l1GasMaxPrice: StarknetU128,
  l2GasMaxAmount: z.number().int().min(1).max(1_000_000_000),
  l2GasMaxPrice: z.string().regex(/^[1-9][0-9]{0,38}$/),
  l1DataGasMaxAmount: z.number().int().nonnegative().max(1_000_000),
  l1DataGasMaxPrice: StarknetU128,
});
export type StarknetTx = z.infer<typeof StarknetTx>;
const IconAddress = z.string().regex(/^hx[0-9a-f]{40}$/);
export const IconTx = z.strictObject({
  chainId: z.literal('icon:2'),
  from: IconAddress,
  to: IconAddress,
  loop: z.string().regex(/^[1-9][0-9]{0,26}$/),
  nonce: z.number().int().min(1).max(1_000_000),
  stepLimit: z.number().int().min(100_000).max(25_000_000),
  timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  builtAtMs: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type IconTx = z.infer<typeof IconTx>;
export const EverscaleTx = z.strictObject({
  chainId: z.literal('venom:1002'),
  from: z.string().regex(/^0:[0-9a-f]{64}$/),
  to: z.string().regex(/^0:[0-9a-f]{64}$/),
  evers: Amount,
  timeMs: z
    .number()
    .int()
    .positive()
    .max(2 ** 53 - 1),
  expireAt: z.number().int().positive().max(0xffff_ffff),
  builtAtMs: z.number().int().positive(),
  bounce: z.boolean(),
  deploy: z.boolean(),
});
export type EverscaleTx = z.infer<typeof EverscaleTx>;
export const WavesTx = z.strictObject({
  chainId: z.literal('waves:84'),
  from: z.string().regex(/^3[1-9A-HJ-NP-Za-km-z]{25,35}$/),
  to: z.string().regex(/^3[1-9A-HJ-NP-Za-km-z]{25,35}$/),
  wavelets: z.string().regex(/^[1-9][0-9]{0,18}$/),
  publicKeyHex: z.string().regex(/^[0-9a-f]{64}$/),
  timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  builtAtMs: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export type WavesTx = z.infer<typeof WavesTx>;
export const RadixTx = z.strictObject({
  chainId: z.literal('radix:stokenet'),
  from: z.string().regex(/^account_tdx_2_1[02-9ac-hj-np-z]{20,60}$/),
  to: z.string().regex(/^account_tdx_2_1[02-9ac-hj-np-z]{20,60}$/),
  attos: z.string().regex(/^[1-9][0-9]{0,28}$/),
  startEpochInclusive: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  endEpochExclusive: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  nonce: z.number().int().nonnegative().max(0xffffffff),
  tipPercentage: z.number().int().nonnegative().max(100),
});
export type RadixTx = z.infer<typeof RadixTx>;
export const IcpTx = z.strictObject({
  chainId: z.literal('icp:00000000000000000000'),
  from: z.string().regex(/^[0-9a-f]{64}$/),
  to: z.string().regex(/^[0-9a-f]{64}$/),
  e8s: z.string().regex(/^[1-9]\d{0,17}$/),
  memo: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  createdAtNanos: z.string().regex(/^(0|[1-9]\d{0,18})$/),
  ingressExpiryNanos: z.string().regex(/^(0|[1-9]\d{0,18})$/),
});
export type IcpTx = z.infer<typeof IcpTx>;
export const ErgoTx = z.strictObject({
  chainId: z.literal('ergo:testnet'),
  from: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{51,52}$/),
  to: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{51,52}$/),
  nanoerg: z.string().regex(/^[1-9]\d{0,18}$/),
  inputs: z
    .array(z.string().regex(/^[0-9a-f]{64}$/))
    .min(1)
    .max(16),
  change: z.string().regex(/^[1-9]\d{0,18}$/),
  fee: z.string().regex(/^[1-9]\d{0,7}$/),
  height: z.number().int().min(1).max(100_000_000),
});
export type ErgoTx = z.infer<typeof ErgoTx>;
export const AlephiumTx = z.strictObject({
  chainId: z.literal('alephium:1'),
  from: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{30,50}$/),
  publicKey: z.string().regex(/^0[23][0-9a-f]{64}$/),
  to: z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{30,50}$/),
  attoalph: z.string().regex(/^[1-9][0-9]{0,38}$/),
  change: z.string().regex(/^[1-9][0-9]{0,38}$/),
  inputs: z
    .array(
      z.strictObject({
        hint: z.number().int().min(-0x80000000).max(0x7fffffff),
        key: z.string().regex(/^[0-9a-f]{64}$/),
      }),
    )
    .min(1)
    .max(64),
  gasAmount: z.number().int().min(20_000).max(5_000_000),
  gasPrice: z.string().regex(/^[1-9][0-9]{10,17}$/),
});
export type AlephiumTx = z.infer<typeof AlephiumTx>;
const AeternityAddress = z.string().regex(/^ak_[1-9A-HJ-NP-Za-km-z]{40,60}$/);
export const AeternityTx = z.strictObject({
  chainId: z.literal('aet:ae_uat'),
  from: AeternityAddress,
  to: AeternityAddress,
  aettos: z.string().regex(/^[1-9][0-9]{0,29}$/),
  fee: z.string().regex(/^[1-9][0-9]{11,17}$/),
  ttl: z.number().int().nonnegative().max(0xffffffff),
  nonce: z.number().int().positive().max(0xffffffff),
});
export type AeternityTx = z.infer<typeof AeternityTx>;
export const ChiaTx = z.strictObject({
  chainId: z.literal('chia:37a90eb5'),
  from: z.string().regex(/^txch1[02-9ac-hj-np-z]+$/),
  to: z.string().regex(/^txch1[02-9ac-hj-np-z]+$/),
  mojos: z.string().regex(/^[1-9][0-9]{0,18}$/),
  fee: z.string().regex(/^(0|[1-9][0-9]{0,18})$/),
  parentCoinId: z.string().regex(/^[0-9a-f]{64}$/),
  coinMojos: z.string().regex(/^[1-9][0-9]{0,18}$/),
});
export type ChiaTx = z.infer<typeof ChiaTx>;
const FuelCoinInput = z.strictObject({
  txId: z.string().regex(/^0x[0-9a-f]{64}$/),
  outputIndex: z.number().int().nonnegative().max(0xffff),
  amount: z.string().regex(/^[1-9][0-9]{0,19}$/),
});
export const FuelTx = z.strictObject({
  chainId: z.literal('fuel:0'),
  from: z.string().regex(/^0x[0-9a-f]{64}$/),
  to: z.string().regex(/^0x[0-9a-f]{64}$/),
  base: z.string().regex(/^[1-9][0-9]{0,19}$/),
  inputs: z.array(FuelCoinInput).min(1).max(8),
  gasLimit: z.number().int().nonnegative().max(30_000_000),
  maxFee: z.string().regex(/^[1-9][0-9]{0,12}$/),
  expiration: z.number().int().positive().max(0xffffffff),
});
export type FuelTx = z.infer<typeof FuelTx>;
const AelfAddress = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,64}$/);
export const AelfTx = z.strictObject({
  chainId: z.literal('aelf:tDVV'),
  from: AelfAddress,
  to: AelfAddress,
  elves: z.string().regex(/^\d{1,19}$/),
  refBlockNumber: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  refBlockPrefix: z.string().regex(/^[0-9a-f]{8}$/),
});
export type AelfTx = z.infer<typeof AelfTx>;
const StarcoinAddress = z.string().regex(/^0x[0-9a-f]{32}$/);
export const StarcoinTx = z.strictObject({
  chainId: z.literal('starcoin:251'),
  from: StarcoinAddress,
  to: StarcoinAddress,
  nano: z.string().regex(/^[1-9][0-9]{0,38}$/),
  sequenceNumber: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  maxGasAmount: z.number().int().min(1).max(50_000_000),
  gasUnitPrice: z.number().int().min(1).max(1_000_000),
  expirationTimestampSecs: z.number().int().positive().max(4_102_444_800),
});
export type StarcoinTx = z.infer<typeof StarcoinTx>;
const ObyteB64Hash = z
  .string()
  .length(44)
  .regex(/^[A-Za-z0-9+/]{43}=$/);
const ObyteAddress = z
  .string()
  .length(32)
  .regex(/^[A-Z2-7]{32}$/);
export const ObyteTx = z.strictObject({
  chainId: z.literal('obyte:testnet'),
  from: ObyteAddress,
  authorPubkey: z.string().regex(/^[A-Za-z0-9+/]{44}$/),
  to: ObyteAddress,
  bytes: z.string().regex(/^[1-9][0-9]{0,15}$/),
  timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  tpsFee: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  parentUnits: z.array(ObyteB64Hash).min(1).max(16),
  lastBall: ObyteB64Hash,
  lastBallUnit: ObyteB64Hash,
  inputs: z
    .array(
      z.strictObject({
        unit: ObyteB64Hash,
        messageIndex: z.number().int().nonnegative().max(0x7fffffff),
        outputIndex: z.number().int().nonnegative().max(0x7fffffff),
        amount: z.string().regex(/^(0|[1-9][0-9]{0,15})$/),
      }),
    )
    .min(1)
    .max(128),
  firstUnit: z.boolean(),
});
export type ObyteTx = z.infer<typeof ObyteTx>;
const ChromiaHex64 = z.string().regex(/^[0-9a-f]{64}$/);
const ChromiaHex66 = z.string().regex(/^[0-9a-f]{66}$/);
export const ChromiaTx = z.strictObject({
  chainId: z.literal('chromia:0x090bcd47149fbb66'),
  from: ChromiaHex64,
  signer: ChromiaHex66,
  to: ChromiaHex64,
  uchr: z.string().regex(/^[1-9][0-9]{0,14}$/),
  nonce: ChromiaHex64,
});
export type ChromiaTx = z.infer<typeof ChromiaTx>;
export const ChromiaRegisterTx = z.strictObject({
  chainId: z.literal('chromia:0x090bcd47149fbb66'),
  from: ChromiaHex64,
  signer: ChromiaHex66,
  register: z.literal(true),
});
export type ChromiaRegisterTx = z.infer<typeof ChromiaRegisterTx>;
const KeetaAddress = z.string().regex(/^keeta_[a-z2-7]{63}$/);
export const KeetaTx = z.strictObject({
  chainId: z.literal('keeta:test'),
  from: KeetaAddress,
  to: KeetaAddress,
  attoKta: z.string().regex(/^[1-9][0-9]{0,38}$/),
  previous: z.string().regex(/^[0-9a-f]{64}$/),
  timestamp: z.number().int().positive().max(0xffffffff),
});
export type KeetaTx = z.infer<typeof KeetaTx>;
const NamadaAddress = z.string().regex(/^tnam1[02-9ac-hj-np-z]{40}$/);
export const NamadaTx = z.strictObject({
  chainId: z.literal('namada:cc0d3e0c033be'),
  from: NamadaAddress,
  to: NamadaAddress,
  namnam: Amount,
  token: NamadaAddress,
  feeToken: NamadaAddress,
  feePerGas: Amount,
  gasLimit: z.number().int().positive().max(1_000_000),
  wasmCodeHash: z.string().regex(/^[0-9a-f]{64}$/),
  timestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}\+00:00$/),
  codeSalt: z.string().regex(/^[0-9a-f]{16}$/),
  dataSalt: z.string().regex(/^[0-9a-f]{16}$/),
});
export type NamadaTx = z.infer<typeof NamadaTx>;
const BtcForkHash = z.string().regex(/^[0-9a-f]{64}$/);
export const BtcForkInput = z.strictObject({
  txid: BtcForkHash,
  vout: z.number().int().nonnegative().max(0xffffffff),
  previousTxHex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/)
    .max(400_000),
});
export const BtcForkTx = z.strictObject({
  chainId: z.enum([
    'btcfork:bch-testnet',
    'btcfork:dash-testnet',
    'btcfork:zcash-testnet',
    'btcfork:defichain-testnet',
    'btcfork:verus-testnet',
  ]),
  from: z.string().min(25).max(100),
  to: z.string().min(25).max(100),
  satoshis: Amount,
  fee: Amount,
  inputs: z.array(BtcForkInput).min(1).max(8),
  expiryHeight: z.number().int().min(1).max(500_000_000).optional(),
});
export type BtcForkTx = z.infer<typeof BtcForkTx>;
const GalaEthRef = z.string().regex(/^eth\|[0-9a-fA-F]{40}$/);
export const GalaTx = z.strictObject({
  chainId: z.literal('gala:testnet'),
  from: GalaEthRef,
  to: GalaEthRef,
  gunits: Amount,
  uniqueKey: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  dtoExpiresAt: z.number().int().min(1_577_836_800_000).max(4_102_444_800_000),
});
export type GalaTx = z.infer<typeof GalaTx>;
const MixinHash32 = z.string().regex(/^[0-9a-f]{64}$/);
export const MixinInput = z.strictObject({
  hash: MixinHash32,
  index: z.number().int().min(0).max(1024),
  key: MixinHash32,
  mask: MixinHash32,
  xinat: Amount,
});
export const MixinTx = z.strictObject({
  chainId: z.literal('mixin:74c6cdb7d51af570'),
  from: z.string().regex(/^XIN[1-9A-HJ-NP-Za-km-z]{80,100}$/),
  to: z.string().regex(/^XIN[1-9A-HJ-NP-Za-km-z]{80,100}$/),
  xinat: Amount,
  inputs: z.array(MixinInput).min(1).max(8),
  toSeed: z.string().regex(/^[0-9a-f]{128}$/),
  changeSeed: z.string().regex(/^[0-9a-f]{128}$/),
});
export type MixinTx = z.infer<typeof MixinTx>;
const QubicIdentity = z.string().regex(/^[A-Z]{60}$/);
export const QubicTx = z.strictObject({
  chainId: z.literal('qubic:mainnet'),
  from: QubicIdentity,
  to: QubicIdentity,
  qu: z.string().regex(/^[1-9]\d{0,18}$/),
  tick: z.number().int().min(1).max(4_000_000_000),
});
export type QubicTx = z.infer<typeof QubicTx>;

export const LedgerUnsignedTx = z.union([
  EvmTx,
  SolanaTx,
  CosmosTx,
  BitcoinTx,
  TronTx,
  SubstrateTx,
  StellarTx,
  AptosTx,
  XrplTx,
  SuiTx,
  NearTx,
  AlgorandTx,
  TonTx,
  CardanoTx,
  AntelopeTx,
  MultiversxTx,
  TezosTx,
  StacksTx,
  VechainTx,
  HyperliquidTx,
  StarknetTx,
  IconTx,
  EverscaleTx,
  WavesTx,
  RadixTx,
  IcpTx,
  ErgoTx,
  AlephiumTx,
  AeternityTx,
  ChiaTx,
  FuelTx,
  AelfTx,
  StarcoinTx,
  ObyteTx,
  ChromiaTx,
  ChromiaRegisterTx,
  KeetaTx,
  NamadaTx,
  BtcForkTx,
  GalaTx,
  MixinTx,
  QubicTx,
]);
export type LedgerUnsignedTx = z.infer<typeof LedgerUnsignedTx>;

export const Signer = z.object({ walletId: z.string(), path: z.string(), address: z.string() });
export type Signer = z.infer<typeof Signer>;

export const TxRecord = z.object({
  id: z.string(),
  intent: TxIntent,
  state: TxState,
  signer: Signer.nullable(),
  unsigned: LedgerUnsignedTx.nullable(),
  simulation: z.unknown().nullable(),
  simulationOk: z.boolean().nullable(),
  decision: Decision.nullable(),
  rawSignedHex: z.string().nullable(),
  hash: z.string().nullable(),
  error: z.string().nullable(),
  createdAtMs: z.number().int(),
  updatedAtMs: z.number().int(),
});
export type TxRecord = z.infer<typeof TxRecord>;

export const AuditActor = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('device'), deviceId: z.string() }),
  z.object({ kind: z.literal('agentSession'), sessionId: z.string() }),
  z.object({ kind: z.literal('automation'), automationId: z.string(), runId: z.string() }),
  z.object({ kind: z.literal('system') }),
]);
export type AuditActor = z.infer<typeof AuditActor>;

/** One hash-chained row; the event's own fields sit beside `event`. */
export const AuditEntry = z
  .object({
    index: z.number().int().nonnegative(),
    atMs: z.number().int(),
    actor: AuditActor,
    event: z.string(),
    txId: z.string().optional(),
    from: TxState.optional(),
    to: TxState.optional(),
    note: z.string().nullable().optional(),
    prevHashHex: z.string(),
    hashHex: z.string(),
  })
  .passthrough();
export type AuditEntry = z.infer<typeof AuditEntry>;

export const Ledger = z.object({
  txs: z.array(TxRecord).default([]),
  audit: z.array(AuditEntry).default([]),
  policies: z.array(Policy).default([]),
});
export type Ledger = z.infer<typeof Ledger>;
