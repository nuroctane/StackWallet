/**
 * Obyte adapter. Addresses are chash160 of the `["sig", {pubkey}]` definition
 * (ripemd160, checksum bits mixed in at pi-digit offsets, RFC4648 base32).
 * Reads go over the hub's public REST JSON API (`POST /api/<method>`, CORS
 * `*`, live-probed); the network is proven by fetching the genesis joint and
 * matching its version/alt. Broadcasts go over the hub websocket, which is the
 * only place `post_joint` is served; the ws layer is injectable for tests.
 *
 * Every hashing/serialization function here mirrors the vendored ocore oracle
 * (`.nur/obyte-oracle`) byte-exactly; the Rust core re-derives the same bytes.
 */
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  chainsForFamily,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type ChainInfo,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const OBYTE_TESTNET = 'obyte:testnet';
export const OBYTE_MAINNET = 'obyte:mainnet';

/** Genesis unit ids; fetching one proves which network an endpoint serves. */
const GENESIS: Record<string, string> = {
  [OBYTE_TESTNET]: 'TvqutGPz3T4Cs6oiChxFlclY92M2MvCvfXR5/FETato=',
  [OBYTE_MAINNET]: 'oj8yEksX9Ubq7lLc+p6F2uyHUuynugeVq4+ikT67X6E=',
};
const ALT: Record<string, string> = { [OBYTE_TESTNET]: '2', [OBYTE_MAINNET]: '1' };
const VERSION: Record<string, string> = { [OBYTE_TESTNET]: '4.0t', [OBYTE_MAINNET]: '4.0' };

export const MAX_CAP = 9_000_000_000_000_000n;
const MAX_INPUTS_PER_PAYMENT = 128;
const MAX_PARENTS_PER_UNIT = 16;
const MAX_UNIT_LENGTH = 5_000_000;
const SIG_PLACEHOLDER = '-'.repeat(88);
const HASH_PLACEHOLDER = '-'.repeat(44);

// ---------------------------------------------------------------------------
// base32 (RFC4648, no padding) — Obyte addresses
// ---------------------------------------------------------------------------

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Uint8Array | undefined {
  if (!/^[A-Z2-7]+$/.test(text)) return undefined;
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of text) {
    const idx = B32_ALPHABET.indexOf(ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// chash160 (ocore chash.js)
// ---------------------------------------------------------------------------

const PI_DIGITS = '14159265358979323846264338327950288419716939937510';

/** Cumulative sums of nonzero pi digits: bit offsets of the 32 checksum bits. */
function chash160Offsets(): number[] {
  const offsets: number[] = [];
  let offset = 0;
  for (const ch of PI_DIGITS) {
    const rel = ch.charCodeAt(0) - 48;
    if (rel === 0) continue;
    offset += rel;
    if (offset >= 160) break;
    offsets.push(offset);
  }
  if (offsets.length !== 32) throw new Error('wrong number of checksum bits');
  return offsets;
}
const OFFSETS_160 = chash160Offsets();

function checksumBytes(clean: Uint8Array): Uint8Array {
  const full = sha256(clean);
  return Uint8Array.from([full[5]!, full[13]!, full[21]!, full[29]!]);
}

const bitAt = (data: Uint8Array, bit: number) => (data[bit >> 3]! >> (7 - (bit & 7))) & 1;

function mixChecksum(clean: Uint8Array, checksum: Uint8Array): Uint8Array {
  const out = new Uint8Array(20);
  let cleanBit = 0;
  let checksumBit = 0;
  let next = 0;
  for (let pos = 0; pos < 160; pos++) {
    let bit: number;
    if (next < OFFSETS_160.length && pos === OFFSETS_160[next]) {
      next++;
      bit = bitAt(checksum, checksumBit++);
    } else {
      bit = bitAt(clean, cleanBit++);
    }
    if (bit) out[pos >> 3]! |= 1 << (7 - (pos & 7));
  }
  return out;
}

function separateChecksum(mixed: Uint8Array): { clean: Uint8Array; checksum: Uint8Array } {
  const clean = new Uint8Array(16);
  const checksum = new Uint8Array(4);
  let cleanBit = 0;
  let checksumBit = 0;
  let next = 0;
  for (let pos = 0; pos < 160; pos++) {
    if (next < OFFSETS_160.length && pos === OFFSETS_160[next]) {
      next++;
      if (bitAt(mixed, pos)) checksum[checksumBit >> 3]! |= 1 << (7 - (checksumBit & 7));
      checksumBit++;
    } else {
      if (bitAt(mixed, pos)) clean[cleanBit >> 3]! |= 1 << (7 - (cleanBit & 7));
      cleanBit++;
    }
  }
  return { clean, checksum };
}

/** ocore getChash160 over an already-serialized source string. */
export function chash160(source: string): string {
  const hash = ripemd160(new TextEncoder().encode(source));
  const clean = hash.subarray(4);
  return base32Encode(mixChecksum(clean, checksumBytes(clean)));
}

/** ocore getSourceString for the `["sig", {pubkey}]` definition. */
function legacySourceString(value: unknown): string {
  const components: string[] = [];
  const walk = (v: unknown): void => {
    if (v === null) throw new Error('null value');
    switch (typeof v) {
      case 'string':
        components.push('s', v);
        return;
      case 'number':
        if (!Number.isSafeInteger(v)) throw new Error('non-integer number');
        components.push('n', v.toString());
        return;
      case 'boolean':
        components.push('b', v.toString());
        return;
      case 'object':
        if (Array.isArray(v)) {
          if (v.length === 0) throw new Error('empty array');
          components.push('[');
          for (const item of v) walk(item);
          components.push(']');
        } else {
          const keys = Object.keys(v).sort();
          if (keys.length === 0) throw new Error('empty object');
          for (const key of keys) {
            components.push(key);
            walk((v as Record<string, unknown>)[key]);
          }
        }
        return;
      default:
        throw new Error(`unsupported type ${typeof v}`);
    }
  };
  walk(value);
  return components.join('\x00');
}

/** ocore getJsonSourceString: canonical compact JSON with sorted keys. */
export function jsonSourceString(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new Error('non-integer number in unit');
      return value.toString();
    case 'string':
      return JSON.stringify(value);
    case 'object':
      if (Array.isArray(value)) return `[${value.map(jsonSourceString).join(',')}]`;
      return `{${Object.keys(value as Record<string, unknown>)
        .sort()
        .map(
          (k) => `${JSON.stringify(k)}:${jsonSourceString((value as Record<string, unknown>)[k])}`,
        )
        .join(',')}}`;
    default:
      throw new Error(`unsupported type ${typeof value}`);
  }
}

function jsonHashB64(value: unknown): string {
  return base64Encode(sha256(new TextEncoder().encode(jsonSourceString(value))));
}

export function base64Encode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64Decode(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return undefined;
  try {
    const bin = atob(text);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/** Validate an Obyte address (32-char base32 with the mixed-in checksum). */
export function isValidObyteAddress(addr: string): boolean {
  if (addr.length !== 32) return false;
  const mixed = base32Decode(addr);
  if (!mixed || mixed.length !== 20) return false;
  const { clean, checksum } = separateChecksum(mixed);
  const expected = checksumBytes(clean);
  return checksum.every((b, i) => b === expected[i]);
}

/** Derive the Obyte address of a 33-byte compressed SEC1 public key. */
export function obyteAddressFromPublicKey(sec1: Uint8Array): string {
  if (sec1.length !== 33 || (sec1[0] !== 0x02 && sec1[0] !== 0x03))
    throw new Error('expected a 33-byte compressed SEC1 public key');
  const definition = ['sig', { pubkey: base64Encode(sec1) }];
  return chash160(legacySourceString(definition));
}

// ---------------------------------------------------------------------------
// commissions (ocore object_length.js, bWithKeys = true for v4)
// ---------------------------------------------------------------------------

/** ocore getLength: strings count chars, numbers 8, bools 1, object keys count. */
export function getLength(value: unknown): number {
  if (value === null) return 0;
  switch (typeof value) {
    case 'boolean':
      return 1;
    case 'number':
      if (!Number.isSafeInteger(value)) throw new Error('non-integer number in unit');
      return 8;
    case 'string':
      return value.length;
    case 'object':
      if (Array.isArray(value)) return value.reduce((a, item) => a + getLength(item), 0);
      return Object.entries(value as Record<string, unknown>).reduce(
        (a, [k, v]) => a + k.length + getLength(v),
        0,
      );
    default:
      throw new Error(`unsupported type ${typeof value}`);
  }
}

// ---------------------------------------------------------------------------
// unsigned transaction (mirrors the Rust `ObyteTx` struct exactly)
// ---------------------------------------------------------------------------

const B64_32 = z
  .string()
  .length(44)
  .regex(/^[A-Za-z0-9+/]{43}=$/);
export const ObyteAddress = z
  .string()
  .length(32)
  .regex(/^[A-Z2-7]{32}$/)
  .refine(isValidObyteAddress, 'checksum mismatch');

export const ObyteInput = z.strictObject({
  unit: B64_32,
  messageIndex: z.number().int().nonnegative().max(0x7fffffff),
  outputIndex: z.number().int().nonnegative().max(0x7fffffff),
  amount: z.string().regex(/^(0|[1-9][0-9]{0,15})$/),
});
export type ObyteInput = z.infer<typeof ObyteInput>;

export const ObyteTx = z.strictObject({
  chainId: z.literal(OBYTE_TESTNET),
  from: ObyteAddress,
  /** Base64 compressed SEC1 public key behind `from` (33 bytes: 44 chars, no padding). */
  authorPubkey: z.string().regex(/^[A-Za-z0-9+/]{44}$/),
  to: ObyteAddress,
  /** Amount in bytes (the Obyte base unit), decimal string, at most MAX_CAP. */
  bytes: z
    .string()
    .regex(/^[1-9][0-9]{0,15}$/)
    .refine((v) => BigInt(v) <= MAX_CAP, `exceeds MAX_CAP ${MAX_CAP}`),
  timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  tpsFee: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  parentUnits: z.array(B64_32).min(1).max(MAX_PARENTS_PER_UNIT),
  lastBall: B64_32,
  lastBallUnit: B64_32,
  inputs: z.array(ObyteInput).min(1).max(MAX_INPUTS_PER_PAYMENT),
  firstUnit: z.boolean(),
});
export type ObyteTx = z.infer<typeof ObyteTx>;

function author(unsigned: ObyteTx, signature: string): Record<string, unknown> {
  return {
    address: unsigned.from,
    authentifiers: { r: signature },
    ...(unsigned.firstUnit ? { definition: ['sig', { pubkey: unsigned.authorPubkey }] } : {}),
  };
}

/** ocore getHeadersSize for this unit shape. */
export function headersCommission(unsigned: ObyteTx): number {
  const header = {
    version: VERSION[unsigned.chainId],
    alt: ALT[unsigned.chainId],
    timestamp: unsigned.timestamp,
    authors: [author(unsigned, SIG_PLACEHOLDER)],
    last_ball: unsigned.lastBall,
    last_ball_unit: unsigned.lastBallUnit,
    tps_fee: unsigned.tpsFee,
  };
  // parent_units is replaced by a fixed 88-char placeholder; the key counts.
  return getLength(header) + 88 + 'parent_units'.length;
}

function paymentMessage(unsigned: ObyteTx, change: number): Record<string, unknown> {
  const amount = Number(BigInt(unsigned.bytes));
  const outputs = [
    { address: unsigned.from, amount: change },
    { address: unsigned.to, amount },
  ].sort((a, b) =>
    a.address === b.address ? a.amount - b.amount : a.address < b.address ? -1 : 1,
  );
  const payload = {
    outputs,
    inputs: unsigned.inputs.map((i) => ({
      unit: i.unit,
      message_index: i.messageIndex,
      output_index: i.outputIndex,
    })),
  };
  return {
    app: 'payment',
    payload_location: 'inline',
    payload_hash: jsonHashB64(payload),
    payload,
  };
}

/** ocore getTotalPayloadSize for this unit shape (change value-independent). */
export function payloadCommission(unsigned: ObyteTx): number {
  const message = {
    app: 'payment',
    payload_location: 'inline',
    payload_hash: HASH_PLACEHOLDER,
    payload: {
      outputs: [
        { address: unsigned.from, amount: 0 },
        { address: unsigned.to, amount: Number(BigInt(unsigned.bytes)) },
      ],
      inputs: unsigned.inputs.map((i) => ({
        unit: i.unit,
        message_index: i.messageIndex,
        output_index: i.outputIndex,
      })),
    },
  };
  return getLength({ messages: [message] });
}

/** (headersCommission, payloadCommission, totalInput, change). */
export function computeCommissions(unsigned: ObyteTx): {
  headers: number;
  payload: number;
  totalInput: bigint;
  change: bigint;
} {
  const headers = headersCommission(unsigned);
  const payload = payloadCommission(unsigned);
  if (headers + payload > MAX_UNIT_LENGTH) throw new Error('unit too large');
  const totalInput = unsigned.inputs.reduce((a, i) => a + BigInt(i.amount), 0n);
  const change = totalInput - BigInt(unsigned.bytes) - BigInt(headers + payload + unsigned.tpsFee);
  return { headers, payload, totalInput, change };
}

/** The full unsigned unit with an 88-char placeholder signature. */
export function buildUnit(unsigned: ObyteTx, signature: string): Record<string, unknown> {
  const { headers, payload, change } = computeCommissions(unsigned);
  if (change <= 0n) throw new Error('inputs do not cover the payment and fees');
  return {
    version: VERSION[unsigned.chainId],
    alt: ALT[unsigned.chainId],
    timestamp: unsigned.timestamp,
    parent_units: [...unsigned.parentUnits].sort(),
    last_ball: unsigned.lastBall,
    last_ball_unit: unsigned.lastBallUnit,
    tps_fee: unsigned.tpsFee,
    authors: [author(unsigned, signature)],
    messages: [paymentMessage(unsigned, Number(change))],
    headers_commission: headers,
    payload_commission: payload,
  };
}

function nakedUnit(unit: Record<string, unknown>): Record<string, unknown> {
  const {
    headers_commission: _hc,
    payload_commission: _pc,
    unit: _u,
    ...rest
  } = unit as Record<string, unknown> & {
    headers_commission?: unknown;
    payload_commission?: unknown;
    unit?: unknown;
  };
  const messages = (rest.messages as Record<string, unknown>[]).map((m) => {
    const { payload: _p, payload_uri: _pu, ...keep } = m;
    return keep;
  });
  return { ...rest, messages };
}

/** ocore getUnitHashToSign. */
export function unitSighash(unsigned: ObyteTx): Uint8Array {
  const naked = nakedUnit(buildUnit(unsigned, SIG_PLACEHOLDER));
  const authors = (naked.authors as Record<string, unknown>[]).map((a) => {
    const { authentifiers: _a, ...keep } = a;
    return keep;
  });
  const source = jsonSourceString({ ...naked, authors });
  return sha256(new TextEncoder().encode(source));
}

/** ocore getUnitHash of a fully signed unit. */
export function unitId(signedUnit: Record<string, unknown>): string {
  const naked = nakedUnit(signedUnit);
  const content_hash = jsonHashB64(naked);
  const stripped = {
    content_hash,
    version: signedUnit.version,
    alt: signedUnit.alt,
    authors: (signedUnit.authors as { address: string }[]).map((a) => ({ address: a.address })),
    parent_units: signedUnit.parent_units,
    last_ball: signedUnit.last_ball,
    last_ball_unit: signedUnit.last_ball_unit,
    timestamp: signedUnit.timestamp,
  };
  return jsonHashB64(stripped);
}

/** Sighash as lowercase hex (for diagnostics/tests). */
export function unitSighashHex(unsigned: ObyteTx): string {
  return bytesToHex(unitSighash(unsigned));
}

// ---------------------------------------------------------------------------
// hub REST API
// ---------------------------------------------------------------------------

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

const Envelope = z.object({
  data: z.unknown().optional(),
  error: z.string().max(1024).optional(),
});

const Witnesses = z.array(ObyteAddress).min(1).max(64);

const BalanceEntry = z
  .object({
    stable: SafeInt,
    pending: SafeInt,
    stable_outputs_count: SafeInt.optional(),
    pending_outputs_count: SafeInt.optional(),
    total: SafeInt.optional(),
  })
  .loose();
const Balances = z.record(z.string(), z.object({ base: BalanceEntry.optional() }).loose());

const Parents = z.object({
  timestamp: z.number().int().positive(),
  parent_units: z.array(B64_32).min(1).max(MAX_PARENTS_PER_UNIT),
  last_stable_mc_ball: B64_32,
  last_stable_mc_ball_unit: B64_32,
  last_stable_mc_ball_mci: SafeInt,
  tps_fee: SafeInt,
  count_primary_aa_triggers: SafeInt.optional(),
});

const PaymentInput = z
  .object({
    unit: B64_32.optional(),
    message_index: SafeInt.optional(),
    output_index: SafeInt.optional(),
    type: z.enum(['issue', 'headers_commission', 'witnessing']).optional(),
  })
  .loose();
const PaymentOutput = z.object({ address: ObyteAddress, amount: SafeInt }).loose();
const PaymentPayload = z
  .object({
    outputs: z.array(PaymentOutput).min(1),
    inputs: z.array(PaymentInput).optional(),
    asset: B64_32.optional(),
  })
  .loose();
const Message = z
  .object({
    app: z.string().max(64),
    payload_location: z.string().max(16),
    payload_hash: z.string().max(64),
    payload: z.unknown().optional(),
  })
  .loose();
const Unit = z
  .object({
    version: z.string().max(16),
    alt: z.string().max(4),
    timestamp: SafeInt.optional(),
    authors: z
      .array(
        z
          .object({
            address: ObyteAddress,
            authentifiers: z.record(z.string(), z.string().max(4096)),
          })
          .loose(),
      )
      .min(1),
    messages: z.array(Message).optional(),
    main_chain_index: SafeInt.optional(),
    unit: z.string().max(64).optional(),
  })
  .loose();
const Joint = z.object({
  unit: Unit,
  ball: B64_32.optional(),
  skiplist_units: z.array(B64_32).optional(),
});
const JointEnvelope = z.object({
  data: z.object({ joint: Joint }).optional(),
  error: z.string().max(1024).optional(),
});

const CoinSelection = z.object({
  inputs_with_proofs: z.array(z.object({ input: PaymentInput })).min(1),
  total_amount: SafeInt,
});

const History = z.object({
  joints: z.array(Joint).max(10000).optional(),
  proofchain_balls: z.array(z.unknown()).optional(),
});

/** The hub REST API answers `{"data": ...}` or `{"error": ...}` with CORS `*`. */
function parseEnvelope<T>(raw: unknown, schema: z.ZodType<T>): T {
  const env = Envelope.parse(raw);
  if (env.error !== undefined) throw new Error(`hub error: ${env.error}`);
  if (env.data === undefined) throw new Error('hub returned neither data nor error');
  return schema.parse(env.data);
}

export type ObyteRestCall = <T>(
  method: string,
  params: unknown,
  schema: z.ZodType<T>,
) => Promise<T>;

/** Minimal injectable broadcast transport; the default speaks the hub websocket. */
export interface ObyteHubTransport {
  /** Resolves to 'accepted' or rejects/returns an error description. */
  postJoint(joint: { unit: Record<string, unknown> }): Promise<unknown>;
  close(): void;
}
export type ObyteHubFactory = (chainId: ChainId) => Promise<ObyteHubTransport>;

export interface ObyteAdapterOptions extends BaseAdapterOptions {
  /** Override the broadcast transport (tests inject a fake). */
  hub?: ObyteHubFactory;
}

/** Built-in chain info used until the catalog is wired (or if it lags). */
export const OBYTE_CHAINS: ChainInfo[] = [
  {
    chainId: OBYTE_MAINNET,
    family: 'obyte',
    name: 'Obyte',
    // Display unit GBYTE; the tx `bytes` field stays in base units (1 GBYTE = 1e9 bytes).
    nativeAsset: { ref: `${OBYTE_MAINNET}:native`, symbol: 'GBYTE', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://explorer.obyte.org/{hash}',
    defaultRpcs: ['https://obyte.org'],
    // The reference wallet (obyte-gui-wallet) predates Obyte's SLIP-44 assignment and
    // derives at m/44'/0'/0'/0/i; coinType 0 keeps seed imports compatible.
    extra: { coinType: 0 },
    layer: 'L1',
    priceId: 'byteball',
  },
  {
    chainId: OBYTE_TESTNET,
    family: 'obyte',
    name: 'Obyte Testnet',
    nativeAsset: { ref: `${OBYTE_TESTNET}:native`, symbol: 'GBYTE', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://testnetexplorer.obyte.org/{hash}',
    defaultRpcs: ['https://testnet.obyte.org'],
    extra: { coinType: 0 },
    layer: 'L1',
  },
];

export class ObyteAdapter extends BaseAdapter<'obyte'> {
  private readonly hubFactory: ObyteHubFactory | undefined;

  override chains(): ChainInfo[] {
    const catalog = chainsForFamily('obyte');
    return catalog.length > 0 ? catalog : OBYTE_CHAINS;
  }

  constructor(opts: ObyteAdapterOptions = {}) {
    const { hub, ...base } = opts;
    super('obyte', base);
    this.hubFactory = hub;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return obyteAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidObyteAddress(addr);
  }

  /** POST /api/<method> on one endpoint that has proven its network. */
  private post<T>(url: string, method: string, params: unknown, schema: z.ZodType<T>): Promise<T> {
    return this.postRaw(url, method, params).then((env) => parseEnvelope(env, schema));
  }

  /** Raw envelope variant for get_joint, whose "joint not found" is a real answer. */
  private postRaw(url: string, method: string, params: unknown): Promise<z.infer<typeof Envelope>> {
    return postJsonText(
      `${url.replace(/\/$/, '')}/api/${method}`,
      params,
      this.fetchOptions(),
    ).then((text) => Envelope.parse(JSON.parse(text)));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const genesis = GENESIS[chainId];
      if (!genesis) throw new Error(`no known Obyte genesis for ${chainId}`);
      const res = JointEnvelope.parse(
        JSON.parse(
          await postJsonText(
            `${url.replace(/\/$/, '')}/api/get_joint`,
            { unit: genesis },
            this.fetchOptions(),
          ),
        ),
      );
      const unit = res.data?.joint.unit;
      if (!unit) throw new Error('endpoint does not serve the expected genesis unit');
      if (unit.alt !== ALT[chainId] || unit.version !== VERSION[chainId])
        throw new Error('Endpoint genesis unit does not match this Obyte network');
    });
  }

  /** Run `query` against an endpoint that proved its network. */
  withEndpoint<T>(
    chainId: ChainId,
    query: (call: ObyteRestCall, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((method, params, schema) => this.post(url, method, params, schema), url);
    });
  }

  /** The broadcast transport for this network (injected in tests). */
  async hub(chainId: ChainId): Promise<ObyteHubTransport> {
    this.requireChain(chainId);
    if (!this.hubFactory) throw new Error('no hub transport configured');
    return this.hubFactory(chainId);
  }

  get hasHubTransport(): boolean {
    return this.hubFactory !== undefined;
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidObyteAddress(addr)) throw new TypeError(`invalid obyte address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const balances = await this.post(
          url,
          'light/get_balances',
          { addresses: [addr] },
          Balances,
        );
        const base = balances[addr]?.base;
        return { stable: BigInt(base?.stable ?? 0), pending: BigInt(base?.pending ?? 0) };
      },
      { equal: (a, b) => a.stable === b.stable && a.pending === b.pending },
    );
    const holding = nativeHolding(chain, value.stable.toString(), provenance);
    if (value.pending > 0n)
      holding.notice = `${value.pending} bytes are still pending confirmation and cannot be spent yet.`;
    return [holding];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidObyteAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined)
      throw new Error('Obyte history has no cursor; all joints are returned');
    return this.withEndpoint(chainId, async (call, url) => {
      const witnesses = await call('get_witnesses', {}, Witnesses);
      const history = await call('light/get_history', { addresses: [addr], witnesses }, History);
      void options;
      const items: TxRecord[] = [];
      for (const joint of history.joints ?? []) {
        const unit = joint.unit;
        if (!unit.unit) continue;
        for (const message of unit.messages ?? []) {
          if (message.app !== 'payment') continue;
          const payload = PaymentPayload.safeParse(message.payload);
          if (!payload.success || payload.data.asset) continue; // base-asset payments only
          const from = unit.authors[0]!.address;
          const received = payload.data.outputs
            .filter((o) => o.address === addr)
            .reduce((a, o) => a + BigInt(o.amount), 0n);
          const sentElsewhere = payload.data.outputs
            .filter((o) => o.address !== addr)
            .reduce((a, o) => a + BigInt(o.amount), 0n);
          if (from !== addr && received === 0n) continue;
          const isOutgoing = from === addr;
          items.push({
            entryId: `${unit.unit}:${items.length}`,
            hash: unit.unit,
            chainId,
            ...(unit.main_chain_index !== undefined ? { blockNumber: unit.main_chain_index } : {}),
            ...(unit.timestamp !== undefined ? { timestampMs: unit.timestamp * 1000 } : {}),
            from,
            to: isOutgoing ? payload.data.outputs.find((o) => o.address !== addr)?.address : from,
            assetDeltas: [
              {
                assetRef: chain.nativeAsset.ref,
                amount: isOutgoing ? `-${sentElsewhere.toString()}` : received.toString(),
              },
            ],
            feeAssetRef: chain.nativeAsset.ref,
            // Fees are inputs-minus-outputs; inputs need per-unit lookups, so skip.
            fee: null,
            status: joint.ball !== undefined ? 'confirmed' : 'pending',
          });
        }
      }
      items.sort((a, b) => (b.timestampMs ?? 0) - (a.timestampMs ?? 0));
      return {
        items,
        coverage:
          'Hub light/get_history for base-asset (GBYTE) payments touching this address. ' +
          'Asset transfers and fees are not listed; fees are inputs minus outputs and require per-input lookups.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(hash)) throw new Error('Invalid Obyte unit id');
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const env = await this.postRaw(url, 'get_joint', { unit: hash });
      if (env.error !== undefined) {
        // A hub answering "joint not found" is a real answer, not a failure.
        if (/joint not found/i.test(env.error)) return { state: 'unknown' } as TxStatus;
        throw new Error(`hub error: ${env.error}`);
      }
      const joint = z.object({ joint: Joint }).parse(env.data).joint;
      if (joint.ball !== undefined) {
        return {
          state: 'confirmed',
          blockNumber: joint.unit.main_chain_index ?? 0,
          ...(joint.unit.timestamp !== undefined
            ? { timestampMs: joint.unit.timestamp * 1000 }
            : {}),
        };
      }
      return { state: 'pending' };
    });
  }
}

export function createObyteAdapter(opts: ObyteAdapterOptions = {}): ObyteAdapter {
  return new ObyteAdapter(opts);
}
