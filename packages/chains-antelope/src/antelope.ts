/**
 * Antelope (EOSIO lineage) adapter for Vaulta (EOS), XPR Network, WAX, Telos
 * native and Libre, plus their testnets. Accounts are 12-character on-chain
 * names; a secp256k1 key controls an account only through that account's
 * permissions. The derived identity of a key is its `PUB_K1_…` form, and the
 * adapter discovers which account names the key is linked to. Every chain API
 * endpoint proves its full chain id, and every Hyperion history endpoint
 * proves it through `/v2/health`, before any answer from it is trusted.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  fetchJson,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  secp256k1Compressed,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type FetchOptions,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export interface AntelopeToken {
  contract: string;
  symbol: string;
  precision: number;
}

export interface AntelopeNetwork {
  /** Full 32-byte chain id as lowercase hex; CAIP-2 carries the first 16 bytes. */
  chainId: string;
  /** The system token on `eosio.token`, which pays for nothing but is what transfers move. */
  token: AntelopeToken;
  /** Hyperion v2 bases, keyless and CORS-open; history and status fallback. */
  hyperion: string[];
  /** Other tokens read for display only. */
  extraTokens?: AntelopeToken[];
}

const caip = (full: string) => `antelope:${full.slice(0, 32)}`;
const system = (symbol: string, precision: number): AntelopeToken => ({
  contract: 'eosio.token',
  symbol,
  precision,
});

const VAULTA_ID = 'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906';
const JUNGLE4_ID = '73e4385a2708e6d7048834fbc1079f2fabb17b3c125b146af438971e90716c4d';
const XPR_ID = '384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0';
const XPR_TESTNET_ID = '71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd';
const WAX_ID = '1064487b3cd1a897ce03ae5b6a865651747e2e152090f99c1d19d44e01aea5a4';
const WAX_TESTNET_ID = 'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12';
const TELOS_ID = '4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11';
const TELOS_TESTNET_ID = '1eaa0824707c8c16bd25145493bf062aecddfeb56c736f6ba6397f3195f33c9f';
const LIBRE_ID = '38b1d7815474d0c60683ecbea321d723e83f5da6ae5f1c1f9fecc69d9ba96465';
const LIBRE_TESTNET_ID = 'b64646740308df2ee06c6b72f34c0f7fa066d940e831f752db2006fcc2b78dee';

export const VAULTA_MAINNET = caip(VAULTA_ID);
export const JUNGLE4_TESTNET = caip(JUNGLE4_ID);
export const XPR_MAINNET = caip(XPR_ID);
export const XPR_TESTNET = caip(XPR_TESTNET_ID);
export const WAX_MAINNET = caip(WAX_ID);
export const WAX_TESTNET = caip(WAX_TESTNET_ID);
export const TELOS_MAINNET = caip(TELOS_ID);
export const TELOS_TESTNET = caip(TELOS_TESTNET_ID);
export const LIBRE_MAINNET = caip(LIBRE_ID);
export const LIBRE_TESTNET = caip(LIBRE_TESTNET_ID);
/** The one network the core signs for (`antelope::TESTNET`). */
export const ANTELOPE_TESTNET = WAX_TESTNET;

export const NETWORKS: Record<string, AntelopeNetwork> = {
  [VAULTA_MAINNET]: {
    chainId: VAULTA_ID,
    token: system('EOS', 4),
    hyperion: ['https://eos.hyperion.eosrio.io', 'https://eos.eosusa.io'],
    // The Vaulta rebrand token; EOS and A swap 1:1 through core.vaulta.
    extraTokens: [{ contract: 'core.vaulta', symbol: 'A', precision: 4 }],
  },
  [JUNGLE4_TESTNET]: {
    chainId: JUNGLE4_ID,
    token: system('EOS', 4),
    hyperion: ['https://jungle4.cryptolions.io'],
  },
  [XPR_MAINNET]: {
    chainId: XPR_ID,
    token: system('XPR', 4),
    hyperion: ['https://proton.eosusa.io'],
  },
  [XPR_TESTNET]: {
    chainId: XPR_TESTNET_ID,
    token: system('XPR', 4),
    hyperion: ['https://test.proton.eosusa.io'],
  },
  [WAX_MAINNET]: {
    chainId: WAX_ID,
    token: system('WAX', 8),
    hyperion: ['https://wax.eosusa.io', 'https://api.waxsweden.org'],
  },
  [WAX_TESTNET]: {
    chainId: WAX_TESTNET_ID,
    token: system('WAX', 8),
    hyperion: [
      'https://testnet.waxsweden.org',
      'https://wax-testnet.eosphere.io',
      'https://test.wax.eosusa.io',
    ],
  },
  [TELOS_MAINNET]: {
    chainId: TELOS_ID,
    token: system('TLOS', 4),
    hyperion: ['https://mainnet.telos.net', 'https://telos.eosusa.io'],
  },
  [TELOS_TESTNET]: {
    chainId: TELOS_TESTNET_ID,
    token: system('TLOS', 4),
    hyperion: ['https://test.telos.eosusa.io'],
  },
  [LIBRE_MAINNET]: {
    chainId: LIBRE_ID,
    token: system('LIBRE', 4),
    hyperion: ['https://lb.libre.org', 'https://libre.eosusa.io'],
  },
  [LIBRE_TESTNET]: {
    chainId: LIBRE_TESTNET_ID,
    token: system('LIBRE', 4),
    hyperion: ['https://testnet.libre.org', 'https://test.libre.eosusa.io'],
  },
};

export function tokenAssetRef(chainId: string, token: AntelopeToken): string {
  return `${chainId}:token:${token.contract}:${token.symbol}`;
}

// ---------------------------------------------------------------------------
// Names and keys

const NAME_CHARS = '.12345abcdefghijklmnopqrstuvwxyz';

/**
 * The u64 behind a name: up to 12 characters of `.12345a-z`, five bits each
 * from the top, with no trailing dot (which would alias the shorter name).
 */
export function nameValue(name: string): bigint | undefined {
  if (!/^[.1-5a-z]{1,12}$/.test(name) || name.endsWith('.')) return undefined;
  let value = 0n;
  for (let i = 0; i < name.length; i++) {
    value |= BigInt(NAME_CHARS.indexOf(name[i]!)) << BigInt(64 - 5 * (i + 1));
  }
  return value;
}

export function isValidAntelopeAccount(name: string): boolean {
  return nameValue(name) !== undefined;
}

const enc = new TextEncoder();
const K1 = enc.encode('K1');

function check4(payload: Uint8Array, suffix?: Uint8Array): Uint8Array {
  const input = new Uint8Array(payload.length + (suffix?.length ?? 0));
  input.set(payload);
  if (suffix) input.set(suffix, payload.length);
  return ripemd160(input).subarray(0, 4);
}

function encodeChecked(prefix: string, payload: Uint8Array, suffix?: Uint8Array): string {
  const raw = new Uint8Array(payload.length + 4);
  raw.set(payload);
  raw.set(check4(payload, suffix), payload.length);
  return prefix + base58.encode(raw);
}

function decodeChecked(text: string, length: number, suffix?: Uint8Array): Uint8Array | undefined {
  let raw: Uint8Array;
  try {
    raw = base58.decode(text);
  } catch {
    return undefined;
  }
  if (raw.length !== length + 4) return undefined;
  const payload = raw.subarray(0, length);
  const sum = check4(payload, suffix);
  for (let i = 0; i < 4; i++) if (raw[length + i] !== sum[i]) return undefined;
  return payload;
}

/** `PUB_K1_…` of a secp256k1 key in any SEC1 encoding (always the compressed point). */
export function antelopePublicKey(key: Uint8Array): string {
  return encodeChecked('PUB_K1_', secp256k1Compressed(key), K1);
}

/**
 * The compressed point of a `PUB_K1_…` key or of a legacy `EOS…` key (the form
 * most nodes still return); anything else, including a bad checksum, is refused.
 */
export function antelopeKeyBytes(key: string): Uint8Array | undefined {
  let point: Uint8Array | undefined;
  if (key.startsWith('PUB_K1_')) point = decodeChecked(key.slice(7), 33, K1);
  else if (key.startsWith('EOS')) point = decodeChecked(key.slice(3), 33);
  if (!point) return undefined;
  try {
    secp256k1.Point.fromBytes(point);
  } catch {
    return undefined;
  }
  return point;
}

/** Canonical `PUB_K1_…` form of a K1 key in either notation. */
export function normalizeAntelopeKey(key: string): string | undefined {
  const point = antelopeKeyBytes(key);
  return point ? antelopePublicKey(point) : undefined;
}

export function isValidAntelopePublicKey(key: string): boolean {
  return key.startsWith('PUB_K1_') && normalizeAntelopeKey(key) === key;
}

/** `SIG_K1_…` of a 65-byte `[27 + 4 + recid, r, s]` signature. */
export function encodeAntelopeSignature(compact: Uint8Array): string {
  if (compact.length !== 65) throw new TypeError('signature must be 65 bytes');
  return encodeChecked('SIG_K1_', compact, K1);
}

export function decodeAntelopeSignature(sig: string): Uint8Array | undefined {
  if (!sig.startsWith('SIG_K1_')) return undefined;
  const raw = decodeChecked(sig.slice(7), 65, K1);
  if (!raw || raw[0]! < 31 || raw[0]! > 34) return undefined;
  return raw;
}

/** eosio's `is_canonical`: both scalars without a sign bit or a redundant leading zero. */
export function isCanonicalSignature(rs: Uint8Array): boolean {
  const r = rs.subarray(0, 32);
  const s = rs.subarray(32, 64);
  return (
    !(r[0]! & 0x80) &&
    !(r[0] === 0 && !(r[1]! & 0x80)) &&
    !(s[0]! & 0x80) &&
    !(s[0] === 0 && !(s[1]! & 0x80))
  );
}

// ---------------------------------------------------------------------------
// Response schemas

const Hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const AntelopeTime = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z?$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

export const ChainInfoResponse = z
  .object({
    chain_id: Hex64,
    head_block_num: SafeInt,
    head_block_time: AntelopeTime,
    last_irreversible_block_num: SafeInt,
    last_irreversible_block_id: Hex64,
  })
  .loose();
export type ChainInfoResponse = z.infer<typeof ChainInfoResponse>;

const Limit = z
  .object({
    available: z.union([SafeInt, z.string().regex(/^-?\d{1,20}$/)]),
    max: z.union([SafeInt, z.string().regex(/^-?\d{1,20}$/)]),
  })
  .loose();
const KeyWeight = z.object({ key: z.string().max(128), weight: SafeInt }).loose();
const Permission = z
  .object({
    perm_name: z.string().max(13),
    parent: z.string().max(13),
    required_auth: z
      .object({
        threshold: SafeInt,
        keys: z.array(KeyWeight).max(64),
        accounts: z.array(z.unknown()).max(64),
        waits: z.array(z.unknown()).max(64),
      })
      .loose(),
  })
  .loose();
export const AccountResponse = z
  .object({
    account_name: z.string().max(13),
    head_block_time: AntelopeTime.optional(),
    cpu_limit: Limit,
    net_limit: Limit,
    ram_quota: z.union([z.number().int(), z.string().regex(/^-?\d{1,20}$/)]),
    ram_usage: SafeInt,
    permissions: z.array(Permission).max(64),
  })
  .loose();
export type AccountResponse = z.infer<typeof AccountResponse>;

const AccountsByAuthorizers = z.object({
  accounts: z
    .array(
      z
        .object({
          account_name: z.string().max(13),
          permission_name: z.string().max(13),
          authorizing_key: z.string().max(128).optional(),
          weight: SafeInt,
          threshold: SafeInt,
        })
        .loose(),
    )
    .max(1000),
});
const KeyAccounts = z.object({ account_names: z.array(z.string().max(13)).max(1000) }).loose();
const BalanceList = z.array(z.string().max(64)).max(16);
const Health = z
  .object({
    health: z
      .array(
        z
          .object({
            service: z.string().max(64),
            service_data: z.object({ chain_id: Hex64.optional() }).loose().nullable().optional(),
          })
          .loose(),
      )
      .max(32),
  })
  .loose();

export const TransactionStatusResponse = z
  .object({
    state: z.enum([
      'LOCALLY_APPLIED',
      'IN_BLOCK',
      'IRREVERSIBLE',
      'FORKED_OUT',
      'FAILED',
      'UNKNOWN',
    ]),
    block_number: SafeInt.optional(),
    block_timestamp: AntelopeTime.optional(),
    irreversible_number: SafeInt.optional(),
  })
  .loose();
const HyperionTransaction = z
  .object({
    executed: z.boolean(),
    trx_id: z.string().regex(/^[0-9a-f]{64}$/),
    lib: SafeInt.optional(),
    actions: z
      .array(z.object({ block_num: SafeInt, '@timestamp': AntelopeTime.optional() }).loose())
      .max(1000)
      .optional(),
  })
  .loose();
const HyperionAction = z
  .object({
    '@timestamp': AntelopeTime.optional(),
    timestamp: AntelopeTime.optional(),
    block_num: SafeInt,
    trx_id: z.string().regex(/^[0-9a-f]{64}$/),
    global_sequence: SafeInt.optional(),
    act: z
      .object({
        account: z.string().max(13),
        name: z.string().max(13),
        authorization: z
          .array(z.object({ actor: z.string().max(13), permission: z.string().max(13) }).loose())
          .max(16)
          .optional(),
        data: z.unknown().optional(),
      })
      .loose(),
  })
  .loose();
const HyperionActions = z.object({ actions: z.array(z.unknown()).max(200) }).loose();
const TransferData = z
  .object({
    from: z.string().max(13),
    to: z.string().max(13),
    quantity: z.string().max(64),
    memo: z.string().max(512).optional(),
  })
  .loose();

/** `head_block_time` and friends are UTC without a zone suffix. */
export function antelopeTimeMs(time: string): number {
  return Date.parse(time.endsWith('Z') ? time : `${time}Z`);
}

/**
 * `"1.23456789 WAX"` to base units, only when the symbol and precision are the
 * token's; anything else is undefined rather than a guess.
 */
export function parseAsset(text: string, token: AntelopeToken): bigint | undefined {
  const m = /^(-?)(\d+)(?:\.(\d+))? ([A-Z]{1,7})$/.exec(text);
  if (!m || m[4] !== token.symbol) return undefined;
  const frac = m[3] ?? '';
  if (frac.length !== token.precision) return undefined;
  const units = BigInt(m[2]! + frac);
  return m[1] === '-' ? -units : units;
}

export function formatAsset(units: bigint, token: AntelopeToken): string {
  const digits = units.toString().padStart(token.precision + 1, '0');
  const whole = digits.slice(0, digits.length - token.precision);
  const frac = digits.slice(digits.length - token.precision);
  return `${whole}${token.precision > 0 ? `.${frac}` : ''} ${token.symbol}`;
}

export class AntelopeRpcError extends Error {
  override readonly name = 'AntelopeRpcError';

  constructor(
    readonly url: string,
    readonly status: number,
    readonly errorName: string,
    readonly detail: string,
  ) {
    super(`${errorName}${detail ? `: ${detail}` : ''}`.slice(0, 512));
  }
}

/** The node's verdict out of an error body (possibly truncated JSON). */
export function antelopeErrorOf(body: string): { name: string; detail: string } | undefined {
  const name = /"name"\s*:\s*"([a-z0-9_]{1,80})"/.exec(body)?.[1];
  if (!name) return undefined;
  const detail = /"message"\s*:\s*"((?:[^"\\]|\\.){0,300})"/g;
  let last = '';
  for (const m of body.matchAll(detail)) last = m[1]!;
  return { name, detail: last };
}

export interface AntelopeNode {
  url: string;
  post<T>(path: string, body: unknown, schema: z.ZodType<T>): Promise<T>;
  info(): Promise<ChainInfoResponse>;
  /** Null when the account does not exist. */
  account(name: string): Promise<AccountResponse | null>;
  balance(account: string, token: AntelopeToken): Promise<bigint>;
}

export type AntelopeAdapterOptions = BaseAdapterOptions;

/** An account the key can sign for, as the chain reported it. */
export interface LinkedAccount {
  account: string;
  permission: string;
}

export class AntelopeAdapter extends BaseAdapter<'antelope'> {
  constructor(opts: AntelopeAdapterOptions = {}) {
    super('antelope', opts);
  }

  network(chainId: ChainId): AntelopeNetwork {
    this.requireChain(chainId);
    const net = NETWORKS[chainId];
    if (!net) throw new Error(`No Antelope network profile for ${chainId}`);
    return net;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return antelopePublicKey(publicKeyBytes(pub));
  }

  /** Account names (send destinations) and `PUB_K1_…` keys (this wallet's identity). */
  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidAntelopeAccount(addr) || isValidAntelopePublicKey(addr);
  }

  private node(url: string, opts: FetchOptions = this.fetchOptions()): AntelopeNode {
    const base = url.replace(/\/$/, '');
    const post = async <T>(path: string, body: unknown, schema: z.ZodType<T>): Promise<T> => {
      let text: string;
      try {
        text = await postJsonText(`${base}${path}`, body, opts);
      } catch (error) {
        // A 4xx/500 with an Antelope error body is the node's answer, not a dead node.
        if (error instanceof HttpError && error.status < 502) {
          const verdict = antelopeErrorOf(error.body);
          if (verdict) throw new AntelopeRpcError(url, error.status, verdict.name, verdict.detail);
        }
        throw error;
      }
      return schema.parse(JSON.parse(text));
    };
    const info = () => post('/v1/chain/get_info', {}, ChainInfoResponse);
    const account = async (name: string): Promise<AccountResponse | null> => {
      try {
        return await post('/v1/chain/get_account', { account_name: name }, AccountResponse);
      } catch (error) {
        if (error instanceof AntelopeRpcError && error.errorName === 'account_query_exception')
          return null;
        throw error;
      }
    };
    const balance = async (acct: string, token: AntelopeToken): Promise<bigint> => {
      const list = await post(
        '/v1/chain/get_currency_balance',
        { code: token.contract, account: acct, symbol: token.symbol },
        BalanceList,
      );
      if (list.length === 0) return 0n;
      if (list.length !== 1) throw new Error('Node reported several balances for one symbol');
      const units = parseAsset(list[0]!, token);
      if (units === undefined || units < 0n) throw new Error('Node reported a malformed balance');
      return units;
    };
    return { url, post, info, account, balance };
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const net = this.network(chainId);
    await this.verifyEndpoint(chainId, url, async () => {
      const info = await this.node(url).info();
      if (info.chain_id !== net.chainId)
        throw new Error('Endpoint chain id does not match this Antelope network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (node: AntelopeNode) => Promise<T>): Promise<T> {
    this.network(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(this.node(url));
    });
  }

  private async hyperion<T>(
    chainId: ChainId,
    path: string,
    schema: z.ZodType<T>,
    opts: FetchOptions = this.fetchOptions(),
  ): Promise<{ value: T; source: string }> {
    const net = this.network(chainId);
    const causes: unknown[] = [];
    for (const base of net.hyperion) {
      try {
        await this.verifyEndpoint(chainId, `hyperion:${base}`, async () => {
          const health = Health.parse(await fetchJson(`${base}/v2/health`, this.fetchOptions()));
          const id = health.health.find((h) => h.service === 'NodeosRPC')?.service_data?.chain_id;
          if (id !== net.chainId) throw new Error('History endpoint chain id does not match');
        });
        return { value: schema.parse(await fetchJson(`${base}${path}`, opts)), source: base };
      } catch (error) {
        if (opts.signal?.aborted) throw error;
        causes.push(error);
      }
    }
    throw new Error(`No history endpoint answered for ${chainId}`, { cause: causes });
  }

  /**
   * Accounts whose permissions list this key, from the chain API first and
   * Hyperion as a fallback. `active` comes before other permissions.
   */
  async accountsForKey(key: string, chainId: ChainId): Promise<LinkedAccount[]> {
    const k1 = normalizeAntelopeKey(key);
    if (!k1) throw new TypeError('Invalid Antelope public key');
    let found: LinkedAccount[];
    try {
      found = await this.withNode(chainId, async (node) => {
        const res = await node.post(
          '/v1/chain/get_accounts_by_authorizers',
          { keys: [k1] },
          AccountsByAuthorizers,
        );
        return res.accounts
          .filter(
            (a) =>
              a.authorizing_key !== undefined &&
              normalizeAntelopeKey(a.authorizing_key) === k1 &&
              a.weight >= a.threshold,
          )
          .map((a) => ({ account: a.account_name, permission: a.permission_name }));
      });
    } catch {
      const { value } = await this.hyperion(
        chainId,
        `/v2/state/get_key_accounts?public_key=${encodeURIComponent(k1)}`,
        KeyAccounts,
      );
      found = value.account_names.map((account) => ({ account, permission: 'active' }));
    }
    const seen = new Set<string>();
    return found
      .filter((a) => isValidAntelopeAccount(a.account) && isValidAntelopeAccount(a.permission))
      .sort(
        (a, b) =>
          a.account.localeCompare(b.account) ||
          Number(b.permission === 'active') - Number(a.permission === 'active') ||
          a.permission.localeCompare(b.permission),
      )
      .filter((a) => {
        const k = `${a.account}@${a.permission}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
  }

  private async accountNames(addr: Address, chainId: ChainId): Promise<string[]> {
    if (isValidAntelopeAccount(addr)) return [addr];
    if (!isValidAntelopePublicKey(addr)) throw new TypeError(`invalid antelope address ${addr}`);
    return [...new Set((await this.accountsForKey(addr, chainId)).map((a) => a.account))];
  }

  /**
   * The system token (and display tokens), summed over every account linked
   * to a key when `addr` is a `PUB_K1_…` key.
   */
  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const net = this.network(chainId);
    const accounts = await this.accountNames(addr, chainId);
    const tokens = [net.token, ...(net.extraTokens ?? [])];
    if (accounts.length === 0) {
      return [
        {
          assetRef: chain.nativeAsset.ref,
          amount: '0',
          updatedAtMs: Date.now(),
          notice:
            'No account on this chain is linked to this key yet. Antelope accounts must be created on chain before they can hold funds.',
        },
      ];
    }
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const node = this.node(url);
        const sums = await Promise.all(
          tokens.map(async (t) => {
            const each = await Promise.all(accounts.map((a) => node.balance(a, t)));
            return each.reduce((s, x) => s + x, 0n).toString();
          }),
        );
        return JSON.stringify(sums);
      },
      { equal: (a, b) => a === b },
    );
    const [nativeAmount, ...extra] = JSON.parse(value) as string[];
    const across =
      addr === accounts[0] ? undefined : `Accounts linked to this key: ${accounts.join(', ')}.`;
    return [
      {
        ...nativeHolding(chain, nativeAmount!, provenance),
        ...(across ? { notice: across } : {}),
      },
      ...(net.extraTokens ?? []).map((t, i) => ({
        assetRef: tokenAssetRef(chainId, t),
        amount: extra[i] ?? '0',
        provenance,
        metadata: { symbol: t.symbol, decimals: t.precision },
        notice: 'Token balance for display; only the system token can be sent.',
        updatedAtMs: Date.now(),
      })),
    ];
  }

  /** Actions touching the account from Hyperion, newest first, paged by offset. */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    const net = this.network(chainId);
    if (cursor !== undefined && !/^[1-9]\d{0,4}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const accounts = await this.accountNames(addr, chainId);
    const account = accounts[0];
    if (!account) return { items: [], coverage: 'No account is linked to this key yet.' };
    const limit = 20;
    const skip = cursor ? Number(cursor) : 0;
    const opts: FetchOptions = {
      ...this.fetchOptions(),
      maxBodyBytes: 4 << 20,
      ...(options?.signal ? { signal: options.signal } : {}),
    };
    const { value, source } = await this.hyperion(
      chainId,
      `/v2/history/get_actions?account=${account}&limit=${limit}&skip=${skip}&sort=desc`,
      HyperionActions,
      opts,
    );
    const items = value.actions
      .map((a) => HyperionAction.safeParse(a))
      .filter((r) => r.success)
      .map((r) => actionRecord(chain.chainId, chain.nativeAsset.ref, net.token, account, r.data));
    return {
      items,
      ...(value.actions.length === limit ? { nextCursor: String(skip + limit) } : {}),
      coverage: `Actions of ${account} from Hyperion history.${
        accounts.length > 1 ? ` Other linked accounts: ${accounts.slice(1).join(', ')}.` : ''
      }`,
      source,
    };
  }

  async info(chainId: ChainId): Promise<ChainInfoResponse> {
    return this.withNode(chainId, (node) => node.info());
  }

  /**
   * POST `/v1/chain/push_transaction`. A node's verdict on the transaction is
   * returned rather than thrown, so failover does not resubmit a rejected one.
   */
  async pushTransaction(
    chainId: ChainId,
    body: unknown,
  ): Promise<{ id: string } | { error: AntelopeRpcError }> {
    const Pushed = z.object({ transaction_id: Hex64 }).loose();
    return this.withNode(chainId, async (node) => {
      try {
        const res = await node.post('/v1/chain/push_transaction', body, Pushed);
        return { id: res.transaction_id };
      } catch (error) {
        if (error instanceof AntelopeRpcError) return { error };
        throw error;
      }
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Antelope transaction id');
    const id = hash.toLowerCase();
    try {
      const st = await this.withNode(chainId, (node) =>
        node.post('/v1/chain/get_transaction_status', { id }, TransactionStatusResponse),
      );
      switch (st.state) {
        case 'IRREVERSIBLE':
          return {
            state: 'confirmed',
            blockNumber: st.block_number ?? 0,
            ...(st.block_timestamp ? { timestampMs: antelopeTimeMs(st.block_timestamp) } : {}),
          };
        case 'IN_BLOCK':
        case 'LOCALLY_APPLIED':
        case 'FORKED_OUT':
          return { state: 'pending' };
        case 'FAILED':
          return { state: 'failed', reason: 'The transaction failed on chain' };
        case 'UNKNOWN':
          break;
      }
    } catch {
      // Not every node runs the finality API; Hyperion answers below.
    }
    try {
      const { value } = await this.hyperion(
        chainId,
        `/v2/history/get_transaction?id=${id}`,
        HyperionTransaction,
      );
      if (!value.executed || value.trx_id !== id) return { state: 'unknown' };
      const block = value.actions?.[0]?.block_num;
      if (block === undefined) return { state: 'pending' };
      if (value.lib !== undefined && block > value.lib) return { state: 'pending' };
      const ts = value.actions?.[0]?.['@timestamp'];
      return {
        state: 'confirmed',
        blockNumber: block,
        ...(ts ? { timestampMs: antelopeTimeMs(ts) } : {}),
      };
    } catch {
      return { state: 'unknown' };
    }
  }
}

function actionRecord(
  chainId: string,
  nativeRef: string,
  token: AntelopeToken,
  holder: string,
  a: z.infer<typeof HyperionAction>,
): TxRecord {
  const time = a['@timestamp'] ?? a.timestamp;
  const base = {
    hash: a.trx_id,
    chainId,
    blockNumber: a.block_num,
    ...(time ? { timestampMs: antelopeTimeMs(time) } : {}),
    feeAssetRef: nativeRef,
    // Antelope charges staked or rented CPU/NET, never a token fee.
    fee: '0',
    status: 'confirmed' as const,
    ...(a.global_sequence !== undefined ? { entryId: `${a.trx_id}:${a.global_sequence}` } : {}),
  };
  const actor = a.act.authorization?.[0]?.actor ?? a.act.account;
  if (a.act.account === token.contract && a.act.name === 'transfer') {
    const data = TransferData.safeParse(a.act.data);
    const units = data.success ? parseAsset(data.data.quantity, token) : undefined;
    if (data.success && units !== undefined && units > 0n) {
      let delta = 0n;
      if (data.data.from === holder) delta -= units;
      if (data.data.to === holder) delta += units;
      return {
        ...base,
        from: data.data.from,
        to: data.data.to,
        assetDeltas: [{ assetRef: nativeRef, amount: delta.toString() }],
      };
    }
  }
  return {
    ...base,
    from: actor,
    description: `${a.act.account}::${a.act.name}`.slice(0, 200),
    assetDeltas: [],
  };
}

export function createAntelopeAdapter(opts?: AntelopeAdapterOptions): AntelopeAdapter {
  return new AntelopeAdapter(opts);
}
