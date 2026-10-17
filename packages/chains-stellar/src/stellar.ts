/**
 * Stellar adapter. Account ids are StrKey `G…` (version byte 6 << 3, the
 * Ed25519 key, CRC16-XModem little-endian, base32). Reads go over Horizon,
 * whose root document names the network passphrase, so every endpoint proves
 * which network it serves before it is trusted.
 */
import { base32nopad } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  fetchJson,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const STELLAR_TESTNET = 'stellar:testnet';
export const STELLAR_PUBNET = 'stellar:pubnet';
export const NETWORK_PASSPHRASES: Record<string, string> = {
  [STELLAR_PUBNET]: 'Public Global Stellar Network ; September 2015',
  [STELLAR_TESTNET]: 'Test SDF Network ; September 2015',
};
const ACCOUNT_VERSION = 6 << 3;

export function crc16xmodem(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++)
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

export function stellarAddressFromPublicKey(key: Uint8Array): string {
  if (key.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  const raw = new Uint8Array(35);
  raw[0] = ACCOUNT_VERSION;
  raw.set(key, 1);
  const crc = crc16xmodem(raw.subarray(0, 33));
  raw[33] = crc & 0xff;
  raw[34] = crc >> 8;
  return base32nopad.encode(raw);
}

/** The Ed25519 key behind a canonical `G…` account id; muxed `M…` ids are refused. */
export function stellarAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^G[A-Z2-7]{55}$/.test(addr)) return undefined;
  try {
    const raw = base32nopad.decode(addr);
    if (raw.length !== 35 || raw[0] !== ACCOUNT_VERSION) return undefined;
    const crc = crc16xmodem(raw.subarray(0, 33));
    if (raw[33] !== (crc & 0xff) || raw[34] !== crc >> 8) return undefined;
    const key = raw.slice(1, 33);
    // 35 bytes leave spare base32 bits; only the canonical spelling is accepted.
    return stellarAddressFromPublicKey(key) === addr ? key : undefined;
  } catch {
    return undefined;
  }
}

export function isValidStellarAddress(addr: string): boolean {
  return stellarAddressBytes(addr) !== undefined;
}

/** Horizon amounts carry exactly seven decimals; returns stroops as a decimal string. */
export function parseStroops(amount: string): string {
  if (!/^\d{1,12}\.\d{7}$/.test(amount)) throw new Error(`Invalid Stellar amount ${amount}`);
  return BigInt(amount.replace('.', '')).toString();
}

const Amount = z.string().regex(/^\d{1,12}\.\d{7}$/);
const Int64 = z.string().regex(/^\d{1,19}$/);
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const AccountId = z.string().regex(/^G[A-Z2-7]{55}$/);

const Root = z.object({ network_passphrase: z.string().max(128) });
export const HorizonAccount = z.object({
  account_id: AccountId,
  sequence: Int64,
  subentry_count: SafeInt,
  num_sponsoring: SafeInt.optional(),
  num_sponsored: SafeInt.optional(),
  balances: z
    .array(
      z.object({
        balance: Amount,
        asset_type: z.string().max(32),
        asset_code: z.string().max(12).optional(),
        asset_issuer: AccountId.optional(),
        selling_liabilities: Amount.optional(),
      }),
    )
    .max(1000),
});
export type HorizonAccount = z.infer<typeof HorizonAccount>;
export const LatestLedger = z.object({
  _embedded: z.object({
    records: z
      .array(
        z.object({
          sequence: SafeInt,
          closed_at: z.string().max(64),
          base_reserve_in_stroops: SafeInt,
          base_fee_in_stroops: SafeInt,
        }),
      )
      .length(1),
  }),
});
const HorizonTx = z.object({
  hash: Hash,
  successful: z.boolean(),
  ledger: SafeInt,
  created_at: z.string().max(64),
  result_xdr: z.string().max(4096).optional(),
});

const ASSETS: Record<string, { code: string; issuer: string; decimals: number }[]> = {
  [STELLAR_PUBNET]: [
    // Circle's USDC issuer (home_domain circle.com).
    {
      code: 'USDC',
      issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
      decimals: 7,
    },
  ],
};

export function assetRef(chainId: string, code: string, issuer: string): string {
  return `${chainId}:asset:${code}-${issuer}`;
}

export type StellarAdapterOptions = BaseAdapterOptions;
export type HorizonGet = <T>(path: string, schema: z.ZodType<T>) => Promise<T | null>;

export class StellarAdapter extends BaseAdapter<'stellar'> {
  constructor(opts: StellarAdapterOptions = {}) {
    super('stellar', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return stellarAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidStellarAddress(addr);
  }

  /** GET under a base url; a 404 is an answer (unfunded account, unknown tx) and yields null. */
  private get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T | null> {
    return this.rest(path, schema, [404])(url);
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const root = await this.get(url, '/', Root);
      if (!root || root.network_passphrase !== NETWORK_PASSPHRASES[chainId])
        throw new Error('Endpoint network passphrase does not match this Stellar network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withHorizon<T>(
    chainId: ChainId,
    query: (get: HorizonGet, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, schema) => this.get(url, path, schema), url);
    });
  }

  /** Form POST, which Horizon's submit endpoint requires; `fetchJson` only GETs. */
  async submit(
    chainId: ChainId,
    envelopeBase64: string,
  ): Promise<{ status: number; body: unknown }> {
    return this.withHorizon(chainId, async (_get, url) => {
      const doFetch = this.fetchImpl ?? globalThis.fetch;
      const res = await doFetch(`${url.replace(/\/$/, '')}/transactions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams({ tx: envelopeBase64 }).toString(),
        signal: AbortSignal.timeout(this.timeoutMs ?? 30_000),
      });
      const text = (await res.text()).slice(0, 1 << 16);
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = undefined;
      }
      // Gateway errors are a failed endpoint, not a verdict on the transaction.
      if (res.status >= 500 && res.status !== 504)
        throw new HttpError(url, res.status, text.slice(0, 512));
      return { status: res.status, body };
    });
  }

  async account(addr: Address, chainId: ChainId): Promise<HorizonAccount | null> {
    if (!isValidStellarAddress(addr)) throw new TypeError(`invalid stellar address ${addr}`);
    return this.withHorizon(chainId, (get) => get(`/accounts/${addr}`, HorizonAccount));
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidStellarAddress(addr)) throw new TypeError(`invalid stellar address ${addr}`);
    const assets = ASSETS[chainId] ?? [];
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const account = await this.get(url, `/accounts/${addr}`, HorizonAccount);
        // An account that was never funded does not exist on the ledger: zero, not an error.
        const balances = account?.balances ?? [];
        const native = balances.find((b) => b.asset_type === 'native');
        const tokens = assets.map((a) => {
          const line = balances.find(
            (b) =>
              b.asset_type !== 'native' && b.asset_code === a.code && b.asset_issuer === a.issuer,
          );
          return line ? parseStroops(line.balance) : '0';
        });
        return JSON.stringify([native ? parseStroops(native.balance) : '0', ...tokens]);
      },
      { equal: (a, b) => a === b },
    );
    const [nativeAmount, ...tokenAmounts] = JSON.parse(value) as string[];
    return [
      nativeHolding(chain, nativeAmount!, provenance),
      ...assets.map((a, i) => ({
        assetRef: assetRef(chainId, a.code, a.issuer),
        amount: tokenAmounts[i] ?? '0',
        provenance,
        metadata: { symbol: a.code, decimals: a.decimals },
        notice: 'Trustline balance from Horizon; token transfers are not enabled.',
        updatedAtMs: Date.now(),
      })),
    ];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidStellarAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,20}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const limit = 20;
    const query = new URLSearchParams({ limit: String(limit), order: 'desc' });
    if (cursor) query.set('cursor', cursor);
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      let raw: unknown;
      try {
        raw = await fetchJson(`${url.replace(/\/$/, '')}/accounts/${addr}/payments?${query}`, opts);
      } catch (err) {
        if (err instanceof HttpError && err.status === 404) return { items: [], source: url };
        throw err;
      }
      const records = PaymentsPage.parse(raw)._embedded.records;
      return {
        items: records.map((r) => paymentRecord(chain.chainId, chain.nativeAsset.ref, addr, r)),
        ...(records.length === limit
          ? { nextCursor: records[records.length - 1]!.paging_token }
          : {}),
        coverage:
          'Horizon payment operations (payments, account creation, merges, path payments). Fees are not listed per operation.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Stellar transaction hash');
    const value = hash.toLowerCase();
    return this.withHorizon(chainId, async (get) => {
      const tx = await get(`/transactions/${value}`, HorizonTx);
      // Horizon only knows transactions that reached a ledger.
      if (!tx) return { state: 'unknown' };
      if (!tx.successful) return { state: 'failed', reason: resultCode(tx.result_xdr) };
      const ts = Date.parse(tx.created_at);
      return {
        state: 'confirmed',
        blockNumber: tx.ledger,
        ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
      };
    });
  }
}

const TX_CODES: Record<number, string> = {
  [-1]: 'tx_failed',
  [-2]: 'tx_too_early',
  [-3]: 'tx_too_late',
  [-4]: 'tx_missing_operation',
  [-5]: 'tx_bad_seq',
  [-6]: 'tx_bad_auth',
  [-7]: 'tx_insufficient_balance',
  [-8]: 'tx_no_source_account',
  [-9]: 'tx_insufficient_fee',
};

/** `TransactionResult`: int64 feeCharged, int32 code, then per-operation results for tx_failed. */
export function resultCode(resultXdr: string | undefined): string {
  if (!resultXdr) return 'transaction failed';
  try {
    const bytes = Uint8Array.from(atob(resultXdr), (c) => c.charCodeAt(0));
    const view = new DataView(bytes.buffer);
    const code = view.getInt32(8);
    const name = TX_CODES[code] ?? `tx_code_${code}`;
    if (code === -1 && bytes.length >= 28) {
      // results<1>: count, opINNER, operation type, operation result code
      const opType = view.getInt32(20);
      const opCode = view.getInt32(24);
      const op = opType === 0 ? 'create_account' : opType === 1 ? 'payment' : `op${opType}`;
      return `${name}: ${op} code ${opCode}`;
    }
    return name;
  } catch {
    return 'transaction failed';
  }
}

const PaymentsPage = z.object({
  _embedded: z.object({
    records: z
      .array(
        z
          .object({
            paging_token: z.string().regex(/^\d{1,20}$/),
            transaction_successful: z.boolean().optional(),
            transaction_hash: Hash,
            type: z.string().max(64),
            created_at: z.string().max(64).optional(),
            source_account: AccountId.optional(),
            asset_type: z.string().max(32).optional(),
            asset_code: z.string().max(12).optional(),
            asset_issuer: AccountId.optional(),
            from: AccountId.optional(),
            to: AccountId.optional(),
            amount: Amount.optional(),
            funder: AccountId.optional(),
            account: AccountId.optional(),
            starting_balance: Amount.optional(),
            into: AccountId.optional(),
          })
          .loose(),
      )
      .max(200),
  }),
});
type PaymentRecord = z.infer<typeof PaymentsPage>['_embedded']['records'][number];

function paymentRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  r: PaymentRecord,
): TxRecord {
  const failed = r.transaction_successful === false;
  let from = r.source_account ?? '';
  let to: string | undefined;
  let moved: { ref: string; amount: bigint; symbol?: string; decimals?: number } | undefined;
  if (r.type === 'create_account' && r.funder && r.account && r.starting_balance) {
    from = r.funder;
    to = r.account;
    moved = { ref: nativeRef, amount: BigInt(parseStroops(r.starting_balance)) };
  } else if (r.type === 'payment' && r.from && r.to && r.amount) {
    from = r.from;
    to = r.to;
    if (r.asset_type === 'native')
      moved = { ref: nativeRef, amount: BigInt(parseStroops(r.amount)) };
    else if (r.asset_code && r.asset_issuer)
      moved = {
        ref: assetRef(chainId, r.asset_code, r.asset_issuer),
        amount: BigInt(parseStroops(r.amount)),
        symbol: r.asset_code,
        decimals: 7,
      };
  } else if (r.type === 'account_merge') {
    from = r.account ?? from;
    to = r.into;
  } else {
    to = r.to;
  }
  let delta = 0n;
  if (moved && !failed) {
    if (to === holder) delta += moved.amount;
    if (from === holder) delta -= moved.amount;
  }
  const ts = r.created_at ? Date.parse(r.created_at) : NaN;
  return {
    entryId: r.paging_token,
    hash: r.transaction_hash,
    chainId,
    from,
    ...(to ? { to } : {}),
    ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
    ...(r.type !== 'payment' && r.type !== 'create_account' ? { description: r.type } : {}),
    assetDeltas: moved
      ? [
          {
            assetRef: moved.ref,
            amount: String(delta),
            ...(moved.symbol ? { symbol: moved.symbol, decimals: moved.decimals } : {}),
          },
        ]
      : [],
    feeAssetRef: nativeRef,
    fee: null,
    status: failed ? 'failed' : 'confirmed',
  };
}

export function createStellarAdapter(opts?: StellarAdapterOptions): StellarAdapter {
  return new StellarAdapter(opts);
}
