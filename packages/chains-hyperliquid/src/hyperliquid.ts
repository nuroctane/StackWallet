/**
 * Hyperliquid (HyperCore) adapter. Accounts are Ethereum addresses; balances
 * live in the order-book L1 and are read from the public `/info` API. The
 * explorer RPC (`…/explorer`) answers per-transaction lookups.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  HttpError,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  secp256k1Uncompressed,
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

export const HYPERLIQUID_MAINNET = 'hype:mainnet';
export const HYPERLIQUID_TESTNET = 'hype:testnet';

/** The `hyperliquidChain` label user-signed actions carry; it is what separates the networks. */
export const CHAIN_LABEL: Record<string, 'Mainnet' | 'Testnet'> = {
  [HYPERLIQUID_MAINNET]: 'Mainnet',
  [HYPERLIQUID_TESTNET]: 'Testnet',
};
/** Spot USDC's token id differs per network; `tokenDetails` for the other one fails. */
const USDC_TOKEN_ID: Record<string, string> = {
  [HYPERLIQUID_MAINNET]: '0x6d1e7cde53ba9467b783cb7c530ce054',
  [HYPERLIQUID_TESTNET]: '0xeb62eee3685fc4c43992febcd9e75443',
};
/** A user-signed action that exists only on that network, carrying its chain label. */
const PINNED_TX: Record<string, string> = {
  [HYPERLIQUID_MAINNET]: '0xac13d9eeaf12d3c9ad8d044699d53602046300d44a15f29b4fdc85416e16adb4',
  [HYPERLIQUID_TESTNET]: '0xc6176fcffca86f05c7910426bf268a00005287b597ab8dd769e01b22bbac48f0',
};
/** Spot balances shown read-only; identity is the token index, decimals are `weiDecimals`. */
const SPOT_TOKENS: Record<string, { index: number; coin: string; decimals: number }[]> = {
  [HYPERLIQUID_MAINNET]: [
    { index: 0, coin: 'USDC', decimals: 8 },
    { index: 150, coin: 'HYPE', decimals: 8 },
  ],
  [HYPERLIQUID_TESTNET]: [
    { index: 0, coin: 'USDC', decimals: 8 },
    { index: 1105, coin: 'HYPE', decimals: 8 },
  ],
};
/** HyperCore launched in 2023; history paging stops there. */
const GENESIS_MS = 1_672_531_200_000;
const HISTORY_WINDOW_MS = 90 * 24 * 60 * 60 * 1000;

export function spotAssetRef(chainId: string, index: number): string {
  return `${chainId}:spot:${index}`;
}

/** EIP-55 when mixed case; all-lowercase and all-uppercase hex are accepted as is. */
export function isValidHyperliquidAddress(addr: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return false;
  const body = addr.slice(2);
  if (/^0+$/.test(body)) return false;
  if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(body.toLowerCase())));
  for (let i = 0; i < 40; i++) {
    const c = body[i]!;
    if (!/[a-fA-F]/.test(c)) continue;
    const upper = parseInt(hash[i]!, 16) >= 8;
    if ((c === c.toUpperCase()) !== upper) return false;
  }
  return true;
}

/** The canonical spelling the core signs: lowercase `0x` hex. */
export function normalizeHyperliquidAddress(addr: string): string {
  if (!isValidHyperliquidAddress(addr)) throw new TypeError(`invalid hyperliquid address ${addr}`);
  return addr.toLowerCase();
}

export function hyperliquidAddressFromPublicKey(sec1: Uint8Array): string {
  const full = secp256k1Uncompressed(sec1);
  return `0x${bytesToHex(keccak_256(full.subarray(1)).subarray(12))}`;
}

/**
 * A non-negative decimal string as integer units at `decimals` places.
 * `truncate` drops extra precision (withdrawable carries up to 10 places);
 * otherwise extra non-zero digits are an error.
 */
export function decimalToUnits(value: string, decimals: number, truncate = false): bigint {
  const m = /^(\d{1,20})(?:\.(\d{1,30}))?$/.exec(value);
  if (!m) throw new Error(`Invalid decimal amount ${value.slice(0, 40)}`);
  let frac = m[2] ?? '';
  if (frac.length > decimals) {
    if (!truncate && /[1-9]/.test(frac.slice(decimals)))
      throw new Error('Amount has more precision than the asset');
    frac = frac.slice(0, decimals);
  }
  return BigInt(m[1]!) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
}

export function endpointKind(url: string): 'api' | 'explorer' {
  try {
    return /\/explorer\/?$/.test(new URL(url).pathname) ? 'explorer' : 'api';
  } catch {
    return 'api';
  }
}
const trim = (url: string): string => url.replace(/\/$/, '');

export function cleanMessage(message: string): string {
  return message.replace(/[^\x20-\x7e]/g, '').slice(0, 512);
}

const Decimal = z.string().regex(/^\d{1,20}(\.\d{1,30})?$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Hex32 = z.string().regex(/^0x[0-9a-f]{64}$/);
const LowerAddress = z.string().regex(/^0x[0-9a-f]{40}$/);
export const ClearinghouseState = z.object({ withdrawable: Decimal }).loose();
export const SpotState = z.object({
  balances: z
    .array(
      // Some entries omit `token`; they never match a catalogued index.
      z
        .object({
          coin: z.string().max(64),
          token: SafeInt.optional(),
          total: Decimal,
          hold: Decimal,
        })
        .loose(),
    )
    .max(4096),
});
export const UserRole = z.object({ role: z.string().max(32) }).loose();
const TokenDetails = z.object({ name: z.literal('USDC') }).loose();
export const ExplorerTx = z
  .object({
    time: SafeInt,
    user: LowerAddress,
    action: z.object({ type: z.string().max(64) }).loose(),
    block: SafeInt,
    hash: Hex32,
    error: z.string().max(4096).nullable(),
  })
  .loose();
export type ExplorerTx = z.infer<typeof ExplorerTx>;
const TxDetails = z.union([
  z.object({ type: z.literal('txDetails'), tx: ExplorerTx }),
  z.object({ type: z.literal('error'), message: z.string().max(4096) }),
]);
export const UserDetails = z.object({
  type: z.literal('userDetails'),
  txs: z.array(ExplorerTx).max(10_000),
});
export const LedgerEntry = z.object({
  time: SafeInt,
  hash: Hex32,
  delta: z.object({ type: z.string().max(64) }).loose(),
});
export type LedgerEntry = z.infer<typeof LedgerEntry>;
export const Ledger = z.array(LedgerEntry).max(10_000);

/** One `/info` (api) or explorer RPC (explorer) request bound to an endpoint that proved its network. */
export type HlCall = <T>(body: Record<string, unknown>, schema: z.ZodType<T>) => Promise<T>;

export type HyperliquidAdapterOptions = BaseAdapterOptions;

export class HyperliquidAdapter extends BaseAdapter<'hyperliquid'> {
  constructor(opts: HyperliquidAdapterOptions = {}) {
    super('hyperliquid', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return hyperliquidAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidHyperliquidAddress(addr);
  }

  /** POST JSON to an exact URL; `/info` errors come back as HTTP 4xx/5xx with a short body. */
  async postTo<T>(url: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    return schema.parse(JSON.parse(await postJsonText(url, body, this.fetchOptions())));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const kind = endpointKind(url);
    await this.verifyEndpoint(chainId, url, async () => {
      if (kind === 'api') {
        const tokenId = USDC_TOKEN_ID[chainId];
        if (!tokenId) throw new Error('No network proof for this Hyperliquid chain');
        try {
          await this.postTo(`${trim(url)}/info`, { type: 'tokenDetails', tokenId }, TokenDetails);
        } catch (err) {
          if (err instanceof HttpError)
            throw new Error('Endpoint does not serve this Hyperliquid network');
          throw err;
        }
        return;
      }
      const res = await this.postTo(
        trim(url),
        { type: 'txDetails', hash: PINNED_TX[chainId] },
        TxDetails,
      );
      if (res.type !== 'txDetails' || res.tx.action['hyperliquidChain'] !== CHAIN_LABEL[chainId])
        throw new Error('Explorer does not serve this Hyperliquid network');
    });
  }

  /**
   * Run `query` against the first endpoint of `kind` that proves its network.
   * Returns undefined when no endpoint of that kind is configured.
   */
  async withKind<T>(
    chainId: ChainId,
    kind: 'api' | 'explorer',
    query: (call: HlCall, url: string) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T | undefined> {
    this.requireChain(chainId);
    const urls = this.rpc
      .endpoints(chainId)
      .map((e) => e.url)
      .filter((u) => endpointKind(u) === kind);
    if (urls.length === 0) return undefined;
    let lastError: unknown;
    for (const url of urls) {
      try {
        await this.checkNetwork(chainId, url);
        const target = kind === 'api' ? `${trim(url)}/info` : trim(url);
        return await query((body, schema) => this.postTo(target, body, schema), url);
      } catch (err) {
        if (signal?.aborted) throw err;
        lastError = err;
      }
    }
    throw lastError instanceof Error ? lastError : new Error(`No Hyperliquid ${kind} answered`);
  }

  /** Like `withKind('api')` but an absent API endpoint is an error. */
  async withApi<T>(chainId: ChainId, query: (call: HlCall, url: string) => Promise<T>): Promise<T> {
    const res = await this.withKind(chainId, 'api', async (call, url) => ({
      value: await query(call, url),
    }));
    if (!res) throw new Error('No Hyperliquid API endpoint is configured');
    return res.value;
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidHyperliquidAddress(addr))
      throw new TypeError(`invalid hyperliquid address ${addr}`);
    const user = addr.toLowerCase();
    return this.withApi(chainId, async (call, url) => {
      const [perp, spot] = await Promise.all([
        call({ type: 'clearinghouseState', user }, ClearinghouseState),
        call({ type: 'spotClearinghouseState', user }, SpotState),
      ]);
      const now = Date.now();
      const provenance = { kind: 'single', endpoint: url } as const;
      const holdings: Holding[] = [
        {
          assetRef: chain.nativeAsset.ref,
          amount: decimalToUnits(perp.withdrawable, 6, true).toString(),
          updatedAtMs: now,
          provenance,
          notice:
            'Withdrawable USDC in the HyperCore perp account; margin held by open positions is excluded.',
        },
      ];
      for (const token of SPOT_TOKENS[chainId] ?? []) {
        const entry = spot.balances.find((b) => b.token === token.index && b.coin === token.coin);
        const assetRef = spotAssetRef(chainId, token.index);
        const metadata = { symbol: token.coin, decimals: token.decimals };
        const notice = 'HyperCore spot balance; spot transfers are not enabled.';
        try {
          holdings.push({
            assetRef,
            amount: entry ? decimalToUnits(entry.total, token.decimals).toString() : '0',
            updatedAtMs: now,
            provenance,
            metadata,
            notice,
          });
        } catch (err) {
          holdings.push({
            assetRef,
            amount: '0',
            updatedAtMs: now,
            metadata,
            notice,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return holdings;
    });
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidHyperliquidAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{13}$/.test(cursor)) throw new Error('Invalid history cursor');
    const user = addr.toLowerCase();
    const endTime = cursor !== undefined ? Number(cursor) : Date.now();
    const startTime = Math.max(GENESIS_MS, endTime - HISTORY_WINDOW_MS);
    const page = await this.withKind(
      chainId,
      'api',
      async (call, url): Promise<Page<TxRecord>> => {
        const entries = await call(
          { type: 'userNonFundingLedgerUpdates', user, startTime, endTime },
          Ledger,
        );
        const items = entries
          .filter((e) => e.time >= startTime && e.time <= endTime)
          .sort((a, b) => b.time - a.time)
          .map((e) => ledgerRecord(chain.chainId, chain.nativeAsset.ref, user, e));
        return {
          items,
          ...(startTime > GENESIS_MS ? { nextCursor: String(startTime - 1) } : {}),
          coverage:
            'HyperCore non-funding ledger in 90-day pages: USDC sends, deposits, withdrawals and perp/spot moves carry perp USDC changes; spot sends, vault and lending events are listed without balance changes. Trades and funding are not included.',
          source: url,
        };
      },
      options?.signal,
    );
    return (
      page ?? {
        items: [],
        coverage: 'No Hyperliquid API endpoint is configured, so history is unavailable.',
      }
    );
  }

  /** The explorer's record of an L1 transaction hash; undefined when it has none. */
  async txDetails(hash: TxHash, chainId: ChainId): Promise<ExplorerTx | undefined> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Hyperliquid transaction hash');
    const res = await this.withKind(chainId, 'explorer', (call) =>
      call({ type: 'txDetails', hash: hash.toLowerCase() }, TxDetails),
    );
    return res?.type === 'txDetails' && res.tx.hash === hash.toLowerCase() ? res.tx : undefined;
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    const tx = await this.txDetails(hash, chainId);
    return tx ? explorerStatus(tx) : { state: 'unknown' };
  }
}

export function explorerStatus(tx: ExplorerTx): TxStatus {
  if (tx.error !== null) return { state: 'failed', reason: cleanMessage(tx.error) };
  return { state: 'confirmed', blockNumber: tx.block, timestampMs: tx.time };
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}
function micro(v: unknown): bigint {
  const s = str(v);
  return s !== undefined && Decimal.safeParse(s).success ? decimalToUnits(s, 6, true) : 0n;
}

export function ledgerRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  e: LedgerEntry,
): TxRecord {
  const d = e.delta as Record<string, unknown>;
  const from = (str(d['user']) ?? holder).toLowerCase();
  const toRaw = str(d['destination']) ?? str(d['vault']);
  const to = toRaw?.toLowerCase();
  let delta: bigint | undefined;
  let fee = 0n;
  switch (d.type) {
    case 'internalTransfer': {
      const amount = micro(d['usdc']);
      delta = (to === holder ? amount : 0n) - (from === holder ? amount : 0n);
      if (from === holder) fee = micro(d['fee']);
      break;
    }
    case 'deposit':
      delta = micro(d['usdc']);
      break;
    case 'withdraw':
      delta = -micro(d['usdc']);
      fee = micro(d['fee']);
      break;
    case 'accountClassTransfer':
      delta = d['toPerp'] === true ? micro(d['usdc']) : -micro(d['usdc']);
      break;
    case 'send':
      if (d['token'] === 'USDC') {
        const amount = micro(d['amount']);
        const perp =
          (to === holder && d['destinationDex'] === '' ? amount : 0n) -
          (from === holder && d['sourceDex'] === '' ? amount : 0n);
        // Spot-to-spot sends do not touch the perp USDC this asset tracks.
        if (perp !== 0n) delta = perp;
        if (from === holder && d['feeToken'] === 'USDC') fee = micro(d['fee']);
      }
      break;
  }
  return {
    hash: e.hash,
    chainId,
    from,
    ...(to && /^0x[0-9a-f]{40}$/.test(to) ? { to } : {}),
    timestampMs: e.time,
    ...(delta === undefined ? { description: cleanMessage(String(d.type)).slice(0, 64) } : {}),
    assetDeltas: delta === undefined ? [] : [{ assetRef: nativeRef, amount: delta.toString() }],
    feeAssetRef: nativeRef,
    fee: fee.toString(),
    status: 'confirmed',
  };
}

export function createHyperliquidAdapter(opts?: HyperliquidAdapterOptions): HyperliquidAdapter {
  return new HyperliquidAdapter(opts);
}
