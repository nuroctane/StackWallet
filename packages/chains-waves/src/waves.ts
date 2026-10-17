/**
 * Waves adapter. Addresses are base58 of
 * `0x01 || chainByte || keccak256(blake2b256(pubkey))[0..20] || checksum`;
 * reads go over the public node REST API, whose height-1 block signature is
 * pinned per network so every endpoint proves which network it serves.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  fetchText,
  postJsonText,
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

export const WAVES_MAINNET = 'waves:87';
export const WAVES_TESTNET = 'waves:84';

/** keccak256(blake2b256(x)): the Waves secure hash behind addresses. */
export function wavesSecureHash(data: Uint8Array): Uint8Array {
  return keccak_256(blake2b(data, { dkLen: 32 }));
}

export function wavesChainByte(chainId: string): number {
  if (chainId === WAVES_TESTNET) return 84; // 'T'
  if (chainId === WAVES_MAINNET) return 87; // 'W'
  throw new Error(`Unknown Waves chain ${chainId}`);
}

export function parseWavesAddress(
  addr: string,
): { hash: Uint8Array; chainByte: number } | undefined {
  if (!/^[1-9A-HJ-NP-Za-km-z]{26,36}$/.test(addr)) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(addr);
  } catch {
    return undefined;
  }
  if (bytes.length !== 26 || bytes[0] !== 1) return undefined;
  const checksum = wavesSecureHash(bytes.subarray(0, 22)).subarray(0, 4);
  for (let i = 0; i < 4; i++) if (bytes[22 + i] !== checksum[i]) return undefined;
  if (base58.encode(bytes) !== addr) return undefined;
  return { hash: bytes.subarray(2, 22), chainByte: bytes[1]! };
}

export function isValidWavesAddress(addr: string, chainId?: string): boolean {
  const parsed = parseWavesAddress(addr);
  if (!parsed) return false;
  return chainId === undefined || parsed.chainByte === wavesChainByte(chainId);
}

/** The address of a 32-byte Waves public key on the given network. */
export function wavesAddressFromPublicKey(publicKey: Uint8Array, chainId: string): string {
  if (publicKey.length !== 32) throw new Error('Waves public key must be 32 bytes');
  const raw = new Uint8Array(26);
  raw[0] = 1;
  raw[1] = wavesChainByte(chainId);
  raw.set(wavesSecureHash(publicKey).subarray(0, 20), 2);
  raw.set(wavesSecureHash(raw.subarray(0, 22)).subarray(0, 4), 22);
  return base58.encode(raw);
}

/**
 * Node answers carry bare JSON numbers that can exceed 2^53 (balances in
 * wavelets); quote long integer literals so they parse as exact strings.
 */
export function parseWavesJson(text: string): unknown {
  return JSON.parse(text.replace(/([:[,]\s*)(\d{16,})(?=\s*[,}\]])/g, '$1"$2"'));
}

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Wavelets = z.union([
  z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  z.string().regex(/^\d{1,19}$/),
]);
const TxIdB58 = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,64}$/);
const AddressB58 = z.string().max(36);

const BlockAt1 = z.object({ signature: z.string().max(120).optional() });
const Balance = z.object({
  address: z.string().optional(),
  confirmations: SafeInt.optional(),
  balance: Wavelets,
});
const AssetBalance = z.object({ balance: Wavelets });
const TxInfo = z.object({
  id: TxIdB58.optional(),
  height: SafeInt.optional(),
  timestamp: SafeInt.optional(),
  applicationStatus: z.string().max(32).optional(),
});
const HeadHeader = z.object({ timestamp: SafeInt, height: SafeInt.optional() });

const HistoryEntry = z
  .object({
    type: z.number().int(),
    id: TxIdB58,
    sender: AddressB58.optional(),
    recipient: AddressB58.optional(),
    amount: Wavelets.optional(),
    fee: Wavelets.optional(),
    assetId: z.string().max(64).nullish(),
    feeAssetId: z.string().max(64).nullish(),
    timestamp: SafeInt.optional(),
    height: SafeInt.optional(),
    applicationStatus: z.string().max(32).optional(),
  })
  .loose();
const HistoryPage = z.array(z.array(HistoryEntry).max(100)).max(8);

/** Height-1 block signatures pin the network an endpoint serves. */
const GENESIS_SIGNATURES: Record<string, string> = {
  [WAVES_TESTNET]:
    '5uqnLK3Z9eiot6FyYBfwUnbyid3abicQbAZjz38GQ1Q8XigQMxTK4C1zNkqS1SVw7FqSidbZKxWAKLVoEsp4nNqa',
  [WAVES_MAINNET]:
    'FSH8eAAzZNqnG8xgTZtz5xuLqXySsXgAjmFEC25hXMbEufiGjqWPnGCZFt6gLiVLJny16ipxRNAkkzjjhqTjBE2',
};

/** Mainnet reads worth showing; token transfers themselves are not enabled. */
const ASSETS: Record<string, { id: string; symbol: string; decimals: number }[]> = {
  [WAVES_MAINNET]: [
    { id: '34N9YcEETLWn93qYQ64EsP1x89tSruJU44RrEMSXXEPJ', symbol: 'USDT', decimals: 6 },
  ],
};

export type WavesAdapterOptions = BaseAdapterOptions;
export type WavesCall = <T>(path: string, schema: z.ZodType<T>) => Promise<T>;

export class WavesAdapter extends BaseAdapter<'waves'> {
  constructor(opts: WavesAdapterOptions = {}) {
    super('waves', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    // A Waves account's public key is the 32-byte Waves (Curve25519) key the
    // core derives from the SLIP-10 seed, not the raw Ed25519 verifying key.
    requireCurve(pub, 'ed25519');
    return wavesAddressFromPublicKey(publicKeyBytes(pub), chainId);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidWavesAddress(addr, chainId);
  }

  private async get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    const text = await fetchText(`${url.replace(/\/$/, '')}${path}`, this.fetchOptions());
    return schema.parse(parseWavesJson(text));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const genesis = await this.get(url, '/blocks/at/1', BlockAt1);
      if (genesis.signature !== GENESIS_SIGNATURES[chainId])
        throw new Error('Endpoint height-1 block does not match this Waves network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: WavesCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, schema) => this.get(url, path, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidWavesAddress(addr, chainId))
      throw new TypeError(`invalid waves address ${addr} for ${chainId}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const res = await this.get(url, `/addresses/balance/${addr}`, Balance);
        return BigInt(res.balance).toString();
      },
      { equal: (a, b) => a === b },
    );
    const tokens: Holding[] = [];
    for (const asset of ASSETS[chainId] ?? []) {
      const assetRef = `${chainId}:asset:${asset.id}`;
      const metadata = { symbol: asset.symbol, decimals: asset.decimals };
      const notice = 'Waves asset balance is read-only; asset transfers are not enabled.';
      try {
        const observed = await withCrossCheck(
          this.rpc,
          chainId,
          async (url) => {
            await this.checkNetwork(chainId, url);
            const res = await this.get(url, `/assets/balance/${addr}/${asset.id}`, AssetBalance);
            return BigInt(res.balance).toString();
          },
          { equal: (a, b) => a === b },
        );
        tokens.push({
          assetRef,
          amount: observed.value,
          provenance: observed.provenance,
          metadata,
          notice,
          updatedAtMs: Date.now(),
        });
      } catch (err) {
        tokens.push({
          assetRef,
          amount: '0',
          metadata,
          notice,
          updatedAtMs: Date.now(),
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    return [nativeHolding(chain, value, provenance), ...tokens];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidWavesAddress(addr, chainId)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(cursor))
      throw new Error('Invalid history cursor');
    return this.withNode(chainId, async (call, url) => {
      const suffix = cursor ? `?after=${cursor}` : '';
      const pages = await call(`/transactions/address/${addr}/limit/20${suffix}`, HistoryPage);
      const entries = pages.flat();
      return {
        items: entries.map((e) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, e)),
        ...(entries.length === 20 ? { nextCursor: entries[entries.length - 1]!.id } : {}),
        coverage:
          'Node account transaction index. Native WAVES transfers carry net changes; other transaction types are listed without balance changes.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(hash))
      throw new Error('Invalid Waves transaction id');
    return this.withNode(chainId, async (call) => {
      const confirmed = await this.tryGet(call, `/transactions/info/${hash}`, TxInfo);
      if (confirmed) {
        if (confirmed.applicationStatus === 'script_execution_failed')
          return { state: 'failed', reason: 'script execution failed' };
        return {
          state: 'confirmed',
          blockNumber: confirmed.height ?? 0,
          ...(confirmed.timestamp !== undefined ? { timestampMs: confirmed.timestamp } : {}),
        };
      }
      const pending = await this.tryGet(call, `/transactions/unconfirmed/info/${hash}`, TxInfo);
      return pending ? { state: 'pending' } : { state: 'unknown' };
    });
  }

  /** POST a transaction broadcast; HTTP errors come back with their body. */
  async postBroadcast(chainId: ChainId, json: unknown): Promise<{ status: number; text: string }> {
    return this.withNode(chainId, async (_call, url) => {
      try {
        const text = await postJsonText(
          `${url.replace(/\/$/, '')}/transactions/broadcast`,
          json,
          this.fetchOptions(),
        );
        return { status: 200, text };
      } catch (err) {
        if (err instanceof HttpError) return { status: err.status, text: err.body };
        throw err;
      }
    });
  }

  /** A 404 from these endpoints is an answer ("not here"), not a failure. */
  private async tryGet<T>(call: WavesCall, path: string, schema: z.ZodType<T>): Promise<T | null> {
    try {
      return await call(path, schema);
    } catch (err) {
      if (err instanceof HttpError && err.status === 404) return null;
      throw err;
    }
  }
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  e: z.infer<typeof HistoryEntry>,
): TxRecord {
  const failed = e.applicationStatus === 'script_execution_failed';
  let delta = 0n;
  let moves = false;
  if (e.type === 4 && e.assetId == null && e.amount !== undefined && !failed) {
    const amount = BigInt(e.amount);
    if (e.recipient === holder) delta += amount;
    if (e.sender === holder) delta -= amount;
    moves = true;
  }
  const fee =
    e.sender === holder && e.feeAssetId == null && e.fee !== undefined ? BigInt(e.fee) : null;
  return {
    hash: e.id,
    chainId,
    from: e.sender ?? '',
    ...(e.recipient ? { to: e.recipient } : {}),
    ...(e.height !== undefined ? { blockNumber: e.height } : {}),
    ...(e.timestamp !== undefined ? { timestampMs: e.timestamp } : {}),
    ...(e.type !== 4 ? { description: `Waves transaction type ${e.type}` } : {}),
    assetDeltas: moves ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: fee === null ? null : String(fee),
    status: failed ? 'failed' : 'confirmed',
  };
}

export function createWavesAdapter(opts?: WavesAdapterOptions): WavesAdapter {
  return new WavesAdapter(opts);
}

export { HeadHeader };
