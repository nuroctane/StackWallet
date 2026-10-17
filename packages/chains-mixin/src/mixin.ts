/**
 * Mixin adapter (self-custodial KERNEL flow only — never the app-custodial
 * Safe/Messenger APIs). Addresses are `XIN` + base58(spendPub || viewPub ||
 * sha3-256 checksum); the kernel RPC is a small POST envelope at
 * https://kernel.mixin.dev (CORS reflects the Origin; probed live). The
 * kernel has no address-balance RPC: UTXO discovery requires view-key
 * scanning, which lives in the Rust core and is not wired yet, so balances
 * and preparation need an injected UTXO provider (see .nur/wiring/mixin.md).
 */
import { sha3_256 } from '@noble/hashes/sha3.js';
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
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
import type { ChainFamily, ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

/** Mainnet network id (first 16 hex of the kernel network hash, live-probed). */
export const MIXIN_MAINNET = 'mixin:74c6cdb7d51af570';
/** Full kernel network hash from `getinfo`. */
export const MIXIN_NETWORK_ID = '74c6cdb7d51af57037faa1f5544f8331ced001df5964331911ca51385993b375';
/** sha256 of the XIN asset uuid. */
export const XIN_ASSET_ID = 'a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc';
/** `mixin` is not in core-client's ChainFamily enum yet; see .nur/wiring/mixin.md. */
export const MIXIN_FAMILY = 'mixin' as ChainFamily;
export const XIN_DECIMALS = 8;

export const MIXIN_CHAINS: ChainInfo[] = [
  {
    chainId: MIXIN_MAINNET,
    family: MIXIN_FAMILY,
    name: 'Mixin Kernel',
    nativeAsset: { ref: `${MIXIN_MAINNET}:native`, symbol: 'XIN', decimals: XIN_DECIMALS },
    testnet: false,
    defaultRpcs: ['https://kernel.mixin.dev'],
    extra: { coinType: 2365 },
    priceId: 'mixin',
    layer: 'L1',
  },
];

export function mixinAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^XIN[1-9A-HJ-NP-Za-km-z]{80,100}$/.test(addr)) return undefined;
  let data: Uint8Array;
  try {
    data = base58.decode(addr.slice(3));
  } catch {
    return undefined;
  }
  if (data.length !== 68) return undefined;
  const checksum = sha3_256(
    new Uint8Array([...new TextEncoder().encode('XIN'), ...data.subarray(0, 64)]),
  );
  for (let i = 0; i < 4; i++) if (checksum[i] !== data[64 + i]) return undefined;
  return data.subarray(0, 64);
}

export function isValidMixinAddress(addr: string): boolean {
  return mixinAddressBytes(addr) !== undefined;
}

/** The 64-byte account public key (spendPub || viewPub) to a `XIN` address. */
export function mixinAddressFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 64) throw new Error('Mixin public key must be 64 bytes (spend || view)');
  const checksum = sha3_256(new Uint8Array([...new TextEncoder().encode('XIN'), ...publicKey]));
  return `XIN${base58.encode(new Uint8Array([...publicKey, ...checksum.subarray(0, 4)]))}`;
}

export class MixinRpcError extends Error {
  constructor(
    message: string,
    readonly method: string,
  ) {
    super(message);
    this.name = 'MixinRpcError';
  }
}

/** One spendable kernel UTXO of the user, as `getutxo` reports it. */
export interface MixinUtxo {
  hash: string;
  index: number;
  key: string;
  mask: string;
  xinat: string;
}
export type MixinUtxoProvider = (address: Address) => Promise<MixinUtxo[]>;

export interface MixinAdapterOptions extends BaseAdapterOptions {
  /**
   * Source of the user's spendable UTXOs (hash, index, ghost key, mask,
   * amount). The kernel itself cannot enumerate them; see the wiring doc.
   */
  utxos?: MixinUtxoProvider;
}

const Hash32 = z.string().regex(/^[0-9a-fA-F]{64}$/);
const Envelope = <T extends z.ZodTypeAny>(data: T) =>
  z.object({ data: data.nullable().optional(), error: z.string().max(2048).optional() }).loose();

export const GetInfoResult = z
  .object({
    network: Hash32,
    graph: z.object({ topology: z.number().int().nonnegative().optional() }).loose().optional(),
  })
  .loose();
/** Durable transaction object; `snapshot` present means locally finalized. */
export const TransactionResult = z
  .object({
    hex: z.string().max(8_388_608).optional(),
    snapshot: z.string().nullable().optional(),
  })
  .loose();
/** Stored output; `lock` is the consuming transaction when spent/locked. */
export const UtxoResult = z
  .object({
    amount: z
      .string()
      .regex(/^\d{1,30}(\.\d{1,8})?$/)
      .optional(),
    keys: z.array(Hash32).max(16).optional(),
    mask: Hash32.optional(),
    lock: Hash32.nullable().optional(),
  })
  .loose();

export class MixinAdapter extends BaseAdapter {
  readonly utxos: MixinUtxoProvider | undefined;

  constructor(opts: MixinAdapterOptions = {}) {
    super(MIXIN_FAMILY, { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(MIXIN_CHAINS) });
    this.utxos = opts.utxos;
  }

  override chains(): ChainInfo[] {
    const catalog = chainsForFamily(MIXIN_FAMILY);
    return catalog.length > 0 ? catalog : MIXIN_CHAINS;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return mixinAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidMixinAddress(addr);
  }

  /** One kernel RPC call; the envelope answers errors as strings at HTTP 200. */
  async call<T>(
    url: string,
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): Promise<T | null> {
    if (!/^[a-z]+$/.test(method)) throw new Error('Invalid kernel method');
    const text = await postJsonText(
      url,
      { id: 'stackwallet', method, params },
      this.fetchOptions(),
    );
    const envelope = Envelope(schema).parse(JSON.parse(text));
    if (envelope.error !== undefined) throw new MixinRpcError(envelope.error, method);
    return (envelope.data ?? null) as T | null;
  }

  private checkNetwork(chainId: ChainId, url: string): Promise<void> {
    return this.verifyEndpoint(chainId, url, async () => {
      const info = await this.call(url, 'getinfo', [], GetInfoResult);
      if (!info || info.network.toLowerCase() !== MIXIN_NETWORK_ID)
        throw new Error('Endpoint serves another Mixin kernel network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidMixinAddress(addr)) throw new TypeError(`invalid mixin address ${addr}`);
    if (!this.utxos)
      throw new Error(
        'The Mixin kernel has no address-balance RPC and UTXO discovery needs ' +
          'view-key scanning in the core (not wired yet); provide MixinAdapterOptions.utxos.',
      );
    let endpoint = '';
    const total = await withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const candidates = await this.utxos!(addr);
      let sum = 0n;
      for (const u of candidates.slice(0, 64)) {
        if (!/^[0-9a-f]{64}$/.test(u.hash) || !/^\d{1,20}$/.test(u.xinat)) continue;
        const utxo = await this.call(url, 'getutxo', [u.hash, u.index], UtxoResult);
        if (utxo && !utxo.lock) sum += BigInt(u.xinat);
      }
      endpoint = url;
      return sum.toString();
    });
    return [
      {
        ...nativeHolding(chain, total, { kind: 'single', endpoint }),
        notice:
          'Summed over the injected UTXO set only; the kernel cannot enumerate address balances.',
      },
    ];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidMixinAddress(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'The kernel indexes outputs by ghost key, not by address; history needs view-key scanning, which is not wired yet.',
    };
  }

  /**
   * `gettransaction` reads durable storage (a nonempty `snapshot` is the
   * node's finalization record); `getcachetransaction` reads the mempool
   * cache. Absent from both is unknown.
   */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Mixin transaction hash');
    const value = hash.toLowerCase();
    return this.withNode(chainId, async (url) => {
      const durable = await this.call(url, 'gettransaction', [value], TransactionResult);
      if (durable) {
        // The kernel's topological order is node-local, not a block height.
        if (durable.snapshot) return { state: 'confirmed', blockNumber: 0 };
        return { state: 'pending' };
      }
      const cached = await this.call(url, 'getcachetransaction', [value], TransactionResult);
      if (cached) return { state: 'pending' };
      return { state: 'unknown' };
    });
  }
}

export function createMixinAdapter(opts?: MixinAdapterOptions): MixinAdapter {
  return new MixinAdapter(opts);
}
