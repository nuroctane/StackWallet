/**
 * Namada adapter. Addresses are bech32m with HRP `tnam` over 21 bytes: a kind
 * discriminator (0 = implicit, 1 = established; >= 2 are internal protocol
 * accounts a wallet never pays) plus a 20-byte hash. An implicit account is
 * `sha256(0x00 || ed25519_pubkey)[..20]`. Balances are CometBFT `abci_query`
 * storage reads under the multitoken account
 * `#<multitoken>/#<token>/balance/#<owner>` (a 32-byte little-endian amount);
 * status and history come from the official indexer REST API. The CometBFT
 * `/status` `node_info.network` proves which network an endpoint serves.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32m } from '@scure/base';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  fetchJson,
  fetchJsonRpc,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  HttpError,
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

/**
 * CAIP-2 forbids dots in the reference, but Namada native chain ids are
 * `<name>.<hash>`; the CAIP reference is the hash suffix.
 */
export const NAMADA_MAINNET = 'namada:5f5de2dd1b88cba30586420';
export const NAMADA_HOUSEFIRE = 'namada:cc0d3e0c033be';
export const NATIVE_CHAIN_ID: Record<string, string> = {
  [NAMADA_MAINNET]: 'namada.5f5de2dd1b88cba30586420',
  [NAMADA_HOUSEFIRE]: 'housefire-alpaca.cc0d3e0c033be',
};
export const NAMADA_HRP = 'tnam';
/** Established NAM token account; identical on mainnet and housefire genesis. */
export const NAM_TOKEN = ['tnam1q9gr66cvu4hrzm0', 'sd5kmlnjje82gs3xlfg3', 'v6nu7'].join('');
/** Internal multitoken account (`InternalAddress::Multitoken`, raw disc 9). */
const MULTITOKEN = new Uint8Array([9, ...new Uint8Array(20)]);

export const NAMADA_CHAINS: ChainInfo[] = [
  {
    chainId: NAMADA_MAINNET,
    family: 'namada',
    name: 'Namada',
    nativeAsset: { ref: `${NAMADA_MAINNET}:native`, symbol: 'NAM', decimals: 6 },
    testnet: false,
    explorerTxUrl: 'https://namada.world/tx/{hash}',
    defaultRpcs: ['https://rpc.namada.net'],
    extra: { coinType: 877 },
    priceId: 'namada',
    layer: 'L1',
  },
  {
    chainId: NAMADA_HOUSEFIRE,
    family: 'namada',
    name: 'Namada Housefire',
    nativeAsset: { ref: `${NAMADA_HOUSEFIRE}:native`, symbol: 'NAM', decimals: 6 },
    testnet: true,
    // Heliax's documented Housefire host first, the older community host
    // second; both were NXDOMAIN when probed. Kept so the testnet
    // configuration stays visible until an RPC revives.
    defaultRpcs: ['https://rpc.testnet.namada.net', 'https://rpc.housefire.namada.tech'],
    extra: { coinType: 877 },
    layer: 'L1',
  },
];

const INDEXER: Record<string, string> = {
  [NAMADA_MAINNET]: 'https://indexer.namada.net',
  // Heliax's documented Housefire indexer resolves but answers 404 on every
  // route; left empty so Housefire fails closed instead of borrowing mainnet.
  [NAMADA_HOUSEFIRE]: '',
};

export function namadaAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^tnam1[02-9ac-hj-np-z]{40}$/.test(addr)) return undefined;
  try {
    const decoded = bech32m.decode(addr as `${string}1${string}`, 45);
    if (decoded.prefix !== NAMADA_HRP) return undefined;
    const bytes = Uint8Array.from(bech32m.fromWords(decoded.words));
    if (bytes.length !== 21 || bytes[0]! > 1 || bytes.subarray(1).every((b) => b === 0))
      return undefined;
    // Only canonical encodings are accepted anywhere the address is an input.
    if (bech32m.encode(NAMADA_HRP, decoded.words, 45) !== addr) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

export function encodeNamadaAddress(bytes: Uint8Array): string | undefined {
  if (bytes.length !== 21 || bytes[0]! > 1) return undefined;
  return bech32m.encode(NAMADA_HRP, bech32m.toWords(bytes), 45);
}

export function isValidNamadaAddress(addr: string): boolean {
  return namadaAddressBytes(addr) !== undefined;
}

/** Implicit account: raw disc 0 || sha256(0x00 || pubkey)[..20], bech32m. */
export function namadaAddressFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  const tagged = new Uint8Array(33);
  tagged.set(publicKey, 1);
  const hash = sha256(tagged);
  return bech32m.encode(
    NAMADA_HRP,
    bech32m.toWords(new Uint8Array([0, ...hash.subarray(0, 20)])),
    45,
  );
}

const base64Bytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const AbciValue = z.object({
  code: z.number().int(),
  log: z.string().max(4096).optional(),
  value: z.string().max(8192).nullish(),
});
const StatusResult = z.object({
  node_info: z.object({ network: z.string().max(128) }),
  sync_info: z.object({
    latest_block_height: z
      .string()
      .regex(/^\d{1,19}$/)
      .optional(),
  }),
});
const WrapperTx = z.object({
  id: z.string().regex(/^[0-9a-f]{64}$/),
  blockHeight: z.number().int().nonnegative(),
  exitCode: z.enum(['applied', 'rejected']),
  innerTransactions: z.array(
    z.object({
      id: z.string().regex(/^[0-9a-f]{64}$/),
      kind: z.string().max(64),
      data: z.string().max(8192).optional(),
      exitCode: z.enum(['applied', 'rejected']),
    }),
  ),
});
const HistoryEntry = z.object({
  tx: z.object({
    id: z.string().regex(/^[0-9a-f]{64}$/),
    wrapperId: z.string().regex(/^[0-9a-f]{64}$/),
    kind: z.string().max(64),
    exitCode: z.enum(['applied', 'rejected']),
    data: z.string().max(8192).optional(),
  }),
  target: z.string().max(64).optional(),
  kind: z.enum(['received', 'sent']),
  blockHeight: z.number().int().nonnegative().optional(),
});
const HistoryPage = z.object({
  results: z.array(HistoryEntry).max(64),
  pagination: z.object({
    page: z.union([z.number().int(), z.string().regex(/^\d+$/)]),
    totalPages: z.union([z.number().int(), z.string().regex(/^\d+$/)]),
  }),
});
const TransferData = z.object({
  sources: z.array(z.object({ owner: z.string().max(64), amount: z.string().regex(/^\d+$/) })),
  targets: z.array(z.object({ owner: z.string().max(64), amount: z.string().regex(/^\d+$/) })),
});

export type NamadaAdapterOptions = BaseAdapterOptions;
export type NamadaCall = <T>(
  method: string,
  params: Record<string, unknown>,
  schema: z.ZodType<T>,
) => Promise<T>;

export class NamadaAdapter extends BaseAdapter<'namada'> {
  constructor(opts: NamadaAdapterOptions = {}) {
    super('namada', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(NAMADA_CHAINS) });
  }

  override chains(): ChainInfo[] {
    const catalog = chainsForFamily('namada');
    return catalog.length > 0 ? catalog : NAMADA_CHAINS;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return namadaAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidNamadaAddress(addr);
  }

  private call<T>(
    url: string,
    method: string,
    params: Record<string, unknown>,
    schema: z.ZodType<T>,
  ): Promise<T> {
    return fetchJsonRpc(url, method, params, this.fetchOptions()).then((res) => schema.parse(res));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const status = await this.call(url, 'status', {}, StatusResult);
      if (status.node_info.network !== NATIVE_CHAIN_ID[chainId])
        throw new Error('Endpoint serves another Namada network');
      const height = Number(status.sync_info.latest_block_height ?? 0);
      if (height > 0) this.noteBlock(url, height);
    });
  }

  withNode<T>(chainId: ChainId, query: (call: NamadaCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((method, params, schema) => this.call(url, method, params, schema), url);
    });
  }

  /**
   * Transparent NAM balance: a raw storage read under
   * `#<multitoken>/#<NAM>/balance/#<owner>`, decoded as a 32-byte LE amount.
   * Anchored live against the indexer on mainnet (50991780312 namnam).
   */
  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const owner = namadaAddressBytes(addr);
    if (!owner) throw new TypeError(`invalid namada address ${addr}`);
    // The multitoken segment is an internal address; encode it raw, bypassing
    // the spendable-kinds gate of encodeNamadaAddress.
    const multitoken = bech32m.encode(NAMADA_HRP, bech32m.toWords(MULTITOKEN), 45);
    const key = `#${multitoken}/#${NAM_TOKEN}/balance/#${addr}`;
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const res = await this.call(
          url,
          'abci_query',
          { path: `/shell/value/${key}`, data: '', height: '0', prove: false },
          AbciValue,
        );
        if (res.code !== 0) {
          // An untouched account has no balance entry yet: zero.
          if (/no value found|not found|does not exist/i.test(res.log ?? '')) return '0';
          throw new Error(`abci_query rejected the balance read: ${res.log ?? res.code}`);
        }
        const bytes = base64Bytes(res.value ?? '');
        if (bytes.length !== 32 || bytes.subarray(8).some((b) => b !== 0))
          throw new Error('unexpected balance encoding');
        const view = new DataView(bytes.buffer, bytes.byteOffset);
        return view.getBigUint64(0, true).toString();
      },
      { equal: (a, b) => a === b },
    );
    const holding = nativeHolding(chain, value, provenance);
    holding.notice =
      'Transparent balance only; funds in the shielded (MASP) pool are not visible to this read.';
    return [holding];
  }

  private indexer(chainId: ChainId): string {
    const base = INDEXER[chainId];
    if (!base) throw new Error(`No live Namada indexer for ${chainId}`);
    return base;
  }

  /**
   * Schema-checked indexer GET, using the adapter's fetch implementation.
   * Wasm checksums and gas prices are chain state, so the indexer must be the
   * one tracking `chainId`; a chain without a live indexer fails here rather
   * than borrowing mainnet's answers.
   */
  async indexerGet<T>(chainId: ChainId, path: string, schema: z.ZodType<T>): Promise<T> {
    return schema.parse(await fetchJson(`${this.indexer(chainId)}${path}`, this.fetchOptions()));
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.requireChain(chainId);
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Namada transaction hash');
    let res;
    try {
      res = WrapperTx.parse(
        await fetchJson(
          `${this.indexer(chainId)}/api/v1/chain/wrapper/${hash.toLowerCase()}`,
          this.fetchOptions(),
        ),
      );
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) return { state: 'unknown' };
      throw error;
    }
    if (res.exitCode === 'rejected') return { state: 'failed', reason: 'wrapper rejected' };
    const failed = res.innerTransactions.find((t) => t.exitCode === 'rejected');
    if (failed) return { state: 'failed', reason: `inner transaction ${failed.kind} rejected` };
    return { state: 'confirmed', blockNumber: res.blockHeight };
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidNamadaAddress(addr)) throw new Error('Invalid history address');
    const page = Math.max(1, Number(cursor ?? '1') || 1);
    const res = HistoryPage.parse(
      await fetchJson(
        `${this.indexer(chainId)}/api/v1/chain/history?addresses=${encodeURIComponent(addr)}&page=${page}`,
        this.fetchOptions(),
      ),
    );
    const assetRef = chain.nativeAsset.ref;
    const items: TxRecord[] = [];
    for (const entry of res.results) {
      let from = '';
      let to: string | undefined;
      let amount = '0';
      try {
        const data = TransferData.parse(JSON.parse(entry.tx.data ?? '{}'));
        const counterpart = entry.kind === 'sent' ? data.targets[0] : data.sources[0];
        from = entry.kind === 'sent' ? addr : (data.sources[0]?.owner ?? '');
        to = entry.kind === 'sent' ? counterpart?.owner : addr;
        amount = counterpart?.amount ?? '0';
      } catch {
        continue; // unparseable kinds (bonds, votes) are not transfer history
      }
      if (!isValidNamadaAddress(from) || (to !== undefined && !isValidNamadaAddress(to))) continue;
      items.push({
        entryId: entry.tx.id,
        hash: entry.tx.wrapperId,
        chainId,
        ...(entry.blockHeight !== undefined ? { blockNumber: entry.blockHeight } : {}),
        from,
        ...(to !== undefined ? { to } : {}),
        assetDeltas: [{ assetRef, amount: entry.kind === 'sent' ? `-${amount}` : amount }],
        feeAssetRef: assetRef,
        fee: null,
        status: entry.tx.exitCode === 'applied' ? 'confirmed' : 'failed',
      });
    }
    const totalPages = Number(res.pagination.totalPages);
    return {
      items,
      ...(page < totalPages ? { nextCursor: String(page + 1) } : {}),
      source: `${this.indexer(chainId)}/api/v1/chain/history`,
    };
  }
}

export function createNamadaAdapter(opts?: NamadaAdapterOptions): NamadaAdapter {
  return new NamadaAdapter(opts);
}
