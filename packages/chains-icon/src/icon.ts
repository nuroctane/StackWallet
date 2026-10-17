/**
 * ICON (goloop) adapter. Addresses are `hx` + 40 lowercase hex of
 * sha3-256(uncompressed pubkey)[12..] — ICON uses SHA3-256, not keccak.
 * Reads go over the goloop JSON-RPC v3 API; every endpoint proves its
 * network by reporting the pinned block-1,000,000 hash of the chain.
 * Indexed history comes from the public tracker REST API (keyless).
 */
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  fetchJson,
  fetchJsonRpc,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
  secp256k1Uncompressed,
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

export const ICON_MAINNET = 'icon:1';
export const ICON_LISBON = 'icon:2';

export const IconAddress = z.string().regex(/^hx[0-9a-f]{40}$/);
const TxHashHex = z.string().regex(/^0x[0-9a-f]{64}$/);
/** Canonical goloop hex quantity: 0x0 or 0x followed by a non-zero-padded hex. */
const HexQuantity = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/);

/** Block 1,000,000 hash per network (live-probed; mainnet node and tracker agree). */
const ANCHOR_HEIGHT = '0xf4240';
const ANCHOR_HASH: Record<string, string> = {
  [ICON_MAINNET]: 'd945aeae050639e2f8f67f8cb4cb456ab833cf0923e69326e12b066ff51d311c',
  [ICON_LISBON]: '0368d6a741b4d91e8ca1ec503168c804ad6b215975a74617c24fa2d4abaccce0',
};

/** Public keyless tracker REST API per network (CORS verified). */
export const ICON_TRACKER: Record<string, string> = {
  [ICON_MAINNET]: 'https://tracker.icon.community',
  [ICON_LISBON]: 'https://tracker.lisbon.icon.community',
};

/** Balanced Dollar (bnUSD), the main ICON-native stablecoin; mainnet only. */
const IRC2: Record<string, { address: string; symbol: string; decimals: number }[]> = {
  [ICON_MAINNET]: [
    { address: 'cx88fd7df7ddff82f7cc735c871dc519838cb235bb', symbol: 'bnUSD', decimals: 18 },
  ],
};

export function iconAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^hx[0-9a-f]{40}$/.test(addr)) return undefined;
  const bytes = hexToBytes(addr.slice(2));
  if (bytes.every((b) => b === 0)) return undefined;
  return bytes;
}

export function isValidIconAddress(addr: string): boolean {
  return iconAddressBytes(addr) !== undefined;
}

export function iconAddressFromPublicKey(sec1: Uint8Array): string {
  const full = secp256k1Uncompressed(sec1);
  return `hx${bytesToHex(sha3_256(full.subarray(1)).subarray(12))}`;
}

const BlockAnchor = z.object({ block_hash: z.string().regex(/^[0-9a-f]{64}$/) });
const LastBlock = z.object({
  height: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  block_hash: z.string().regex(/^[0-9a-f]{64}$/),
  time_stamp: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
const TxResult = z.object({
  status: HexQuantity,
  blockHeight: HexQuantity,
  failure: z
    .object({ code: HexQuantity.optional(), message: z.string().max(2048).optional() })
    .optional(),
});
const TxByHash = z.object({
  txHash: TxHashHex.optional(),
  txIndex: HexQuantity.optional(),
  blockHeight: HexQuantity.optional(),
});

/** Live-probed defaults; used until the shared catalog wires the icon family. */
export const ICON_CHAINS: ChainInfo[] = [
  {
    chainId: ICON_LISBON,
    family: 'icon',
    name: 'ICON Lisbon',
    nativeAsset: { ref: `${ICON_LISBON}:native`, symbol: 'ICX', decimals: 18 },
    testnet: true,
    explorerTxUrl: 'https://tracker.lisbon.icon.community/transaction/{hash}',
    defaultRpcs: ['https://api.lisbon.icon.community/api/v3'],
    layer: 'L1',
  },
  {
    chainId: ICON_MAINNET,
    family: 'icon',
    name: 'ICON',
    nativeAsset: { ref: `${ICON_MAINNET}:native`, symbol: 'ICX', decimals: 18 },
    testnet: false,
    explorerTxUrl: 'https://tracker.icon.community/transaction/{hash}',
    defaultRpcs: ['https://ctz.solidwallet.io/api/v3', 'https://api.icon.community/api/v3'],
    layer: 'L1',
    priceId: 'icon',
  },
];

export type IconAdapterOptions = BaseAdapterOptions;
export type IconCall = <T>(method: string, params: unknown, schema: z.ZodType<T>) => Promise<T>;

export class IconAdapter extends BaseAdapter<'icon'> {
  private readonly knownChains: ChainInfo[];

  constructor(opts: IconAdapterOptions = {}) {
    const catalog = chainsForFamily('icon');
    const chains = catalog.length ? catalog : ICON_CHAINS;
    super('icon', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(chains) });
    this.knownChains = chains;
  }

  override chains(): ChainInfo[] {
    return this.knownChains;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return iconAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidIconAddress(addr);
  }

  /** One JSON-RPC v3 call; fetchJsonRpc turns a goloop error reply into a JsonRpcError. */
  private async call<T>(url: string, method: string, params: unknown, schema: z.ZodType<T>) {
    return schema.parse(
      await fetchJsonRpc(url, method, params as Record<string, unknown>, this.fetchOptions()),
    );
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const anchor = await this.call(
        url,
        'icx_getBlockByHeight',
        { height: ANCHOR_HEIGHT },
        BlockAnchor,
      );
      if (anchor.block_hash !== ANCHOR_HASH[chainId])
        throw new Error('Endpoint block anchor does not match this ICON network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: IconCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((method, params, schema) => this.call(url, method, params, schema), url);
    });
  }

  /** The chain head a proven endpoint reports; also feeds pool health. */
  async headBlock(
    chainId: ChainId,
  ): Promise<{ height: number; hash: string; timestampMs: number }> {
    return this.withNode(chainId, async (call, url) => {
      const head = await call('icx_getLastBlock', {}, LastBlock);
      this.noteBlock(url, head.height);
      return {
        height: head.height,
        hash: head.block_hash,
        timestampMs: Math.floor(head.time_stamp / 1000),
      };
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidIconAddress(addr)) throw new TypeError(`invalid icon address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const balance = await this.call(url, 'icx_getBalance', { address: addr }, HexQuantity);
        return BigInt(balance).toString();
      },
      { equal: (a, b) => a === b },
    );
    const tokens: Holding[] = [];
    for (const token of IRC2[chainId] ?? []) {
      const assetRef = `${chainId}:irc2:${token.address}`;
      const metadata = { symbol: token.symbol, decimals: token.decimals };
      const notice = 'IRC-2 balance from balanceOf; token transfers are not enabled.';
      try {
        const observed = await withCrossCheck(
          this.rpc,
          chainId,
          async (url) => {
            await this.checkNetwork(chainId, url);
            const balance = await this.call(
              url,
              'icx_call',
              {
                to: token.address,
                dataType: 'call',
                data: { method: 'balanceOf', params: { _owner: addr } },
              },
              HexQuantity,
            );
            return BigInt(balance).toString();
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
    if (!isValidIconAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[0-9]{1,9}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const tracker = ICON_TRACKER[chainId];
    if (!tracker) {
      return { items: [], coverage: 'No tracker is configured for this ICON network.' };
    }
    const limit = 25;
    const query = new URLSearchParams({ address: addr, limit: String(limit) });
    if (cursor) query.set('skip', cursor);
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    const res = TrackerPage.parse(
      await fetchJson(`${tracker}/api/v1/transactions?${query.toString()}`, opts),
    );
    return {
      items: res.map((t) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t)),
      ...(res.length === limit ? { nextCursor: String((Number(cursor) || 0) + limit) } : {}),
      coverage:
        'ICON tracker account transactions. ICX transfers carry net changes; SCORE calls are listed without balance changes. Fees are step charged to the sender.',
      source: tracker,
    };
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid ICON transaction hash');
    const txHash = hash.toLowerCase();
    return this.withNode(chainId, async (call) => {
      try {
        const result = await call('icx_getTransactionResult', { txHash }, TxResult);
        if (result.status === '0x1') {
          return {
            state: 'confirmed',
            blockNumber: Number(BigInt(result.blockHeight)),
          };
        }
        return {
          state: 'failed',
          ...(result.failure?.message ? { reason: result.failure.message.slice(0, 256) } : {}),
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        // goloop answers "Pending: Pending" (-31002) while the tx sits in the mempool.
        if (/pending/i.test(message)) return { state: 'pending' };
        if (!/not found/i.test(message)) throw err;
      }
      // No result yet: a hash the node still knows about is pending, else unknown.
      try {
        await call('icx_getTransactionByHash', { txHash }, TxByHash);
        return { state: 'pending' };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (/not found|pending/i.test(message)) return { state: 'unknown' };
        throw err;
      }
    });
  }
}

const TrackerTx = z.object({
  hash: TxHashHex,
  from_address: z.string().max(64),
  to_address: z.string().max(64),
  value: z.string().max(80),
  block_timestamp: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  block_number: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  transaction_fee: z.string().max(80),
  status: z.string().max(16),
  method: z.string().max(64).optional(),
  transaction_type: z.number().int().nonnegative().max(10).optional(),
});
const TrackerPage = z.array(TrackerTx).max(200);

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof TrackerTx>,
): TxRecord {
  const failed = t.status !== '0x1';
  let delta = 0n;
  const plainTransfer = !t.method;
  if (plainTransfer && /^0x[0-9a-f]+$/.test(t.value) && !failed) {
    const amount = BigInt(t.value);
    if (t.to_address === holder) delta += amount;
    if (t.from_address === holder) delta -= amount;
  }
  const fee =
    t.from_address === holder && /^0x[0-9a-f]+$/.test(t.transaction_fee)
      ? BigInt(t.transaction_fee)
      : 0n;
  return {
    hash: t.hash,
    chainId,
    from: t.from_address,
    ...(t.to_address ? { to: t.to_address } : {}),
    blockNumber: t.block_number,
    timestampMs: Math.floor(t.block_timestamp / 1000),
    ...(t.method ? { description: t.method } : {}),
    assetDeltas:
      delta !== 0n || plainTransfer ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: String(fee),
    status: failed ? 'failed' : 'confirmed',
  };
}

export function createIconAdapter(opts?: IconAdapterOptions): IconAdapter {
  return new IconAdapter(opts);
}
