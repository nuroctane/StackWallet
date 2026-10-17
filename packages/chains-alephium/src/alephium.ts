/**
 * Alephium adapter. P2PKH addresses are base58 of `0x00 || blake2b-256(compressed
 * secp256k1 pubkey)` with no checksum. Reads go over the full-node REST API,
 * which proves which network it serves by its `/infos/chain-params` network id
 * (mainnet 0, testnet 1); history comes from the keyless explorer backend.
 */
import { base58 } from '@scure/base';
import { blake2b } from '@noble/hashes/blake2.js';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
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
  type ChainInfo,
  type Holding,
  type HistoryOptions,
  type Page,
  type RpcPool,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

/** CAIP-2 references are the chain's `network_id`. */
export const ALEPHIUM_MAINNET = 'alephium:0';
export const ALEPHIUM_TESTNET = 'alephium:1';
export const ALPH_NETWORK_ID: Readonly<Record<string, number>> = Object.freeze({
  [ALEPHIUM_MAINNET]: 0,
  [ALEPHIUM_TESTNET]: 1,
});
export const ALPH_DECIMALS = 18;

function chain(
  chainId: string,
  name: string,
  testnet: boolean,
  rpcs: string[],
  explorerTxUrl: string,
): ChainInfo {
  return {
    chainId,
    family: 'alephium',
    name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'ALPH', decimals: ALPH_DECIMALS },
    testnet,
    explorerTxUrl,
    defaultRpcs: rpcs,
    extra: { coinType: 1234 },
    layer: 'L1',
    ...(testnet ? {} : { priceId: 'alephium' }),
  };
}

/** Used until the shared catalog lists the family; the catalog wins once it does. */
export const ALEPHIUM_CHAINS: readonly ChainInfo[] = Object.freeze([
  chain(
    ALEPHIUM_MAINNET,
    'Alephium',
    false,
    ['https://node.mainnet.alephium.org', 'https://backend.mainnet.alephium.org'],
    'https://explorer.alephium.org/transactions/{hash}',
  ),
  chain(
    ALEPHIUM_TESTNET,
    'Alephium Testnet',
    true,
    ['https://node.testnet.alephium.org', 'https://backend.testnet.alephium.org'],
    'https://testnet.alephium.org/transactions/{hash}',
  ),
]);

export function alephiumChains(): ChainInfo[] {
  const listed = chainsForFamily('alephium');
  return listed.length > 0 ? listed : [...ALEPHIUM_CHAINS];
}

const P2PKH = 0x00;

/** The 33 bytes (`0x00 || pubkey hash`) behind a canonical P2PKH address, or undefined. */
export function alphAddressBytes(addr: string): Uint8Array | undefined {
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(addr);
  } catch {
    return undefined;
  }
  if (bytes.length !== 33 || bytes[0] !== P2PKH) return undefined;
  if (bytes.subarray(1).every((b) => b === 0)) return undefined;
  return bytes;
}

export function isValidAlphAddress(addr: string): boolean {
  return alphAddressBytes(addr) !== undefined;
}

export function alphAddressFromPublicKey(sec1: Uint8Array): string {
  const compressed = secp256k1Compressed(sec1);
  const bytes = new Uint8Array(33);
  bytes.set(blake2b(compressed, { dkLen: 32 }), 1);
  return base58.encode(bytes);
}

/** The shard group of a P2PKH address (djb2 hint of the pubkey hash, xor-folded, mod 4). */
export function alphGroupOfAddress(addr: string): number | undefined {
  const bytes = alphAddressBytes(addr);
  if (!bytes) return undefined;
  let hash = 5381;
  for (const byte of bytes.subarray(1)) hash = (Math.imul(hash, 33) + byte) >>> 0;
  const hint = (hash | 1) >>> 0;
  return (
    (((hint >>> 24) ^ ((hint >>> 16) & 0xff) ^ ((hint >>> 8) & 0xff) ^ (hint & 0xff)) >>> 0) % 4
  );
}

const Hex32 = z.string().regex(/^[0-9a-f]{64}$/);
const AttoAlph = z.string().regex(/^[0-9]{1,39}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const ChainParams = z.object({
  networkId: z.number().int().nonnegative().max(255),
  groups: z.number().int().positive().max(16),
});
export const Balance = z.object({
  balance: AttoAlph,
  lockedBalance: AttoAlph.optional(),
  utxoNum: SafeInt.optional(),
});
export const Utxos = z.object({
  utxos: z
    .array(
      z.object({
        ref: z.object({ hint: z.number().int(), key: Hex32 }),
        amount: AttoAlph,
        tokens: z
          .array(z.object({ id: Hex32, amount: AttoAlph }))
          .max(64)
          .optional(),
        lockTime: SafeInt.optional(),
      }),
    )
    .max(4096),
});
export const TxStatusInfo = z.object({
  type: z.enum(['Confirmed', 'MemPooled', 'TxNotFound']),
  blockHash: Hex32.optional(),
  txIndex: SafeInt.optional(),
});
export const BlockHeader = z.object({
  hash: Hex32,
  timestamp: SafeInt,
  height: SafeInt,
  chainFrom: SafeInt,
  chainTo: SafeInt,
});
export const SubmitResult = z.object({
  txId: Hex32,
  fromGroup: SafeInt,
  toGroup: SafeInt,
});
const HistoryInput = z.object({
  address: z.string().max(64).optional(),
  attoAlphAmount: AttoAlph.optional(),
});
const HistoryOutput = z.object({
  address: z.string().max(64).optional(),
  attoAlphAmount: AttoAlph.optional(),
});
const HistoryTx = z.object({
  hash: Hex32,
  timestamp: SafeInt.optional(),
  inputs: z.array(HistoryInput).max(1024),
  outputs: z.array(HistoryOutput).max(1024),
  gasAmount: SafeInt,
  gasPrice: AttoAlph,
  coinbase: z.boolean(),
  scriptExecutionOk: z.boolean().optional(),
});
const HistoryPage = z.array(HistoryTx).max(1000);

const HISTORY_LIMIT = 20;
const MAX_HISTORY_PAGE = 500;

export type AlphAdapterOptions = BaseAdapterOptions;
export type AlphGet = <T>(path: string, schema: z.ZodType<T>) => Promise<T>;
export type AlphPost = <T>(path: string, body: unknown, schema: z.ZodType<T>) => Promise<T>;
export interface AlphNode {
  get: AlphGet;
  post: AlphPost;
  url: string;
}

export class AlephiumAdapter extends BaseAdapter<'alephium'> {
  constructor(opts: AlphAdapterOptions = {}) {
    super('alephium', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(alephiumChains()) });
  }

  override chains(): ChainInfo[] {
    return alephiumChains();
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return alphAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidAlphAddress(addr);
  }

  private get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    return fetchJson(`${url.replace(/\/$/, '')}${path}`, this.fetchOptions()).then((v) =>
      schema.parse(v),
    );
  }

  private post<T>(url: string, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    return postJsonText(`${url.replace(/\/$/, '')}${path}`, body, this.fetchOptions()).then(
      (text) => schema.parse(JSON.parse(text)),
    );
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const params = await this.get(url, '/infos/chain-params', ChainParams);
      if (params.networkId !== ALPH_NETWORK_ID[chainId])
        throw new Error('Endpoint network id does not match this Alephium network');
    });
  }

  /** Node endpoints only: explorer backends share the rpc list but speak a different API. */
  private nodePool(): RpcPool {
    const inner = this.rpc;
    return {
      endpoints: (chainId) =>
        inner
          .endpoints(chainId)
          .filter((e) => !/backend\.(mainnet|testnet)\.alephium\.org/.test(e.url)),
      setEndpoints: (chainId, urls) => inner.setEndpoints(chainId, urls),
    };
  }

  /** Keep dependent observations on one node endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (node: AlphNode) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.nodePool(), chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query({
        get: (path, schema) => this.get(url, path, schema),
        post: (path, body, schema) => this.post(url, path, body, schema),
        url,
      });
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidAlphAddress(addr)) throw new TypeError(`invalid alephium address ${addr}`);
    const observed = await withCrossCheck(
      this.nodePool(),
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const balance = await this.get(url, `/addresses/${addr}/balance`, Balance);
        return `${BigInt(balance.balance)}:${BigInt(balance.lockedBalance ?? 0)}`;
      },
      { equal: (a, b) => a === b },
    );
    const [total, locked] = observed.value.split(':') as [string, string];
    const holding = nativeHolding(chain, total, observed.provenance);
    if (locked !== '0')
      holding.notice = `${locked} attoalph of this balance is timelocked and cannot be spent yet.`;
    return [holding];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidAlphAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[1-9]\d{0,3}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const page = cursor === undefined ? 1 : Number(cursor);
    if (page > MAX_HISTORY_PAGE) throw new Error('Invalid history cursor');
    // Only the explorer backend serves indexed address history.
    const backends = this.rpc
      .endpoints(chainId)
      .filter((e) => /backend\.(mainnet|testnet)\.alephium\.org/.test(e.url));
    if (backends.length === 0)
      return {
        items: [],
        coverage:
          'No explorer backend endpoint is configured for this network, so history is unavailable.',
      };
    let lastError: unknown;
    for (const { url } of backends) {
      try {
        const txs = HistoryPage.parse(
          await fetchJson(
            `${url.replace(/\/$/, '')}/addresses/${addr}/transactions?page=${page}&limit=${HISTORY_LIMIT}`,
            { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) },
          ),
        );
        return {
          items: txs
            .filter((t) => !t.coinbase)
            .map((t) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t)),
          ...(txs.length === HISTORY_LIMIT ? { nextCursor: String(page + 1) } : {}),
          coverage:
            'Alephium explorer-backend account transactions. Token movements are not listed; the fee is gas burned by the sender.',
          source: url,
        };
      } catch (err) {
        if (options?.signal?.aborted) throw err;
        lastError = err;
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Alephium history is unavailable');
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Alephium transaction id');
    const id = hash.toLowerCase();
    return this.withNode(chainId, async ({ get }) => {
      const status = await get(`/transactions/status?txId=${id}`, TxStatusInfo);
      if (status.type === 'TxNotFound') return { state: 'unknown' };
      if (status.type === 'MemPooled') return { state: 'pending' };
      if (!status.blockHash) return { state: 'pending' };
      const block = await get(`/blockflow/blocks/${status.blockHash}`, BlockHeader);
      return {
        state: 'confirmed',
        blockNumber: block.height,
        timestampMs: block.timestamp,
      };
    });
  }
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof HistoryTx>,
): TxRecord {
  let delta = 0n;
  let from = '';
  let to = '';
  for (const input of t.inputs) {
    if (input.address === holder && input.attoAlphAmount !== undefined)
      delta -= BigInt(input.attoAlphAmount);
    if (input.address && !from) from = input.address;
  }
  for (const output of t.outputs) {
    if (output.address === holder && output.attoAlphAmount !== undefined)
      delta += BigInt(output.attoAlphAmount);
    if (output.address && output.address !== from && !to) to = output.address;
  }
  const failed = t.scriptExecutionOk === false;
  const fee = from === holder ? BigInt(t.gasAmount) * BigInt(t.gasPrice) : 0n;
  return {
    hash: t.hash,
    chainId,
    from,
    ...(to ? { to } : {}),
    ...(t.timestamp !== undefined ? { timestampMs: t.timestamp } : {}),
    assetDeltas: delta !== 0n ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: String(fee),
    status: failed ? 'failed' : 'confirmed',
  };
}

export function createAlephiumAdapter(opts?: AlphAdapterOptions): AlephiumAdapter {
  return new AlephiumAdapter(opts);
}
