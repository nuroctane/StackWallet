/**
 * VeChainThor adapter. Addresses are Ethereum-style keccak addresses that thor
 * reports in lowercase; reads go over the thorest REST API, and every endpoint
 * proves which network it serves by its genesis block id.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  fetchJson,
  nativeHolding,
  postJsonText,
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

/** CAIP-2 references are the last 16 bytes of the genesis id, as VeChain's WalletConnect uses. */
export const VECHAIN_TESTNET = 'vechain:87721b09ed2e15997f466536b20bb127';
export const VECHAIN_MAINNET = 'vechain:b1ac3413d346d43539627e6be7ec1b4a';
export const VECHAIN_GENESIS: Readonly<Record<string, string>> = Object.freeze({
  [VECHAIN_TESTNET]: '0x000000000b2bce3c70bc649a02749e8687721b09ed2e15997f466536b20bb127',
  [VECHAIN_MAINNET]: '0x00000000851caf3cfdb6e899cf5958bfb1ac3413d346d43539627e6be7ec1b4a',
});
/** The energy (VTHO) built-in contract; VTHO pays every VeChain fee. */
export const VTHO_ADDRESS = '0x0000000000000000000000000000456e65726779';
export const vthoAssetRef = (chainId: string) => `${chainId}:vip180:${VTHO_ADDRESS}`;

function chain(
  chainId: string,
  name: string,
  testnet: boolean,
  rpcs: string[],
  explorerTxUrl: string,
): ChainInfo {
  return {
    chainId,
    family: 'vechain',
    name,
    nativeAsset: { ref: `${chainId}:native`, symbol: 'VET', decimals: 18 },
    testnet,
    explorerTxUrl,
    defaultRpcs: rpcs,
    extra: { coinType: 818 },
    layer: 'L1',
    ...(testnet ? {} : { priceId: 'vechain' }),
  };
}

/** Used until the shared catalog lists the family; the catalog wins once it does. */
export const VECHAIN_CHAINS: readonly ChainInfo[] = Object.freeze([
  chain(
    VECHAIN_MAINNET,
    'VeChain',
    false,
    [
      'https://mainnet.vechain.org',
      'https://mainnet.vecha.in',
      'https://node-mainnet.vechain.energy',
    ],
    'https://explore.vechain.org/transactions/{hash}',
  ),
  chain(
    VECHAIN_TESTNET,
    'VeChain Testnet',
    true,
    [
      'https://testnet.vechain.org',
      'https://testnet.vecha.in',
      'https://node-testnet.vechain.energy',
    ],
    'https://insight.vecha.in/#/test/txs/{hash}',
  ),
]);

export function vechainChains(): ChainInfo[] {
  const listed = chainsForFamily('vechain');
  return listed.length > 0 ? listed : [...VECHAIN_CHAINS];
}

function checksum(lower: string): string {
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(lower)));
  let out = '0x';
  for (let i = 0; i < 40; i++)
    out += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i]!;
  return out;
}

/** 20 address bytes from lowercase hex or a valid EIP-55 spelling; the zero address is refused. */
export function vechainAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return undefined;
  const lower = addr.slice(2).toLowerCase();
  if (addr.slice(2) !== lower && checksum(lower) !== addr) return undefined;
  if (/^0{40}$/.test(lower)) return undefined;
  return hexToBytes(lower);
}

export function isValidVechainAddress(addr: string): boolean {
  return vechainAddressBytes(addr) !== undefined;
}

/** The canonical lowercase form the core signs over. */
export function normalizeVechainAddress(addr: string): string | undefined {
  return isValidVechainAddress(addr) ? addr.toLowerCase() : undefined;
}

export function vechainAddressFromPublicKey(sec1: Uint8Array): string {
  const full = secp256k1Uncompressed(sec1);
  return `0x${bytesToHex(keccak_256(full.subarray(1)).subarray(12))}`;
}

const Hex256 = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const Id = z.string().regex(/^0x[0-9a-f]{64}$/);
const Addr = z.string().regex(/^0x[0-9a-f]{40}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const Block = z.object({
  number: SafeInt,
  id: Id,
  timestamp: SafeInt,
  baseFeePerGas: Hex256.optional(),
});
export const Account = z.object({ balance: Hex256, energy: Hex256, hasCode: z.boolean() });
const Receipt = z
  .object({
    reverted: z.boolean(),
    gasUsed: SafeInt.optional(),
    paid: Hex256.optional(),
    meta: z.object({ blockID: Id, blockNumber: SafeInt, blockTimestamp: SafeInt }),
  })
  .nullable();
const TxLookup = z
  .object({
    id: Id,
    meta: z.object({ blockID: Id, blockNumber: SafeInt, blockTimestamp: SafeInt }).nullable(),
  })
  .nullable();
const TransferLogs = z
  .array(
    z.object({
      sender: Addr,
      recipient: Addr,
      amount: Hex256,
      meta: z.object({
        blockID: Id,
        blockNumber: SafeInt,
        blockTimestamp: SafeInt,
        txID: Id,
        txOrigin: Addr,
        clauseIndex: z.number().int().nonnegative().max(1024),
      }),
    }),
  )
  .max(100);

const HISTORY_PAGE = 20;
const MAX_HISTORY_OFFSET = 10_000;

export type VechainAdapterOptions = BaseAdapterOptions;
export type VechainGet = <T>(path: string, schema: z.ZodType<T>) => Promise<T>;
export type VechainPost = <T>(path: string, body: unknown, schema: z.ZodType<T>) => Promise<T>;
export interface VechainNode {
  get: VechainGet;
  post: VechainPost;
  url: string;
}

export class VechainAdapter extends BaseAdapter<'vechain'> {
  constructor(opts: VechainAdapterOptions = {}) {
    super('vechain', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(vechainChains()) });
  }

  override chains(): ChainInfo[] {
    return vechainChains();
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return vechainAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidVechainAddress(addr);
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
      const genesis = await this.get(url, '/blocks/0', Block);
      if (genesis.id !== VECHAIN_GENESIS[chainId])
        throw new Error('Endpoint genesis block does not match this VeChain network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (node: VechainNode) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
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
    const owner = normalizeVechainAddress(addr);
    if (!owner) throw new TypeError(`invalid vechain address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const account = await this.get(url, `/accounts/${owner}`, Account);
        return `${BigInt(account.balance)}:${BigInt(account.energy)}`;
      },
      { equal: (a, b) => a === b },
    );
    const [vet, vtho] = value.split(':') as [string, string];
    // Cross-check provenance describes the pair; report each side's own other value.
    const split = (i: 0 | 1) =>
      provenance.kind === 'disagreed'
        ? { ...provenance, other: provenance.other.split(':')[i] ?? provenance.other }
        : provenance;
    const updatedAtMs = Date.now();
    return [
      nativeHolding(chain, vet, split(0), updatedAtMs),
      {
        assetRef: vthoAssetRef(chainId),
        amount: vtho,
        provenance: split(1),
        metadata: { symbol: 'VTHO', decimals: 18 },
        notice:
          'VTHO is generated by held VET and pays every VeChain fee; VTHO transfers are not enabled.',
        updatedAtMs,
      },
    ];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    const owner = normalizeVechainAddress(addr);
    if (!owner) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[1-9]\d{0,5}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const offset = cursor === undefined ? 0 : Number(cursor);
    if (offset > MAX_HISTORY_OFFSET) throw new Error('Invalid history cursor');
    if (options?.signal?.aborted) throw options.signal.reason;
    return withFailover(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const logs = await this.post(
          url,
          '/logs/transfer',
          {
            options: { offset, limit: HISTORY_PAGE },
            criteriaSet: [{ sender: owner }, { recipient: owner }],
            order: 'desc',
          },
          TransferLogs,
        );
        return {
          items: logs.map((log, i) =>
            transferRecord(chain.chainId, chain.nativeAsset.ref, owner, log, offset + i),
          ),
          ...(logs.length === HISTORY_PAGE ? { nextCursor: String(offset + HISTORY_PAGE) } : {}),
          coverage:
            'VET transfer logs from the node, including transfers made by contracts. VTHO movements and fees are not listed.',
          source: url,
        };
      },
      options?.signal ? { signal: options.signal } : {},
    );
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid VeChain transaction id');
    const id = `0x${hash.replace(/^0x/, '').toLowerCase()}`;
    return this.withNode(chainId, async ({ get }) => {
      const receipt = await get(`/transactions/${id}/receipt`, Receipt);
      if (receipt) {
        if (receipt.reverted) return { state: 'failed', reason: 'reverted' };
        return {
          state: 'confirmed',
          blockNumber: receipt.meta.blockNumber,
          timestampMs: receipt.meta.blockTimestamp * 1000,
        };
      }
      const pending = await get(`/transactions/${id}?pending=true`, TxLookup);
      return pending ? { state: 'pending' } : { state: 'unknown' };
    });
  }
}

function transferRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  log: z.infer<typeof TransferLogs>[number],
  position: number,
): TxRecord {
  const amount = BigInt(log.amount);
  let delta = 0n;
  if (log.recipient === holder) delta += amount;
  if (log.sender === holder) delta -= amount;
  return {
    entryId: `${log.meta.txID}:${log.meta.clauseIndex}:${position}`,
    hash: log.meta.txID,
    chainId,
    from: log.sender,
    to: log.recipient,
    blockNumber: log.meta.blockNumber,
    timestampMs: log.meta.blockTimestamp * 1000,
    ...(log.meta.txOrigin !== log.sender ? { description: 'Contract transfer' } : {}),
    assetDeltas: [{ assetRef: nativeRef, amount: String(delta) }],
    feeAssetRef: vthoAssetRef(chainId),
    fee: null,
    status: 'confirmed',
  };
}

export function createVechainAdapter(opts?: VechainAdapterOptions): VechainAdapter {
  return new VechainAdapter(opts);
}
