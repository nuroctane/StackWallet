/**
 * Starcoin adapter. Addresses are the last 16 bytes of
 * sha3-256(ed25519_pubkey || 0x00) as `0x` + 32 lowercase hex. Reads go over
 * the Starcoin JSON-RPC; `chain.info` proves the network (`chain_id`) on
 * every endpoint before dependent calls run.
 */
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  JsonRpcError,
  MemoryRpcPool,
  chainsForFamily,
  fetchJsonRpc,
  nativeHolding,
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

export const STARCOIN_MAINNET = 'starcoin:1';
export const STARCOIN_BARNARD = 'starcoin:251';
const NUMERIC_CHAIN_ID: Record<string, number> = {
  [STARCOIN_MAINNET]: 1,
  [STARCOIN_BARNARD]: 251,
};

export const STARCOIN_CHAINS: ChainInfo[] = [
  {
    chainId: STARCOIN_MAINNET,
    family: 'starcoin',
    name: 'Starcoin',
    nativeAsset: { ref: `${STARCOIN_MAINNET}:native`, symbol: 'STC', decimals: 9 },
    testnet: false,
    explorerTxUrl: 'https://stcscan.io/main/transactions/detail/{hash}',
    defaultRpcs: ['https://main-seed.starcoin.org'],
    extra: { coinType: 101010 },
    priceId: 'starcoin',
    layer: 'L1',
  },
  {
    chainId: STARCOIN_BARNARD,
    family: 'starcoin',
    name: 'Starcoin Barnard',
    nativeAsset: { ref: `${STARCOIN_BARNARD}:native`, symbol: 'STC', decimals: 9 },
    testnet: true,
    explorerTxUrl: 'https://stcscan.io/barnard/transactions/detail/{hash}',
    defaultRpcs: ['https://barnard-seed.starcoin.org'],
    extra: { coinType: 101010 },
    layer: 'L1',
  },
];

export function starcoinAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^0x[0-9a-f]{32}$/.test(addr)) return undefined;
  const bytes = hexToBytes(addr.slice(2));
  if (bytes.every((b) => b === 0)) return undefined;
  return bytes;
}

export function isValidStarcoinAddress(addr: string): boolean {
  return starcoinAddressBytes(addr) !== undefined;
}

/** Last 16 bytes of the single-signature auth key sha3-256(pubkey || 0x00). */
export function starcoinAddressFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  const preimage = new Uint8Array(33);
  preimage.set(publicKey);
  const authKey = sha3_256(preimage);
  return `0x${[...authKey.subarray(16)].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

const StrOrNum = z.union([z.string().regex(/^\d{1,20}$/), z.number().int().nonnegative()]);
export const ChainInfoResult = z.object({
  chain_id: z.number().int().nonnegative().max(0xffffffff),
  genesis_hash: z
    .string()
    .regex(/^0x[0-9a-f]{64}$/)
    .optional(),
  head: z.object({ number: StrOrNum.optional() }),
});
export const BlockHeader = z.object({
  number: StrOrNum.optional(),
  timestamp: StrOrNum.optional(),
});
export const Block = z.object({ header: BlockHeader });
/** `{decode: false}` resource reads return raw BCS bytes as hex. */
export const RawResource = z.object({
  raw: z
    .string()
    .regex(/^0x[0-9a-f]*$/)
    .max(4096),
});
/** `{decode: true}` account resource; only the sequence number is trusted. */
export const AccountResource = z.object({
  json: z
    .object({
      sequence_number: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
    })
    .loose()
    .optional(),
  raw: z.string().max(4096).optional(),
});
export const TransactionInfo = z.object({
  block_number: StrOrNum.optional(),
  status: z.string().max(64),
  gas_used: StrOrNum.optional(),
});
export const GasPrice = StrOrNum;
export const NextSequence = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).nullable();

export type StarcoinAdapterOptions = BaseAdapterOptions;
export type StarcoinCall = <T>(
  method: string,
  params: unknown[],
  schema: z.ZodType<T>,
) => Promise<T>;

export class StarcoinAdapter extends BaseAdapter<'starcoin'> {
  constructor(opts: StarcoinAdapterOptions = {}) {
    super('starcoin', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(STARCOIN_CHAINS) });
  }

  override chains(): ChainInfo[] {
    const catalog = chainsForFamily('starcoin');
    return catalog.length > 0 ? catalog : STARCOIN_CHAINS;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return starcoinAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidStarcoinAddress(addr);
  }

  private call<T>(
    url: string,
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): Promise<T> {
    return fetchJsonRpc(url, method, params, this.fetchOptions()).then((res) => schema.parse(res));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const info = await this.call(url, 'chain.info', [], ChainInfoResult);
      if (info.chain_id !== NUMERIC_CHAIN_ID[chainId])
        throw new Error('Endpoint serves another Starcoin network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(
    chainId: ChainId,
    query: (call: StarcoinCall, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((method, params, schema) => this.call(url, method, params, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidStarcoinAddress(addr)) throw new TypeError(`invalid starcoin address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        try {
          const res = await this.call(
            url,
            'state.get_resource',
            [addr, '0x1::Account::Balance<0x1::STC::STC>'],
            RawResource,
          );
          // Raw is exactly the u128 token value, little-endian.
          const bytes = hexToBytes(res.raw.slice(2));
          if (bytes.length !== 16) throw new Error('unexpected balance resource length');
          let balance = 0n;
          for (let i = 15; i >= 0; i--) balance = (balance << 8n) | BigInt(bytes[i]!);
          return balance.toString();
        } catch (err) {
          // An address that never received STC has no balance resource: zero.
          if (err instanceof JsonRpcError) return '0';
          throw err;
        }
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidStarcoinAddress(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'No keyless Starcoin history indexer is reachable (stcscan API answers 500 and sets no CORS headers), so history is unavailable.',
    };
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Starcoin transaction hash');
    const value = hash.toLowerCase();
    return this.withNode(chainId, async (call) => {
      try {
        const info = await call('chain.get_transaction_info', [value], TransactionInfo);
        if (info.status === 'Executed') {
          return { state: 'confirmed', blockNumber: Number(info.block_number ?? 0) };
        }
        return { state: 'failed', reason: info.status };
      } catch (err) {
        if (err instanceof JsonRpcError) return { state: 'unknown' };
        throw err;
      }
    });
  }
}

export function createStarcoinAdapter(opts?: StarcoinAdapterOptions): StarcoinAdapter {
  return new StarcoinAdapter(opts);
}
