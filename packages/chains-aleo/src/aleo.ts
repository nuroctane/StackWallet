/**
 * Aleo adapter, read-only. Every Aleo execution — including
 * `credits.aleo/transfer_public` — is a zero-knowledge proof the client must
 * prove locally with snarkVM; there is no sign-and-broadcast path. Shipping
 * a prover is out of scope (see `.nur/wiring/aleo.md`), so this adapter
 * serves balances and transaction status and the signing entry points stay
 * `NotImplementedError`. Addresses are bech32m (not bech32), hrp `aleo`,
 * 32-byte payload: the little-endian x-coordinate of the account's
 * Edwards-BLS12 group element. Byte-pinned against `@provablehq/sdk` (run in
 * `.nur/aleo-oracle`); the Rust core (`aleo.rs`) pins the same vectors.
 *
 * Every read is network-proven against the pinned genesis block hash of the
 * selected network (`/v1/{net}/block/0`).
 *
 * Wiring shim: `aleo` is not yet in the `ChainFamily` enum or chain catalog
 * (the lead wires shared files from `.nur/wiring/aleo.md`). Until then this
 * package carries its own `ChainInfo` (cast to the shared type) and overrides
 * `chains()`.
 */
import { bech32m } from '@scure/base';
import {
  BaseAdapter,
  MemoryRpcPool,
  UnsupportedKeyError,
  nativeHolding,
  publicKeyBytes,
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

export const ALEO_MAINNET = 'aleo:mainnet';
export const ALEO_TESTNET = 'aleo:testnet';
export const ALEO_API = 'https://api.explorer.provable.com';
/** ALEO has 6 decimals; the base unit is the microcredit. */
export const ALEO_DECIMALS = 6;

/** Genesis block hashes, the network proof (probed 2026-10-17). */
export const ALEO_GENESIS: Record<string, string> = {
  [ALEO_MAINNET]: 'ab19dklwl9vp63zu3hwg57wyhvmqf92fx5g8x0t6dr72py8r87pxupqfne5t9',
  [ALEO_TESTNET]: 'ab1sm6kyqle2ftg4z8gegafqrjy0jwjhzu6fmy73726dgszrtxhxvfqha0eee',
};

const HRP = 'aleo';
/** BLS12-377 scalar-field modulus as a BigInt; payloads must stay below it. */
const FIELD_R = BigInt('0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001');

/** The bech32m address for a 32-byte payload (little-endian field element). */
export function aleoAddressFromPayload(payload: Uint8Array): string {
  if (payload.length !== 32) throw new Error('Aleo address payload must be 32 bytes');
  let value = 0n;
  for (let i = 31; i >= 0; i--) value = (value << 8n) | BigInt(payload[i]!);
  if (value >= FIELD_R) throw new Error('payload is not a scalar-field element');
  return bech32m.encode(HRP, bech32m.toWords(payload));
}

/** Validates an `aleo1…` address and returns its 32-byte payload, or undefined. */
export function aleoAddressBytes(address: string): Uint8Array | undefined {
  if (address.length > 90) return undefined;
  try {
    const { prefix, words } = bech32m.decode(address as `${string}1${string}`);
    if (prefix !== HRP) return undefined;
    const payload = bech32m.fromWords(words);
    if (payload.length !== 32) return undefined;
    return aleoAddressFromPayload(payload) === address ? payload : undefined;
  } catch {
    return undefined;
  }
}

export function isValidAleoAddress(address: string): boolean {
  return aleoAddressBytes(address) !== undefined;
}

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const BlockHash = z.string().regex(/^ab1[02-9ac-hj-np-z]{58}$/);
const GenesisBlock = z.object({ block_hash: BlockHash }).loose();
/** Mapping values arrive as JSON strings like `"1u64"`; `null` when unfunded. */
const MappingValue = z.union([z.string().regex(/^\d{1,20}u64$/), z.null()]);
const TransactionObject = z
  .object({
    type: z.string().max(32).optional(),
    status: z.string().max(32).optional(),
    execution: z.unknown().optional(),
    fee: z.unknown().optional(),
  })
  .loose();

/**
 * Local catalog entries used until the lead wires `aleo` into the shared
 * `ChainFamily` enum and catalog (see `.nur/wiring/aleo.md`).
 */
export const ALEO_CHAINS: ChainInfo[] = [
  {
    chainId: ALEO_MAINNET,
    family: 'aleo' as ChainInfo['family'],
    name: 'Aleo',
    nativeAsset: { ref: `${ALEO_MAINNET}:native`, symbol: 'ALEO', decimals: ALEO_DECIMALS },
    testnet: false,
    explorerTxUrl: 'https://explorer.provable.com/transaction/{hash}',
    defaultRpcs: [ALEO_API],
    extra: { coinType: 683 },
    priceId: 'aleo',
  },
  {
    chainId: ALEO_TESTNET,
    family: 'aleo' as ChainInfo['family'],
    name: 'Aleo Testnet',
    nativeAsset: { ref: `${ALEO_TESTNET}:native`, symbol: 'ALEO', decimals: ALEO_DECIMALS },
    testnet: true,
    explorerTxUrl: 'https://testnet.explorer.provable.com/transaction/{hash}',
    defaultRpcs: [ALEO_API],
    extra: { coinType: 1 },
    priceId: 'aleo',
  },
];

const NET_PATH: Record<string, string> = {
  [ALEO_MAINNET]: 'mainnet',
  [ALEO_TESTNET]: 'testnet',
};

export type AleoAdapterOptions = BaseAdapterOptions;

export class AleoAdapter extends BaseAdapter {
  constructor(opts: AleoAdapterOptions = {}) {
    // 'aleo' enters ChainFamily with the lead's wiring; the catalog shim
    // above keeps the pool honest in the meantime.
    super('aleo' as never, {
      ...opts,
      rpc: opts.rpc ?? new MemoryRpcPool(ALEO_CHAINS),
    });
  }

  override chains(): ChainInfo[] {
    const wired = super.chains();
    return wired.length > 0 ? wired : ALEO_CHAINS;
  }

  /**
   * Aleo key derivation (seed -> private key -> address) runs through
   * Poseidon hashing inside snarkVM, which the core does not carry, so no
   * `PublicKey` the core holds derives an Aleo address today.
   */
  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    void publicKeyBytes(pub);
    throw new UnsupportedKeyError(
      `Aleo addresses come from snarkVM Poseidon key derivation; the core holds no such key (curve ${pub.curve})`,
    );
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidAleoAddress(addr);
  }

  private netPath(chainId: ChainId): string {
    const path = NET_PATH[chainId];
    if (!path) throw new Error(`unknown Aleo chain ${chainId}`);
    return path;
  }

  /** The network proof: the endpoint must serve the pinned genesis block hash. */
  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const net = this.netPath(chainId);
    await this.verifyEndpoint(chainId, url, async () => {
      const block = await this.rest(`/v1/${net}/block/0`, GenesisBlock, [])(url);
      if (block === null || block.block_hash !== ALEO_GENESIS[chainId])
        throw new Error('Endpoint serves the wrong Aleo network');
    });
  }

  /** Latest block height (also forwarded to the pool's health tracking). */
  async latestHeight(chainId: ChainId): Promise<number> {
    const net = this.netPath(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const height = await this.rest(`/v1/${net}/latest/height`, SafeInt, [])(url);
      if (height === null) throw new Error('height endpoint not found');
      this.noteBlock(url, height);
      return height;
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidAleoAddress(addr)) throw new TypeError(`invalid aleo address ${addr}`);
    const net = this.netPath(chainId);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const res = await this.rest(
          `/v2/${net}/program/credits.aleo/mapping/account/${addr}`,
          MappingValue,
          [404],
        )(url);
        return res === null ? '0' : res.slice(0, -3);
      },
      { equal: (a, b) => a === b },
    );
    return [
      {
        ...nativeHolding(chain, value, provenance),
        notice:
          'Public credits.aleo balance from the account mapping; record-held (private) balances are invisible to any API by design.',
      },
    ];
  }

  /**
   * The Provable explorer API has no per-address history endpoint (probed
   * 2026-10-17: `/v1/{net}/address/{addr}/transactions` is 404), so transfer
   * history reports its gap.
   */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidAleoAddress(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'The keyless Provable API offers no per-address history endpoint, so transfer history is unavailable.',
    };
  }

  /**
   * `/v1/{net}/transaction/{id}` answers the accepted transaction object or
   * 404s; a transaction with a fee but no execution was rejected on-chain.
   * Unconfirmed broadcasts are invisible (no mempool endpoint).
   */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^at1[02-9ac-hj-np-z]{58}$/.test(hash)) throw new Error('Invalid Aleo transaction id');
    const net = this.netPath(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const tx = await this.rest(`/v1/${net}/transaction/${hash}`, TransactionObject, [404])(url);
      if (tx === null) return { state: 'unknown' };
      if (tx.type === 'rejected' || (tx.execution === undefined && tx.fee !== undefined))
        return { state: 'failed', reason: 'transaction was rejected on-chain (fee only)' };
      // Resolve the including block for a height (two cheap keyless lookups).
      const blockHash = await this.rest(`/v1/${net}/find/blockHash/${hash}`, BlockHash, [404])(url);
      if (blockHash === null) throw new Error('node lost an included transaction');
      const height = await this.rest(`/v1/${net}/height/${blockHash}`, SafeInt, [404])(url);
      if (height === null) throw new Error('node lost the inclusion block');
      return { state: 'confirmed', blockNumber: height };
    });
  }
}

export function createAleoAdapter(opts?: AleoAdapterOptions): AleoAdapter {
  return new AleoAdapter(opts);
}
