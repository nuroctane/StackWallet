/**
 * Substrate adapter. Accounts are 32-byte Ed25519 public keys shown as SS58
 * under each network's prefix; reads go over public JSON-RPC (`state_getStorage`
 * of `System.Account`), and every endpoint first proves its genesis hash, whose
 * first 16 bytes are the CAIP-2 reference.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  MemoryRpcPool,
  UnsupportedKeyError,
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
  type HistoryOptions,
  type Holding,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const SUBSTRATE_WESTEND = 'polkadot:e143f23803ac50e8f6f8e62695d1ce9e';
export const SUBSTRATE_WESTEND_ASSET_HUB = 'polkadot:67f9723393ef76214df0118c34bbbd3d';

/** Asset Hub `Assets` pallet tokens read alongside the native balance. */
interface AssetToken {
  id: number;
  symbol: string;
  decimals: number;
}

export interface SubstrateNetwork {
  /** Full genesis hash, 0x-prefixed. */
  genesis: string;
  /** SS58 prefix addresses are displayed with. */
  ss58: number;
  /** Prefixes accepted on input; the runtime constant when it differs from the registry's. */
  accept: readonly number[];
  /** Width of `AccountData` balances; Bittensor stores u64. */
  balanceBytes: 8 | 16;
  /** Where the native balance lives: `System.Account`, or Chainflip's `Flip.Account`. */
  store: 'system' | 'flip';
  /** Existential deposit in planck, read from the runtime constants. */
  existentialDeposit: bigint;
  assets?: readonly AssetToken[];
}

/** Verified against each live runtime (`system_properties`, `System.SS58Prefix`, metadata). */
export const SUBSTRATE_NETWORKS: Readonly<Record<string, SubstrateNetwork>> = {
  'polkadot:91b171bb158e2d3848fa23a9f1c25182': {
    genesis: '0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3',
    ss58: 0,
    accept: [0],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 10_000_000_000n,
  },
  'polkadot:b0a8d493285c2df73290dfb7e61f870f': {
    genesis: '0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe',
    ss58: 2,
    accept: [2],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 333_333_333n,
  },
  'polkadot:68d56f15f85d3136970ec16946040bc1': {
    genesis: '0x68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f',
    ss58: 0,
    accept: [0],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 100_000_000n,
    assets: [
      { id: 1984, symbol: 'USDt', decimals: 6 },
      { id: 1337, symbol: 'USDC', decimals: 6 },
    ],
  },
  'polkadot:48239ef607d7928874027a43a6768920': {
    genesis: '0x48239ef607d7928874027a43a67689209727dfb3d3dc5e5b03a39bdc2eda771a',
    ss58: 2,
    accept: [2],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 3_333_333n,
    assets: [{ id: 1984, symbol: 'USDt', decimals: 6 }],
  },
  'polkadot:2f0555cc76fc2840a25a6ea3b9637146': {
    genesis: '0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03',
    ss58: 42,
    accept: [42],
    balanceBytes: 8,
    store: 'system',
    existentialDeposit: 500n,
  },
  'polkadot:afdc188f45c71dacbaa0b62e16a91f72': {
    genesis: '0xafdc188f45c71dacbaa0b62e16a91f726c7b8699a9748cdf715459de6b7f366d',
    ss58: 63,
    accept: [63, 0],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 1_000_000_000_000n,
  },
  'polkadot:262e1b2ad728475fd6fe88e62d34c200': {
    genesis: '0x262e1b2ad728475fd6fe88e62d34c200abe6fd693931ddad144059b1eb884e5b',
    ss58: 6,
    accept: [6, 0],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 10_000_000_000n,
  },
  'polkadot:fc41b9bd8ef8fe53d58c7ea67c794c7e': {
    genesis: '0xfc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c',
    ss58: 10,
    accept: [10],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 100_000_000_000n,
  },
  'polkadot:baf5aabe40646d11f0ee8abbdc64f4a4': {
    genesis: '0xbaf5aabe40646d11f0ee8abbdc64f4a4b7674925cba08e4a05ff9ebed6e2126b',
    ss58: 8,
    accept: [8],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 100_000_000_000n,
  },
  'polkadot:fe1b4c55fd4d668101126434206571a7': {
    genesis: '0xfe1b4c55fd4d668101126434206571a7838a8b6b93a6d1b95d607e78e6c53763',
    ss58: 137,
    accept: [137],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 1_000_000_000_000n,
  },
  'polkadot:7e4e32d0feafd4f9c9414b0be86373f9': {
    genesis: '0x7e4e32d0feafd4f9c9414b0be86373f9a1efa904809b683453a9af6856d38ad5',
    ss58: 69,
    accept: [69],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 0n,
  },
  'polkadot:8b8c140b0af9db70686583e3f6bf2a59': {
    genesis: '0x8b8c140b0af9db70686583e3f6bf2a59052bfe9584b97d20c45068281e976eb9',
    ss58: 2112,
    accept: [2112],
    balanceBytes: 16,
    store: 'flip',
    existentialDeposit: 0n,
  },
  [SUBSTRATE_WESTEND]: {
    genesis: '0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e',
    ss58: 42,
    accept: [42],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 10_000_000_000n,
  },
  [SUBSTRATE_WESTEND_ASSET_HUB]: {
    genesis: '0x67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9',
    ss58: 42,
    accept: [42],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 1_000_000_000n,
  },
  'polkadot:374057be67b355151f271ff70c3db983': {
    genesis: '0x374057be67b355151f271ff70c3db98308c62c8adc48dc6724b6a009a1a014fd',
    ss58: 42,
    accept: [42],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 10_000_000_000n,
  },
  'polkadot:d6eec26135305a8ad257a20d00335728': {
    genesis: '0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2',
    ss58: 42,
    accept: [42],
    balanceBytes: 16,
    store: 'system',
    existentialDeposit: 100_000_000n,
  },
};

/** The family's entries in the shared catalog. */
export const SUBSTRATE_CHAINS: readonly ChainInfo[] = Object.freeze(chainsForFamily('substrate'));

// ---------------------------------------------------------------- SS58

const SS58PRE = new TextEncoder().encode('SS58PRE');

function ss58Checksum(prefix: Uint8Array, account: Uint8Array): Uint8Array {
  const input = new Uint8Array(SS58PRE.length + prefix.length + account.length);
  input.set(SS58PRE);
  input.set(prefix, SS58PRE.length);
  input.set(account, SS58PRE.length + prefix.length);
  return blake2b(input).subarray(0, 2);
}

function prefixBytes(prefix: number): Uint8Array {
  if (prefix < 64) return Uint8Array.of(prefix);
  return Uint8Array.of(((prefix & 0xfc) >> 2) | 0x40, (prefix >> 8) | ((prefix & 0x03) << 6));
}

export function ss58Encode(account: Uint8Array, prefix: number): string {
  if (account.length !== 32) throw new TypeError('SS58 account must be 32 bytes');
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 16383 || prefix === 46 || prefix === 47)
    throw new TypeError('unsupported SS58 prefix');
  const p = prefixBytes(prefix);
  const out = new Uint8Array(p.length + 34);
  out.set(p);
  out.set(account, p.length);
  out.set(ss58Checksum(p, account), p.length + 32);
  return base58.encode(out);
}

/** Canonical SS58 of a non-zero 32-byte account, or undefined. */
export function ss58Decode(addr: string): { prefix: number; account: Uint8Array } | undefined {
  if (!/^[1-9A-HJ-NP-Za-km-z]{40,50}$/.test(addr)) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(addr);
  } catch {
    return undefined;
  }
  const b0 = bytes[0];
  if (b0 === undefined || b0 >= 128) return undefined;
  let prefix: number;
  let plen: number;
  if (b0 < 64) {
    prefix = b0;
    plen = 1;
  } else {
    const b1 = bytes[1] ?? 0;
    prefix = (((b0 << 2) | (b1 >> 6)) & 0xff) | ((b1 & 0x3f) << 8);
    plen = 2;
  }
  if (bytes.length !== plen + 34) return undefined;
  const account = bytes.slice(plen, plen + 32);
  const check = ss58Checksum(bytes.subarray(0, plen), account);
  if (check[0] !== bytes[plen + 32] || check[1] !== bytes[plen + 33]) return undefined;
  if (account.every((b) => b === 0)) return undefined;
  try {
    if (ss58Encode(account, prefix) !== addr) return undefined;
  } catch {
    return undefined;
  }
  return { prefix, account };
}

export function substrateNetwork(chainId: string): SubstrateNetwork | undefined {
  return Object.hasOwn(SUBSTRATE_NETWORKS, chainId) ? SUBSTRATE_NETWORKS[chainId] : undefined;
}

/** The account behind an address valid on `chainId`, or undefined. */
export function substrateAccount(addr: string, chainId: string): Uint8Array | undefined {
  const decoded = ss58Decode(addr);
  const net = substrateNetwork(chainId);
  if (!decoded || !net || !net.accept.includes(decoded.prefix)) return undefined;
  return decoded.account;
}

/** Any canonical SS58 account address; with a chain id, only that network's prefixes. */
export function isValidSubstrateAddress(addr: string, chainId?: string): boolean {
  return chainId === undefined
    ? ss58Decode(addr) !== undefined
    : substrateAccount(addr, chainId) !== undefined;
}

export function substrateAddressFromPublicKey(pub: Uint8Array, prefix = 42): string {
  if (pub.length !== 32) throw new UnsupportedKeyError('ed25519 public key must be 32 bytes');
  return ss58Encode(pub, prefix);
}

// ---------------------------------------------------------------- storage

const SYSTEM_ACCOUNT = '26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9';
const FLIP_ACCOUNT = 'eb20d33519ac778c3e52b5f3678a05c8b99d880ec681799c0cf30e8886371da9';
const ASSETS_ACCOUNT = '682a59d51ab9e48a8c8cc418ff9708d2b99d880ec681799c0cf30e8886371da9';
export const TIMESTAMP_NOW = '0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb';

const blake2Concat = (data: Uint8Array) =>
  bytesToHex(blake2b(data, { dkLen: 16 })) + bytesToHex(data);

export function accountStorageKey(
  account: Uint8Array,
  store: 'system' | 'flip' = 'system',
): string {
  return `0x${store === 'flip' ? FLIP_ACCOUNT : SYSTEM_ACCOUNT}${blake2Concat(account)}`;
}

export function assetAccountStorageKey(assetId: number, account: Uint8Array): string {
  const id = new Uint8Array(4);
  new DataView(id.buffer).setUint32(0, assetId, true);
  return `0x${ASSETS_ACCOUNT}${blake2Concat(id)}${blake2Concat(account)}`;
}

function leUint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

export interface AccountState {
  nonce: number;
  free: bigint;
  reserved: bigint;
  frozen: bigint;
}

export const StorageValue = z.union([
  z.null(),
  z
    .string()
    .max(4096)
    .regex(/^0x(?:[0-9a-f]{2})*$/),
]);

/** `AccountInfo` from `System.Account`, or Chainflip's `{ balance, bond }`; absent is empty. */
export function decodeAccount(
  value: string | null,
  net: Pick<SubstrateNetwork, 'balanceBytes' | 'store'>,
): AccountState {
  if (value === null) return { nonce: 0, free: 0n, reserved: 0n, frozen: 0n };
  const bytes = hexToBytes(value.slice(2));
  if (net.store === 'flip') {
    if (bytes.length !== 32) throw new Error('Unexpected Flip.Account layout');
    // The bond stays in the balance; it is the part that cannot be redeemed.
    return {
      nonce: 0,
      free: leUint(bytes.subarray(0, 16)),
      reserved: 0n,
      frozen: leUint(bytes.subarray(16, 32)),
    };
  }
  const w = net.balanceBytes;
  if (bytes.length !== 16 + 3 * w + 16) throw new Error('Unexpected System.Account layout');
  return {
    nonce: Number(leUint(bytes.subarray(0, 4))),
    free: leUint(bytes.subarray(16, 16 + w)),
    reserved: leUint(bytes.subarray(16 + w, 16 + 2 * w)),
    frozen: leUint(bytes.subarray(16 + 2 * w, 16 + 3 * w)),
  };
}

/** What `transfer_keep_alive` may move: free minus the frozen part reserves do not cover, minus the ED. */
export function spendable(state: AccountState, existentialDeposit: bigint): bigint {
  const frozenFree = state.frozen > state.reserved ? state.frozen - state.reserved : 0n;
  const locked = frozenFree > existentialDeposit ? frozenFree : existentialDeposit;
  return state.free > locked ? state.free - locked : 0n;
}

// ---------------------------------------------------------------- adapter

export const H256Hex = z.string().regex(/^0x[0-9a-f]{64}$/);
const BlockNumberHex = z
  .string()
  .regex(/^0x[0-9a-f]{1,8}$/)
  .transform((h) => Number.parseInt(h, 16));
export const Header = z.object({ number: BlockNumberHex, parentHash: H256Hex });
export const RuntimeVersion = z.object({
  specName: z.string().max(64),
  specVersion: z.number().int().positive().max(0xffffffff),
  transactionVersion: z.number().int().nonnegative().max(0xffffffff),
});

export type SubstrateAdapterOptions = BaseAdapterOptions;
export type SubstrateCall = <T>(
  method: string,
  params: unknown[],
  schema: z.ZodType<T>,
) => Promise<T>;

export function substrateChains(): ChainInfo[] {
  return chainsForFamily('substrate');
}

export class SubstrateAdapter extends BaseAdapter<'substrate'> {
  constructor(opts: SubstrateAdapterOptions = {}) {
    super('substrate', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(substrateChains()) });
  }

  override chains(): ChainInfo[] {
    return substrateChains();
  }

  network(chainId: ChainId): SubstrateNetwork {
    this.requireChain(chainId);
    const net = substrateNetwork(chainId);
    if (!net) throw new Error(`No Substrate runtime details for ${chainId}`);
    return net;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    const net = this.network(chainId);
    requireCurve(pub, 'ed25519');
    return substrateAddressFromPublicKey(publicKeyBytes(pub), net.ss58);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.network(chainId);
    return isValidSubstrateAddress(addr, chainId);
  }

  private rpcCall<T>(
    url: string,
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): Promise<T> {
    return fetchJsonRpc(url, method, params, this.fetchOptions()).then((r) => schema.parse(r));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const net = this.network(chainId);
    await this.verifyEndpoint(chainId, url, async () => {
      const genesis = await this.rpcCall(url, 'chain_getBlockHash', [0], H256Hex);
      if (genesis !== net.genesis)
        throw new Error('Endpoint genesis hash does not match this Substrate network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(
    chainId: ChainId,
    query: (call: SubstrateCall, url: string) => Promise<T>,
  ): Promise<T> {
    this.network(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((method, params, schema) => this.rpcCall(url, method, params, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const net = this.network(chainId);
    const account = substrateAccount(addr, chainId);
    if (!account) throw new TypeError(`invalid ${chain.name} address ${addr}`);
    const key = accountStorageKey(account, net.store);
    const total = (s: AccountState) => (s.free + s.reserved).toString();
    const { value: state, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        return decodeAccount(await this.rpcCall(url, 'state_getStorage', [key], StorageValue), net);
      },
      {
        equal: (a, b) => a.free === b.free && a.reserved === b.reserved && a.frozen === b.frozen,
        describe: total,
      },
    );
    const { reserved, frozen } = state;
    const native = nativeHolding(chain, total(state), provenance);
    if (net.store === 'flip') {
      if (frozen > 0n)
        native.notice = `${frozen} of this balance is bonded and cannot be redeemed.`;
    } else if (reserved > 0n || frozen > 0n) {
      const usable = spendable(state, net.existentialDeposit);
      native.notice = `Total includes ${reserved} reserved and ${frozen} frozen; ${usable} is transferable.`;
    }
    const tokens: Holding[] = [];
    for (const token of net.assets ?? []) {
      const assetRef = `${chainId}:asset:${token.id}`;
      const metadata = { symbol: token.symbol, decimals: token.decimals };
      const notice = 'Asset Hub Assets pallet balance; token transfers are not enabled.';
      try {
        const observed = await withCrossCheck(
          this.rpc,
          chainId,
          async (url) => {
            await this.checkNetwork(chainId, url);
            const raw = await this.rpcCall(
              url,
              'state_getStorage',
              [assetAccountStorageKey(token.id, account)],
              StorageValue,
            );
            if (raw === null) return '0';
            const bytes = hexToBytes(raw.slice(2));
            if (bytes.length < 18) throw new Error('Unexpected Assets.Account layout');
            return leUint(bytes.subarray(0, 16)).toString();
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
    return [native, ...tokens];
  }

  override getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    if (!this.validateAddress(addr, chainId))
      return Promise.reject(new Error('Invalid history address'));
    // Substrate nodes do not index by account; Subscan and other indexers need API keys.
    return Promise.resolve({
      items: [],
      coverage:
        'Substrate nodes keep no per-account history and no keyless indexer is configured, so history is unavailable.',
    });
  }

  /**
   * A node cannot look an extrinsic up by hash; transfers this wallet sent are
   * tracked by `substrateTransferStatus`, which knows the sender, nonce and era.
   */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.network(chainId);
    if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error('Invalid Substrate extrinsic hash');
    return { state: 'unknown' };
  }
}

export function createSubstrateAdapter(opts?: SubstrateAdapterOptions): SubstrateAdapter {
  return new SubstrateAdapter(opts);
}
