/**
 * Starknet adapter. Accounts are OpenZeppelin account contracts whose address
 * is Pedersen-derived from the class hash and the Stark public key; reads go
 * over the JSON-RPC API, whose `starknet_chainId` proves the network. The
 * "public key" this adapter receives is the 32-byte Stark public key (x
 * coordinate) ground from the core's secp256k1 secret, never the SEC1 point.
 */
import { Field } from '@noble/curves/abstract/modular.js';
import { poseidon } from '@noble/curves/abstract/poseidon.js';
import { weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
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
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const STARKNET_MAINNET = 'starknet:SN_MAIN';
export const STARKNET_SEPOLIA = 'starknet:SN_SEPOLIA';
/** OpenZeppelin AccountUpgradeable (SRC-6, constructor `public_key`), on mainnet and Sepolia. */
export const ACCOUNT_CLASS_HASH = [
  '0x05b4b537eaa2399e3a',
  'a99c4e2e0208ebd6c71b',
  'c1467938cd52c798c601',
  'e43564',
].join('');
/** STRK ERC-20; the same address on mainnet and Sepolia. */
export const STRK_TOKEN = [
  '0x04718f5a0fc34cc1af',
  '16a1cdee98ffb20c31f5',
  'cd61d6ab07201858f428',
  '7c938d',
].join('');
const USDC_MAINNET = [
  '0x053c91253bc9682c04',
  '929ca02ed00b3e423f67',
  '10d2ee7e0d5ebb06f3ec',
  'f368a8',
].join('');

const CHAIN_FELT: Record<string, string> = {
  [STARKNET_MAINNET]: '0x534e5f4d41494e',
  [STARKNET_SEPOLIA]: '0x534e5f5345504f4c4941',
};

/**
 * Stand-in catalog until the curated catalog gains Starknet entries; the
 * constructor seeds the RPC pool from it and `chains()` prefers the catalog
 * the moment it does. Endpoints were live-probed for CORS.
 */
export const STARKNET_CHAINS: ChainInfo[] = [
  {
    chainId: STARKNET_MAINNET,
    family: 'starknet',
    name: 'Starknet',
    nativeAsset: { ref: `${STARKNET_MAINNET}:native`, symbol: 'STRK', decimals: 18 },
    testnet: false,
    explorerTxUrl: 'https://voyager.online/tx/{hash}',
    defaultRpcs: [
      'https://starknet-rpc.publicnode.com',
      'https://starknet.drpc.org',
      'https://api.cartridge.gg/x/starknet/mainnet',
    ],
    extra: { coinType: 9004 },
    priceId: 'starknet',
    layer: 'L2',
    parent: 'Ethereum',
  },
  {
    chainId: STARKNET_SEPOLIA,
    family: 'starknet',
    name: 'Starknet Sepolia',
    nativeAsset: { ref: `${STARKNET_SEPOLIA}:native`, symbol: 'STRK', decimals: 18 },
    testnet: true,
    explorerTxUrl: 'https://sepolia.voyager.online/tx/{hash}',
    defaultRpcs: [
      'https://starknet-sepolia-rpc.publicnode.com',
      'https://starknet-sepolia.drpc.org',
      'https://api.cartridge.gg/x/starknet/sepolia',
    ],
    extra: { coinType: 9004 },
    layer: 'L2',
    parent: 'Ethereum',
  },
];

// ---------------------------------------------------------------------------
// Felt arithmetic helpers: the Stark field, its curve, Pedersen and Poseidon.

/** 2^251 + 17·2^192 + 1. */
export const STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001n;
/** 2^251 - 256: contract addresses are reduced below this. */
export const ADDR_BOUND = 2n ** 251n - 256n;
const CURVE_ORDER = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2fn;

const StarkPoint = weierstrass({
  a: 1n,
  b: 3141592653589793238462643383279502884197169399375105820974944592307816406665n,
  p: STARK_PRIME,
  n: CURVE_ORDER,
  Gx: 874739451078007766457464989774322083649278607533249481151382481072868806602n,
  Gy: 152666792071518830868575557812948353041420400780739481342941381225525861407n,
  h: 1n,
});
const Fp = Field(STARK_PRIME);

/** StarkWare's nothing-up-my-sleeve Pedersen points: shift, x-low, x-high, y-low, y-high. */
const PEDERSEN_POINTS = [
  [
    2089986280348253421170679821480865132823066470938446095505822317253594081284n,
    1713931329540660377023406109199410414810705867260802078187082345529207694986n,
  ],
  [
    996781205833008774514500082376783249102396023663454813447423147977397232763n,
    1668503676786377725805489344771023921079126552019160156920634619255970485781n,
  ],
  [
    2251563274489750535117886426533222435294046428347329203627021249169616184184n,
    1798716007562728905295480679789526322175868328062420237419143593021674992973n,
  ],
  [
    2138414695194151160943305727036575959195309218611738193261179310511854807447n,
    113410276730064486255102093846540133784865286929052426931474106396135072156n,
  ],
  [
    2379962749567351885752724891227938183011949129833673362440656643086021394946n,
    776496453633298175483985398648758586525933812536653089401905292063708816422n,
  ],
] as const;

type AffinePoint = InstanceType<typeof StarkPoint>;

const pedersenTables = (() => {
  let tables: AffinePoint[][] | undefined;
  return () => {
    if (!tables) {
      const build = (low: readonly [bigint, bigint], high: readonly [bigint, bigint]) => {
        const out: AffinePoint[] = [];
        let p = StarkPoint.fromAffine({ x: low[0], y: low[1] });
        for (let i = 0; i < 248; i++) {
          out.push(p);
          p = p.double();
        }
        p = StarkPoint.fromAffine({ x: high[0], y: high[1] });
        for (let i = 0; i < 4; i++) {
          out.push(p);
          p = p.double();
        }
        return out;
      };
      tables = [
        build(PEDERSEN_POINTS[1], PEDERSEN_POINTS[2]),
        build(PEDERSEN_POINTS[3], PEDERSEN_POINTS[4]),
      ];
    }
    return tables;
  };
})();

export function pedersen(a: bigint, b: bigint): bigint {
  if (a < 0n || a >= STARK_PRIME || b < 0n || b >= STARK_PRIME)
    throw new RangeError('Pedersen input outside the field');
  let acc = StarkPoint.fromAffine({ x: PEDERSEN_POINTS[0][0], y: PEDERSEN_POINTS[0][1] });
  const tables = pedersenTables();
  for (const [value, table] of [
    [a, tables[0]!],
    [b, tables[1]!],
  ] as const) {
    let v = value;
    for (let j = 0; j < 252; j++) {
      const pt = table[j]!;
      if (acc.equals(pt)) throw new Error('Pedersen hit a table point');
      if (v & 1n) acc = acc.add(pt);
      v >>= 1n;
    }
  }
  return acc.toAffine().x;
}

/** `pedersen(...pedersen(pedersen(0, d0), d1)..., len)`. */
export function computeHashOnElements(data: bigint[]): bigint {
  let acc = 0n;
  for (const d of data) acc = pedersen(acc, d);
  return pedersen(acc, BigInt(data.length));
}

const poseidonSmall = (() => {
  const constant = (idx: number) =>
    Fp.create(Fp.fromBytes(sha256(utf8ToBytes(`Hades${idx}`)), true));
  const roundConstants: bigint[][] = [];
  for (let round = 0; round < 91; round++)
    roundConstants.push([constant(3 * round), constant(3 * round + 1), constant(3 * round + 2)]);
  return poseidon({
    Fp,
    t: 3,
    roundsFull: 8,
    roundsPartial: 83,
    sboxPower: 3,
    reversePartialPowIdx: true,
    mds: [
      [3n, 1n, 1n],
      [1n, -1n, 1n],
      [1n, 1n, -2n],
    ],
    roundConstants,
  });
})();

/** Sponge over width-3 Hades: append 1, pad to the rate, absorb into a zero state. */
export function poseidonHashMany(values: bigint[]): bigint {
  for (const v of values)
    if (v < 0n || v >= STARK_PRIME) throw new RangeError('Poseidon input outside the field');
  const padded = [...values, 1n];
  while (padded.length % 2 !== 0) padded.push(0n);
  let state: bigint[] = [0n, 0n, 0n];
  for (let i = 0; i < padded.length; i += 2) {
    state = poseidonSmall([state[0]! + padded[i]!, state[1]! + padded[i + 1]!, state[2]!]);
  }
  return state[0]!;
}

/** `sn_keccak`: Keccak-256 truncated to 250 bits. */
export function getSelectorFromName(name: string): bigint {
  return bytesToNumberBE(keccak_256(utf8ToBytes(name))) & ((1n << 250n) - 1n);
}

// ---------------------------------------------------------------------------
// Addresses.

/** Minimal `0x` hex, the JSON-RPC FELT form. */
export const feltHex = (value: bigint): string => `0x${value.toString(16)}`;
export const feltPadded = (value: bigint): string => `0x${value.toString(16).padStart(64, '0')}`;

const ADDRESS_RE = /^0x[0-9a-fA-F]{1,64}$/;

export function isValidStarknetAddress(addr: string): boolean {
  if (!ADDRESS_RE.test(addr)) return false;
  try {
    const value = BigInt(addr);
    return value >= 0x100n && value < ADDR_BOUND;
  } catch {
    return false;
  }
}

/** Padded lowercase form, as the core requires on the unsigned transaction. */
export function normalizeStarknetAddress(addr: string): string {
  if (!isValidStarknetAddress(addr)) throw new Error(`invalid Starknet address ${addr}`);
  return feltPadded(BigInt(addr));
}

/**
 * The OpenZeppelin account address for a 32-byte big-endian Stark public key:
 * Pedersen over (prefix, deployer 0, salt = key, class hash, calldata hash),
 * reduced below the address bound.
 */
export function starknetAddressFromPublicKey(starkPublicKey: Uint8Array): string {
  if (starkPublicKey.length !== 32)
    throw new Error('a Starknet public key is the 32-byte Stark key x coordinate');
  const x = bytesToNumberBE(starkPublicKey);
  // A valid key's x has a curve point; fromHex rejects otherwise.
  StarkPoint.fromHex(`02${bytesToHex(starkPublicKey)}`);
  const constructorHash = computeHashOnElements([x]);
  const raw = computeHashOnElements([
    bytesToNumberBE(utf8ToBytes('STARKNET_CONTRACT_ADDRESS')),
    0n,
    x,
    BigInt(ACCOUNT_CLASS_HASH),
    constructorHash,
  ]);
  return feltPadded(raw % ADDR_BOUND);
}

// ---------------------------------------------------------------------------
// The adapter.

const Felt = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const FeltList = z.array(Felt).min(1).max(8);
export const BlockHead = z.object({
  block_number: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  timestamp: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  l1_gas_price: z.object({ price_in_fri: Felt }),
  l2_gas_price: z.object({ price_in_fri: Felt }),
  l1_data_gas_price: z.object({ price_in_fri: Felt }),
});
const Receipt = z.object({
  execution_status: z.string().max(32),
  finality_status: z.string().max(32),
  block_number: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  revert_reason: z.string().max(4096).optional(),
});
const TxStatusResult = z.object({
  finality_status: z.string().max(32),
  execution_status: z.string().max(32).optional(),
});

const ERC20: Record<string, { address: string; symbol: string; decimals: number }[]> = {
  [STARKNET_MAINNET]: [{ address: USDC_MAINNET, symbol: 'USDC', decimals: 6 }],
};

export type StarknetAdapterOptions = BaseAdapterOptions;
export type StarknetCall = <T>(
  method: string,
  params: unknown[] | Record<string, unknown>,
  schema: z.ZodType<T>,
) => Promise<T>;

export class StarknetAdapter extends BaseAdapter<'starknet'> {
  constructor(opts: StarknetAdapterOptions = {}) {
    super('starknet', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(STARKNET_CHAINS) });
  }

  override chains(): ChainInfo[] {
    const catalog = chainsForFamily('starknet');
    return catalog.length > 0 ? catalog : STARKNET_CHAINS;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return starknetAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidStarknetAddress(addr);
  }

  private call<T>(
    url: string,
    method: string,
    params: unknown[] | Record<string, unknown>,
    schema: z.ZodType<T>,
  ): Promise<T> {
    return fetchJsonRpc(url, method, params, this.fetchOptions()).then((res) => schema.parse(res));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const id = await this.call(url, 'starknet_chainId', [], Felt);
      if (id.toLowerCase() !== CHAIN_FELT[chainId])
        throw new Error('Endpoint serves another Starknet network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(
    chainId: ChainId,
    query: (call: StarknetCall, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((method, params, schema) => this.call(url, method, params, schema), url);
    });
  }

  private balanceOf(call: StarknetCall, token: string, holder: string): Promise<bigint> {
    return call(
      'starknet_call',
      [
        {
          contract_address: token,
          entry_point_selector: feltHex(getSelectorFromName('balanceOf')),
          calldata: [feltHex(BigInt(holder))],
        },
        'latest',
      ],
      FeltList,
    ).then((res) => BigInt(res[0]!) + (BigInt(res[1] ?? '0x0') << 128n));
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidStarknetAddress(addr)) throw new TypeError(`invalid starknet address ${addr}`);
    const holder = normalizeStarknetAddress(addr);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        return this.balanceOf((m, p, s) => this.call(url, m, p, s), STRK_TOKEN, holder).then((v) =>
          v.toString(),
        );
      },
      { equal: (a, b) => a === b },
    );
    const tokens: Holding[] = [];
    for (const token of ERC20[chainId] ?? []) {
      const assetRef = `${chainId}:erc20:${token.address}`;
      const metadata = { symbol: token.symbol, decimals: token.decimals };
      const notice = 'ERC-20 balance from balanceOf; token transfers are not enabled.';
      try {
        const observed = await withCrossCheck(
          this.rpc,
          chainId,
          async (url) => {
            await this.checkNetwork(chainId, url);
            return this.balanceOf((m, p, s) => this.call(url, m, p, s), token.address, holder).then(
              (v) => v.toString(),
            );
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

  /** No keyless Starknet indexer exists (Voyager's API requires a key). */
  override getHistory(addr: Address, chainId: ChainId): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidStarknetAddress(addr)) return Promise.reject(new Error('Invalid history address'));
    return Promise.resolve({
      items: [],
      coverage: 'No keyless Starknet indexer is known, so history is unavailable.',
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(hash)) throw new Error('Invalid Starknet transaction hash');
    return this.withNode(chainId, async (call) => {
      try {
        const receipt = await call('starknet_getTransactionReceipt', [hash], Receipt);
        if (receipt.execution_status === 'REVERTED')
          return {
            state: 'failed',
            reason: (receipt.revert_reason ?? 'REVERTED').slice(0, 512),
          };
        if (receipt.execution_status === 'SUCCEEDED')
          return receipt.block_number !== undefined
            ? { state: 'confirmed', blockNumber: receipt.block_number }
            : { state: 'pending' };
        return { state: 'failed', reason: receipt.execution_status };
      } catch (err) {
        if (!isHashNotFound(err)) throw err;
      }
      try {
        const status = await call('starknet_getTransactionStatus', [hash], TxStatusResult);
        return status.finality_status === 'NOT_FOUND' ? { state: 'unknown' } : { state: 'pending' };
      } catch (err) {
        if (isHashNotFound(err)) return { state: 'unknown' };
        throw err;
      }
    });
  }
}

/** JSON-RPC error 29 (`TRANSACTION_HASH_NOT_FOUND`). */
export function isHashNotFound(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === 29
  );
}

/** JSON-RPC error 20 (`CONTRACT_NOT_FOUND`), also how undeployed accounts report. */
export function isContractNotFound(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === 20
  );
}

export function createStarknetAdapter(opts?: StarknetAdapterOptions): StarknetAdapter {
  return new StarknetAdapter(opts);
}
