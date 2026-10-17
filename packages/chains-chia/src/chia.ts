/**
 * Chia adapter. Addresses are bech32m of a 32-byte puzzle hash (`xch1…` /
 * `txch1…`); a wallet address commits to the standard
 * pay-to-delegated-puzzle curried with the holder's *synthetic* BLS public
 * key. Reads go over the keyless coinset.org full-node RPC, whose
 * `get_network_info` proves which network it serves.
 *
 * Signing stays in the Rust core (`fam-chia`); this package never sees a
 * private key. The core's `Curve` enum predates BLS12-381, so the key kind
 * is checked by length (48-byte compressed G1) until the enum grows the
 * variant.
 */
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { bech32m } from '@scure/base';
import {
  BaseAdapter,
  nativeHolding,
  postJsonText,
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

/** CAIP-2 references are the first 8 bytes of each network's genesis challenge. */
export const CHIA_MAINNET = 'chia:ccd5bb71';
export const CHIA_TESTNET = 'chia:37a90eb5';

const NETWORKS: Record<string, { prefix: string; networkName: string }> = {
  [CHIA_MAINNET]: { prefix: 'xch', networkName: 'mainnet' },
  [CHIA_TESTNET]: { prefix: 'txch', networkName: 'testnet11' },
};

export function chiaNetworkPrefix(chainId: ChainId): string {
  const net = NETWORKS[chainId];
  if (!net) throw new Error(`unknown chia chain ${chainId}`);
  return net.prefix;
}

/** The 32-byte puzzle hash inside an `xch1…`/`txch1…` bech32m address. */
export function chiaAddressBytes(addr: string, prefix?: string): Uint8Array | undefined {
  if (!/^[a-z0-9]{10,90}$/.test(addr)) return undefined;
  try {
    const { prefix: hrp, words } = bech32m.decode(addr as `${string}1${string}`, 90);
    if (prefix !== undefined && hrp !== prefix) return undefined;
    if (hrp !== 'xch' && hrp !== 'txch') return undefined;
    const bytes = bech32m.fromWords(words);
    if (bytes.length !== 32 || bytes.every((b) => b === 0)) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

export function isValidChiaAddress(addr: string, prefix?: string): boolean {
  return chiaAddressBytes(addr, prefix) !== undefined;
}

export function chiaAddressFromPuzzleHash(puzzleHash: Uint8Array, prefix: string): string {
  if (puzzleHash.length !== 32) throw new Error('puzzle hash must be 32 bytes');
  return bech32m.encode(prefix, bech32m.toWords(puzzleHash), 90);
}

// ---------------------------------------------------------------------------
// Minimal CLVM s-expressions: enough to curry the standard puzzle and hash it.
// ---------------------------------------------------------------------------

type SExp = Uint8Array | [SExp, SExp];

const atom = (bytes: Uint8Array): SExp => bytes;
const pair = (l: SExp, r: SExp): SExp => [l, r];
const list = (...items: SExp[]): SExp => {
  let out: SExp = new Uint8Array(0);
  for (let i = items.length - 1; i >= 0; i--) out = [items[i]!, out];
  return out;
};

export function sexpTreeHash(sexp: SExp): Uint8Array {
  return sexp instanceof Uint8Array
    ? sha256(concatBytes(Uint8Array.of(1), sexp))
    : sha256(concatBytes(Uint8Array.of(2), sexpTreeHash(sexp[0]), sexpTreeHash(sexp[1])));
}

/** Tree hash of the byte-for-byte standard puzzle every Chia wallet deploys. */
export const STANDARD_PUZZLE_TREE_HASH =
  'e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52';
const DEFAULT_HIDDEN_PUZZLE_HASH =
  '711d6c4e32c92e53179b199484cf8c897542bc57f2b22582799f9d657eec4699';

/** Serialized standard puzzle MOD (without the curried key). */
const MOD_HEX =
  'ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080';

/** `(2 (1 . MOD) (4 (1 . key) 1))` — the curry shape the network expects. */
function curriedStandardPuzzle(syntheticPk: Uint8Array): SExp {
  return list(
    atom(Uint8Array.of(2)),
    pair(atom(Uint8Array.of(1)), parseSexp(hexToBytes(MOD_HEX))[0]),
    list(
      atom(Uint8Array.of(4)),
      pair(atom(Uint8Array.of(1)), atom(syntheticPk)),
      atom(Uint8Array.of(1)),
    ),
  );
}

export function parseSexp(bytes: Uint8Array, i = 0): [SExp, number] {
  const b = bytes[i];
  if (b === undefined) throw new Error('truncated s-expression');
  if (b === 0xff) {
    const [l, j] = parseSexp(bytes, i + 1);
    const [r, k] = parseSexp(bytes, j);
    return [[l, r], k];
  }
  if (b === 0x80) return [new Uint8Array(0), i + 1];
  if (b <= 0x7f) return [Uint8Array.of(b), i + 1];
  const at = (j: number): number => {
    const v = bytes[j];
    if (v === undefined) throw new Error('truncated s-expression');
    return v;
  };
  let len: number;
  let next: number;
  if (b < 0xc0) {
    len = b & 0x3f;
    next = i + 1;
  } else if (b < 0xe0) {
    len = ((b & 0x1f) << 8) | at(i + 1);
    next = i + 2;
  } else if (b < 0xf0) {
    len = ((b & 0x0f) << 16) | (at(i + 1) << 8) | at(i + 2);
    next = i + 3;
  } else if (b < 0xf8) {
    len = ((b & 0x07) << 24) | (at(i + 1) << 16) | (at(i + 2) << 8) | at(i + 3);
    next = i + 4;
  } else throw new Error('atom too long');
  if (next + len > bytes.length) throw new Error('truncated s-expression');
  return [bytes.slice(next, next + len), next + len];
}

const BLS12_381_FR = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');

/**
 * The synthetic public key committed to by a wallet's standard puzzle:
 * `pk + H(pk || hidden_puzzle_hash) * G`. Mirrors the Rust core exactly.
 */
export function syntheticPublicKey(pk: Uint8Array): Uint8Array {
  if (pk.length !== 48) throw new Error('chia public key must be 48 bytes');
  const offset =
    BigInt('0x' + bytesToHex(sha256(concatBytes(pk, hexToBytes(DEFAULT_HIDDEN_PUZZLE_HASH))))) %
    BLS12_381_FR;
  const point = bls12_381.G1.Point.fromBytes(pk).add(bls12_381.G1.Point.BASE.multiply(offset));
  return point.toBytes(true);
}

/** Puzzle hash of the standard puzzle locked to this base public key. */
export function standardPuzzleHash(pk: Uint8Array): Uint8Array {
  return sexpTreeHash(curriedStandardPuzzle(syntheticPublicKey(pk)));
}

export function chiaAddressFromPublicKey(pk: Uint8Array, prefix: string): string {
  return chiaAddressFromPuzzleHash(standardPuzzleHash(pk), prefix);
}

// ---------------------------------------------------------------------------
// coinset.org full-node RPC schemas.
// ---------------------------------------------------------------------------

const Hex32 = z.string().regex(/^0x[0-9a-f]{64}$/);
const Mojo = z.union([
  z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  z.string().regex(/^\d{1,19}$/),
]);
const CoinSchema = z.object({
  parent_coin_info: Hex32,
  puzzle_hash: Hex32,
  amount: Mojo,
});
export const CoinRecord = z.object({
  coin: CoinSchema,
  coinbase: z.boolean(),
  confirmed_block_index: z.number().int().nonnegative(),
  spent_block_index: z.number().int().nonnegative(),
  spent: z.boolean(),
  timestamp: z.number().int().nonnegative(),
});
const CoinRecords = z.object({
  success: z.literal(true),
  coin_records: z.array(CoinRecord).max(100_000),
});
const CoinRecordByName = z.object({
  success: z.literal(true),
  coin_record: CoinRecord.nullable().optional(),
});
const NetworkInfo = z.object({
  success: z.literal(true),
  network_name: z.string().max(64),
});
const BlockchainState = z.object({
  success: z.literal(true),
  blockchain_state: z.object({
    peak: z.object({ height: z.number().int().nonnegative() }).nullable(),
  }),
});
const PushTx = z.object({
  success: z.boolean(),
  status: z.string().max(64).optional(),
  error: z.string().max(4096).nullable().optional(),
});

export type ChiaAdapterOptions = BaseAdapterOptions;
export type ChiaCall = <T>(path: string, body: unknown, schema: z.ZodType<T>) => Promise<T>;

/**
 * Local chain definitions. The shared catalog has no chia entry yet; when the
 * lead lands one, these values must move there unchanged (the hand-off notes
 * in `.nur/wiring/chia.md` carry the same table).
 */
export const CHIA_CHAINS: ChainInfo[] = [
  {
    chainId: CHIA_MAINNET,
    family: 'chia',
    name: 'Chia',
    nativeAsset: { ref: `${CHIA_MAINNET}:native`, symbol: 'XCH', decimals: 12 },
    testnet: false,
    explorerTxUrl: 'https://xchscan.com/txns/{hash}',
    defaultRpcs: ['https://api.coinset.org'],
  },
  {
    chainId: CHIA_TESTNET,
    family: 'chia',
    name: 'Chia testnet11',
    nativeAsset: { ref: `${CHIA_TESTNET}:native`, symbol: 'TXCH', decimals: 12 },
    testnet: true,
    explorerTxUrl: 'https://testnet11.spacescan.io/txns/{hash}',
    defaultRpcs: ['https://testnet11.api.coinset.org'],
  },
];

export class ChiaAdapter extends BaseAdapter<'chia'> {
  constructor(opts: ChiaAdapterOptions = {}) {
    super('chia', opts);
  }

  override chains(): ChainInfo[] {
    return [...CHIA_CHAINS];
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    // The core's Curve enum has no bls12-381 variant yet, so the key arrives
    // tagged with the derivation path's curve; the 48-byte compressed G1
    // encoding is the real check until the enum grows the variant.
    const bytes = publicKeyBytes(pub);
    if (bytes.length !== 48)
      throw new Error(`a chia address needs a 48-byte compressed G1 key (curve ${pub.curve})`);
    return chiaAddressFromPublicKey(bytes, chiaNetworkPrefix(chainId));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidChiaAddress(addr, chiaNetworkPrefix(chainId));
  }

  private post<T>(url: string, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    return postJsonText(`${url.replace(/\/$/, '')}${path}`, body, this.fetchOptions()).then(
      (text) => schema.parse(JSON.parse(text)),
    );
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const net = NETWORKS[chainId];
    if (!net) throw new Error(`unknown chia chain ${chainId}`);
    await this.verifyEndpoint(chainId, url, async () => {
      const info = await this.post(url, '/get_network_info', {}, NetworkInfo);
      if (info.network_name !== net.networkName)
        throw new Error(`Endpoint serves ${info.network_name}, not ${chainId}`);
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: ChiaCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, body, schema) => this.post(url, path, body, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const ph = chiaAddressBytes(addr, chiaNetworkPrefix(chainId));
    if (!ph) throw new TypeError(`invalid chia address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const records = await this.post(
          url,
          '/get_coin_records_by_puzzle_hash',
          { puzzle_hash: `0x${bytesToHex(ph)}`, include_spent_coins: false },
          CoinRecords,
        );
        return records.coin_records
          .filter((r) => !r.spent)
          .reduce((sum, r) => sum + BigInt(r.coin.amount), 0n)
          .toString();
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    const ph = chiaAddressBytes(addr, chiaNetworkPrefix(chainId));
    if (!ph) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,12}$/.test(cursor))
      throw new Error('Invalid history cursor');
    return this.withNode(chainId, async (call, url) => {
      void options;
      const startHeight = cursor === undefined ? 0 : Number(cursor);
      const [records, state] = await Promise.all([
        call(
          '/get_coin_records_by_puzzle_hash',
          {
            puzzle_hash: `0x${bytesToHex(ph)}`,
            include_spent_coins: true,
            ...(startHeight > 0 ? { start_height: startHeight } : {}),
          },
          CoinRecords,
        ),
        call('/get_blockchain_state', {}, BlockchainState),
      ]);
      const peak = state.blockchain_state.peak?.height ?? 0;
      const items: TxRecord[] = [];
      for (const r of records.coin_records) {
        const name = coinName(r.coin);
        items.push(coinRecord(chain.chainId, chain.nativeAsset.ref, name, r, 'received'));
        if (r.spent && r.spent_block_index > 0)
          items.push(coinRecord(chain.chainId, chain.nativeAsset.ref, name, r, 'spent'));
      }
      items.sort((a, b) => (b.blockNumber ?? 0) - (a.blockNumber ?? 0));
      const latest = records.coin_records.reduce(
        (m, r) => Math.max(m, r.confirmed_block_index, r.spent_block_index),
        0,
      );
      return {
        items,
        ...(latest > 0 && latest < peak ? { nextCursor: String(latest + 1) } : {}),
        coverage:
          'Coin records for this puzzle hash. Each receive and each spend is one entry keyed by the coin id (a Chia transaction has no single hash; the spent coin id is the reference). Fees are not derivable from coin records alone.',
        source: url,
      };
    });
  }

  /** A Chia transaction reference is the id of the coin the transfer spent. */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid chia coin id');
    const name = `0x${hash.replace(/^0x/, '').toLowerCase()}`;
    return this.withNode(chainId, async (call) => {
      const res = await call('/get_coin_record_by_name', { name }, CoinRecordByName);
      const record = res.coin_record;
      if (!record) return { state: 'unknown' };
      if (record.spent)
        return record.spent_block_index > 0
          ? {
              state: 'confirmed',
              blockNumber: record.spent_block_index,
              timestampMs: record.timestamp * 1000,
            }
          : { state: 'pending' };
      return { state: 'unknown' };
    });
  }
}

/** Minimal big-endian CLVM integer bytes (zero-prefixed when the high bit is set). */
export function clvmIntBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new Error('negative amount');
  const out: number[] = [];
  let v = value;
  while (v > 0n) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  if (out.length > 0 && (out[0]! & 0x80) !== 0) out.unshift(0);
  return Uint8Array.from(out);
}

/**
 * The coin's consensus name: `sha256(parent || puzzle_hash || amount)` where
 * the amount serializes as a minimal CLVM integer (chia `Coin::coin_id()`),
 * not as a fixed eight-byte integer.
 */
export function coinName(coin: z.infer<typeof CoinSchema>): string {
  return bytesToHex(
    sha256(
      concatBytes(
        hexToBytes(coin.parent_coin_info.slice(2)),
        hexToBytes(coin.puzzle_hash.slice(2)),
        clvmIntBytes(BigInt(coin.amount)),
      ),
    ),
  );
}

function coinRecord(
  chainId: string,
  nativeRef: string,
  name: string,
  r: z.infer<typeof CoinRecord>,
  direction: 'received' | 'spent',
): TxRecord {
  const received = direction === 'received';
  return {
    entryId: `${name}:${direction}`,
    hash: name,
    chainId,
    ...(received
      ? { blockNumber: r.confirmed_block_index, timestampMs: r.timestamp * 1000 }
      : { blockNumber: r.spent_block_index }),
    from: '',
    assetDeltas: [
      {
        assetRef: nativeRef,
        amount: received ? String(r.coin.amount) : `-${BigInt(r.coin.amount)}`,
      },
    ],
    feeAssetRef: nativeRef,
    fee: null,
    status: received || r.spent_block_index > 0 ? 'confirmed' : 'pending',
  };
}

export function createChiaAdapter(opts?: ChiaAdapterOptions): ChiaAdapter {
  return new ChiaAdapter(opts);
}
