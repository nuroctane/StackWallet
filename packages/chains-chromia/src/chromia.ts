/**
 * Chromia (Postchain / FT4) adapter. Account addresses are 32-byte FT4
 * account ids (sha256 of a merkle leaf over the compressed secp256k1 public
 * key), rendered as 64 lowercase hex characters. Reads go over the postchain
 * REST API: `GET /config/{brid}/features` proves the network and merkle
 * version, `POST /query_gtv/{brid}` answers FT4 queries as GTV (DER) binary,
 * and `GET /tx/{brid}/{rid}/status` reports transaction status.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  MemoryRpcPool,
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

export const CHROMIA_MAINNET = 'chromia:0x15c0ca99bee60a3b';
export const CHROMIA_TESTNET = 'chromia:0x090bcd47149fbb66';

/** Balance notice for an account id without an FT4 account; the UI offers registration on it. */
export const CHROMIA_UNREGISTERED_NOTICE =
  'No FT4 account exists for this id yet; the first incoming transfer stays pending until the account is registered.';

export interface ChromiaNetwork {
  /** Full 32-byte blockchain rid, uppercase hex as the REST API expects. */
  brid: string;
  /** Native asset id on the economy chain. */
  assetId: string;
}

export const CHROMIA_NETWORKS: Record<string, ChromiaNetwork> = {
  [CHROMIA_MAINNET]: {
    brid: '15C0CA99BEE60A3B23829968771C50E491BD00D2E3AE448580CD48A8D71E7BBA',
    assetId: '5f16d1545a0881f971b164f1601cbbf51c29efd0633b2730da18c403c3b428b5',
  },
  [CHROMIA_TESTNET]: {
    brid: '090BCD47149FBB66F02489372E88A454E7A5645ADDE82125D40DF1EF0C76F874',
    assetId: '9ef73a786a66f435b3b40e72f5e9d85a4b09815997e087c809913e1e7ec686b4',
  },
};

/** Local chain infos until the shared catalog gains Chromia entries. */
export const CHROMIA_CHAINS: ChainInfo[] = [
  {
    chainId: CHROMIA_TESTNET,
    family: 'chromia',
    name: 'Chromia Testnet',
    nativeAsset: { ref: `${CHROMIA_TESTNET}:native`, symbol: 'CHR', decimals: 6 },
    testnet: true,
    defaultRpcs: [
      'https://node0.testnet.chromia.com:7740',
      'https://node1.testnet.chromia.com:7740',
      'https://node2.testnet.chromia.com:7740',
    ],
    priceId: 'chromia',
  },
  {
    chainId: CHROMIA_MAINNET,
    family: 'chromia',
    name: 'Chromia',
    nativeAsset: { ref: `${CHROMIA_MAINNET}:native`, symbol: 'CHR', decimals: 6 },
    testnet: false,
    defaultRpcs: [
      'https://system.chromaway.com',
      'https://chromia.validatrium.club',
      'https://chromia.mainnet-system.nodeops.ninja',
      'https://chromia-api.hashkey.cloud',
    ],
    priceId: 'chromia',
  },
];

// ---------------------------------------------------------------------------
// GTV codec (DER, explicit context tags 0..6)
// ---------------------------------------------------------------------------

export type Gtv = null | Uint8Array | string | number | bigint | Gtv[] | { [key: string]: Gtv };

function tlv(tag: number, content: Uint8Array): number[] {
  const len = content.length;
  const head: number[] = [tag];
  if (len < 128) {
    head.push(len);
  } else {
    const n: number[] = [];
    let v = len;
    while (v > 0) {
      n.unshift(v & 0xff);
      v >>= 8;
    }
    head.push(0x80 | n.length, ...n);
  }
  return [...head, ...content];
}

const text = new TextEncoder();

function derInteger(value: number | bigint): number[] {
  let v = BigInt(value);
  if (v < 0n) throw new Error('GTV integer must be non-negative');
  const bytes: number[] = [];
  do {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v > 0n);
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return tlv(0x02, Uint8Array.from(bytes));
}

/** Canonical DER encoding of a GTV value; dict keys are sorted. */
export function gtvEncode(value: Gtv): Uint8Array {
  if (value === null) return Uint8Array.from(tlv(0xa0, Uint8Array.from([0x05, 0x00])));
  if (value instanceof Uint8Array)
    return Uint8Array.from(tlv(0xa1, Uint8Array.from(tlv(0x04, value))));
  if (typeof value === 'string')
    return Uint8Array.from(tlv(0xa2, Uint8Array.from(tlv(0x0c, text.encode(value)))));
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('GTV integer out of range');
    return Uint8Array.from(tlv(0xa3, Uint8Array.from(derInteger(value))));
  }
  if (typeof value === 'bigint')
    return Uint8Array.from(tlv(0xa6, Uint8Array.from(derInteger(value))));
  if (Array.isArray(value)) {
    const inner = value.flatMap((item) => [...gtvEncode(item)]);
    return Uint8Array.from(tlv(0xa5, Uint8Array.from(tlv(0x30, Uint8Array.from(inner)))));
  }
  const keys = Object.keys(value).sort();
  const pairs = keys.flatMap((k) => [
    ...tlv(0x30, Uint8Array.from([...tlv(0x0c, text.encode(k)), ...gtvEncode(value[k]!)])),
  ]);
  return Uint8Array.from(tlv(0xa4, Uint8Array.from(tlv(0x30, Uint8Array.from(pairs)))));
}

/** Decodes one GTV value; integers and big integers both surface as bigint. */
export function gtvDecode(buf: Uint8Array): Gtv {
  const [value, end] = decodeAt(buf, 0);
  if (end !== buf.length) throw new Error('Trailing bytes after GTV value');
  return value;
}

function decodeAt(buf: Uint8Array, off: number): [Gtv, number] {
  const tag = buf[off];
  if (tag === undefined) throw new Error('Truncated GTV');
  let p = off + 1;
  let len = buf[p++];
  if (len === undefined) throw new Error('Truncated GTV length');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('Indefinite or oversized GTV length');
    len = 0;
    for (let i = 0; i < n; i++) {
      const b = buf[p++];
      if (b === undefined) throw new Error('Truncated GTV length');
      len = (len << 8) | b;
    }
  }
  if (p + len > buf.length) throw new Error('Truncated GTV content');
  const content = buf.subarray(p, p + len);
  const next = p + len;
  const decodeSeq = (b: Uint8Array): Gtv[] => {
    const items: Gtv[] = [];
    let q = 0;
    while (q < b.length) {
      const [v, nq] = decodeAt(b, q);
      items.push(v);
      q = nq;
    }
    return items;
  };
  const decodeInt = (b: Uint8Array): bigint => {
    let v = 0n;
    for (const byte of b) v = (v << 8n) | BigInt(byte);
    // Two's complement: a set high bit on the first byte means negative.
    if (b.length > 0 && (b[0]! & 0x80) !== 0) v -= 1n << BigInt(b.length * 8);
    return v;
  };
  const cls = tag >> 6;
  if (cls === 2) {
    // Explicit context tags 0..6 carry one inner universal value.
    const innerTag = content[0];
    if (innerTag === undefined) throw new Error('Empty explicit GTV tag');
    const rest = content.subarray(1);
    switch (tag & 0x1f) {
      case 0: {
        if (innerTag !== 0x05 || rest.length !== 1 || rest[0] !== 0)
          throw new Error('Malformed GTV null');
        return [null, next];
      }
      case 1: {
        if (innerTag !== 0x04) throw new Error('Malformed GTV byte array');
        const lenLen = readLen(rest, 0);
        return [new Uint8Array(rest.subarray(lenLen.next, lenLen.next + lenLen.len)), next];
      }
      case 2: {
        if (innerTag !== 0x0c) throw new Error('Malformed GTV string');
        const lenLen = readLen(rest, 0);
        return [
          new TextDecoder().decode(rest.subarray(lenLen.next, lenLen.next + lenLen.len)),
          next,
        ];
      }
      case 3:
      case 6: {
        if (innerTag !== 0x02) throw new Error('Malformed GTV integer');
        const lenLen = readLen(rest, 0);
        return [decodeInt(rest.subarray(lenLen.next, lenLen.next + lenLen.len)), next];
      }
      case 4: {
        if (innerTag !== 0x30) throw new Error('Malformed GTV dict');
        const lenLen = readLen(rest, 0);
        const pairs = decodeSeq(rest.subarray(lenLen.next, lenLen.next + lenLen.len));
        const dict: { [key: string]: Gtv } = {};
        for (const pair of pairs) {
          if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string')
            throw new Error('Malformed GTV dict entry');
          const value = pair[1];
          if (value === undefined) throw new Error('Malformed GTV dict entry');
          dict[pair[0]] = value;
        }
        return [dict, next];
      }
      case 5: {
        if (innerTag !== 0x30) throw new Error('Malformed GTV array');
        const lenLen = readLen(rest, 0);
        return [decodeSeq(rest.subarray(lenLen.next, lenLen.next + lenLen.len)), next];
      }
      default:
        throw new Error(`Unsupported GTV explicit tag ${tag & 0x1f}`);
    }
  }
  // Universal tags appear inside dict entries and around explicit contents.
  if (tag === 0x30) return [decodeSeq(content), next];
  if (tag === 0x04) return [new Uint8Array(content), next];
  if (tag === 0x0c) return [new TextDecoder().decode(content), next];
  if (tag === 0x02) return [decodeInt(content), next];
  if (tag === 0x05) return [null, next];
  throw new Error(`Unsupported GTV tag 0x${tag.toString(16)}`);
}

/** Reads a DER length starting at `off`; returns {len, next}. */
function readLen(buf: Uint8Array, off: number): { len: number; next: number } {
  let len = buf[off];
  if (len === undefined) throw new Error('Truncated GTV length');
  let p = off + 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('Bad GTV length');
    len = 0;
    for (let i = 0; i < n; i++) {
      const b = buf[p++];
      if (b === undefined) throw new Error('Truncated GTV length');
      len = (len << 8) | b;
    }
  }
  if (p + len > buf.length) throw new Error('Truncated GTV content');
  return { len, next: p };
}

// ---------------------------------------------------------------------------
// Merkle hash (version 2): leaf sha256(0x01||gtv), node 0x00, array root 0x07,
// empty subtree 32 zero bytes; odd elements carry up unpaired.
// ---------------------------------------------------------------------------

type Tree =
  | { kind: 'empty' }
  | { kind: 'leaf'; value: Gtv }
  | { kind: 'node'; arrayRoot: boolean; left: Tree; right: Tree };

const EMPTY: Tree = { kind: 'empty' };

function buildTree(value: Gtv): Tree {
  if (!Array.isArray(value)) return { kind: 'leaf', value };
  const leaves = value.map(buildTree);
  if (leaves.length === 0) return { kind: 'node', arrayRoot: true, left: EMPTY, right: EMPTY };
  if (leaves.length === 1 && leaves[0]!.kind === 'node')
    return { kind: 'node', arrayRoot: true, left: leaves[0]!, right: EMPTY };
  let level = leaves;
  while (level.length > 1) {
    const next: Tree[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const right = level[i + 1];
      next.push(
        right === undefined
          ? level[i]!
          : { kind: 'node', arrayRoot: false, left: level[i]!, right },
      );
    }
    level = next;
  }
  const root = level[0]!;
  return root.kind === 'node'
    ? { kind: 'node', arrayRoot: true, left: root.left, right: root.right }
    : { kind: 'node', arrayRoot: true, left: root, right: EMPTY };
}

function merkleHash(tree: Tree): Uint8Array {
  if (tree.kind === 'empty') return new Uint8Array(32);
  if (tree.kind === 'leaf') return sha256(Uint8Array.from([1, ...gtvEncode(tree.value)]));
  return sha256(
    Uint8Array.from([tree.arrayRoot ? 7 : 0, ...merkleHash(tree.left), ...merkleHash(tree.right)]),
  );
}

/** Transaction rids and account ids are this hash of a GTV value. */
export function gtvHash(value: Gtv): Uint8Array {
  return merkleHash(buildTree(value));
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

const ADDRESS = /^[0-9a-f]{64}$/;

export function isValidChromiaAddress(addr: string): boolean {
  return ADDRESS.test(addr);
}

/** Compressed secp256k1 public key -> 32-byte FT4 account id, lowercase hex. */
export function chromiaAccountIdFromPublicKey(sec1: Uint8Array): string {
  const compressed = secp256k1.Point.fromHex(bytesToHex(sec1)).toBytes(true);
  // A lone leaf hashes identically under merkle versions 1 and 2.
  return bytesToHex(sha256(Uint8Array.from([1, ...gtvEncode(compressed)])));
}

/**
 * The single-sig auth descriptor [0, [["A","T"], pubkey], null] and its id
 * (the economy chain mandates both flags).
 */
export function chromiaAuthDescriptor(sec1: Uint8Array): Gtv {
  const compressed = secp256k1.Point.fromHex(bytesToHex(sec1)).toBytes(true);
  return [0, [['A', 'T'], compressed], null];
}

export function chromiaAuthDescriptorId(sec1: Uint8Array): Uint8Array {
  return gtvHash(chromiaAuthDescriptor(sec1));
}

function network(chainId: string): ChromiaNetwork {
  const net = CHROMIA_NETWORKS[chainId];
  if (!net) throw new Error(`Unknown Chromia network ${chainId}`);
  return net;
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

const Features = z.object({ merkle_hash_version: z.number().int() });
const GtvNull = z.null();
const GtvBigInt = z.bigint();
const Account = z.looseObject({ id: z.instanceof(Uint8Array) });
const TxStatusResponse = z.object({
  status: z.enum(['unknown', 'waiting', 'confirmed', 'rejected']),
  rejectReason: z.string().max(4096).optional(),
  rejectTimestamp: z.number().int().optional(),
});
const BlockHead = z.looseObject({
  rid: z.string(),
  height: z.number().int().nonnegative(),
  transactions: z
    .array(z.looseObject({ rid: z.string() }))
    .max(4096)
    .optional(),
});

export type ChromiaAdapterOptions = BaseAdapterOptions;
export type ChromiaQuery = <T>(
  name: string,
  args: Record<string, Gtv>,
  schema: z.ZodType<T>,
) => Promise<T>;

export class ChromiaAdapter extends BaseAdapter<'chromia'> {
  constructor(opts: ChromiaAdapterOptions = {}) {
    super('chromia', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(CHROMIA_CHAINS) });
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return chromiaAccountIdFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidChromiaAddress(addr);
  }

  private async get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    const res = await (this.fetchImpl ?? fetch)(`${url.replace(/\/$/, '')}${path}`, {
      signal: AbortSignal.timeout(this.timeoutMs ?? 15_000),
    });
    if (!res.ok) throw new Error(`Chromia node answered ${res.status} for ${path}`);
    return schema.parse(await res.json());
  }

  private async query<T>(
    url: string,
    name: string,
    args: Record<string, Gtv>,
    schema: z.ZodType<T>,
  ): Promise<T> {
    const res = await (this.fetchImpl ?? fetch)(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', Accept: 'application/octet-stream' },
      body: new Uint8Array(gtvEncode([name, args])),
      signal: AbortSignal.timeout(this.timeoutMs ?? 15_000),
    });
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).replace(/[^\x20-\x7e]/g, '').slice(0, 256);
      throw new Error(`Chromia query ${name} failed: ${res.status} ${detail}`.trim());
    }
    return schema.parse(gtvDecode(new Uint8Array(await res.arrayBuffer())));
  }

  private bridOf(chainId: ChainId): string {
    this.requireChain(chainId);
    return network(chainId).brid;
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const brid = this.bridOf(chainId);
      const features = await this.get(url, `/config/${brid}/features`, Features);
      if (features.merkle_hash_version !== 2)
        throw new Error('Endpoint does not serve a merkle v2 Chromia chain');
      // A non-FT4 chain would not know this query; an unregistered account
      // answering null is the expected success path.
      await this.query(
        `${url.replace(/\/$/, '')}/query_gtv/${brid}`,
        'ft4.get_asset_balance',
        { account_id: new Uint8Array(32), asset_id: hexToBytes(network(chainId).assetId) },
        z.union([GtvNull, GtvBigInt]),
      );
    });
  }

  /** Runs `query` on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, run: (query: ChromiaQuery, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    const brid = this.bridOf(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const query: ChromiaQuery = (name, args, schema) =>
        this.query(`${url.replace(/\/$/, '')}/query_gtv/${brid}`, name, args, schema);
      return run(query, url);
    });
  }

  /** Posts a signed GTX body to a network-proven endpoint. */
  async postWire(chainId: ChainId, bytes: Uint8Array): Promise<{ status: number; text: string }> {
    const brid = this.bridOf(chainId);
    return this.withNode(chainId, async (_query, url) => {
      const res = await (this.fetchImpl ?? fetch)(`${url.replace(/\/$/, '')}/tx/${brid}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', Accept: 'application/json' },
        body: new Uint8Array(bytes),
        signal: AbortSignal.timeout(this.timeoutMs ?? 15_000),
      });
      return { status: res.status, text: await res.text().catch(() => '') };
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidChromiaAddress(addr)) throw new TypeError(`invalid chromia address ${addr}`);
    const assetId = hexToBytes(network(chainId).assetId);
    const accountId = hexToBytes(addr);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const brid = network(chainId).brid;
        const q = <T>(name: string, args: Record<string, Gtv>, schema: z.ZodType<T>) =>
          this.query(`${url.replace(/\/$/, '')}/query_gtv/${brid}`, name, args, schema);
        const balance = await q(
          'ft4.get_asset_balance',
          { account_id: accountId, asset_id: assetId },
          z.union([GtvNull, GtvBigInt]),
        );
        const account = await q(
          'ft4.get_account_by_id',
          { id: accountId },
          z.union([GtvNull, Account]),
        );
        return {
          balance: balance === null ? '0' : balance.toString(),
          registered: account !== null,
        };
      },
      { equal: (a, b) => a.balance === b.balance && a.registered === b.registered },
    );
    const holding = nativeHolding(chain, value.balance, provenance);
    if (!value.registered) holding.notice = CHROMIA_UNREGISTERED_NOTICE;
    return [holding];
  }

  /** The FT4 history entry shape is not yet verified live; report no history. */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidChromiaAddress(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'Chromia FT4 transfer history is not mapped yet; balances and status are still live.',
    };
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!ADDRESS.test(hash)) throw new Error('Invalid Chromia transaction id');
    const brid = this.bridOf(chainId);
    return this.withNode(chainId, async (_query, url) => {
      const res = await this.get(url, `/tx/${brid}/${hash.toUpperCase()}/status`, TxStatusResponse);
      switch (res.status) {
        case 'unknown':
          return { state: 'unknown' };
        case 'waiting':
          return { state: 'pending' };
        case 'rejected':
          return {
            state: 'failed',
            ...(res.rejectReason
              ? { reason: res.rejectReason.replace(/[^\x20-\x7e]/g, '').slice(0, 512) }
              : {}),
          };
        case 'confirmed': {
          // The status endpoint carries no height; find the tx in recent
          // blocks, else report the current height as a conservative bound.
          const blocks = await this.get(
            url,
            `/blocks/${brid}?limit=25&txs=true`,
            z.array(BlockHead).max(25),
          );
          const rid = hash.toUpperCase();
          const own = blocks.find((b) => b.transactions?.some((t) => t.rid === rid));
          return { state: 'confirmed', blockNumber: own?.height ?? blocks[0]?.height ?? 0 };
        }
      }
    });
  }
}

export function createChromiaAdapter(opts?: ChromiaAdapterOptions): ChromiaAdapter {
  return new ChromiaAdapter(opts);
}
