/**
 * aelf adapter. Addresses are base58check of `sha256(sha256(pubkey))` over the
 * full 65-byte uncompressed SEC1 point; reads go over the node REST API, whose
 * `chainStatus` names the chain ("AELF" / "tDVV"), so every endpoint proves
 * which network it serves.
 *
 * aelf has no keyless balance or view endpoint: `/api/blockChain/executeTransaction`
 * rejects a signature that does not recover to the transaction's `from`. View
 * calls (GetBalance) are therefore signed with a well-known empty throwaway key
 * that holds no funds and is nobody's credential; the queried account travels
 * inside the call params.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { createBase58check } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
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
  type TxHash,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const AELF_MAINNET = 'aelf:AELF';
export const AELF_TESTNET = 'aelf:tDVV';
const base58check = createBase58check(sha256);

/** `AElf.Contracts.MultiToken`, resolved live from each genesis contract. */
export const AELF_TOKEN_CONTRACTS: Record<string, string> = {
  [AELF_MAINNET]: 'JRmBduh4nXWi1aXgdUsj5gJrzeZb2LxmrAbf7W99faZSvoAaE',
  [AELF_TESTNET]: '7RzVGiuVWkvL4VfVHdZfQF2Tri3sgLe9U991bohHFfSRZXuGX',
};

/** Fallback catalog until the family is wired into @stackwallet/chains. */
export const AELF_CHAINS: ChainInfo[] = [
  {
    chainId: AELF_MAINNET,
    family: 'aelf',
    name: 'aelf',
    nativeAsset: { ref: `${AELF_MAINNET}:native`, symbol: 'ELF', decimals: 8 },
    testnet: false,
    explorerTxUrl: 'https://aelfscan.io/AELF/tx/{hash}',
    defaultRpcs: ['https://aelf-public-node.aelf.io'],
    extra: { coinType: 1616 },
    priceId: 'aelf',
    layer: 'L1',
  },
  {
    chainId: AELF_TESTNET,
    family: 'aelf',
    name: 'aelf testnet',
    nativeAsset: { ref: `${AELF_TESTNET}:native`, symbol: 'ELF', decimals: 8 },
    testnet: true,
    explorerTxUrl: 'https://aelfscan.io/tDVV/tx/{hash}',
    defaultRpcs: ['https://tdvv-public-node.aelf.io'],
    extra: { coinType: 1616 },
    layer: 'L1',
  },
];

export function aelfAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(addr)) return undefined;
  try {
    const bytes = base58check.decode(addr);
    if (bytes.length !== 32 || bytes.every((b) => b === 0)) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

export function isValidAelfAddress(addr: string): boolean {
  return aelfAddressBytes(addr) !== undefined;
}

export function aelfAddressFromPublicKey(sec1: Uint8Array): string {
  return base58check.encode(sha256(sha256(secp256k1Uncompressed(sec1))));
}

// ---- minimal protobuf ----
function varint(value: bigint): number[] {
  const out: number[] = [];
  let v = value;
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return out;
}
const keyField = (field: number, wire: number) => varint(BigInt((field << 3) | wire));
export const protoBytes = (field: number, bytes: Uint8Array | number[]) => [
  ...keyField(field, 2),
  ...varint(BigInt(bytes.length)),
  ...bytes,
];
export const protoInt = (field: number, value: bigint) => [...keyField(field, 0), ...varint(value)];
const protoString = (field: number, value: string) => [
  ...protoBytes(field, new TextEncoder().encode(value)),
];
const addressMessage = (addr: string): number[] => {
  const bytes = aelfAddressBytes(addr);
  if (!bytes) throw new Error(`invalid aelf address ${addr}`);
  return protoBytes(1, bytes);
};

/** The serialized aelf `Transaction`; signature appended when given. */
export function transactionBytes(
  input: {
    from: string;
    to: string;
    refBlockNumber: bigint;
    refBlockPrefix: string;
    methodName: string;
    params: Uint8Array | number[];
  },
  signature?: Uint8Array,
): Uint8Array {
  if (!/^[0-9a-f]{8}$/.test(input.refBlockPrefix))
    throw new Error('invalid reference block prefix');
  const raw = [
    ...protoBytes(1, addressMessage(input.from)),
    ...protoBytes(2, addressMessage(input.to)),
    ...protoInt(3, input.refBlockNumber),
    ...protoBytes(
      4,
      input.refBlockPrefix.match(/../g)!.map((b) => parseInt(b, 16)),
    ),
    ...protoString(5, input.methodName),
    ...protoBytes(6, input.params),
  ];
  return Uint8Array.from(signature ? [...raw, ...protoBytes(10000, signature)] : raw);
}

/** Throwaway keypair whose only job is making read-only view calls parse. */
const VIEW_SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0));
export const VIEW_CALLER = aelfAddressFromPublicKey(secp256k1.getPublicKey(VIEW_SECRET, true));

function viewSignature(raw: Uint8Array): Uint8Array {
  const digest = sha256(raw);
  const compact = secp256k1.sign(digest, VIEW_SECRET, { prehash: false, lowS: true });
  const want = secp256k1.getPublicKey(VIEW_SECRET, false);
  for (const recid of [0, 1]) {
    try {
      const pub = secp256k1.Signature.fromBytes(compact)
        .addRecoveryBit(recid)
        .recoverPublicKey(digest);
      if (pub.toBytes(false).every((b, i) => b === want[i]))
        return Uint8Array.from([...compact, recid]);
    } catch {
      /* try the other parity */
    }
  }
  throw new Error('could not recover the view-call signature');
}

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Hash32 = z.string().regex(/^[0-9a-fA-F]{64}$/);
export const ChainStatus = z.object({
  ChainId: z.string().max(16),
  BestChainHeight: SafeInt.optional(),
  BestChainHash: Hash32.optional(),
  LongestChainHeight: SafeInt.optional(),
  LongestChainHash: Hash32.optional(),
  LastIrreversibleBlockHeight: SafeInt.optional(),
});
export type AelfChainStatus = z.infer<typeof ChainStatus>;
const TransactionResult = z.object({
  TransactionId: Hash32.optional(),
  Status: z.string().max(32),
  BlockNumber: SafeInt.optional(),
  BlockHash: Hash32.optional(),
  Error: z.string().max(2048).optional(),
});
const AelfError = z
  .object({ Error: z.object({ Message: z.string().max(2048) }).partial() })
  .partial();

/** Reads the aelf `{ "Error": { "Message": … } }` body an HttpError carries. */
export function aelfErrorMessage(error: unknown): string | undefined {
  if (!(error instanceof HttpError)) return undefined;
  try {
    return AelfError.parse(JSON.parse(error.body)).Error?.Message;
  } catch {
    return undefined;
  }
}

/** Parses a protobuf response keeping only the fields asked for. */
export function readProtoFields(
  bytes: Uint8Array,
): { field: number; value: bigint | Uint8Array }[] {
  const out: { field: number; value: bigint | Uint8Array }[] = [];
  let i = 0;
  const readVarint = (): bigint => {
    let v = 0n;
    let shift = 0n;
    for (;;) {
      if (i >= bytes.length) throw new Error('truncated protobuf');
      const b = bytes[i++]!;
      v |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return v;
      shift += 7n;
      if (shift > 70n) throw new Error('varint overflow');
    }
  };
  while (i < bytes.length) {
    const key = readVarint();
    const field = Number(key >> 3n);
    const wire = Number(key & 7n);
    if (wire === 0) out.push({ field, value: readVarint() });
    else if (wire === 2) {
      const len = Number(readVarint());
      if (len > bytes.length - i) throw new Error('truncated protobuf');
      out.push({ field, value: bytes.subarray(i, i + len) });
      i += len;
    } else if (wire === 5) i += 4;
    else if (wire === 1) i += 8;
    else throw new Error('unsupported protobuf wire type');
  }
  return out;
}

/** Decodes `GetBalanceOutput { symbol = 1, owner = 2, balance = 3 (int64) }`. */
export function decodeGetBalanceOutput(bytes: Uint8Array): bigint {
  const balance = readProtoFields(bytes).find((f) => f.field === 3);
  if (balance === undefined) return 0n;
  if (typeof balance.value !== 'bigint') throw new Error('balance is not a varint');
  return balance.value;
}

export type AelfAdapterOptions = BaseAdapterOptions;
export type AelfCall = <T>(path: string, body: unknown, schema: z.ZodType<T>) => Promise<T>;

export class AelfAdapter extends BaseAdapter<'aelf'> {
  constructor(opts: AelfAdapterOptions = {}) {
    super('aelf', opts);
  }

  /** Catalog entries win once the family is wired in; the fallback keeps the adapter usable now. */
  override chains(): ChainInfo[] {
    const wired = super.chains();
    return wired.length > 0 ? wired : AELF_CHAINS;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return aelfAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidAelfAddress(addr);
  }

  private post<T>(url: string, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    return postJsonText(`${url.replace(/\/$/, '')}${path}`, body, this.fetchOptions()).then(
      (text) => schema.parse(JSON.parse(text)),
    );
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const status = await this.chainStatusOf(url);
      if (`aelf:${status.ChainId}` !== chainId)
        throw new Error('Endpoint serves a different aelf chain');
    });
  }

  /** Network-proven chain status of one endpoint. */
  async chainStatusOf(url: string): Promise<AelfChainStatus> {
    const status = ChainStatus.parse(
      await fetchJson(`${url.replace(/\/$/, '')}/api/blockChain/chainStatus`, this.fetchOptions()),
    );
    const height = status.BestChainHeight ?? status.LongestChainHeight;
    if (height !== undefined) this.noteBlock(url, height);
    return status;
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: AelfCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, body, schema) => this.post(url, path, body, schema), url);
    });
  }

  /**
   * Runs a read-only contract view on an endpoint. aelf requires the call to
   * carry a signature that recovers to `from`, so it is signed with the
   * well-known empty throwaway key; nothing about the user's funds depends on it.
   */
  async viewCall(
    url: string,
    input: { to: string; methodName: string; params: Uint8Array | number[] },
    refBlock?: { number: bigint; prefix: string },
  ): Promise<Uint8Array> {
    let ref = refBlock;
    if (!ref) {
      const s = await this.chainStatusOf(url);
      const height = s.BestChainHeight ?? s.LongestChainHeight;
      const hash = s.BestChainHash ?? s.LongestChainHash;
      if (height === undefined || hash === undefined)
        throw new Error('Node did not report a head block');
      ref = { number: BigInt(height), prefix: hash.slice(0, 8).toLowerCase() };
    }
    const raw = transactionBytes({
      from: VIEW_CALLER,
      ...input,
      refBlockNumber: ref.number,
      refBlockPrefix: ref.prefix,
    });
    const signed = transactionBytes(
      { from: VIEW_CALLER, ...input, refBlockNumber: ref.number, refBlockPrefix: ref.prefix },
      viewSignature(raw),
    );
    const hex = [...signed].map((b) => b.toString(16).padStart(2, '0')).join('');
    const text = await postJsonText(
      `${url.replace(/\/$/, '')}/api/blockChain/executeTransaction`,
      { RawTransaction: hex },
      this.fetchOptions(),
    );
    const encoded = z
      .string()
      .max(1 << 16)
      .parse(JSON.parse(text));
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new Error('view result is not base64');
    const binary = atob(encoded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  }

  /** Native ELF balance via the token contract's GetBalance view. */
  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidAelfAddress(addr)) throw new TypeError(`invalid aelf address ${addr}`);
    const token = AELF_TOKEN_CONTRACTS[chainId];
    if (!token) throw new Error(`no token contract known for ${chainId}`);
    const params = [...protoString(1, 'ELF'), ...protoBytes(2, addressMessage(addr))];
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const out = await this.viewCall(url, { to: token, methodName: 'GetBalance', params });
        return decodeGetBalanceOutput(out).toString();
      },
      { equal: (a, b) => a === b },
    );
    return [
      {
        ...nativeHolding(chain, value, provenance),
        notice:
          'Read through a GetBalance view call signed with a well-known empty key; aelf has no keyless balance endpoint.',
      },
    ];
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid aelf transaction id');
    const id = hash.toLowerCase();
    return this.withNode(chainId, async (_call, url) => {
      const res = TransactionResult.parse(
        await fetchJson(
          `${url.replace(/\/$/, '')}/api/blockChain/transactionResult?transactionId=${id}`,
          this.fetchOptions(),
        ),
      );
      switch (res.Status) {
        case 'MINED':
          return {
            state: 'confirmed',
            blockNumber: res.BlockNumber ?? 0,
          } satisfies TxStatus;
        case 'PENDING':
        case 'PENDING_VALIDATION':
          return { state: 'pending' } satisfies TxStatus;
        case 'FAILED':
        case 'NODE_VALIDATION_FAILED':
        case 'CONFLICT':
          return { state: 'failed', reason: res.Error ?? res.Status } satisfies TxStatus;
        default:
          return { state: 'unknown' } satisfies TxStatus;
      }
    });
  }
}

export function createAelfAdapter(opts?: AelfAdapterOptions): AelfAdapter {
  return new AelfAdapter(opts);
}
