/**
 * Aptos adapter, also serving the Aptos-compatible Movement and Supra mainnets
 * for reads. Account addresses are `0x` + 64 lowercase hex (AIP-40 long form);
 * a fresh single-key Ed25519 account is `sha3-256(pubkey || 0x00)`. Every
 * endpoint proves its ledger chain id before any answer from it is trusted.
 */
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  HttpError,
  fetchJson,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type FetchOptions,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const APTOS_MAINNET = 'aptos:1';
export const APTOS_TESTNET = 'aptos:2';
export const MOVEMENT_MAINNET = 'movement:126';
export const SUPRA_MAINNET = 'supra:8';

const APTOS_COIN = '0x1::aptos_coin::AptosCoin';

/**
 * `aptos` nodes speak the Aptos REST API verbatim. Supra forked it: the ledger
 * root is missing, view results are wrapped in `{ result }` and account
 * history has another shape, so only balances are read there.
 */
export interface AptosNetwork {
  ledgerChainId: number;
  dialect: 'aptos' | 'supra';
  coinType: string;
}
export const NETWORKS: Record<string, AptosNetwork> = {
  [APTOS_MAINNET]: { ledgerChainId: 1, dialect: 'aptos', coinType: APTOS_COIN },
  [APTOS_TESTNET]: { ledgerChainId: 2, dialect: 'aptos', coinType: APTOS_COIN },
  // Movement keeps the Aptos framework, so MOVE is still `AptosCoin`.
  [MOVEMENT_MAINNET]: { ledgerChainId: 126, dialect: 'aptos', coinType: APTOS_COIN },
  [SUPRA_MAINNET]: { ledgerChainId: 8, dialect: 'supra', coinType: '0x1::supra_coin::SupraCoin' },
};

/** Circle's native USDC fungible-asset metadata object on Aptos mainnet. */
const TOKENS: Record<string, { metadata: string; symbol: string; decimals: number }[]> = {
  [APTOS_MAINNET]: [
    {
      metadata: '0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b',
      symbol: 'USDC',
      decimals: 6,
    },
  ],
};

export function faAssetRef(chainId: string, metadata: string): string {
  return `${chainId}:fa:${metadata}`;
}

export function aptosAddressFromPublicKey(key: Uint8Array): string {
  if (key.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  const input = new Uint8Array(33);
  input.set(key);
  return `0x${bytesToHex(sha3_256(input))}`;
}

/** The 32 address bytes of a canonical long-form address; reserved 0x0..0xf are refused. */
export function aptosAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^0x[0-9a-f]{64}$/.test(addr)) return undefined;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(addr.slice(2 + 2 * i, 4 + 2 * i), 16);
  if (out.subarray(0, 31).every((b) => b === 0) && out[31]! < 0x10) return undefined;
  return out;
}

export function isValidAptosAddress(addr: string): boolean {
  return aptosAddressBytes(addr) !== undefined;
}

/**
 * Pads a pasted address to the long form the core signs over. Leading zeros
 * are often dropped by tools; padding is the only reading of such input.
 */
export function normalizeAptosAddress(input: string): string | undefined {
  const m = /^0x([0-9a-fA-F]{1,64})$/.exec(input.trim());
  if (!m) return undefined;
  const long = `0x${m[1]!.toLowerCase().padStart(64, '0')}`;
  return isValidAptosAddress(long) ? long : undefined;
}

const U64 = z.string().regex(/^\d{1,20}$/);
const Hash = z.string().regex(/^0x[0-9a-f]{64}$/);
const AnyAddress = z.string().regex(/^0x[0-9a-f]{1,64}$/);

export const LedgerInfo = z.object({
  chain_id: z.number().int().nonnegative().max(255),
  ledger_version: U64,
  ledger_timestamp: U64,
  block_height: U64,
});
export type LedgerInfo = z.infer<typeof LedgerInfo>;
const SupraBlock = z.object({
  height: z.number().int().nonnegative(),
  view: z.object({ epoch_id: z.object({ chain_id: z.number().int().nonnegative() }) }),
});
export const AccountInfo = z.object({ sequence_number: U64 });
export const GasEstimate = z.object({
  gas_estimate: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  prioritized_gas_estimate: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
});
const ViewU64 = z.array(U64).length(1);
const SupraViewU64 = z.object({ result: ViewU64 });

const EntryPayload = z
  .object({
    type: z.string().max(64),
    function: z.string().max(512).optional(),
    type_arguments: z.array(z.string().max(512)).max(32).optional(),
    arguments: z.array(z.unknown()).max(64).optional(),
  })
  .loose();
export const UserTransaction = z
  .object({
    type: z.literal('user_transaction'),
    hash: Hash,
    version: U64,
    success: z.boolean(),
    vm_status: z.string().max(1024),
    timestamp: U64,
    sender: AnyAddress,
    sequence_number: U64,
    gas_used: U64,
    gas_unit_price: U64,
    payload: EntryPayload.optional(),
  })
  .loose();
export const PendingTransaction = z
  .object({ type: z.literal('pending_transaction'), hash: Hash })
  .loose();
export const ChainTransaction = z.union([
  UserTransaction,
  PendingTransaction,
  z.object({ type: z.string().max(64), hash: Hash }).loose(),
]);
const AccountTransactions = z.array(z.unknown()).max(100);

export type AptosAdapterOptions = BaseAdapterOptions;

/** One endpoint that proved its chain id; dependent reads stay on it. */
export interface AptosNode {
  url: string;
  get<T>(path: string, schema: z.ZodType<T>): Promise<T | null>;
  view(fn: string, typeArgs: string[], args: string[]): Promise<string>;
  ledger(): Promise<LedgerInfo>;
}

export class AptosAdapter extends BaseAdapter<'aptos'> {
  constructor(opts: AptosAdapterOptions = {}) {
    super('aptos', opts);
  }

  network(chainId: ChainId): AptosNetwork {
    this.requireChain(chainId);
    const net = NETWORKS[chainId];
    if (!net) throw new Error(`No Aptos network profile for ${chainId}`);
    return net;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return aptosAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidAptosAddress(addr);
  }

  private node(chainId: ChainId, url: string, opts: FetchOptions = this.fetchOptions()): AptosNode {
    const net = this.network(chainId);
    const base = url.replace(/\/$/, '');
    const get = async <T>(path: string, schema: z.ZodType<T>): Promise<T | null> => {
      try {
        return schema.parse(await fetchJson(`${base}${path}`, opts));
      } catch (error) {
        if (error instanceof HttpError && error.status === 404) return null;
        throw error;
      }
    };
    const view = async (fn: string, typeArgs: string[], args: string[]): Promise<string> => {
      const text = await postJsonText(
        `${base}/view`,
        { function: fn, type_arguments: typeArgs, arguments: args },
        opts,
      );
      const body: unknown = JSON.parse(text);
      const out = net.dialect === 'supra' ? SupraViewU64.parse(body).result : ViewU64.parse(body);
      return BigInt(out[0]!).toString();
    };
    const ledger = async (): Promise<LedgerInfo> => {
      const info = await get('', LedgerInfo);
      if (!info) throw new Error('Aptos node did not report its ledger');
      return info;
    };
    return { url, get, view, ledger };
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const net = this.network(chainId);
    await this.verifyEndpoint(chainId, url, async () => {
      const node = this.node(chainId, url);
      const id =
        net.dialect === 'supra'
          ? (await node.get('/block', SupraBlock))?.view.epoch_id.chain_id
          : (await node.ledger()).chain_id;
      if (id !== net.ledgerChainId)
        throw new Error('Endpoint chain id does not match this Aptos network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (node: AptosNode) => Promise<T>): Promise<T> {
    this.network(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(this.node(chainId, url));
    });
  }

  /** The next sequence number; accounts that were never touched read as 0. */
  static async sequenceNumber(node: AptosNode, addr: Address): Promise<string> {
    const account = await node.get(`/accounts/${addr}`, AccountInfo);
    return account ? BigInt(account.sequence_number).toString() : '0';
  }

  /** Coin balance including the paired fungible-asset store after the FA migration. */
  static nativeBalance(node: AptosNode, coinType: string, addr: Address): Promise<string> {
    return node.view('0x1::coin::balance', [coinType], [addr]);
  }

  /** BCS POST to `/transactions`; the caller interprets the node's verdict. */
  async submit(chainId: ChainId, bytes: Uint8Array): Promise<{ status: number; body: unknown }> {
    if (this.network(chainId).dialect !== 'aptos') throw new Error('Broadcast is not supported');
    return this.withNode(chainId, async (node) => {
      const doFetch = this.fetchImpl ?? globalThis.fetch;
      const res = await doFetch(`${node.url.replace(/\/$/, '')}/transactions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x.aptos.signed_transaction+bcs',
          accept: 'application/json',
        },
        body: bytes as BodyInit,
        signal: AbortSignal.timeout(this.timeoutMs ?? 30_000),
      });
      const text = (await res.text()).slice(0, 1 << 16);
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = undefined;
      }
      // Gateway and node errors are a failed endpoint, not a verdict on the transaction.
      if (res.status >= 500 || res.status === 429)
        throw new HttpError(node.url, res.status, text.slice(0, 512));
      return { status: res.status, body };
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const net = this.network(chainId);
    if (!isValidAptosAddress(addr)) throw new TypeError(`invalid aptos address ${addr}`);
    const tokens = TOKENS[chainId] ?? [];
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const node = this.node(chainId, url);
        const amounts = await Promise.all([
          AptosAdapter.nativeBalance(node, net.coinType, addr),
          ...tokens.map((t) =>
            node.view(
              '0x1::primary_fungible_store::balance',
              ['0x1::fungible_asset::Metadata'],
              [addr, t.metadata],
            ),
          ),
        ]);
        return JSON.stringify(amounts);
      },
      { equal: (a, b) => a === b },
    );
    const [nativeAmount, ...tokenAmounts] = JSON.parse(value) as string[];
    return [
      nativeHolding(chain, nativeAmount!, provenance),
      ...tokens.map((t, i) => ({
        assetRef: faAssetRef(chainId, t.metadata),
        amount: tokenAmounts[i] ?? '0',
        provenance,
        metadata: { symbol: t.symbol, decimals: t.decimals },
        notice: 'Primary fungible store balance; token transfers are not enabled.',
        updatedAtMs: Date.now(),
      })),
    ];
  }

  /**
   * Transactions the account sent, newest first, paged by sequence number.
   * The REST API has no keyless index of incoming transfers.
   */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    const net = this.network(chainId);
    if (!isValidAptosAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[1-9]\d{0,15}$/.test(cursor))
      throw new Error('Invalid history cursor');
    if (net.dialect !== 'aptos')
      return { items: [], coverage: 'Transaction history is not available on this network.' };
    const limit = 20;
    const opts: FetchOptions = {
      ...this.fetchOptions(),
      maxBodyBytes: 8 << 20,
      ...(options?.signal ? { signal: options.signal } : {}),
    };
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const node = this.node(chainId, url, opts);
      const end = cursor ? Number(cursor) : Number(await AptosAdapter.sequenceNumber(node, addr));
      if (!Number.isSafeInteger(end) || end <= 0) return { items: [], source: url };
      const start = Math.max(0, end - limit);
      const raw = await node.get(
        `/accounts/${addr}/transactions?start=${start}&limit=${end - start}`,
        AccountTransactions,
      );
      const items = (raw ?? [])
        .map((t) => UserTransaction.safeParse(t))
        .filter((r) => r.success)
        .map((r) => userRecord(chain.chainId, chain.nativeAsset.ref, net.coinType, addr, r.data))
        .reverse();
      return {
        items,
        ...(start > 0 ? { nextCursor: String(start) } : {}),
        coverage:
          'Transactions this account sent (REST, by sequence number). Incoming transfers are not listed.',
        source: url,
      };
    });
  }

  async transaction(
    hash: TxHash,
    chainId: ChainId,
  ): Promise<z.infer<typeof ChainTransaction> | null> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Aptos transaction hash');
    if (this.network(chainId).dialect !== 'aptos')
      throw new Error('Transaction status is not supported on this network');
    return this.withNode(chainId, (node) =>
      node.get(`/transactions/by_hash/${hash.toLowerCase()}`, ChainTransaction),
    );
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    const tx = await this.transaction(hash, chainId);
    if (!tx) return { state: 'unknown' };
    if (tx.type === 'pending_transaction') return { state: 'pending' };
    const user = UserTransaction.safeParse(tx);
    if (!user.success) return { state: 'unknown' };
    if (!user.data.success) return { state: 'failed', reason: user.data.vm_status.slice(0, 256) };
    const version = Number(user.data.version);
    return {
      state: 'confirmed',
      blockNumber: version,
      timestampMs: Math.floor(Number(user.data.timestamp) / 1000),
    };
  }
}

const TRANSFER_FUNCTIONS = new Set([
  '0x1::aptos_account::transfer',
  '0x1::aptos_account::transfer_coins',
  '0x1::coin::transfer',
]);

function userRecord(
  chainId: string,
  nativeRef: string,
  coinType: string,
  holder: string,
  t: z.infer<typeof UserTransaction>,
): TxRecord {
  const p = t.payload;
  const fn = p?.function;
  const args = p?.arguments ?? [];
  let to: string | undefined;
  let moved: bigint | undefined;
  if (fn && TRANSFER_FUNCTIONS.has(fn) && args.length === 2) {
    const native =
      fn === '0x1::aptos_account::transfer' ||
      (p?.type_arguments?.length === 1 && p.type_arguments[0] === coinType);
    const [dest, amount] = args;
    const destOk = typeof dest === 'string' && /^0x[0-9a-f]{1,64}$/.test(dest);
    if (destOk) to = `0x${dest.slice(2).padStart(64, '0')}`;
    if (native && destOk && typeof amount === 'string' && /^\d{1,20}$/.test(amount))
      moved = BigInt(amount);
  }
  const from = `0x${t.sender.slice(2).padStart(64, '0')}`;
  let delta = 0n;
  if (moved !== undefined && t.success) {
    if (from === holder) delta -= moved;
    if (to === holder) delta += moved;
  }
  const fee = BigInt(t.gas_used) * BigInt(t.gas_unit_price);
  return {
    hash: t.hash,
    chainId,
    blockNumber: Number(t.version),
    timestampMs: Math.floor(Number(t.timestamp) / 1000),
    from,
    ...(to ? { to } : {}),
    ...(moved === undefined && fn ? { description: fn.slice(0, 200) } : {}),
    assetDeltas: moved !== undefined ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: fee.toString(),
    status: t.success ? 'confirmed' : 'failed',
  };
}

export function createAptosAdapter(opts?: AptosAdapterOptions): AptosAdapter {
  return new AptosAdapter(opts);
}
