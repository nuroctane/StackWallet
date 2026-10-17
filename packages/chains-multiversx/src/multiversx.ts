/**
 * MultiversX adapter (mainnet read-only, devnet signing). Addresses are the
 * bech32 (`erd`) of the 32-byte Ed25519 public key. Reads go to either the
 * MultiversX API or a proxy gateway; both serve `/network/config`, whose
 * `erd_chain_id` is the CAIP-2 reference, so every endpoint proves its network.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { bech32 } from '@scure/base';
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
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const MULTIVERSX_MAINNET = 'mvx:1';
export const MULTIVERSX_DEVNET = 'mvx:D';
const HRP = 'erd';
const ADDRESS_RE = /^erd1[02-9ac-hj-np-z]{58}$/;

/** Mainnet ESDTs read alongside EGLD. Token transfers are not enabled. */
const ESDTS: Record<string, { identifier: string; symbol: string; decimals: number }[]> = {
  [MULTIVERSX_MAINNET]: [{ identifier: 'USDC-c76f1f', symbol: 'USDC', decimals: 6 }],
};

export function multiversxAddressFromPublicKey(key: Uint8Array): string {
  if (key.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  return bech32.encode(HRP, bech32.toWords(key));
}

/** The 32-byte account behind a canonical lowercase `erd1…` address. */
export function multiversxAddressBytes(addr: string): Uint8Array | undefined {
  if (!ADDRESS_RE.test(addr)) return undefined;
  try {
    const { prefix, words } = bech32.decode(addr as `${string}1${string}`);
    if (prefix !== HRP) return undefined;
    const bytes = bech32.fromWords(words);
    if (bytes.length !== 32 || bytes.every((b) => b === 0)) return undefined;
    return multiversxAddressFromPublicKey(bytes) === addr ? bytes : undefined;
  } catch {
    return undefined;
  }
}

export function isValidMultiversxAddress(addr: string): boolean {
  return multiversxAddressBytes(addr) !== undefined;
}

/** Smart contract accounts start with eight zero bytes; they are not Ed25519 keys. */
export function isMultiversxContract(addr: string): boolean {
  const bytes = multiversxAddressBytes(addr);
  return bytes !== undefined && bytes.subarray(0, 8).every((b) => b === 0);
}

export function esdtAssetRef(chainId: string, identifier: string): string {
  return `${chainId}:esdt:${identifier}`;
}

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Atto = z.string().regex(/^\d{1,40}$/);
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const Addr = z.string().regex(ADDRESS_RE);

export const NetworkConfig = z.object({
  data: z.object({
    config: z
      .object({
        erd_chain_id: z.string().max(16),
        erd_min_gas_limit: SafeInt,
        erd_min_gas_price: SafeInt,
        erd_gas_per_data_byte: SafeInt.optional(),
        erd_min_transaction_version: SafeInt.optional(),
      })
      .loose(),
  }),
});
export type NetworkConfig = z.infer<typeof NetworkConfig>['data']['config'];

const ApiAccount = z.object({ address: Addr, balance: Atto, nonce: SafeInt });
const GatewayAccount = z.object({
  data: z.object({ account: z.object({ address: Addr, balance: Atto, nonce: SafeInt }) }),
});
const ApiToken = z.object({ identifier: z.string().max(64), balance: Atto });
const GatewayToken = z.object({
  data: z.object({ tokenData: z.object({ balance: Atto }) }),
});
const TxState = z.string().max(32);
const ApiTx = z.object({
  txHash: Hash,
  status: TxState,
  nonce: SafeInt.optional(),
  sender: Addr.optional(),
  round: SafeInt.optional(),
  timestamp: SafeInt.optional(),
});
const GatewayTx = z.object({
  data: z.object({
    transaction: z.object({
      hash: Hash,
      status: TxState,
      nonce: SafeInt.optional(),
      sender: Addr.optional(),
      round: SafeInt.optional(),
      timestamp: SafeInt.optional(),
    }),
  }),
});
const ApiSend = z.object({ txHash: Hash });
const GatewaySend = z.object({ data: z.object({ txHash: Hash }) });
const Rejection = z.object({
  message: z.string().max(4096).optional(),
  error: z.string().max(4096).optional(),
});

export interface MvxAccount {
  address: string;
  balance: string;
  nonce: number;
}
export interface MvxTx {
  hash: string;
  status: string;
  nonce?: number;
  sender?: string;
  round?: number;
  timestampMs?: number;
}
export type MvxSendResult = { hash: string } | { rejected: string };

/** One endpoint that proved its network, speaking either the API or the gateway dialect. */
export interface MvxNode {
  readonly url: string;
  readonly kind: 'api' | 'gateway';
  config(): Promise<NetworkConfig>;
  account(addr: string): Promise<MvxAccount>;
  token(addr: string, identifier: string): Promise<string>;
  /** Null when the endpoint does not know the hash. */
  transaction(hash: string): Promise<MvxTx | null>;
  send(signed: Record<string, unknown>): Promise<MvxSendResult>;
}

/**
 * Gateways (`mx-chain-proxy-go`) and the API answer different paths; a host
 * named `*gateway*` is a gateway, anything else is treated as the API.
 */
export function endpointKind(url: string): 'api' | 'gateway' {
  try {
    return /gateway/i.test(new URL(url).hostname) ? 'gateway' : 'api';
  } catch {
    return 'api';
  }
}

const trim = (url: string): string => url.replace(/\/$/, '');

/** A text sanitized for display: printable ASCII only, bounded. */
export function cleanMessage(message: string): string {
  return message.replace(/[^\x20-\x7e]/g, '').slice(0, 512);
}

export type MultiversxAdapterOptions = BaseAdapterOptions;

export class MultiversxAdapter extends BaseAdapter<'multiversx'> {
  constructor(opts: MultiversxAdapterOptions = {}) {
    super('multiversx', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    const key = publicKeyBytes(pub);
    if (key.length !== 32 || !ed25519.utils.isValidPublicKey(key, false))
      throw new TypeError('Not an Ed25519 public key');
    return multiversxAddressFromPublicKey(key);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidMultiversxAddress(addr);
  }

  /** GET that yields null for the statuses that mean "not known here". */
  private async get<T>(
    url: string,
    path: string,
    schema: z.ZodType<T>,
    notFound: (e: HttpError) => boolean = () => false,
  ): Promise<T | null> {
    try {
      return schema.parse(await fetchJson(`${trim(url)}${path}`, this.fetchOptions()));
    } catch (error) {
      if (error instanceof HttpError && notFound(error)) return null;
      throw error;
    }
  }

  private async must<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    const value = await this.get(url, path, schema);
    if (value === null) throw new Error(`${path} returned nothing`);
    return value;
  }

  private node(url: string): MvxNode {
    const kind = endpointKind(url);
    const config = async () => (await this.must(url, '/network/config', NetworkConfig)).data.config;
    if (kind === 'gateway')
      return {
        url,
        kind,
        config,
        account: async (addr) =>
          (await this.must(url, `/address/${addr}`, GatewayAccount)).data.account,
        token: async (addr, id) =>
          (await this.must(url, `/address/${addr}/esdt/${id}`, GatewayToken)).data.tokenData
            .balance,
        transaction: async (hash) => {
          // The proxy answers an unknown hash with HTTP 500 "transaction not found".
          const res = await this.get(
            url,
            `/transaction/${hash}?withResults=false`,
            GatewayTx,
            (e) => (e.status === 404 || e.status === 500) && /transaction not found/i.test(e.body),
          );
          if (!res) return null;
          const t = res.data.transaction;
          return {
            hash: t.hash,
            status: t.status,
            ...(t.nonce !== undefined ? { nonce: t.nonce } : {}),
            ...(t.sender ? { sender: t.sender } : {}),
            ...(t.round !== undefined ? { round: t.round } : {}),
            ...(t.timestamp !== undefined ? { timestampMs: t.timestamp * 1000 } : {}),
          };
        },
        send: (signed) =>
          this.post(url, '/transaction/send', signed, (b) => GatewaySend.parse(b).data.txHash),
      };
    return {
      url,
      kind,
      config,
      account: (addr) =>
        this.must(url, `/accounts/${addr}?fields=address,balance,nonce`, ApiAccount),
      token: async (addr, id) => {
        const t = await this.get(
          url,
          `/accounts/${addr}/tokens/${id}?fields=identifier,balance`,
          ApiToken,
          (e) => e.status === 404,
        );
        if (t && t.identifier !== id) throw new Error('API returned a different token');
        return t?.balance ?? '0';
      },
      transaction: async (hash) => {
        const t = await this.get(
          url,
          `/transactions/${hash}?fields=txHash,status,nonce,sender,round,timestamp`,
          ApiTx,
          (e) => e.status === 404,
        );
        if (!t) return null;
        return {
          hash: t.txHash,
          status: t.status,
          ...(t.nonce !== undefined ? { nonce: t.nonce } : {}),
          ...(t.sender ? { sender: t.sender } : {}),
          ...(t.round !== undefined ? { round: t.round } : {}),
          ...(t.timestamp !== undefined ? { timestampMs: t.timestamp * 1000 } : {}),
        };
      },
      send: (signed) => this.post(url, '/transactions', signed, (b) => ApiSend.parse(b).txHash),
    };
  }

  /** A 400 is the network's verdict on the transaction, not a broken endpoint. */
  private async post(
    url: string,
    path: string,
    body: Record<string, unknown>,
    hashOf: (body: unknown) => string,
  ): Promise<MvxSendResult> {
    try {
      const text = await postJsonText(`${trim(url)}${path}`, body, this.fetchOptions());
      return { hash: hashOf(JSON.parse(text)) };
    } catch (error) {
      if (!(error instanceof HttpError) || error.status !== 400) throw error;
      let reason = error.body;
      try {
        const r = Rejection.parse(JSON.parse(error.body));
        reason = r.message ?? r.error ?? error.body;
      } catch {
        // Keep the raw (bounded) body as the reason.
      }
      return { rejected: cleanMessage(reason) };
    }
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const config = await this.node(url).config();
      if (`mvx:${config.erd_chain_id}` !== chainId)
        throw new Error('Endpoint serves another MultiversX network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (node: MvxNode) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(this.node(url));
    });
  }

  /**
   * Like `withNode`, restricted to one dialect, in pool order. Resolves to
   * undefined when no endpoint of that kind is configured.
   */
  async withKind<T>(
    chainId: ChainId,
    kind: MvxNode['kind'],
    query: (node: MvxNode) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T | undefined> {
    this.requireChain(chainId);
    const urls = this.rpc
      .endpoints(chainId)
      .map((e) => e.url)
      .filter((u) => endpointKind(u) === kind);
    if (urls.length === 0) return undefined;
    let lastError: unknown;
    for (const url of urls) {
      try {
        await this.checkNetwork(chainId, url);
        return await query(this.node(url));
      } catch (err) {
        if (signal?.aborted) throw err;
        lastError = err;
      }
    }
    throw lastError instanceof Error ? lastError : new Error(`No MultiversX ${kind} answered`);
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidMultiversxAddress(addr)) throw new TypeError(`invalid multiversx address ${addr}`);
    const tokens = ESDTS[chainId] ?? [];
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const node = this.node(url);
        const account = await node.account(addr);
        if (account.address !== addr) throw new Error('Endpoint returned a different account');
        const balances = await Promise.all(tokens.map((t) => node.token(addr, t.identifier)));
        return JSON.stringify([account.balance, ...balances]);
      },
      { equal: (a, b) => a === b },
    );
    const [native, ...amounts] = JSON.parse(value) as string[];
    return [
      nativeHolding(chain, BigInt(native!).toString(), provenance),
      ...tokens.map((t, i) => ({
        assetRef: esdtAssetRef(chainId, t.identifier),
        amount: BigInt(amounts[i] ?? '0').toString(),
        provenance,
        metadata: { symbol: t.symbol, decimals: t.decimals },
        notice: 'ESDT balance; token transfers are not enabled.',
        updatedAtMs: Date.now(),
      })),
    ];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidMultiversxAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^(0|[1-9]\d{0,3})$/.test(cursor))
      throw new Error('Invalid history cursor');
    const from = Number(cursor ?? '0');
    const size = 20;
    // The API's elastic index serves at most 10,000 results per query window.
    if (from + size > 10_000)
      return { items: [], coverage: 'Older history is not served by the API.' };
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    const query = new URLSearchParams({
      from: String(from),
      size: String(size),
      fields: 'txHash,sender,receiver,value,fee,status,round,timestamp,function',
    });
    const page = await this.withKind(
      chainId,
      'api',
      async ({ url }): Promise<Page<TxRecord>> => {
        const txs = HistoryPage.parse(
          await fetchJson(`${trim(url)}/accounts/${addr}/transactions?${query.toString()}`, opts),
        );
        return {
          items: txs.map((t) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t)),
          ...(txs.length === size ? { nextCursor: String(from + size) } : {}),
          coverage:
            'MultiversX API account transactions. EGLD values carry net changes; token transfers and contract calls are listed without balance changes, and smart contract results (refunds, inner transfers) are not counted.',
          source: url,
        };
      },
      options?.signal,
    );
    return (
      page ?? {
        items: [],
        coverage: 'No MultiversX API endpoint is configured, so history is unavailable.',
      }
    );
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid MultiversX transaction hash');
    const value = hash.toLowerCase();
    return this.withNode(chainId, async (node) => toStatus(value, await node.transaction(value)));
  }
}

export function toStatus(hash: string, t: MvxTx | null): TxStatus {
  if (!t) return { state: 'unknown' };
  if (t.hash !== hash) throw new Error('Endpoint returned a different transaction');
  switch (t.status) {
    case 'success':
    case 'executed':
      return {
        state: 'confirmed',
        blockNumber: t.round ?? 0,
        ...(t.timestampMs !== undefined ? { timestampMs: t.timestampMs } : {}),
      };
    case 'fail':
    case 'invalid':
      return { state: 'failed', reason: t.status };
    default:
      // "pending", "received", "partially-executed": not final in both shards yet.
      return { state: 'pending' };
  }
}

const HistoryPage = z
  .array(
    z.object({
      txHash: Hash,
      sender: Addr,
      receiver: Addr,
      value: Atto,
      fee: Atto.optional(),
      status: TxState,
      round: SafeInt.optional(),
      timestamp: SafeInt.optional(),
      function: z.string().max(128).optional(),
    }),
  )
  .max(100);

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof HistoryPage>[number],
): TxRecord {
  const failed = t.status === 'fail' || t.status === 'invalid';
  let delta = 0n;
  if (!failed) {
    const amount = BigInt(t.value);
    if (t.receiver === holder) delta += amount;
    if (t.sender === holder) delta -= amount;
  }
  const plain = t.function === undefined || t.function === 'transfer';
  return {
    hash: t.txHash,
    chainId,
    from: t.sender,
    to: t.receiver,
    ...(t.round !== undefined ? { blockNumber: t.round } : {}),
    ...(t.timestamp !== undefined ? { timestampMs: t.timestamp * 1000 } : {}),
    ...(!plain ? { description: cleanMessage(t.function!) } : {}),
    assetDeltas: delta !== 0n || plain ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    feeAssetRef: nativeRef,
    fee: t.sender === holder ? (t.fee ?? null) : '0',
    status: failed ? 'failed' : t.status === 'success' ? 'confirmed' : 'pending',
  };
}

export function createMultiversxAdapter(opts?: MultiversxAdapterOptions): MultiversxAdapter {
  return new MultiversxAdapter(opts);
}
