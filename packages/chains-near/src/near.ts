/**
 * NEAR adapter. Keys sign for their implicit account (the 64 lowercase hex
 * characters of the Ed25519 key); transfers may go to implicit or named
 * accounts. Reads use keyless JSON-RPC, whose `status` names the genesis hash,
 * so every endpoint proves which network it serves before it is trusted.
 * History comes from the FastNEAR transaction indexer.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  HttpError,
  JsonRpcError,
  MalformedResponseError,
  nativeHolding,
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

export const NEAR_TESTNET = 'near:testnet';
export const NEAR_MAINNET = 'near:mainnet';
export const GENESIS_HASHES: Record<string, string> = {
  [NEAR_MAINNET]: 'EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H',
  [NEAR_TESTNET]: 'FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b',
};
/** FastNEAR's keyless transaction indexer; JSON-RPC nodes keep no per-account history. */
export const TX_INDEXERS: Record<string, string> = {
  [NEAR_MAINNET]: 'https://tx.main.fastnear.com',
  [NEAR_TESTNET]: 'https://tx.test.fastnear.com',
};
/** Blocks after the referenced block during which the network accepts a transaction. */
export const VALIDITY_PERIOD_BLOCKS = 86_400;
/** yoctoNEAR locked per byte of account storage. */
export const STORAGE_PRICE_PER_BYTE = 10n ** 19n;
const MAX_BODY = 4 << 20;

const ACCOUNT_ID = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

/** NEAR account id rules: 2..=64 bytes of dot-separated `[a-z0-9]` runs joined by single `-` or `_`. */
export function isValidNearAccountId(id: string): boolean {
  return id.length >= 2 && id.length <= 64 && ACCOUNT_ID.test(id);
}

export function isImplicitAccount(id: string): boolean {
  return /^[0-9a-f]{64}$/.test(id);
}

export const isValidNearAddress = isValidNearAccountId;

export function nearAddressFromPublicKey(key: Uint8Array): string {
  if (key.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  return bytesToHex(key);
}

/** `ed25519:<base58>` form RPC uses for the access key of an implicit account. */
export function implicitPublicKey(account: string): string {
  if (!isImplicitAccount(account)) throw new TypeError('Not an implicit NEAR account');
  return `ed25519:${base58.encode(hexToBytes(account))}`;
}

export const Yocto = z.string().regex(/^\d{1,40}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const Base58Hash = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
const AccountIdSchema = z.string().min(2).max(64);

const Status = z.object({ chain_id: z.string().max(64), genesis_hash: Base58Hash });
export const ViewAccount = z.object({
  amount: Yocto,
  locked: Yocto,
  storage_usage: SafeInt,
  block_height: SafeInt,
});
export type ViewAccount = z.infer<typeof ViewAccount>;
export const ViewAccessKey = z.union([
  z.object({
    nonce: SafeInt,
    permission: z.union([z.literal('FullAccess'), z.object({}).loose()]),
    block_height: SafeInt,
  }),
  // Nodes report a missing key as a result carrying `error`.
  z.object({ error: z.string().max(512) }),
]);
export const Block = z.object({
  header: z.object({
    height: SafeInt,
    hash: Base58Hash,
    timestamp_nanosec: z.string().regex(/^\d{1,25}$/),
    gas_price: Yocto,
  }),
});
export type Block = z.infer<typeof Block>;
const CallResult = z.object({ result: z.array(z.number().int().min(0).max(255)).max(4096) });

const ErrorEnvelope = z.object({
  name: z.string().max(64).optional(),
  cause: z
    .object({ name: z.string().max(64) })
    .loose()
    .optional(),
  code: z.number().int(),
  message: z.string().transform((m) => m.slice(0, 512)),
  data: z.unknown().optional(),
});
const Envelope = z.object({
  jsonrpc: z.literal('2.0'),
  result: z.unknown().optional(),
  error: ErrorEnvelope.optional(),
});

/** Errors that answer the question (absent account, unknown hash, rejected tx) rather than fail the endpoint. */
const ANSWERS = new Set([
  'UNKNOWN_ACCOUNT',
  'UNKNOWN_ACCESS_KEY',
  'UNKNOWN_TRANSACTION',
  'UNKNOWN_BLOCK',
  'INVALID_TRANSACTION',
  'TIMEOUT_ERROR',
  'PARSE_ERROR',
]);

export type RpcAnswer<T> =
  | { ok: true; result: T }
  | { ok: false; name: string; data?: unknown; message: string };

export type NearCall = <T>(
  method: string,
  params: Record<string, unknown> | unknown[],
  schema: z.ZodType<T>,
) => Promise<RpcAnswer<T>>;

const USDC = '17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1';
const TOKENS: Record<string, { contract: string; symbol: string; decimals: number }[]> = {
  [NEAR_MAINNET]: [{ contract: USDC, symbol: 'USDC', decimals: 6 }],
};

export function tokenRef(chainId: string, contract: string): string {
  return `${chainId}:nep141:${contract}`;
}

export type NearAdapterOptions = BaseAdapterOptions;

export class NearAdapter extends BaseAdapter<'near'> {
  constructor(opts: NearAdapterOptions = {}) {
    super('near', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return nearAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidNearAccountId(addr);
  }

  /** POST bounded JSON, keeping the error `cause` that `fetchJsonRpc` drops. */
  private async post(url: string, body: unknown, signal?: AbortSignal): Promise<unknown> {
    const doFetch = this.fetchImpl ?? globalThis.fetch;
    const timeout = AbortSignal.timeout(this.timeoutMs ?? 15_000);
    const res = await doFetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    });
    const declared = Number(res.headers.get('content-length') ?? '0');
    if (declared > MAX_BODY) throw new MalformedResponseError(url, 'body too large');
    const text = await res.text();
    if (text.length > MAX_BODY) throw new MalformedResponseError(url, 'body too large');
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw res.ok
        ? new MalformedResponseError(url, 'body is not JSON')
        : new HttpError(url, res.status, text.slice(0, 512));
    }
    if (!res.ok && (res.status >= 500 || !Envelope.safeParse(json).success))
      throw new HttpError(url, res.status, text.slice(0, 512));
    return json;
  }

  async call<T>(
    url: string,
    method: string,
    params: Record<string, unknown> | unknown[],
    schema: z.ZodType<T>,
  ): Promise<RpcAnswer<T>> {
    const raw = await this.post(url, { jsonrpc: '2.0', id: 1, method, params });
    const env = Envelope.safeParse(raw);
    if (!env.success) throw new MalformedResponseError(url, 'not a JSON-RPC 2.0 envelope');
    const { error } = env.data;
    if (error) {
      const name = error.cause?.name ?? error.name ?? '';
      if (ANSWERS.has(name))
        return {
          ok: false,
          name,
          message: error.message,
          ...(error.data !== undefined ? { data: error.data } : {}),
        };
      throw new JsonRpcError(url, error.code, `${name} ${error.message}`.trim(), error.data);
    }
    if (!(typeof raw === 'object' && raw !== null && 'result' in raw))
      throw new MalformedResponseError(url, 'envelope has neither result nor error');
    return { ok: true, result: schema.parse(env.data.result) };
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const st = await this.call(url, 'status', [], Status);
      if (!st.ok || st.result.genesis_hash !== GENESIS_HASHES[chainId])
        throw new Error('Endpoint genesis hash does not match this NEAR network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: NearCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((method, params, schema) => this.call(url, method, params, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidNearAccountId(addr)) throw new TypeError(`invalid NEAR account ${addr}`);
    const tokens = TOKENS[chainId] ?? [];
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const call: NearCall = (m, p, s) => this.call(url, m, p, s);
        const native = await viewAccount(call, addr);
        const balances = await Promise.all(tokens.map((t) => ftBalance(call, t.contract, addr)));
        return JSON.stringify([native?.amount ?? '0', ...balances]);
      },
      { equal: (a, b) => a === b },
    );
    const [nativeAmount, ...tokenAmounts] = JSON.parse(value) as string[];
    return [
      nativeHolding(chain, nativeAmount!, provenance),
      ...tokens.map((t, i) => ({
        assetRef: tokenRef(chainId, t.contract),
        amount: tokenAmounts[i] ?? '0',
        provenance,
        metadata: { symbol: t.symbol, decimals: t.decimals },
        notice: 'NEP-141 balance from ft_balance_of; token transfers are not enabled.',
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
    if (!isValidNearAccountId(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,30}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const indexer = TX_INDEXERS[chainId];
    if (!indexer) return { items: [], coverage: 'No NEAR transaction indexer for this network.' };
    const limit = 20;
    const list = AccountTxs.parse(
      await this.post(
        `${indexer}/v0/account`,
        { account_id: addr, limit, ...(cursor ? { resume_token: cursor } : {}) },
        options?.signal,
      ),
    );
    const entries = list.account_txs.slice(0, limit);
    const details = new Map<string, IndexedTx>();
    if (entries.length > 0) {
      const res = IndexedTxs.parse(
        await this.post(
          `${indexer}/v0/transactions`,
          { tx_hashes: entries.map((e) => e.transaction_hash) },
          options?.signal,
        ),
      );
      for (const t of res.transactions) if (t) details.set(t.transaction.hash, t);
    }
    return {
      items: entries.map((e) =>
        historyRecord(
          chain.chainId,
          chain.nativeAsset.ref,
          addr,
          e,
          details.get(e.transaction_hash),
        ),
      ),
      ...(entries.length === limit && list.resume_token ? { nextCursor: list.resume_token } : {}),
      coverage:
        'FastNEAR account transactions. Transfer and function-call deposits carry native changes; refunds and token movements are not listed. Fees are the gas burnt across the transaction and its receipts.',
      source: indexer,
    };
  }

  /** Execution status from RPC; `sender` routes the lookup to the signer's shard. */
  async txStatus(hash: TxHash, sender: string, chainId: ChainId): Promise<TxStatus> {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(hash))
      throw new Error('Invalid NEAR transaction hash');
    if (!isValidNearAccountId(sender)) throw new Error('Invalid NEAR sender');
    return this.withNode(chainId, (call) => rpcTxStatus(call, hash, sender));
  }

  /** Indexer lookup, because RPC needs the sender, which the adapter contract does not pass. */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(hash))
      throw new Error('Invalid NEAR transaction hash');
    this.requireChain(chainId);
    const indexer = TX_INDEXERS[chainId];
    if (!indexer) return { state: 'unknown' };
    const res = IndexedTxs.parse(
      await this.post(`${indexer}/v0/transactions`, { tx_hashes: [hash] }),
    );
    const t = res.transactions.find((x) => x?.transaction.hash === hash);
    if (!t) return { state: 'unknown' };
    const live = await this.txStatus(hash, t.transaction.signer_id, chainId);
    if (live.state !== 'unknown') return live;
    // RPC nodes drop transactions after a few epochs; the indexer is archival.
    const height = t.execution_outcome?.block_height;
    const first = t.receipts?.[0]?.execution_outcome.outcome.status;
    if (height === undefined || first === undefined) return live;
    if (first && typeof first === 'object' && 'Failure' in first)
      return { state: 'failed', reason: failureReason(first.Failure) };
    return {
      state: 'confirmed',
      blockNumber: height,
      ...(t.execution_outcome?.block_timestamp !== undefined
        ? { timestampMs: Math.floor(t.execution_outcome.block_timestamp / 1e6) }
        : {}),
    };
  }
}

export async function viewAccount(call: NearCall, account: string): Promise<ViewAccount | null> {
  const r = await call(
    'query',
    { request_type: 'view_account', finality: 'final', account_id: account },
    ViewAccount,
  );
  if (r.ok) return r.result;
  if (r.name === 'UNKNOWN_ACCOUNT') return null;
  throw new Error(`view_account failed: ${r.name}`);
}

export async function ftBalance(
  call: NearCall,
  contract: string,
  account: string,
): Promise<string> {
  const args = btoa(JSON.stringify({ account_id: account }));
  const r = await call(
    'query',
    {
      request_type: 'call_function',
      finality: 'final',
      account_id: contract,
      method_name: 'ft_balance_of',
      args_base64: args,
    },
    CallResult,
  );
  if (!r.ok) throw new Error(`ft_balance_of failed: ${r.name}`);
  const value: unknown = JSON.parse(new TextDecoder().decode(Uint8Array.from(r.result.result)));
  return Yocto.parse(value);
}

const ExecStatus = z.union([
  z.object({ SuccessValue: z.string().max(1 << 16) }),
  z.object({ SuccessReceiptId: Base58Hash }),
  z.object({ Failure: z.unknown() }),
  z.string().max(64),
]);
const RpcTx = z.object({
  final_execution_status: z.string().max(64),
  status: ExecStatus.optional(),
  transaction_outcome: z.object({ block_hash: Base58Hash }).loose().optional(),
});

/** Error variant names down the first branch, e.g. `ActionError AccountDoesNotExist`. */
export function failureReason(failure: unknown): string {
  const names: string[] = [];
  let node = failure;
  for (let depth = 0; depth < 6; depth++) {
    if (typeof node === 'string') {
      if (/^[A-Z]\w{0,63}$/.test(node)) names.push(node);
      break;
    }
    if (!node || typeof node !== 'object') break;
    const o = node as Record<string, unknown>;
    const key = 'kind' in o ? 'kind' : Object.keys(o)[0];
    if (!key) break;
    if (key !== 'kind') {
      // Lowercase keys are payload fields (account ids, nonces), not variants.
      if (!/^[A-Z]\w{0,63}$/.test(key)) break;
      names.push(key);
    }
    node = o[key];
  }
  return names.join(' ') || 'transaction failed';
}

export async function rpcTxStatus(call: NearCall, hash: string, sender: string): Promise<TxStatus> {
  const r = await call(
    'tx',
    { tx_hash: hash, sender_account_id: sender, wait_until: 'NONE' },
    RpcTx,
  );
  if (!r.ok) {
    if (r.name === 'UNKNOWN_TRANSACTION' || r.name === 'TIMEOUT_ERROR') return { state: 'unknown' };
    throw new Error(`tx status failed: ${r.name}`);
  }
  const { final_execution_status: level, status, transaction_outcome: outcome } = r.result;
  if (level !== 'FINAL' || !status || typeof status === 'string' || !outcome)
    return { state: 'pending' };
  if ('Failure' in status) return { state: 'failed', reason: failureReason(status.Failure) };
  const block = await call('block', { block_id: outcome.block_hash }, Block);
  if (!block.ok) return { state: 'pending' };
  const ts = Number(BigInt(block.result.header.timestamp_nanosec) / 1_000_000n);
  return { state: 'confirmed', blockNumber: block.result.header.height, timestampMs: ts };
}

const AccountTxs = z.object({
  account_txs: z
    .array(
      z
        .object({
          transaction_hash: Base58Hash,
          tx_block_height: SafeInt,
          tx_block_timestamp: z.string().regex(/^\d{1,25}$/),
          is_success: z.boolean().optional(),
        })
        .loose(),
    )
    .max(200),
  resume_token: z
    .string()
    .regex(/^\d{1,30}$/)
    .nullish(),
});
const Action = z.union([
  z.string().max(64),
  z.record(z.string().max(64), z.object({ deposit: Yocto.optional() }).loose()),
]);
const IndexedTx = z.object({
  transaction: z
    .object({
      hash: Base58Hash,
      signer_id: AccountIdSchema,
      receiver_id: AccountIdSchema,
      actions: z.array(Action).max(256),
    })
    .loose(),
  execution_outcome: z
    .object({
      block_height: SafeInt.optional(),
      // Nanoseconds as a JSON number: only millisecond precision survives, which is enough.
      block_timestamp: z.number().nonnegative().optional(),
      outcome: z.object({ tokens_burnt: Yocto }).loose(),
    })
    .loose()
    .optional(),
  receipts: z
    .array(
      z
        .object({
          execution_outcome: z
            .object({
              outcome: z.object({ tokens_burnt: Yocto, status: ExecStatus.optional() }).loose(),
            })
            .loose(),
        })
        .loose(),
    )
    .max(512)
    .optional(),
});
type IndexedTx = z.infer<typeof IndexedTx>;
const IndexedTxs = z.object({ transactions: z.array(IndexedTx.nullable()).max(200) });

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  entry: z.infer<typeof AccountTxs>['account_txs'][number],
  tx: IndexedTx | undefined,
): TxRecord {
  const failed = entry.is_success === false;
  const timestampMs = Number(BigInt(entry.tx_block_timestamp) / 1_000_000n);
  const base = {
    hash: entry.transaction_hash,
    chainId,
    blockNumber: entry.tx_block_height,
    timestampMs,
    feeAssetRef: nativeRef,
    status: failed ? ('failed' as const) : ('confirmed' as const),
  };
  if (!tx) return { ...base, from: '', assetDeltas: [], fee: null };
  const { signer_id: from, receiver_id: to, actions } = tx.transaction;
  let deposit = 0n;
  const kinds: string[] = [];
  for (const a of actions) {
    if (typeof a === 'string') {
      kinds.push(a);
      continue;
    }
    for (const [kind, body] of Object.entries(a)) {
      kinds.push(kind);
      if ((kind === 'Transfer' || kind === 'FunctionCall') && body.deposit)
        deposit += BigInt(body.deposit);
    }
  }
  let delta = 0n;
  if (!failed) {
    if (to === holder) delta += deposit;
    if (from === holder) delta -= deposit;
  }
  let fee: bigint | null = null;
  if (tx.execution_outcome) {
    fee = BigInt(tx.execution_outcome.outcome.tokens_burnt);
    for (const r of tx.receipts ?? []) fee += BigInt(r.execution_outcome.outcome.tokens_burnt);
  }
  const onlyTransfer = kinds.length > 0 && kinds.every((k) => k === 'Transfer');
  return {
    ...base,
    from,
    to,
    ...(onlyTransfer ? {} : { description: [...new Set(kinds)].join(', ').slice(0, 120) }),
    assetDeltas: deposit > 0n ? [{ assetRef: nativeRef, amount: String(delta) }] : [],
    fee: fee === null ? null : fee.toString(),
  };
}

export function createNearAdapter(opts?: NearAdapterOptions): NearAdapter {
  return new NearAdapter(opts);
}
