/**
 * Cardano adapter. Addresses are CIP-19 Shelley addresses (bech32 `addr…` /
 * `addr_test…`): a header byte, the blake2b-224 hash of the payment key and,
 * for base addresses, the hash of the stake key.
 *
 * Two kinds of keyless, browser-reachable endpoint share one rpc list:
 * - the Emurgo Yoroi backend (`…/api`) for UTxOs, balances, history and status;
 * - Koios' Ogmios passthrough (`…/ogmios`) for protocol parameters and submission.
 * Koios' REST routes send no `access-control-allow-origin` header on responses,
 * so a browser cannot read them; only `/ogmios` and `/submittx` can be used.
 * Every endpoint proves its network before it is trusted: Ogmios by the
 * genesis network magic, the indexer by a pinned historical block hash.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { bech32 } from '@scure/base';
import {
  BaseAdapter,
  RpcFailoverError,
  fetchJsonRpc,
  hasHealthTracking,
  nativeHolding,
  postJsonText,
  fetchJson,
  publicKeyBytes,
  requireCurve,
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

export const CARDANO_PREPROD = 'cip34:0-1';
export const CARDANO_MAINNET = 'cip34:1-764824073';
export const NETWORK_MAGIC: Record<string, number> = {
  [CARDANO_PREPROD]: 1,
  [CARDANO_MAINNET]: 764824073,
};
/** Hash of the last block at or before (epoch 100, slot 1000): immutable, and unique per network. */
export const ANCHOR_BLOCKS: Record<string, string> = {
  [CARDANO_PREPROD]: '5bb2f713b96a8fa5c98b469450377e49aa732f015aa3fd8c440407554f2e393f',
  [CARDANO_MAINNET]: '77934503c6509360b4d79985da58bde30d5bec25ef39f2217c6b74ccf34efae3',
};
const BECH32_LIMIT = 1023;
const BASE_KEY_KEY = 0;
const BASE_KEY_SCRIPT = 2;
const ENTERPRISE_KEY = 6;

export interface CardanoAddress {
  raw: Uint8Array;
  kind: number;
  /** blake2b-224 of the payment key. */
  payment: Uint8Array;
}

const networkOf = (chainId: string): 0 | 1 => (chainId === CARDANO_MAINNET ? 1 : 0);

export function keyHash(publicKey: Uint8Array): Uint8Array {
  return blake2b(publicKey, { dkLen: 28 });
}

function encodeRaw(network: 0 | 1, raw: Uint8Array): string {
  return bech32.encode(network === 1 ? 'addr' : 'addr_test', bech32.toWords(raw), BECH32_LIMIT);
}

/** Base address for `payment || stake` (64 bytes) or enterprise for a lone payment key (32 bytes). */
export function cardanoAddressFromPublicKey(key: Uint8Array, chainId = CARDANO_PREPROD): string {
  const network = networkOf(chainId);
  if (key.length === 32) {
    return encodeRaw(network, Uint8Array.from([(ENTERPRISE_KEY << 4) | network, ...keyHash(key)]));
  }
  if (key.length === 64) {
    return encodeRaw(
      network,
      Uint8Array.from([
        (BASE_KEY_KEY << 4) | network,
        ...keyHash(key.subarray(0, 32)),
        ...keyHash(key.subarray(32)),
      ]),
    );
  }
  throw new TypeError('Cardano public key must be 32 (payment) or 64 (payment || stake) bytes');
}

/**
 * A canonical lowercase Shelley address with a key payment credential for the
 * chain's network (base or enterprise). Script, pointer, Byron and
 * other-network addresses are refused, as the core refuses them.
 */
export function cardanoAddressBytes(
  addr: string,
  chainId = CARDANO_PREPROD,
): CardanoAddress | undefined {
  const network = networkOf(chainId);
  const prefix = network === 1 ? 'addr' : 'addr_test';
  if (addr.length > 120 || !addr.startsWith(`${prefix}1`)) return undefined;
  try {
    const decoded = bech32.decode(addr as `${string}1${string}`, BECH32_LIMIT);
    if (decoded.prefix !== prefix) return undefined;
    const raw = bech32.fromWords(decoded.words);
    const header = raw[0];
    if (header === undefined || (header & 0x0f) !== network) return undefined;
    const kind = header >> 4;
    const len =
      kind === BASE_KEY_KEY || kind === BASE_KEY_SCRIPT ? 57 : kind === ENTERPRISE_KEY ? 29 : 0;
    if (raw.length !== len || encodeRaw(network, raw) !== addr) return undefined;
    return { raw, kind, payment: raw.slice(1, 29) };
  } catch {
    return undefined;
  }
}

export function isValidCardanoAddress(addr: string, chainId = CARDANO_PREPROD): boolean {
  return cardanoAddressBytes(addr, chainId) !== undefined;
}

export type EndpointKind = 'indexer' | 'ogmios';
export function endpointKind(url: string): EndpointKind {
  return url.replace(/\/+$/, '').endsWith('/ogmios') ? 'ogmios' : 'indexer';
}

const Lovelace = z.string().regex(/^(0|[1-9][0-9]{0,16})$/);
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const SafeUint = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Bech = z.string().min(1).max(256);

export const BestBlock = z.object({
  epoch: SafeUint,
  slot: SafeUint,
  globalSlot: SafeUint,
  hash: Hash,
  height: SafeUint,
});
export type BestBlock = z.infer<typeof BestBlock>;
export const Utxo = z.object({
  tx_hash: Hash,
  tx_index: z.number().int().min(0).max(0xffffffff),
  receiver: Bech,
  amount: Lovelace,
  assets: z.array(z.unknown()).max(10_000),
  block_num: SafeUint.nullable().optional(),
  script_ref: z.unknown().optional(),
});
export type Utxo = z.infer<typeof Utxo>;
const UtxoList = z.array(Utxo).max(20_000);
const UtxoSum = z.object({
  sum: Lovelace.nullable(),
  tokensBalance: z.array(z.unknown()).max(10_000).optional(),
});
const AnchorAnswer = z.object({ blockHashes: z.record(z.string(), Hash.nullable()) });
const IoEntry = z
  .object({ address: Bech, amount: Lovelace, assets: z.array(z.unknown()).max(10_000).optional() })
  .loose();
export const IndexedTx = z
  .object({
    hash: Hash,
    fee: Lovelace.nullable().optional(),
    tx_state: z.string().max(32),
    block_num: SafeUint.nullable().optional(),
    block_hash: Hash.nullable().optional(),
    time: z.string().max(64).nullable().optional(),
    inputs: z.array(IoEntry).max(5000),
    outputs: z.array(IoEntry).max(5000),
  })
  .loose();
export type IndexedTx = z.infer<typeof IndexedTx>;
const HistoryList = z.array(IndexedTx).max(100);
const TxMap = z.record(z.string(), IndexedTx);

const Genesis = z.object({ networkMagic: SafeUint }).loose();
const Coin = z.object({ ada: z.object({ lovelace: SafeUint }) });
export const OgmiosParams = z
  .object({
    minFeeCoefficient: SafeUint,
    minFeeConstant: Coin,
    minUtxoDepositCoefficient: SafeUint,
    maxTransactionSize: z.object({ bytes: SafeUint }),
  })
  .loose();
export interface ProtocolParams {
  minFeeA: number;
  minFeeB: number;
  coinsPerUtxoByte: number;
  maxTxSize: number;
}

const BIG_BODY = { maxBodyBytes: 4 << 20 };

export type CardanoAdapterOptions = BaseAdapterOptions;

export class CardanoAdapter extends BaseAdapter<'cardano'> {
  constructor(opts: CardanoAdapterOptions = {}) {
    super('cardano', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return cardanoAddressFromPublicKey(publicKeyBytes(pub), chainId);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidCardanoAddress(addr, chainId);
  }

  private async post<T>(url: string, path: string, body: unknown, schema: z.ZodType<T>) {
    const text = await postJsonText(`${url.replace(/\/+$/, '')}${path}`, body, {
      ...this.fetchOptions(),
      ...BIG_BODY,
    });
    return schema.parse(JSON.parse(text));
  }

  private ogmios<T>(
    url: string,
    method: string,
    params: Record<string, unknown>,
    schema: z.ZodType<T>,
  ) {
    return fetchJsonRpc(url, method, params, this.fetchOptions()).then((r) => schema.parse(r));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      if (endpointKind(url) === 'ogmios') {
        const g = await this.ogmios(
          url,
          'queryNetwork/genesisConfiguration',
          { era: 'shelley' },
          Genesis,
        );
        if (g.networkMagic !== NETWORK_MAGIC[chainId])
          throw new Error('Endpoint network magic does not match this Cardano network');
      } else {
        const a = await this.post(
          url,
          '/v2.1/lastBlockBySlot',
          { slots: [[100, 1000]] },
          AnchorAnswer,
        );
        if (a.blockHashes['100,1000'] !== ANCHOR_BLOCKS[chainId])
          throw new Error('Endpoint history does not match this Cardano network');
      }
    });
  }

  /**
   * Failover across the endpoints of one kind, after each proves its network.
   * Keeps dependent observations on one endpoint.
   */
  async withEndpoint<T>(
    chainId: ChainId,
    kind: EndpointKind,
    query: (url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    const urls = this.rpc
      .endpoints(chainId)
      .map((e) => e.url)
      .filter((u) => endpointKind(u) === kind);
    if (urls.length === 0)
      throw new Error(`No Cardano ${kind} endpoint is configured for ${chainId}`);
    const tracking = hasHealthTracking(this.rpc) ? this.rpc : undefined;
    const causes: { url: string; error: unknown }[] = [];
    for (const url of urls) {
      const started = Date.now();
      try {
        await this.checkNetwork(chainId, url);
        const value = await query(url);
        tracking?.markHealthy(url, Date.now() - started);
        return value;
      } catch (error) {
        tracking?.markFailed(url);
        causes.push({ url, error });
      }
    }
    throw new RpcFailoverError(chainId, causes);
  }

  tip(chainId: ChainId): Promise<BestBlock> {
    return this.withEndpoint(chainId, 'indexer', async (url) => {
      const best = BestBlock.parse(
        await fetchJson(`${url.replace(/\/+$/, '')}/v2/bestblock`, this.fetchOptions()),
      );
      this.noteBlock(url, best.height);
      return best;
    });
  }

  utxos(addr: Address, chainId: ChainId): Promise<Utxo[]> {
    if (!isValidCardanoAddress(addr, chainId))
      throw new TypeError(`invalid cardano address ${addr}`);
    return this.withEndpoint(chainId, 'indexer', (url) =>
      this.post(url, '/txs/utxoForAddresses', { addresses: [addr] }, UtxoList),
    );
  }

  protocolParams(chainId: ChainId): Promise<ProtocolParams> {
    return this.withEndpoint(chainId, 'ogmios', async (url) => {
      const p = await this.ogmios(url, 'queryLedgerState/protocolParameters', {}, OgmiosParams);
      return {
        minFeeA: p.minFeeCoefficient,
        minFeeB: p.minFeeConstant.ada.lovelace,
        coinsPerUtxoByte: p.minUtxoDepositCoefficient,
        maxTxSize: p.maxTransactionSize.bytes,
      };
    });
  }

  /** Ogmios `submitTransaction`; JSON-RPC errors come back as values, with HTTP 400. */
  async submit(
    chainId: ChainId,
    cborHex: string,
  ): Promise<{ id?: string; error?: { code: number; message: string } }> {
    return this.withEndpoint(chainId, 'ogmios', async (url) => {
      const doFetch = this.fetchImpl ?? globalThis.fetch;
      const res = await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'submitTransaction',
          params: { transaction: { cbor: cborHex } },
          id: 1,
        }),
        signal: AbortSignal.timeout(this.timeoutMs ?? 30_000),
      });
      const text = (await res.text()).slice(0, 1 << 16);
      if (res.status >= 500) throw new Error(`HTTP ${res.status} from ${url}`);
      const parsed = SubmitAnswer.safeParse(safeJson(text));
      if (!parsed.success) throw new Error(`Unexpected submit answer (HTTP ${res.status})`);
      if (parsed.data.result) return { id: parsed.data.result.transaction.id };
      const err = parsed.data.error!;
      return { error: { code: err.code, message: err.message.slice(0, 512) } };
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidCardanoAddress(addr, chainId))
      throw new TypeError(`invalid cardano address ${addr}`);
    let endpoint = '';
    const sum = await this.withEndpoint(chainId, 'indexer', async (url) => {
      endpoint = url;
      return this.post(url, '/txs/utxoSumForAddresses', { addresses: [addr] }, UtxoSum);
    });
    const holding = nativeHolding(chain, sum.sum ?? '0', { kind: 'single', endpoint });
    const tokens = sum.tokensBalance?.length ?? 0;
    return [
      tokens > 0
        ? {
            ...holding,
            notice: `Includes ADA locked with ${tokens} native token(s); only ADA-only UTxOs are spendable here.`,
          }
        : holding,
    ];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidCardanoAddress(addr, chainId)) throw new Error('Invalid history address');
    let after: { block: string; tx: string } | undefined;
    if (cursor !== undefined) {
      const m = /^([0-9a-f]{64})\.([0-9a-f]{64})$/.exec(cursor);
      if (!m) throw new Error('Invalid history cursor');
      after = { block: m[1]!, tx: m[2]! };
    }
    const limit = 20;
    return this.withEndpoint(chainId, 'indexer', async (url) => {
      const best = BestBlock.parse(
        await fetchJson(`${url.replace(/\/+$/, '')}/v2/bestblock`, {
          ...this.fetchOptions(),
          ...(options?.signal ? { signal: options.signal } : {}),
        }),
      );
      const txs = await this.post(
        url,
        '/v2/txs/history',
        { addresses: [addr], untilBlock: best.hash, limit, ...(after ? { after } : {}) },
        HistoryList,
      );
      const last = txs[txs.length - 1];
      return {
        items: txs.map((t) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t)),
        ...(txs.length === limit && last?.block_hash
          ? { nextCursor: `${last.block_hash}.${last.hash}` }
          : {}),
        coverage:
          'Yoroi backend: transactions touching this exact address, oldest first; ADA deltas only (native tokens are not listed).',
        source: url,
      };
    });
  }

  /** The indexed transaction, or null when the indexer has not seen it in a block. */
  indexedTx(hash: string, chainId: ChainId): Promise<IndexedTx | null> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Cardano transaction hash');
    const value = hash.toLowerCase();
    return this.withEndpoint(chainId, 'indexer', async (url) => {
      const map = await this.post(url, '/v2/txs/get', { txHashes: [value] }, TxMap);
      return map[value] ?? null;
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    const tx = await this.indexedTx(hash, chainId);
    if (!tx) return { state: 'unknown' };
    if (tx.tx_state === 'Failed') return { state: 'failed', reason: 'script validation failed' };
    if (tx.tx_state !== 'Successful' || tx.block_num == null) return { state: 'pending' };
    const ts = tx.time ? Date.parse(tx.time) : NaN;
    return {
      state: 'confirmed',
      blockNumber: tx.block_num,
      ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
    };
  }
}

const SubmitAnswer = z
  .object({
    result: z.object({ transaction: z.object({ id: Hash }) }).optional(),
    error: z.object({ code: z.number().int(), message: z.string() }).loose().optional(),
  })
  .refine((a) => (a.result === undefined) !== (a.error === undefined));

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function historyRecord(chainId: string, nativeRef: string, holder: string, t: IndexedTx): TxRecord {
  let delta = 0n;
  for (const i of t.inputs) if (i.address === holder) delta -= BigInt(i.amount);
  for (const o of t.outputs) if (o.address === holder) delta += BigInt(o.amount);
  const failed = t.tx_state === 'Failed';
  const from = t.inputs[0]?.address ?? '';
  const to = t.outputs.find((o) => o.address !== from)?.address ?? t.outputs[0]?.address;
  const ts = t.time ? Date.parse(t.time) : NaN;
  return {
    hash: t.hash,
    chainId,
    from,
    ...(to ? { to } : {}),
    ...(t.block_num != null ? { blockNumber: t.block_num } : {}),
    ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
    assetDeltas: failed ? [] : [{ assetRef: nativeRef, amount: delta.toString() }],
    feeAssetRef: nativeRef,
    fee: t.fee ?? null,
    status: failed ? 'failed' : t.tx_state === 'Successful' ? 'confirmed' : 'pending',
  };
}

export function createCardanoAdapter(opts?: CardanoAdapterOptions): CardanoAdapter {
  return new CardanoAdapter(opts);
}
