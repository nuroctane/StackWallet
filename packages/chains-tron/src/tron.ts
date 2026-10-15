/**
 * Tron adapter. Addresses are base58check of `0x41 || keccak(pubkey)[12..]`;
 * reads go over the java-tron HTTP API, whose genesis block id ends with the
 * CAIP-2 reference, so every endpoint proves which network it serves.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createBase58check } from '@scure/base';
import {
  BaseAdapter,
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
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

const base58check = createBase58check(sha256);
const PREFIX = 0x41;

export function tronAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr)) return undefined;
  try {
    const bytes = base58check.decode(addr);
    if (bytes.length !== 21 || bytes[0] !== PREFIX || bytes.subarray(1).every((b) => b === 0))
      return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

export function isValidTronAddress(addr: string): boolean {
  return tronAddressBytes(addr) !== undefined;
}

/** `41…` hex as java-tron reports it when `visible` is off. */
export function tronAddressFromHex(hex: string): string | undefined {
  if (!/^41[0-9a-fA-F]{40}$/.test(hex)) return undefined;
  const addr = base58check.encode(hexToBytes(hex.toLowerCase()));
  return isValidTronAddress(addr) ? addr : undefined;
}

export function tronAddressFromPublicKey(sec1: Uint8Array): string {
  const full = secp256k1Uncompressed(sec1);
  const payload = new Uint8Array(21);
  payload[0] = PREFIX;
  payload.set(keccak_256(full.subarray(1)).subarray(12), 1);
  return base58check.encode(payload);
}

/**
 * java-tron emits balances as bare JSON numbers that can exceed 2^53; quote
 * long integer literals so they survive parsing as exact decimal strings.
 */
export function parseTronJson(text: string): unknown {
  return JSON.parse(text.replace(/([:[,]\s*)(-?\d{16,})(?=\s*[,}\]])/g, '$1"$2"'));
}

const Sun = z.union([
  z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  z.string().regex(/^\d{1,19}$/),
]);
const BlockId = z.string().regex(/^[0-9a-f]{64}$/);
const TxId = z.string().regex(/^[0-9a-f]{64}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const Block = z.object({
  blockID: BlockId,
  block_header: z.object({
    raw_data: z.object({ number: SafeInt.optional(), timestamp: SafeInt.optional() }),
  }),
});
const Account = z.object({ balance: Sun.optional(), address: z.string().optional() });
const ConstantCall = z.object({
  result: z.object({ result: z.literal(true) }),
  constant_result: z.array(z.string().regex(/^[0-9a-f]{64}$/)).length(1),
});
const TxInfo = z.object({
  id: TxId.optional(),
  blockNumber: SafeInt.optional(),
  blockTimeStamp: SafeInt.optional(),
  result: z.string().max(32).optional(),
  resMessage: z.string().max(2048).optional(),
});

const TRC20: Record<string, { address: string; symbol: string; decimals: number }[]> = {
  'tron:0x2b6653dc': [
    { address: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', symbol: 'USDT', decimals: 6 },
  ],
};

export type TronAdapterOptions = BaseAdapterOptions;
export type TronCall = <T>(path: string, body: unknown, schema: z.ZodType<T>) => Promise<T>;

export class TronAdapter extends BaseAdapter<'tron'> {
  constructor(opts: TronAdapterOptions = {}) {
    super('tron', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return tronAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidTronAddress(addr);
  }

  private post<T>(url: string, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    return postJsonText(`${url.replace(/\/$/, '')}${path}`, body, this.fetchOptions()).then(
      (text) => schema.parse(parseTronJson(text)),
    );
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const genesis = await this.post(url, '/wallet/getblockbynum', { num: 0 }, Block);
      if (`tron:0x${genesis.blockID.slice(-8)}` !== chainId)
        throw new Error('Endpoint genesis block does not match this Tron network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: TronCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, body, schema) => this.post(url, path, body, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidTronAddress(addr)) throw new TypeError(`invalid tron address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const account = await this.post(
          url,
          '/wallet/getaccount',
          { address: addr, visible: true },
          Account,
        );
        // An address that never received TRX is not an account yet: zero, not an error.
        return BigInt(account.balance ?? 0).toString();
      },
      { equal: (a, b) => a === b },
    );
    const tokens: Holding[] = [];
    const owner = bytesToHex(tronAddressBytes(addr)!.subarray(1)).padStart(64, '0');
    for (const token of TRC20[chainId] ?? []) {
      const assetRef = `${chainId}:trc20:${token.address}`;
      const metadata = { symbol: token.symbol, decimals: token.decimals };
      const notice = 'TRC-20 balance from balanceOf; token transfers are not enabled.';
      try {
        const observed = await withCrossCheck(
          this.rpc,
          chainId,
          async (url) => {
            await this.checkNetwork(chainId, url);
            const res = await this.post(
              url,
              '/wallet/triggerconstantcontract',
              {
                owner_address: addr,
                contract_address: token.address,
                function_selector: 'balanceOf(address)',
                parameter: owner,
                visible: true,
              },
              ConstantCall,
            );
            return BigInt(`0x${res.constant_result[0]}`).toString();
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

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidTronAddress(addr)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^[A-Za-z0-9_-]{1,256}$/.test(cursor))
      throw new Error('Invalid history cursor');
    // Only TronGrid serves the indexed /v1 account API; plain java-tron nodes do not.
    const indexers = this.rpc.endpoints(chainId).filter((e) => /\.trongrid\.io\/?$/.test(e.url));
    if (indexers.length === 0)
      return {
        items: [],
        coverage: 'No TronGrid endpoint is configured for this network, so history is unavailable.',
      };
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    let lastError: unknown;
    for (const { url } of indexers) {
      try {
        await this.checkNetwork(chainId, url);
        const query = new URLSearchParams({ limit: '20', order_by: 'block_timestamp,desc' });
        if (cursor) query.set('fingerprint', cursor);
        const res = HistoryPage.parse(
          await fetchJson(
            `${url.replace(/\/$/, '')}/v1/accounts/${addr}/transactions?${query.toString()}`,
            opts,
          ),
        );
        return {
          items: res.data.map((t) => historyRecord(chain.chainId, chain.nativeAsset.ref, addr, t)),
          ...(res.meta.fingerprint ? { nextCursor: res.meta.fingerprint } : {}),
          coverage:
            'TronGrid account transactions. TRX transfers carry net changes; other contract calls (TRC-20, staking, resources) are listed without balance changes. Fees are TRX burned for bandwidth and energy.',
          source: url,
        };
      } catch (err) {
        if (options?.signal?.aborted) throw err;
        lastError = err;
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Tron history is unavailable');
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Tron transaction id');
    const value = hash.replace(/^0x/, '').toLowerCase();
    return this.withNode(chainId, async (call) => {
      const solid = await call('/walletsolidity/gettransactioninfobyid', { value }, TxInfo);
      if (solid.blockNumber !== undefined) {
        if (solid.result === 'FAILED')
          return { state: 'failed', reason: decodeMessage(solid.resMessage ?? 'FAILED') };
        return {
          state: 'confirmed',
          blockNumber: solid.blockNumber,
          ...(solid.blockTimeStamp !== undefined ? { timestampMs: solid.blockTimeStamp } : {}),
        };
      }
      const head = await call('/wallet/gettransactioninfobyid', { value }, TxInfo);
      return head.blockNumber !== undefined ? { state: 'pending' } : { state: 'unknown' };
    });
  }
}

const HexOrBase58 = z.string().max(64);
const HistoryPage = z.object({
  success: z.literal(true),
  data: z
    .array(
      z.object({
        txID: TxId,
        blockNumber: SafeInt.optional(),
        block_timestamp: SafeInt.optional(),
        ret: z
          .array(z.object({ contractRet: z.string().max(64).optional(), fee: SafeInt.optional() }))
          .max(4)
          .optional(),
        net_fee: SafeInt.optional(),
        energy_fee: SafeInt.optional(),
        raw_data: z.object({
          contract: z
            .array(
              z.object({
                type: z.string().max(64),
                parameter: z.object({
                  value: z
                    .object({
                      owner_address: HexOrBase58.optional(),
                      to_address: HexOrBase58.optional(),
                      amount: Sun.optional(),
                    })
                    .loose(),
                }),
              }),
            )
            .max(4),
        }),
      }),
    )
    .max(200),
  meta: z
    .object({
      fingerprint: z
        .string()
        .regex(/^[A-Za-z0-9_-]{1,256}$/)
        .optional(),
    })
    .loose(),
});

function readable(addr: string | undefined): string {
  if (!addr) return '';
  return tronAddressFromHex(addr) ?? (isValidTronAddress(addr) ? addr : '');
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  t: z.infer<typeof HistoryPage>['data'][number],
): TxRecord {
  const contract = t.raw_data.contract[0];
  const value = contract?.parameter.value;
  const from = readable(value?.owner_address);
  const to = readable(value?.to_address);
  const outcome = t.ret?.[0]?.contractRet;
  const failed = outcome !== undefined && outcome !== 'SUCCESS';
  let delta = 0n;
  if (contract?.type === 'TransferContract' && value?.amount !== undefined && !failed) {
    const amount = BigInt(value.amount);
    if (to === holder) delta += amount;
    if (from === holder) delta -= amount;
  }
  // ret.fee is the whole burn (bandwidth plus energy) charged to the owner.
  const fee =
    from === holder ? BigInt(t.ret?.[0]?.fee ?? (t.net_fee ?? 0) + (t.energy_fee ?? 0)) : 0n;
  return {
    hash: t.txID,
    chainId,
    from,
    ...(to ? { to } : {}),
    ...(t.blockNumber !== undefined ? { blockNumber: t.blockNumber } : {}),
    ...(t.block_timestamp !== undefined ? { timestampMs: t.block_timestamp } : {}),
    ...(contract && contract.type !== 'TransferContract' ? { description: contract.type } : {}),
    assetDeltas:
      delta !== 0n || contract?.type === 'TransferContract'
        ? [{ assetRef: nativeRef, amount: String(delta) }]
        : [],
    feeAssetRef: nativeRef,
    fee: String(fee),
    status: failed ? 'failed' : 'confirmed',
  };
}

/** java-tron sometimes hex-encodes error messages. */
export function decodeMessage(message: string): string {
  const text = /^(?:[0-9a-fA-F]{2}){1,1024}$/.test(message)
    ? new TextDecoder().decode(hexToBytes(message.toLowerCase()))
    : message;
  return text.replace(/[^\x20-\x7e]/g, '').slice(0, 512);
}

export function createTronAdapter(opts?: TronAdapterOptions): TronAdapter {
  return new TronAdapter(opts);
}
