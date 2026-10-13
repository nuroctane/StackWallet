/**
 * EVM address work and read-only RPC queries. The checked send path lives in
 * `send.ts` and the Rust core; generic adapter signing methods remain disabled.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  BaseAdapter,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
  secp256k1Uncompressed,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type Holding,
  type TxHash,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

// 32 bytes is the widest quantity the EVM produces; longer is a hostile node.
const HexQuantity = z
  .string()
  .regex(/^0x[0-9a-fA-F]+$/)
  .max(66);
const Wei = HexQuantity.transform((h) => BigInt(h));
const TxHashHex = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const Receipt = z
  .object({
    status: HexQuantity.refine((v) => BigInt(v) === 0n || BigInt(v) === 1n).optional(),
    blockNumber: HexQuantity.refine((v) => BigInt(v) <= BigInt(Number.MAX_SAFE_INTEGER)).nullable(),
    transactionHash: TxHashHex,
  })
  .nullable();
const TxByHash = z.object({ hash: TxHashHex }).nullable();

const ascii = (s: string) => new TextEncoder().encode(s);

/** EIP-55 mixed-case checksum encoding of a 20-byte address. */
export function toChecksumAddress(addressHex: string): string {
  const lower = addressHex.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(lower)) throw new TypeError('address must be 20 bytes of hex');
  const hash = bytesToHex(keccak_256(ascii(lower)));
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    const c = lower[i]!;
    out += parseInt(hash[i]!, 16) >= 8 ? c.toUpperCase() : c;
  }
  return out;
}

export function isValidEvmAddress(addr: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return false;
  const body = addr.slice(2);
  if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
  return toChecksumAddress(addr) === addr;
}

export type EvmAdapterOptions = BaseAdapterOptions;

export class EvmAdapter extends BaseAdapter<'evm'> {
  private trackedTokens: { chainId: string; address: string; symbol: string; decimals: number }[] =
    [];

  setTrackedTokens(
    tokens: { chainId: string; address: string; symbol: string; decimals: number }[],
  ): void {
    this.trackedTokens = z
      .array(
        z.object({
          chainId: z.string().regex(/^eip155:\d+$/),
          address: z.string().refine(isValidEvmAddress),
          symbol: z.string().regex(/^[\x20-\x7e]{1,12}$/),
          decimals: z.number().int().min(0).max(36),
        }),
      )
      .max(100)
      .parse(tokens);
  }
  constructor(opts: EvmAdapterOptions = {}) {
    super('evm', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    const full = secp256k1Uncompressed(publicKeyBytes(pub));
    const hash = keccak_256(full.subarray(1));
    return toChecksumAddress(bytesToHex(hash.subarray(12)));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidEvmAddress(addr);
  }

  /** One JSON-RPC call with endpoint failover; the result is validated by `schema`. */
  call<T>(chainId: ChainId, method: string, params: unknown[], schema: z.ZodType<T>): Promise<T> {
    return withFailover(this.rpc, chainId, this.checkedRpc(chainId, method, params, schema));
  }

  private checkedRpc<T>(chainId: ChainId, method: string, params: unknown[], schema: z.ZodType<T>) {
    return async (url: string) => {
      await this.verifyEndpoint(chainId, url, async () => {
        const id = await this.jsonRpc('eth_chainId', [], Wei)(url);
        if (`eip155:${id}` !== chainId)
          throw new Error('RPC chain id does not match the requested EVM chain');
      });
      return this.jsonRpc(method, params, schema)(url);
    };
  }

  /** One JSON-RPC call against a specific endpoint, for callers that run their own failover. */
  rawCall<T>(url: string, method: string, params: unknown[], schema: z.ZodType<T>): Promise<T> {
    return this.jsonRpc(method, params, schema)(url);
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidEvmAddress(addr)) throw new TypeError(`invalid evm address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      this.checkedRpc(chainId, 'eth_getBalance', [addr, 'latest'], Wei),
      { equal: (a, b) => a === b, describe: (v) => v.toString() },
    );
    const tokens: Holding[] = [];
    // Bound RPC concurrency: tracking many contracts must not flood public endpoints.
    for (const token of this.trackedTokens.filter((t) => t.chainId === chainId)) {
      const assetRef = `${chainId}:erc20:${token.address.toLowerCase()}`;
      const metadata = { symbol: token.symbol, decimals: token.decimals };
      try {
        const balance = await withCrossCheck(
          this.rpc,
          chainId,
          this.checkedRpc(
            chainId,
            'eth_call',
            [
              {
                to: token.address,
                data: `0x70a08231${addr.slice(2).toLowerCase().padStart(64, '0')}`,
              },
              'latest',
            ],
            z
              .string()
              .regex(/^0x[0-9a-fA-F]{64}$/)
              .transform((h) => BigInt(h)),
          ),
          { equal: (a, b) => a === b, describe: (v) => v.toString() },
        );
        tokens.push({
          assetRef,
          amount: balance.value.toString(),
          provenance: balance.provenance,
          updatedAtMs: Date.now(),
          metadata,
        });
      } catch (err) {
        tokens.push({
          assetRef,
          amount: '0',
          updatedAtMs: Date.now(),
          metadata,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    return [nativeHolding(chain, value.toString(), provenance), ...tokens];
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.requireChain(chainId);
    TxHashHex.parse(hash);
    const receipt = await this.call(
      chainId,
      'eth_getTransactionReceipt',
      [hash],
      Receipt.refine(
        (r) => r === null || r.transactionHash.toLowerCase() === hash.toLowerCase(),
        'Receipt transaction hash does not match the requested transaction',
      ),
    );
    if (receipt && receipt.blockNumber) {
      const blockNumber = Number(BigInt(receipt.blockNumber));
      // Pre-Byzantium receipts have no status field; treat inclusion as success.
      if (receipt.status === undefined || BigInt(receipt.status) === 1n) {
        return { state: 'confirmed', blockNumber };
      }
      return { state: 'failed', reason: 'reverted' };
    }
    const pending = await this.call(
      chainId,
      'eth_getTransactionByHash',
      [hash],
      TxByHash.refine(
        (r) => r === null || r.hash.toLowerCase() === hash.toLowerCase(),
        'Transaction hash does not match the requested transaction',
      ),
    );
    return pending ? { state: 'pending' } : { state: 'unknown' };
  }
}

export function createEvmAdapter(opts?: EvmAdapterOptions): EvmAdapter {
  return new EvmAdapter(opts);
}
