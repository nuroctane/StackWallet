/**
 * EVM adapter. Offline address work and read-only JSON-RPC queries are done
 * here directly; transaction building, decoding and simulation arrive with
 * viem in a later phase and slot into the `NotImplementedError` methods.
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
const Receipt = z
  .object({
    status: HexQuantity.optional(),
    blockNumber: HexQuantity.nullable(),
    transactionHash: z.string().optional(),
  })
  .nullable();
const TxByHash = z.object({ hash: z.string() }).nullable();

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

  private call<T>(
    chainId: ChainId,
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): Promise<T> {
    return withFailover(this.rpc, chainId, this.jsonRpc(method, params, schema));
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidEvmAddress(addr)) throw new TypeError(`invalid evm address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      this.jsonRpc('eth_getBalance', [addr, 'latest'], Wei),
      { equal: (a, b) => a === b, describe: (v) => v.toString() },
    );
    return [nativeHolding(chain, value.toString(), provenance)];
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.requireChain(chainId);
    const receipt = await this.call(chainId, 'eth_getTransactionReceipt', [hash], Receipt);
    if (receipt && receipt.blockNumber) {
      const blockNumber = Number(BigInt(receipt.blockNumber));
      // Pre-Byzantium receipts have no status field; treat inclusion as success.
      if (receipt.status === undefined || BigInt(receipt.status) === 1n) {
        return { state: 'confirmed', blockNumber };
      }
      return { state: 'failed', reason: 'reverted' };
    }
    const pending = await this.call(chainId, 'eth_getTransactionByHash', [hash], TxByHash);
    return pending ? { state: 'pending' } : { state: 'unknown' };
  }
}

export function createEvmAdapter(opts?: EvmAdapterOptions): EvmAdapter {
  return new EvmAdapter(opts);
}
