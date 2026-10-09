/**
 * EVM adapter. Offline address work and read-only JSON-RPC queries are done
 * here directly; transaction building, decoding and simulation arrive with
 * viem in a later phase and slot into the `NotImplementedError` methods.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  MemoryRpcPool,
  NotImplementedError,
  UnknownChainError,
  chainsForFamily,
  fetchJsonRpc,
  publicKeyBytes,
  requireCurve,
  secp256k1Uncompressed,
  withFailover,
  type Address,
  type ChainAdapter,
  type ChainInfo,
  type Holding,
  type Page,
  type RpcPool,
  type SignedTx,
  type Simulation,
  type TxHash,
  type TxRecord,
  type TxStatus,
  type UnsignedTx,
} from '@stackwallet/chains';
import type {
  ChainId,
  PublicKey,
  Signature,
  SignRequest,
  TxIntent,
} from '@stackwallet/core-client';
import { z } from 'zod';

// 32 bytes is the widest quantity the EVM produces; longer is a hostile node.
const HexQuantity = z
  .string()
  .regex(/^0x[0-9a-fA-F]+$/)
  .max(66);
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

export interface EvmAdapterOptions {
  rpc?: RpcPool;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export class EvmAdapter implements ChainAdapter {
  readonly family = 'evm' as const;
  readonly rpc: RpcPool;
  private readonly fetchImpl: typeof fetch | undefined;
  private readonly timeoutMs: number | undefined;

  constructor(opts: EvmAdapterOptions = {}) {
    this.rpc = opts.rpc ?? defaultPool();
    this.fetchImpl = opts.fetch;
    this.timeoutMs = opts.timeoutMs;
  }

  chains(): ChainInfo[] {
    return chainsForFamily('evm');
  }

  private chain(chainId: ChainId): ChainInfo {
    const c = this.chains().find((x) => x.chainId === chainId);
    if (!c) throw new UnknownChainError(chainId);
    return c;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.chain(chainId);
    requireCurve(pub, 'secp256k1');
    const full = secp256k1Uncompressed(publicKeyBytes(pub));
    const hash = keccak_256(full.subarray(1));
    return toChecksumAddress(bytesToHex(hash.subarray(12)));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.chain(chainId);
    return isValidEvmAddress(addr);
  }

  /** Schema validation runs inside failover so a node returning garbage is skipped like a dead one. */
  private call<T>(
    chainId: ChainId,
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): Promise<T> {
    const opts = {
      ...(this.fetchImpl ? { fetch: this.fetchImpl } : {}),
      ...(this.timeoutMs !== undefined ? { timeoutMs: this.timeoutMs } : {}),
    };
    return withFailover(this.rpc, chainId, async (url) =>
      schema.parse(await fetchJsonRpc(url, method, params, opts)),
    );
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.chain(chainId);
    if (!isValidEvmAddress(addr)) throw new TypeError(`invalid evm address ${addr}`);
    const hex = await this.call(chainId, 'eth_getBalance', [addr, 'latest'], HexQuantity);
    return [
      { assetRef: chain.nativeAsset.ref, amount: BigInt(hex).toString(), updatedAtMs: Date.now() },
    ];
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.chain(chainId);
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

  getHistory(_addr: Address, _chainId: ChainId, _cursor?: string): Promise<Page<TxRecord>> {
    return Promise.reject(new NotImplementedError('chains-evm.getHistory', 'phase 3'));
  }

  build(_intent: TxIntent, _chainId: ChainId): Promise<UnsignedTx> {
    return Promise.reject(new NotImplementedError('chains-evm.build', 'phase 3'));
  }

  simulate(_tx: UnsignedTx): Promise<Simulation> {
    return Promise.reject(new NotImplementedError('chains-evm.simulate', 'phase 3'));
  }

  sighashes(_tx: UnsignedTx): SignRequest[] {
    throw new NotImplementedError('chains-evm.sighashes', 'phase 3');
  }

  attach(_tx: UnsignedTx, _sigs: Signature[]): SignedTx {
    throw new NotImplementedError('chains-evm.attach', 'phase 3');
  }

  broadcast(_tx: SignedTx): Promise<TxHash> {
    return Promise.reject(new NotImplementedError('chains-evm.broadcast', 'phase 3'));
  }
}

function defaultPool(): RpcPool {
  return new MemoryRpcPool(chainsForFamily('evm'));
}

export function createEvmAdapter(opts?: EvmAdapterOptions): EvmAdapter {
  return new EvmAdapter(opts);
}
