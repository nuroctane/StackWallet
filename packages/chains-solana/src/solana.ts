/**
 * Solana adapter. Addresses are base58 ed25519 public keys; reads go over
 * JSON-RPC. Versioned transaction assembly, lookup tables and SPL token
 * handling arrive with @solana/kit in a later phase.
 */
import { base58 } from '@scure/base';
import {
  MemoryRpcPool,
  NotImplementedError,
  UnknownChainError,
  UnsupportedKeyError,
  chainsForFamily,
  fetchJsonRpc,
  publicKeyBytes,
  requireCurve,
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

export function isValidSolanaAddress(addr: string): boolean {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr)) return false;
  try {
    return base58.decode(addr).length === 32;
  } catch {
    return false;
  }
}

// Lamport balances come back as JSON numbers; values beyond 2^53 would lose
// precision in JSON.parse itself, which is acceptable for a single account.
const BalanceResult = z.object({
  context: z.object({ slot: z.number().int() }),
  value: z.number().int().nonnegative(),
});

const SignatureStatuses = z.object({
  value: z.array(
    z
      .object({
        slot: z.number().int(),
        confirmations: z.number().int().nullable(),
        err: z.unknown().nullable(),
        confirmationStatus: z.enum(['processed', 'confirmed', 'finalized']).nullable().optional(),
      })
      .nullable(),
  ),
});

export interface SolanaAdapterOptions {
  rpc?: RpcPool;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export class SolanaAdapter implements ChainAdapter {
  readonly family = 'solana' as const;
  readonly rpc: RpcPool;
  private readonly fetchImpl: typeof fetch | undefined;
  private readonly timeoutMs: number | undefined;

  constructor(opts: SolanaAdapterOptions = {}) {
    this.rpc = opts.rpc ?? new MemoryRpcPool(chainsForFamily('solana'));
    this.fetchImpl = opts.fetch;
    this.timeoutMs = opts.timeoutMs;
  }

  chains(): ChainInfo[] {
    return chainsForFamily('solana');
  }

  private chain(chainId: ChainId): ChainInfo {
    const c = this.chains().find((x) => x.chainId === chainId);
    if (!c) throw new UnknownChainError(chainId);
    return c;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.chain(chainId);
    requireCurve(pub, 'ed25519');
    const bytes = publicKeyBytes(pub);
    if (bytes.length !== 32) throw new UnsupportedKeyError('ed25519 public key must be 32 bytes');
    return base58.encode(bytes);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.chain(chainId);
    return isValidSolanaAddress(addr);
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
    if (!isValidSolanaAddress(addr)) throw new TypeError(`invalid solana address ${addr}`);
    const res = await this.call(
      chainId,
      'getBalance',
      [addr, { commitment: 'confirmed' }],
      BalanceResult,
    );
    return [
      {
        assetRef: chain.nativeAsset.ref,
        amount: BigInt(res.value).toString(),
        updatedAtMs: Date.now(),
      },
    ];
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.chain(chainId);
    const res = await this.call(
      chainId,
      'getSignatureStatuses',
      [[hash], { searchTransactionHistory: true }],
      SignatureStatuses,
    );
    const entry = res.value[0];
    if (!entry) return { state: 'unknown' };
    if (entry.err !== null && entry.err !== undefined) {
      return { state: 'failed', reason: JSON.stringify(entry.err).slice(0, 512) };
    }
    const level =
      entry.confirmationStatus ?? (entry.confirmations === null ? 'finalized' : 'confirmed');
    if (level === 'processed') return { state: 'pending' };
    return { state: 'confirmed', blockNumber: entry.slot };
  }

  getHistory(_addr: Address, _chainId: ChainId, _cursor?: string): Promise<Page<TxRecord>> {
    return Promise.reject(new NotImplementedError('chains-solana.getHistory', 'phase 4'));
  }

  build(_intent: TxIntent, _chainId: ChainId): Promise<UnsignedTx> {
    return Promise.reject(new NotImplementedError('chains-solana.build', 'phase 4'));
  }

  simulate(_tx: UnsignedTx): Promise<Simulation> {
    return Promise.reject(new NotImplementedError('chains-solana.simulate', 'phase 4'));
  }

  sighashes(_tx: UnsignedTx): SignRequest[] {
    throw new NotImplementedError('chains-solana.sighashes', 'phase 4');
  }

  attach(_tx: UnsignedTx, _sigs: Signature[]): SignedTx {
    throw new NotImplementedError('chains-solana.attach', 'phase 4');
  }

  broadcast(_tx: SignedTx): Promise<TxHash> {
    return Promise.reject(new NotImplementedError('chains-solana.broadcast', 'phase 4'));
  }
}

export function createSolanaAdapter(opts?: SolanaAdapterOptions): SolanaAdapter {
  return new SolanaAdapter(opts);
}
