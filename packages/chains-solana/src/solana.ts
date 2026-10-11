/**
 * Solana adapter. Addresses are base58 ed25519 public keys; reads go over
 * JSON-RPC. Versioned transaction assembly, lookup tables and SPL token
 * handling arrive with @solana/kit in a later phase.
 */
import { base58 } from '@scure/base';
import {
  BaseAdapter,
  UnsupportedKeyError,
  nativeHolding,
  publicKeyBytes,
  requireCurve,
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

export function isValidSolanaAddress(addr: string): boolean {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr)) return false;
  try {
    return base58.decode(addr).length === 32;
  } catch {
    return false;
  }
}

// Unsafe JSON numbers cannot become trustworthy base-unit amounts after parsing.
const BalanceResult = z.object({
  context: z.object({ slot: z.number().int() }),
  value: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
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

export type SolanaAdapterOptions = BaseAdapterOptions;
type ClusterRpc = <T>(method: string, params: unknown[], schema: z.ZodType<T>) => Promise<T>;

export class SolanaAdapter extends BaseAdapter<'solana'> {
  constructor(opts: SolanaAdapterOptions = {}) {
    super('solana', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    const bytes = publicKeyBytes(pub);
    if (bytes.length !== 32) throw new UnsupportedKeyError('ed25519 public key must be 32 bytes');
    return base58.encode(bytes);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidSolanaAddress(addr);
  }

  private call<T>(
    chainId: ChainId,
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): Promise<T> {
    return withFailover(this.rpc, chainId, this.jsonRpc(method, params, schema));
  }

  /** Verify the endpoint's cluster before a signing-flow RPC touches it. */
  clusterCall<T>(
    chainId: ChainId,
    method: string,
    params: unknown[],
    schema: z.ZodType<T>,
  ): Promise<T> {
    return this.withCluster(chainId, (rpc) => rpc(method, params, schema));
  }

  /** Keep dependent observations on one verified endpoint during failover. */
  withCluster<T>(chainId: ChainId, query: (rpc: ClusterRpc) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      const genesis = await this.jsonRpc('getGenesisHash', [], z.string().max(44))(url);
      if (!isValidSolanaAddress(genesis) || `solana:${genesis.slice(0, 32)}` !== chainId)
        throw new Error('RPC genesis hash does not match this Solana cluster');
      return query((method, params, schema) => this.jsonRpc(method, params, schema)(url));
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidSolanaAddress(addr)) throw new TypeError(`invalid solana address ${addr}`);
    const getBalance = this.jsonRpc(
      'getBalance',
      [addr, { commitment: 'confirmed' }],
      BalanceResult,
    );
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        const res = await getBalance(url);
        // getBalance carries the slot it was evaluated at, so the head comes for free.
        this.noteBlock(url, res.context.slot);
        return BigInt(res.value).toString();
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.requireChain(chainId);
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
}

export function createSolanaAdapter(opts?: SolanaAdapterOptions): SolanaAdapter {
  return new SolanaAdapter(opts);
}
