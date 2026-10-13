/**
 * Solana adapter. Addresses are base58 ed25519 public keys; reads go over
 * JSON-RPC. Public token balances are explicit mint reads; signing remains
 * restricted to the core's supported transaction forms.
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
const SafeSlot = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const SolAddress = z.string().max(44).refine(isValidSolanaAddress);
const TokenAmount = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/)
  .refine((s) => BigInt(s) <= 0xffffffffffffffffn);
export const SPL_TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const SPL_TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const TrackedSolanaToken = z.object({
  chainId: z.string().regex(/^solana:[1-9A-HJ-NP-Za-km-z]{32}$/),
  address: SolAddress,
  symbol: z.string().regex(/^[\x20-\x7e]{1,12}$/),
  decimals: z.number().int().min(0).max(36),
  programId: z.enum([SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM]),
});
export type TrackedSolanaToken = z.infer<typeof TrackedSolanaToken>;
const MintResult = z.object({
  context: z.object({ slot: SafeSlot }),
  value: z
    .object({
      executable: z.literal(false),
      owner: z.enum([SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM]),
      data: z.object({
        parsed: z.object({
          type: z.literal('mint'),
          info: z.object({
            decimals: z.number().int().min(0).max(36),
            isInitialized: z.literal(true),
            supply: TokenAmount,
          }),
        }),
      }),
    })
    .nullable(),
});
const TokenAccounts = z.object({
  context: z.object({ slot: SafeSlot }),
  value: z
    .array(
      z.object({
        pubkey: SolAddress,
        account: z.object({
          executable: z.literal(false),
          owner: z.enum([SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM]),
          data: z.object({
            parsed: z.object({
              type: z.literal('account'),
              info: z.object({
                mint: SolAddress,
                owner: SolAddress,
                state: z.enum(['initialized', 'frozen']),
                tokenAmount: z.object({
                  amount: TokenAmount,
                  decimals: z.number().int().min(0).max(36),
                }),
              }),
            }),
          }),
        }),
      }),
    )
    .max(1024),
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

async function mintInfo(rpc: ClusterRpc, mint: string) {
  SolAddress.parse(mint);
  const result = await rpc(
    'getAccountInfo',
    [mint, { commitment: 'confirmed', encoding: 'jsonParsed' }],
    MintResult,
  );
  if (!result.value) throw new Error('Token mint does not exist on this cluster');
  return {
    programId: result.value.owner,
    decimals: result.value.data.parsed.info.decimals,
    slot: result.context.slot,
  };
}
export async function solanaTokenInfo(adapter: SolanaAdapter, chainId: string, mint: string) {
  return adapter.withCluster(chainId, (rpc) => mintInfo(rpc, mint));
}

export class SolanaAdapter extends BaseAdapter<'solana'> {
  private trackedTokens: TrackedSolanaToken[] = [];
  setTrackedTokens(tokens: TrackedSolanaToken[]): void {
    this.trackedTokens = z.array(TrackedSolanaToken).max(100).parse(tokens);
  }
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
    const tokens: Holding[] = [];
    for (const token of this.trackedTokens.filter((t) => t.chainId === chainId)) {
      const assetRef = `${chainId}:spl:${token.address}`;
      const metadata = { symbol: token.symbol, decimals: token.decimals };
      const notice =
        'Public token-account balance only; frozen, withheld or confidential amounts may restrict spendability. Token transfers are not enabled.';
      try {
        const observed = await withCrossCheck(
          this.rpc,
          chainId,
          async (url) => {
            const rpc: ClusterRpc = (method, params, schema) =>
              this.jsonRpc(method, params, schema)(url);
            const genesis = await rpc('getGenesisHash', [], SolAddress);
            if (`solana:${genesis.slice(0, 32)}` !== chainId)
              throw new Error('RPC genesis hash does not match this Solana cluster');
            const mint = await mintInfo(rpc, token.address);
            if (mint.programId !== token.programId || mint.decimals !== token.decimals)
              throw new Error('Mint program or decimals changed; retrack this token');
            const accounts = await rpc(
              'getTokenAccountsByOwner',
              [
                addr,
                { mint: token.address },
                { commitment: 'confirmed', encoding: 'jsonParsed', minContextSlot: mint.slot },
              ],
              TokenAccounts,
            );
            if (accounts.context.slot < mint.slot)
              throw new Error('Token balance observation predates mint observation');
            const seen = new Set<string>();
            let sum = 0n;
            for (const entry of accounts.value) {
              const info = entry.account.data.parsed.info;
              if (
                seen.has(entry.pubkey) ||
                entry.account.owner !== token.programId ||
                info.owner !== addr ||
                info.mint !== token.address ||
                info.tokenAmount.decimals !== token.decimals
              )
                throw new Error('Token account identity, program or decimals differ');
              seen.add(entry.pubkey);
              sum += BigInt(info.tokenAmount.amount);
            }
            if (sum > 0xffffffffffffffffn) throw new Error('Token account sum exceeds u64 bounds');
            this.noteBlock(url, accounts.context.slot);
            return sum.toString();
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
