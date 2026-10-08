/**
 * The adapter contract from `docs/CHAINS.md`. Adapters receive public keys
 * and signatures and return unsigned/signed transactions; they never see a
 * private key or a share.
 */
import { z } from 'zod';
import type {
  Amount,
  AssetRef,
  ChainFamily,
  ChainId,
  PublicKey,
  Signature,
  SignRequest,
  TxIntent,
} from '@stackwallet/core-client';

export type Address = string;
export type TxHash = string;

export const ChainInfo = z.object({
  chainId: z.string(),
  family: z.enum(['evm', 'bitcoin', 'solana', 'cosmos']),
  name: z.string(),
  nativeAsset: z.object({ ref: z.string(), symbol: z.string(), decimals: z.number().int() }),
  testnet: z.boolean().default(false),
  explorerTxUrl: z.string().optional(),
  defaultRpcs: z.array(z.string().url()).default([]),
});
export type ChainInfo = z.infer<typeof ChainInfo>;

export interface Holding {
  assetRef: AssetRef;
  amount: Amount;
  updatedAtMs: number;
}

export interface TxRecord {
  hash: TxHash;
  chainId: ChainId;
  blockNumber?: number;
  timestampMs?: number;
  from: Address;
  to?: Address;
  assetDeltas: AssetDelta[];
  feeAssetRef: AssetRef;
  fee: Amount;
  status: 'pending' | 'confirmed' | 'failed';
}

export interface Page<T> {
  items: T[];
  nextCursor?: string;
}

/** Signed base-unit amount as a decimal string with optional leading `-`. */
export interface AssetDelta {
  assetRef: AssetRef;
  amount: string;
}

export type SimulationWarning =
  | { kind: 'approvalGranted'; spender: Address; assetRef: AssetRef; amount: Amount | 'unlimited' }
  | { kind: 'contractUnverified'; address: Address }
  | { kind: 'destinationIsContract'; address: Address }
  | { kind: 'tokenHasTransferFee'; assetRef: AssetRef; bps: number }
  | { kind: 'tokenHasTransferHook'; assetRef: AssetRef }
  | { kind: 'highFee'; feeUsdMicros: number }
  | { kind: 'other'; message: string };

export interface Simulation {
  ok: boolean;
  assetDeltas: AssetDelta[];
  fee: { assetRef: AssetRef; amount: Amount };
  warnings: SimulationWarning[];
  error?: string;
}

/** Opaque, adapter-specific. Serialized into `tx.unsigned_json`. */
export interface UnsignedTx {
  chainId: ChainId;
  family: ChainFamily;
  intentId: string;
  payload: unknown;
}

export interface SignedTx extends UnsignedTx {
  signatures: Signature[];
  rawHex: string;
}

export type TxStatus =
  | { state: 'pending' }
  | { state: 'confirmed'; blockNumber: number; timestampMs?: number }
  | { state: 'failed'; reason?: string }
  | { state: 'replaced'; byHash: TxHash }
  | { state: 'dropped' }
  | { state: 'unknown' };

export interface RpcEndpoint {
  url: string;
  healthy: boolean;
  latencyMs?: number;
  lastErrorAtMs?: number;
}

export interface RpcPool {
  endpoints(chainId: ChainId): RpcEndpoint[];
  setEndpoints(chainId: ChainId, urls: string[]): void;
}

export interface ChainAdapter {
  readonly family: ChainFamily;
  chains(): ChainInfo[];
  deriveAddress(pub: PublicKey, chainId: ChainId): Address;
  getBalances(addr: Address, chainId: ChainId): Promise<Holding[]>;
  getHistory(addr: Address, chainId: ChainId, cursor?: string): Promise<Page<TxRecord>>;
  build(intent: TxIntent, chainId: ChainId): Promise<UnsignedTx>;
  simulate(tx: UnsignedTx): Promise<Simulation>;
  sighashes(tx: UnsignedTx): SignRequest[];
  attach(tx: UnsignedTx, sigs: Signature[]): SignedTx;
  broadcast(tx: SignedTx): Promise<TxHash>;
  status(hash: TxHash, chainId: ChainId): Promise<TxStatus>;
  readonly rpc: RpcPool;
}
