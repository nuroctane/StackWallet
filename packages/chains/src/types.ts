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

/**
 * Family-specific facts an adapter needs for offline work (address derivation
 * and validation). Every key is optional so one schema serves all families.
 */
export const ChainExtra = z.object({
  /** Cosmos account prefix or Bitcoin segwit human-readable part. */
  bech32Prefix: z.string().optional(),
  /** SLIP-44 coin type used by the chain's wallets. */
  coinType: z.number().int().nonnegative().optional(),
  /** Cosmos: how a secp256k1 public key becomes an account address. */
  addressAlgo: z.enum(['secp256k1', 'ethsecp256k1']).optional(),
  /** Cosmos base denom of the native asset, e.g. `uatom`. */
  baseDenom: z.string().optional(),
  /** Cosmos suggested gas price as `<amount><denom>`, e.g. `0.025uatom`. */
  gasPrice: z.string().optional(),
  /** Bitcoin family base58check version bytes. */
  p2pkhVersion: z.number().int().min(0).max(255).optional(),
  p2shVersion: z.number().int().min(0).max(255).optional(),
  /** Bitcoin family: whether bech32 segwit addresses are valid on this network. */
  segwit: z.boolean().optional(),
});
export type ChainExtra = z.infer<typeof ChainExtra>;

export const ChainInfo = z.object({
  chainId: z.string(),
  family: z.enum(['evm', 'bitcoin', 'solana', 'cosmos']),
  name: z.string(),
  nativeAsset: z.object({ ref: z.string(), symbol: z.string(), decimals: z.number().int() }),
  testnet: z.boolean().default(false),
  /** Explorer link template with a `{hash}` placeholder. */
  explorerTxUrl: z.string().optional(),
  /** JSON-RPC urls for evm/solana; REST base urls for bitcoin (mempool API) and cosmos (LCD). */
  defaultRpcs: z.array(z.string().url()).default([]),
  extra: ChainExtra.optional(),
});
export type ChainInfo = z.infer<typeof ChainInfo>;

/**
 * Where a balance came from. A malicious or lagging endpoint can lie, so
 * adapters ask a second endpoint when one is available and report whether the
 * two agreed; the UI shows anything short of `agreed` as unverified.
 */
export type HoldingProvenance =
  | { kind: 'single'; endpoint: string }
  | { kind: 'agreed'; endpoints: [string, string] }
  | { kind: 'disagreed'; endpoints: [string, string]; other: Amount };

export interface Holding {
  assetRef: AssetRef;
  amount: Amount;
  updatedAtMs: number;
  provenance?: HoldingProvenance;
  /** Token metadata is untrusted display data; the contract address remains the identity. */
  metadata?: { symbol: string; decimals: number };
  error?: string;
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
  /** Rolling failure share over the most recent attempts, 0..1. */
  errorRate?: number;
  /** Chain head the endpoint last reported, when the adapter asked for one. */
  lastBlock?: number;
  /** True for endpoints the user added or edited rather than catalog defaults. */
  custom?: boolean;
}

export interface RpcPool {
  endpoints(chainId: ChainId): RpcEndpoint[];
  setEndpoints(chainId: ChainId, urls: string[]): void;
}

export interface ChainAdapter {
  readonly family: ChainFamily;
  chains(): ChainInfo[];
  deriveAddress(pub: PublicKey, chainId: ChainId): Address;
  /** Syntactic + checksum validation only; never touches the network. */
  validateAddress(addr: string, chainId: ChainId): boolean;
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
