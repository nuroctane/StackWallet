import type {
  ChainAdapter,
  ChainRegistry,
  Holding,
  Simulation,
  TxStatus,
} from '@stackwallet/chains';
import type { Account, ChainFamily, LedgerUnsignedTx, TxIntent } from '@stackwallet/core-client';

/**
 * The send path of a family that signs through the core with one plain transfer shape.
 * Older families keep their bespoke branches in `txs.ts` (EVM replacement, Bitcoin coin
 * selection, Solana ceremonies); everything newer plugs in here.
 */
export interface FamilySend {
  family: ChainFamily;
  /** A required field only this family's unsigned transaction carries (its base unit). */
  unit: string;
  /** Networks the core signs on; everything else in the family is receive-only. */
  signingChains: readonly string[];
  /**
   * Recognises this family's unsigned transactions when `unit` alone cannot (a family
   * with a second transaction shape, such as an account registration).
   */
  matches?(unsigned: object): boolean;
  /**
   * A one-time on-chain step an account needs before it can transact (Chromia's FT4
   * registration). It is proposed as a zero-amount native transfer to the account
   * itself, which `prepare` recognises and the core binds to the registration body.
   */
  activation?: {
    /** Verb shown on the account row. */
    label: string;
    title: string;
    /** Whether the native holding reports the step as still pending. */
    needed(holding: Holding): boolean;
    /** Toast once the proposal sits in the approval queue. */
    proposed: string;
  };
  prepare(
    adapter: ChainAdapter,
    intent: TxIntent,
    account: Account,
    options: { tag?: string },
  ): Promise<{ unsigned: LedgerUnsignedTx; simulation: Simulation }>;
  /** False once the prepared transaction can no longer land (expiry, sequence, object versions). */
  approvalValid?(adapter: ChainAdapter, unsigned: object): Promise<boolean>;
  /** Shown when approval or polling finds the transaction expired. */
  expiredReason: string;
  broadcast(adapter: ChainAdapter, unsigned: object, raw: string): Promise<string>;
  status(
    adapter: ChainAdapter,
    unsigned: object,
    hash: string,
  ): Promise<TxStatus | { state: 'expired' }>;
  /** Base58/base64 hashes compare exactly; hex hashes ignore case. */
  hashCaseSensitive?: boolean;
  form: {
    validate(to: string, chainId: string): boolean;
    /** Canonical form of a valid destination (case, padding) before it enters the intent. */
    normalize?(to: string): string;
    invalid: string;
    /** An optional routing field the recipient may need (an exchange's destination tag). */
    tag?: {
      label: string;
      placeholder: string;
      validate(tag: string): boolean;
      invalid: string;
      /** Keyboard hint for touch devices; defaults to text since several families carry free-form memos. */
      inputMode?: 'numeric' | 'text';
    };
    placeholder: string;
    /** Largest amount in base units the family's encoding carries. */
    maxUnits: bigint;
    note: string;
  };
}

const registered: FamilySend[] = [];

export function registerFamilySend(entry: FamilySend): void {
  if (registered.some((r) => r.family === entry.family || r.unit === entry.unit))
    throw new Error(`Family send for ${entry.family} is already registered`);
  registered.push(entry);
}

export function familySendFor(account: Pick<Account, 'family'>): FamilySend | undefined {
  return registered.find((r) => r.family === account.family);
}

export function familySendOf(unsigned: unknown): FamilySend | undefined {
  if (!unsigned || typeof unsigned !== 'object') return undefined;
  return registered.find((r) => r.unit in unsigned || r.matches?.(unsigned) === true);
}

/** Whether an intent is the self-addressed zero transfer that proposes an activation step. */
export function isActivationIntent(
  intent: Pick<TxIntent, 'kind' | 'chainId'> & { to?: string; amount?: string; asset?: string },
  account: Pick<Account, 'address' | 'chainId'>,
): boolean {
  return (
    intent.kind === 'transfer' &&
    intent.to === account.address &&
    intent.amount === '0' &&
    intent.asset === `${account.chainId}:native`
  );
}

export function familyAdapter(
  registry: ChainRegistry,
  entry: FamilySend,
  chainId: string,
): ChainAdapter {
  const a = registry.adapterFor(chainId);
  if (a.family !== entry.family) throw new Error(`${chainId} is not a ${entry.family} network`);
  return a;
}
