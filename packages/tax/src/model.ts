import type { TxRecord } from '@stackwallet/chains';
import { z } from 'zod';

import type { CostMethod, Fiat, Term } from './jurisdictions.js';

/**
 * Labels follow the vocabulary of the tools people import into (CoinTracker,
 * Blockpit, Koinly), so an exported row means the same thing on arrival.
 * `receive` and `send` are the unreviewed defaults: they are treated as an
 * acquisition and a disposal at market value until the user says otherwise.
 */
export const LABELS = [
  'receive',
  'income',
  'staking',
  'airdrop',
  'mining',
  'gift-in',
  'transfer-in',
  'send',
  'payment',
  'gift-out',
  'transfer-out',
  'lost',
  'trade',
  'self',
  'fee',
  'spam',
] as const;
export const Label = z.enum(LABELS);
export type Label = z.infer<typeof Label>;

export const INBOUND_LABELS: readonly Label[] = [
  'receive',
  'income',
  'staking',
  'airdrop',
  'mining',
  'gift-in',
  'transfer-in',
  'spam',
];
export const OUTBOUND_LABELS: readonly Label[] = [
  'send',
  'payment',
  'gift-out',
  'transfer-out',
  'lost',
  'spam',
];
export const INCOME_LABELS: ReadonlySet<Label> = new Set([
  'income',
  'staking',
  'airdrop',
  'mining',
]);

export const LABEL_TEXT: Readonly<Record<Label, string>> = {
  receive: 'Received',
  income: 'Income',
  staking: 'Staking reward',
  airdrop: 'Airdrop',
  mining: 'Mining reward',
  'gift-in': 'Gift received',
  'transfer-in': 'From my other account',
  send: 'Sent',
  payment: 'Payment / sale',
  'gift-out': 'Gift sent',
  'transfer-out': 'To my other account',
  lost: 'Lost or stolen',
  trade: 'Trade',
  self: 'Between my wallets',
  fee: 'Network fee',
  spam: 'Spam · ignore',
};

export const LABEL_HELP: Readonly<Record<Label, string>> = {
  receive: 'Not reviewed. Counted as buying the coins at market value.',
  income: 'Taxable income at market value on receipt; that value becomes the cost basis.',
  staking: 'Income at market value on receipt; that value becomes the cost basis.',
  airdrop: 'Income at market value on receipt; that value becomes the cost basis.',
  mining: 'Income at market value on receipt; that value becomes the cost basis.',
  'gift-in': 'Not income. Enter the giver’s cost and date if you know them.',
  'transfer-in':
    'Not taxable. Coins arriving from an exchange or wallet outside StackWallet: enter what you originally paid, or the basis is reported missing.',
  send: 'Not reviewed. Counted as selling the coins at market value.',
  payment: 'A sale at market value: you paid for something or sold for cash.',
  'gift-out': 'Not a sale. The coins and their basis leave your books.',
  'transfer-out': 'Not taxable. The coins and their basis move to an account outside StackWallet.',
  lost: 'Not a sale. The coins leave your books with no proceeds.',
  trade: 'Swap: the coins given are sold for the market value of the coins received.',
  self: 'Between two StackWallet accounts. Not taxable; basis and dates move with the coins.',
  fee: 'Only a network fee was paid.',
  spam: 'Left out of every calculation and export.',
};

/** One account the report covers, with what is known about its wallet. */
export interface ScopeAccount {
  accountId: string;
  walletId: string;
  walletName: string;
  walletKind: string;
  folderPath: string;
  chainId: string;
  chainName: string;
  address: string;
  testnet: boolean;
}

export interface AccountHistory {
  accountId: string;
  records: readonly TxRecord[];
  /** False when paging stopped early or a read failed: older activity may be missing. */
  complete: boolean;
  sources: readonly string[];
  error?: string | undefined;
  /** Balances observed right after the history was read, to check it adds up. */
  balances?: readonly { assetRef: string; amount: string }[] | undefined;
  balancesAtMs?: number | undefined;
}

export interface AssetInfo {
  ref: string;
  symbol: string;
  /** Null when the token's decimals are unknown; such amounts stay in base units. */
  decimals: number | null;
  /** Price key: a CoinGecko coin id, or `platform/contract` for a token. Null when unpriceable. */
  priceKey: string | null;
  testnet: boolean;
}

export interface PricePoint {
  t: number;
  v: number;
}

/** Price series per price key in the report fiat, ascending by time. */
export type PriceBook = ReadonlyMap<string, readonly PricePoint[]>;

const Decimal = z.string().regex(/^\d{1,30}(\.\d{1,18})?$/);

/** The user's decisions about one event. Kept per event id on this device. */
export const EventOverride = z.object({
  label: Label.optional(),
  note: z.string().max(500).optional(),
  /** Fiat value of the whole event (what was received, or what was given). */
  value: Decimal.optional(),
  /** Original cost for `transfer-in` and `gift-in`, in report fiat. */
  basis: Decimal.optional(),
  /** Original acquisition time for `transfer-in` and `gift-in`. */
  acquiredAtMs: z.number().int().nonnegative().optional(),
});
export type EventOverride = z.infer<typeof EventOverride>;
export const Overrides = z.record(z.string().max(300), EventOverride);
export type Overrides = z.infer<typeof Overrides>;

export type Pooling = 'wallet' | 'universal';
export type FeeTreatment = 'dispose' | 'ignore';

export interface TaxSettings {
  jurisdiction: string;
  method: CostMethod;
  fiat: Fiat;
  pooling: Pooling;
  fees: FeeTreatment;
  year: number;
  includeTestnets: boolean;
}

export interface Leg {
  accountId: string;
  walletId: string;
  assetRef: string;
  /** Signed base units, excluding any fee. */
  amount: bigint;
}

export interface TaxEvent {
  id: string;
  chainId: string;
  hash: string;
  timestampMs: number | null;
  status: 'pending' | 'confirmed' | 'failed';
  /** The label in force: the user's override, else the automatic one. */
  label: Label;
  auto: Label;
  reviewed: boolean;
  legs: Leg[];
  /** Movements between two accounts in scope, per asset. */
  moves: { assetRef: string; fromAccountId: string; toAccountId: string; amount: bigint }[];
  fee: { accountId: string; walletId: string; assetRef: string; amount: bigint } | null;
  feeUnknown: boolean;
  counterparty: string | null;
  note: string;
  override: EventOverride | undefined;
}

export interface Lot {
  id: string;
  pool: string;
  walletId: string;
  assetRef: string;
  amount: bigint;
  /** Remaining basis in fiat micros, or null when it cannot be proven. */
  cost: bigint | null;
  acquiredAtMs: number;
  eventId: string;
}

export interface Disposal {
  id: string;
  eventId: string;
  label: Label;
  walletId: string;
  assetRef: string;
  amount: bigint;
  acquiredAtMs: number | null;
  disposedAtMs: number;
  proceeds: bigint | null;
  cost: bigint | null;
  gain: bigint | null;
  term: Term | null;
  lotId: string | null;
  hash: string;
  chainId: string;
  /** Coins that left the books without a sale (gift, own account elsewhere, lost, ignored fee). */
  removal: boolean;
}

export interface IncomeItem {
  eventId: string;
  label: Label;
  walletId: string;
  assetRef: string;
  amount: bigint;
  atMs: number;
  value: bigint | null;
  hash: string;
  chainId: string;
}

export type IssueCode =
  | 'unreviewed'
  | 'missing-price'
  | 'missing-basis'
  | 'unknown-fee'
  | 'unknown-decimals'
  | 'history-incomplete'
  | 'history-error'
  | 'balance-mismatch'
  | 'pending'
  | 'no-timestamp'
  | 'method-approximation';

export interface Issue {
  code: IssueCode;
  severity: 'blocker' | 'warn' | 'info';
  message: string;
  eventId?: string;
  accountId?: string;
}

export interface Summary {
  fiat: Fiat;
  proceeds: bigint;
  cost: bigint;
  gain: bigint;
  byTerm: Partial<Record<Term, { proceeds: bigint; cost: bigint; gain: bigint; count: number }>>;
  income: bigint;
  incomeByLabel: Partial<Record<Label, bigint>>;
  fees: bigint;
  disposals: number;
  unknownBasisDisposals: number;
  /** Part of `proceeds` from disposals whose basis is unknown, so with no gain or term yet. */
  unknownBasisProceeds: bigint;
  unpricedDisposals: number;
  events: number;
  reviewed: number;
}

export interface Holding {
  walletId: string;
  assetRef: string;
  amount: bigint;
  cost: bigint | null;
  value: bigint | null;
  earliestAtMs: number | null;
  lots: number;
}

export interface Readiness {
  /** 0–1 per dimension; `score` is their minimum so one gap cannot hide behind the rest. */
  history: number;
  reviewed: number;
  priced: number;
  basis: number;
  score: number;
}

export interface TaxReport {
  settings: TaxSettings;
  period: { startMs: number; endMs: number; label: string };
  events: TaxEvent[];
  /** Fiat value of each processed event, or null when it could not be priced. */
  values: ReadonlyMap<string, bigint | null>;
  disposals: Disposal[];
  income: IncomeItem[];
  holdings: Holding[];
  issues: Issue[];
  summary: Summary;
  readiness: Readiness;
}
