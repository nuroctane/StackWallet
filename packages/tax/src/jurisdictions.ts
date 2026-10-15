/**
 * Holding-period and method defaults per tax residence. These are the
 * mechanical rules a ledger can apply (how long a lot was held, which year a
 * date falls in, which matching method is customary); rates, allowances and
 * personal circumstances stay with the filer and their adviser. Every profile
 * says what it does not model so the report never implies more than it did.
 */

export type CostMethod = 'fifo' | 'lifo' | 'hifo' | 'acb';
export type Fiat = 'usd' | 'eur' | 'gbp' | 'chf' | 'cad' | 'aud' | 'czk';
export type Term = 'short' | 'long' | 'exempt' | 'taxable' | 'discount';

export const FIATS: readonly Fiat[] = ['usd', 'eur', 'gbp', 'chf', 'cad', 'aud', 'czk'];

export const FIAT_SYMBOL: Readonly<Record<Fiat, string>> = {
  usd: '$',
  eur: '€',
  gbp: '£',
  chf: 'CHF ',
  cad: 'C$',
  aud: 'A$',
  czk: 'Kč ',
};

export const METHOD_LABEL: Readonly<Record<CostMethod, string>> = {
  fifo: 'FIFO · first in, first out',
  lifo: 'LIFO · last in, first out',
  hifo: 'HIFO · highest cost first',
  acb: 'Average cost (pooled)',
};

export interface Jurisdiction {
  id: string;
  name: string;
  fiat: Fiat;
  method: CostMethod;
  /** Methods the profile allows the user to pick. */
  methods: readonly CostMethod[];
  /** First day of the tax year (UTC), month 1–12. */
  yearStart: { month: number; day: number };
  /** How a disposal is classed from its holding period. */
  term: (acquiredAtMs: number, disposedAtMs: number) => Term;
  /** Short words for the terms this profile produces, in display order. */
  terms: readonly Term[];
  /** Plain-language notes shown with every report and written into every export. */
  notes: readonly string[];
}

/** The same calendar date `years` later, clamped for 29 February. */
export function addYearsUtc(ms: number, years: number): number {
  const d = new Date(ms);
  const y = d.getUTCFullYear() + years;
  const m = d.getUTCMonth();
  const last = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  return Date.UTC(
    y,
    m,
    Math.min(d.getUTCDate(), last),
    d.getUTCHours(),
    d.getUTCMinutes(),
    d.getUTCSeconds(),
    d.getUTCMilliseconds(),
  );
}

const heldMoreThan = (years: number) => (acq: number, disp: number) =>
  disp > addYearsUtc(acq, years);

const AT_NEW_REGIME_MS = Date.UTC(2021, 2, 1);

export const JURISDICTIONS: readonly Jurisdiction[] = [
  {
    id: 'us',
    name: 'United States',
    fiat: 'usd',
    method: 'fifo',
    methods: ['fifo', 'lifo', 'hifo'],
    yearStart: { month: 1, day: 1 },
    term: (a, d) => (heldMoreThan(1)(a, d) ? 'long' : 'short'),
    terms: ['short', 'long'],
    notes: [
      'Long-term means held more than one year. Per-wallet cost basis matches the IRS rule in force since 1 January 2025.',
      'Broker Forms 1099-DA report gross proceeds; basis for coins that moved through self-custody is often missing there. This report shows the basis this device can prove from on-chain history.',
      'Specific identification needs a standing order made before each sale; FIFO is the default when none exists.',
    ],
  },
  {
    id: 'de',
    name: 'Germany',
    fiat: 'eur',
    method: 'fifo',
    methods: ['fifo'],
    yearStart: { month: 1, day: 1 },
    term: (a, d) => (heldMoreThan(1)(a, d) ? 'exempt' : 'taxable'),
    terms: ['taxable', 'exempt'],
    notes: [
      'Private sales (§ 23 EStG): coins held more than one year are tax-free. Gains below the annual exemption limit (Freigrenze) are untaxed only if the total stays below it.',
      'Staking and other income follow their own rules and are listed separately.',
    ],
  },
  {
    id: 'at',
    name: 'Austria',
    fiat: 'eur',
    method: 'fifo',
    methods: ['fifo', 'acb'],
    yearStart: { month: 1, day: 1 },
    term: (a, d) =>
      a >= AT_NEW_REGIME_MS ? 'taxable' : heldMoreThan(1)(a, d) ? 'exempt' : 'taxable',
    terms: ['taxable', 'exempt'],
    notes: [
      'Coins acquired from 1 March 2021 are taxed on every disposal; older coins held more than one year are exempt.',
      'Crypto-to-crypto swaps are not taxable events under Austrian rules; this report still lists them as disposals for review.',
    ],
  },
  {
    id: 'pt',
    name: 'Portugal',
    fiat: 'eur',
    method: 'fifo',
    methods: ['fifo'],
    yearStart: { month: 1, day: 1 },
    term: (a, d) => (d - a >= 365 * 86_400_000 ? 'exempt' : 'taxable'),
    terms: ['taxable', 'exempt'],
    notes: ['Gains on coins held at least 365 days are excluded for residents.'],
  },
  {
    id: 'cz',
    name: 'Czech Republic',
    fiat: 'czk',
    method: 'fifo',
    methods: ['fifo', 'acb'],
    yearStart: { month: 1, day: 1 },
    term: (a, d) => (heldMoreThan(3)(a, d) ? 'exempt' : 'taxable'),
    terms: ['taxable', 'exempt'],
    notes: [
      'Coins held more than three years are exempt; a small annual gross-income exemption may also apply.',
    ],
  },
  {
    id: 'ch',
    name: 'Switzerland',
    fiat: 'chf',
    method: 'fifo',
    methods: ['fifo', 'acb'],
    yearStart: { month: 1, day: 1 },
    term: () => 'exempt',
    terms: ['exempt'],
    notes: [
      'Private capital gains are tax-free for private investors; professional traders are taxed differently.',
      'Wealth tax uses the year-end holdings sheet. Staking rewards are income.',
    ],
  },
  {
    id: 'uk',
    name: 'United Kingdom',
    fiat: 'gbp',
    method: 'acb',
    methods: ['acb'],
    yearStart: { month: 4, day: 6 },
    term: () => 'taxable',
    terms: ['taxable'],
    notes: [
      'Section 104 pooling is approximated by pooled average cost. The same-day and 30-day matching rules are not applied; review disposals with a repurchase within 30 days.',
      'The tax year runs from 6 April to 5 April.',
    ],
  },
  {
    id: 'ca',
    name: 'Canada',
    fiat: 'cad',
    method: 'acb',
    methods: ['acb'],
    yearStart: { month: 1, day: 1 },
    term: () => 'taxable',
    terms: ['taxable'],
    notes: [
      'Adjusted cost base (average cost). Superficial-loss rules are not applied. Business income treatment is not modelled.',
    ],
  },
  {
    id: 'au',
    name: 'Australia',
    fiat: 'aud',
    method: 'fifo',
    methods: ['fifo', 'lifo', 'hifo'],
    yearStart: { month: 7, day: 1 },
    term: (a, d) => (heldMoreThan(1)(a, d) ? 'discount' : 'taxable'),
    terms: ['taxable', 'discount'],
    notes: [
      'Disposals of coins held at least 12 months may qualify for the CGT discount. The tax year runs from 1 July to 30 June.',
    ],
  },
  {
    id: 'fr',
    name: 'France',
    fiat: 'eur',
    method: 'acb',
    methods: ['acb'],
    yearStart: { month: 1, day: 1 },
    term: () => 'taxable',
    terms: ['taxable'],
    notes: [
      'The global-portfolio formula (prix total d’acquisition) is approximated by average cost. Crypto-to-crypto swaps are not taxable in France; they are listed for review.',
    ],
  },
  {
    id: 'other',
    name: 'Other / generic',
    fiat: 'usd',
    method: 'fifo',
    methods: ['fifo', 'lifo', 'hifo', 'acb'],
    yearStart: { month: 1, day: 1 },
    term: (a, d) => (heldMoreThan(1)(a, d) ? 'long' : 'short'),
    terms: ['short', 'long'],
    notes: ['Short and long term split at one year. Check the rules where you are resident.'],
  },
];

export function jurisdiction(id: string): Jurisdiction {
  return JURISDICTIONS.find((j) => j.id === id) ?? (JURISDICTIONS.at(-1) as Jurisdiction);
}

/** The tax year a moment falls in, named by the calendar year it starts in. */
export function taxYearOf(j: Jurisdiction, ms: number): number {
  const d = new Date(ms);
  const y = d.getUTCFullYear();
  const start = Date.UTC(y, j.yearStart.month - 1, j.yearStart.day);
  return ms >= start ? y : y - 1;
}

/** [start, end) of a tax year in UTC ms. */
export function taxYearRange(j: Jurisdiction, year: number): { startMs: number; endMs: number } {
  return {
    startMs: Date.UTC(year, j.yearStart.month - 1, j.yearStart.day),
    endMs: Date.UTC(year + 1, j.yearStart.month - 1, j.yearStart.day),
  };
}

export function taxYearLabel(j: Jurisdiction, year: number): string {
  return j.yearStart.month === 1 && j.yearStart.day === 1
    ? String(year)
    : `${year}/${String((year + 1) % 100).padStart(2, '0')}`;
}

export const TERM_LABEL: Readonly<Record<Term, string>> = {
  short: 'short-term',
  long: 'long-term',
  exempt: 'exempt',
  taxable: 'taxable',
  discount: 'discount-eligible',
};
