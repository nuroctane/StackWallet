import { buildCsv } from './csv.js';
import { FIAT_SYMBOL, jurisdiction, METHOD_LABEL, TERM_LABEL } from './jurisdictions.js';
import {
  LABEL_TEXT,
  type AssetInfo,
  type Label,
  type ScopeAccount,
  type TaxEvent,
  type TaxReport,
} from './model.js';
import { eventFlows } from './normalize.js';
import { buildXlsx, type CellValue, type SheetSpec } from './xlsx.js';

/**
 * Every export is computed from one report, so the JSON, the CSVs and the
 * workbook can never disagree with each other or with the screen. Amounts
 * are exact decimal strings in JSON; money is rounded to cents only where a
 * spreadsheet shows it.
 */

export const DISCLAIMER =
  'Prepared by StackWallet on this device from public chain data and public prices. Not tax advice. Review every flagged item and confirm the rules where you are resident before filing.';

export const CSV_PRESETS = [
  'ledger',
  'disposals',
  'income',
  'holdings',
  'cointracker',
  'blockpit',
  'koinly',
] as const;
export type CsvPreset = (typeof CSV_PRESETS)[number];

export const PRESET_TEXT: Readonly<Record<CsvPreset, { name: string; detail: string }>> = {
  ledger: {
    name: 'Full ledger',
    detail: 'Every transaction with label, value, fee and hash',
  },
  disposals: {
    name: 'Disposals · Form 8949 style',
    detail: 'One row per lot sold: acquired, sold, proceeds, basis, gain, term',
  },
  income: { name: 'Income', detail: 'Staking, airdrops, mining and other income at receipt value' },
  holdings: {
    name: 'Year-end holdings',
    detail: 'Remaining lots with basis and value at the end of the period',
  },
  cointracker: { name: 'CoinTracker CSV', detail: 'CoinTracker’s generic import template' },
  blockpit: { name: 'Blockpit template', detail: 'Columns of the Blockpit Excel template' },
  koinly: { name: 'Koinly universal', detail: 'Koinly’s universal CSV import format' },
};

export interface ExportContext {
  report: TaxReport;
  accounts: readonly ScopeAccount[];
  assets: ReadonlyMap<string, AssetInfo>;
  scopeLabel: string;
  wallets: readonly { id: string; name: string; kind: string; tags: readonly string[] }[];
  generatedAtMs: number;
  sources: readonly string[];
}

/** Exact decimal string of a base-unit amount. Unknown decimals stay in base units. */
export function units(amount: bigint, decimals: number | null): string {
  if (decimals === null || decimals === 0) return amount.toString();
  const neg = amount < 0n;
  const digits = (neg ? -amount : amount).toString().padStart(decimals + 1, '0');
  const whole = digits.slice(0, -decimals);
  const frac = digits.slice(-decimals).replace(/0+$/, '');
  return (neg ? '-' : '') + whole + (frac ? '.' + frac : '');
}

/** Micros to a decimal string with `dp` places, rounding half away from zero. */
export function money(micros: bigint | null, dp = 2): string {
  if (micros === null) return '';
  const neg = micros < 0n;
  const m = neg ? -micros : micros;
  const scale = 10n ** BigInt(6 - dp);
  const q = (m + scale / 2n) / scale;
  const s = q.toString().padStart(dp + 1, '0');
  const out = dp === 0 ? s : `${s.slice(0, -dp)}.${s.slice(-dp)}`;
  return (neg && q !== 0n ? '-' : '') + out;
}

export function formatMoney(micros: bigint | null, fiat: TaxReport['settings']['fiat']): string {
  if (micros === null) return '—';
  const text = money(micros);
  const [whole = '0', frac = '00'] = text.replace('-', '').split('.');
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${micros < 0n ? '−' : ''}${FIAT_SYMBOL[fiat]}${grouped}.${frac}`;
}

const pad = (n: number) => String(n).padStart(2, '0');
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
function parts(ms: number) {
  const d = new Date(ms);
  return {
    y: d.getUTCFullYear(),
    m: pad(d.getUTCMonth() + 1),
    d: pad(d.getUTCDate()),
    hh: pad(d.getUTCHours()),
    mm: pad(d.getUTCMinutes()),
    ss: pad(d.getUTCSeconds()),
  };
}

/** Number when it survives the round trip exactly, else the exact string. */
function amountCell(text: string): CellValue {
  const n = Number(text);
  return Number.isFinite(n) && (n === 0 || String(n) === text) ? n : text;
}
const moneyCell = (micros: bigint | null): CellValue =>
  micros === null ? null : Number(money(micros));

interface Row {
  event: TaxEvent;
  sentAmount: string;
  sentAsset: string;
  receivedAmount: string;
  receivedAsset: string;
  feeAmount: string;
  feeAsset: string;
  first: boolean;
}

function helpers(ctx: ExportContext) {
  const asset = (ref: string) => ctx.assets.get(ref);
  const symbol = (ref: string) => asset(ref)?.symbol ?? ref;
  const amount = (ref: string, n: bigint) => units(n, asset(ref)?.decimals ?? null);
  const accountsById = new Map(ctx.accounts.map((a) => [a.accountId, a]));
  const walletNames = new Map(ctx.wallets.map((w) => [w.id, w.name]));
  const walletName = (id: string) => (id === '*' ? 'All wallets' : (walletNames.get(id) ?? id));
  const eventWallets = (e: TaxEvent) =>
    [
      ...new Set(
        e.legs.map((l) => walletName(l.walletId)).concat(e.fee ? [walletName(e.fee.walletId)] : []),
      ),
    ].join(' + ');
  const chainName = (chainId: string) =>
    ctx.accounts.find((a) => a.chainId === chainId)?.chainName ?? chainId;
  /** Rows per event: outs paired with ins; the fee rides on the first row. */
  const rows = (e: TaxEvent, includeMoves: boolean): Row[] => {
    const { ins, outs } = eventFlows(e);
    const sent = outs.map((o) => ({ a: amount(o.assetRef, o.amount), s: symbol(o.assetRef) }));
    const got = ins.map((i) => ({ a: amount(i.assetRef, i.amount), s: symbol(i.assetRef) }));
    if (includeMoves && e.moves.length > 0 && sent.length === 0 && got.length === 0)
      for (const m of e.moves) {
        const v = { a: amount(m.assetRef, m.amount), s: symbol(m.assetRef) };
        sent.push(v);
        got.push(v);
      }
    const n = Math.max(sent.length, got.length, e.fee ? 1 : 0);
    const out: Row[] = [];
    for (let i = 0; i < n; i++)
      out.push({
        event: e,
        sentAmount: sent[i]?.a ?? '',
        sentAsset: sent[i]?.s ?? '',
        receivedAmount: got[i]?.a ?? '',
        receivedAsset: got[i]?.s ?? '',
        feeAmount: i === 0 && e.fee ? amount(e.fee.assetRef, e.fee.amount) : '',
        feeAsset: i === 0 && e.fee ? symbol(e.fee.assetRef) : '',
        first: i === 0,
      });
    return out;
  };
  return { asset, symbol, amount, accountsById, walletName, eventWallets, chainName, rows };
}

const exported = (e: TaxEvent) => e.label !== 'spam';

const COINTRACKER_TAG: Partial<Record<Label, string>> = {
  staking: 'staking',
  airdrop: 'airdrop',
  mining: 'mining',
  income: 'other_income',
  'gift-in': 'gift',
  'gift-out': 'gift',
  lost: 'lost',
};

const BLOCKPIT_LABEL: Readonly<Record<Label, string>> = {
  receive: 'Deposit',
  income: 'Income',
  staking: 'Staking',
  airdrop: 'Airdrop',
  mining: 'Mining',
  'gift-in': 'Gift',
  'transfer-in': 'Deposit',
  send: 'Withdrawal',
  payment: 'Withdrawal',
  'gift-out': 'Gift',
  'transfer-out': 'Withdrawal',
  lost: 'Lost',
  trade: 'Trade',
  self: 'Fee',
  fee: 'Fee',
  spam: '',
};

const KOINLY_LABEL: Partial<Record<Label, string>> = {
  staking: 'reward',
  airdrop: 'airdrop',
  mining: 'mining',
  income: 'income',
  'gift-in': 'gift',
  'gift-out': 'gift',
  lost: 'lost',
  fee: 'cost',
  self: 'cost',
};

export interface Table {
  columns: string[];
  rows: CellValue[][];
}

export function presetTable(ctx: ExportContext, preset: CsvPreset): Table {
  const { report } = ctx;
  const FIAT = report.settings.fiat.toUpperCase();
  const h = helpers(ctx);
  const events = report.events.filter(exported);
  switch (preset) {
    case 'ledger':
      return {
        columns: [
          'Date (UTC)',
          'Label',
          'Reviewed',
          'Wallet',
          'Chain',
          'Sent amount',
          'Sent asset',
          'Received amount',
          'Received asset',
          'Fee amount',
          'Fee asset',
          `Value (${FIAT})`,
          'Counterparty',
          'Transaction hash',
          'Note',
          'Event id',
        ],
        rows: events.flatMap((e) =>
          h
            .rows(e, true)
            .map((r) => [
              e.timestampMs === null ? '' : iso(e.timestampMs),
              LABEL_TEXT[e.label],
              e.reviewed,
              h.eventWallets(e),
              h.chainName(e.chainId),
              r.sentAmount,
              r.sentAsset,
              r.receivedAmount,
              r.receivedAsset,
              r.feeAmount,
              r.feeAsset,
              r.first ? money(report.values.get(e.id) ?? null) : '',
              e.counterparty ?? '',
              e.hash,
              e.note,
              e.id,
            ]),
        ),
      };
    case 'disposals':
      return {
        columns: [
          'Description',
          'Date acquired',
          'Date sold or disposed',
          `Proceeds (${FIAT})`,
          `Cost basis (${FIAT})`,
          `Gain or loss (${FIAT})`,
          'Term',
          'Basis status',
          'Label',
          'Wallet',
          'Chain',
          'Transaction hash',
          'Lot',
        ],
        rows: report.disposals
          .filter((d) => !d.removal)
          .map((d) => [
            `${h.amount(d.assetRef, d.amount)} ${h.symbol(d.assetRef)}`,
            d.acquiredAtMs === null ? 'UNKNOWN' : iso(d.acquiredAtMs).slice(0, 10),
            iso(d.disposedAtMs).slice(0, 10),
            money(d.proceeds),
            money(d.cost),
            money(d.gain),
            d.term ? TERM_LABEL[d.term] : '',
            d.cost === null ? 'missing: not proven by on-chain history' : 'from on-chain history',
            LABEL_TEXT[d.label],
            h.walletName(d.walletId),
            h.chainName(d.chainId),
            d.hash,
            d.lotId ?? '',
          ]),
      };
    case 'income':
      return {
        columns: [
          'Date (UTC)',
          'Type',
          'Wallet',
          'Asset',
          'Amount',
          `Value (${FIAT})`,
          'Chain',
          'Transaction hash',
        ],
        rows: report.income.map((i) => [
          iso(i.atMs),
          LABEL_TEXT[i.label],
          h.walletName(i.walletId),
          h.symbol(i.assetRef),
          h.amount(i.assetRef, i.amount),
          money(i.value),
          h.chainName(i.chainId),
          i.hash,
        ]),
      };
    case 'holdings':
      return {
        columns: [
          'Wallet',
          'Asset',
          'Amount',
          `Cost basis (${FIAT})`,
          `Value at period end (${FIAT})`,
          `Unrealized gain (${FIAT})`,
          'Earliest acquisition',
          'Lots',
          'Asset id',
        ],
        rows: report.holdings.map((x) => [
          h.walletName(x.walletId),
          h.symbol(x.assetRef),
          h.amount(x.assetRef, x.amount),
          money(x.cost),
          money(x.value),
          x.cost !== null && x.value !== null ? money(x.value - x.cost) : '',
          x.earliestAtMs === null ? '' : iso(x.earliestAtMs).slice(0, 10),
          x.lots,
          x.assetRef,
        ]),
      };
    case 'cointracker':
      return {
        columns: [
          'Date',
          'Received Quantity',
          'Received Currency',
          'Sent Quantity',
          'Sent Currency',
          'Fee Amount',
          'Fee Currency',
          'Tag',
        ],
        rows: events.flatMap((e) =>
          h
            .rows(e, false)
            .filter((r) => r.sentAmount || r.receivedAmount || r.feeAmount)
            .map((r) => {
              const p = parts(e.timestampMs ?? 0);
              return [
                `${p.m}/${p.d}/${p.y} ${p.hh}:${p.mm}:${p.ss}`,
                r.receivedAmount,
                r.receivedAsset,
                r.sentAmount,
                r.sentAsset,
                r.feeAmount,
                r.feeAsset,
                COINTRACKER_TAG[e.label] ?? '',
              ];
            }),
        ),
      };
    case 'blockpit':
      return {
        columns: [
          'Date (UTC)',
          'Integration Name',
          'Label',
          'Outgoing Asset',
          'Outgoing Amount',
          'Incoming Asset',
          'Incoming Amount',
          'Fee Asset (optional)',
          'Fee Amount (optional)',
          'Comment (optional)',
          'Trx. ID (optional)',
        ],
        rows: events.flatMap((e) =>
          h
            .rows(e, false)
            .filter((r) => r.sentAmount || r.receivedAmount || r.feeAmount)
            .map((r) => {
              const p = parts(e.timestampMs ?? 0);
              return [
                `${p.d}.${p.m}.${p.y} ${p.hh}:${p.mm}:${p.ss}`,
                `StackWallet · ${h.eventWallets(e)}`.slice(0, 100),
                BLOCKPIT_LABEL[e.label],
                r.sentAsset,
                r.sentAmount,
                r.receivedAsset,
                r.receivedAmount,
                r.feeAsset,
                r.feeAmount,
                e.note,
                e.hash,
              ];
            }),
        ),
      };
    case 'koinly':
      return {
        columns: [
          'Date',
          'Sent Amount',
          'Sent Currency',
          'Received Amount',
          'Received Currency',
          'Fee Amount',
          'Fee Currency',
          'Net Worth Amount',
          'Net Worth Currency',
          'Label',
          'Description',
          'TxHash',
        ],
        rows: events.flatMap((e) =>
          h
            .rows(e, false)
            .filter((r) => r.sentAmount || r.receivedAmount || r.feeAmount)
            .map((r) => {
              const p = parts(e.timestampMs ?? 0);
              const worth = r.first ? money(report.values.get(e.id) ?? null) : '';
              return [
                `${p.y}-${p.m}-${p.d} ${p.hh}:${p.mm} UTC`,
                r.sentAmount,
                r.sentAsset,
                r.receivedAmount,
                r.receivedAsset,
                r.feeAmount,
                r.feeAsset,
                worth,
                worth ? FIAT : '',
                KOINLY_LABEL[e.label] ?? '',
                e.note || LABEL_TEXT[e.label],
                e.hash,
              ];
            }),
        ),
      };
  }
}

export function exportCsv(
  ctx: ExportContext,
  preset: CsvPreset,
  delimiter: ',' | ';' = ',',
): string {
  const t = presetTable(ctx, preset);
  return buildCsv(t.columns, t.rows, { delimiter, bom: delimiter === ';' });
}

function bigintSafe(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Map)
    return Object.fromEntries([...value].map(([k, v]) => [k, bigintSafe(v)]));
  if (Array.isArray(value)) return value.map(bigintSafe);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, bigintSafe(v)]),
    );
  return value;
}

const decimalMoney = (m: bigint | null) => (m === null ? null : money(m, 6));

/** The full report as a self-describing document, with a SHA-256 digest of its body. */
export async function exportJson(ctx: ExportContext): Promise<string> {
  const { report } = ctx;
  const j = jurisdiction(report.settings.jurisdiction);
  const h = helpers(ctx);
  const body = {
    format: 'stackwallet.tax-report',
    version: 1,
    generatedAt: iso(ctx.generatedAtMs),
    disclaimer: DISCLAIMER,
    jurisdiction: { id: j.id, name: j.name, notes: j.notes },
    settings: { ...report.settings, methodLabel: METHOD_LABEL[report.settings.method] },
    period: {
      label: report.period.label,
      start: iso(report.period.startMs),
      end: iso(report.period.endMs),
    },
    scope: { label: ctx.scopeLabel, wallets: ctx.wallets },
    accounts: ctx.accounts,
    readiness: report.readiness,
    summary: {
      fiat: report.summary.fiat,
      proceeds: decimalMoney(report.summary.proceeds),
      costBasis: decimalMoney(report.summary.cost),
      gain: decimalMoney(report.summary.gain),
      byTerm: Object.fromEntries(
        Object.entries(report.summary.byTerm).map(([k, v]) => [
          k,
          {
            proceeds: decimalMoney(v.proceeds),
            costBasis: decimalMoney(v.cost),
            gain: decimalMoney(v.gain),
            count: v.count,
          },
        ]),
      ),
      income: decimalMoney(report.summary.income),
      incomeByType: Object.fromEntries(
        Object.entries(report.summary.incomeByLabel).map(([k, v]) => [k, decimalMoney(v ?? null)]),
      ),
      networkFees: decimalMoney(report.summary.fees),
      disposals: report.summary.disposals,
      disposalsWithoutBasis: report.summary.unknownBasisDisposals,
      proceedsWithoutBasis: decimalMoney(report.summary.unknownBasisProceeds),
      disposalsWithoutPrice: report.summary.unpricedDisposals,
      events: report.summary.events,
      reviewedEvents: report.summary.reviewed,
    },
    disposals: report.disposals.map((d) => ({
      ...d,
      symbol: h.symbol(d.assetRef),
      amount: h.amount(d.assetRef, d.amount),
      acquiredAt: d.acquiredAtMs === null ? null : iso(d.acquiredAtMs),
      disposedAt: iso(d.disposedAtMs),
      proceeds: decimalMoney(d.proceeds),
      cost: decimalMoney(d.cost),
      gain: decimalMoney(d.gain),
    })),
    income: report.income.map((i) => ({
      ...i,
      symbol: h.symbol(i.assetRef),
      amount: h.amount(i.assetRef, i.amount),
      at: iso(i.atMs),
      value: decimalMoney(i.value),
    })),
    holdings: report.holdings.map((x) => ({
      ...x,
      symbol: h.symbol(x.assetRef),
      amount: h.amount(x.assetRef, x.amount),
      cost: decimalMoney(x.cost),
      value: decimalMoney(x.value),
    })),
    events: report.events.map((e) => ({
      id: e.id,
      chainId: e.chainId,
      hash: e.hash,
      at: e.timestampMs === null ? null : iso(e.timestampMs),
      status: e.status,
      label: e.label,
      automaticLabel: e.auto,
      reviewed: e.reviewed,
      value: decimalMoney(report.values.get(e.id) ?? null),
      legs: e.legs.map((l) => ({
        ...l,
        symbol: h.symbol(l.assetRef),
        amount: h.amount(l.assetRef, l.amount),
      })),
      moves: e.moves.map((m) => ({ ...m, amount: h.amount(m.assetRef, m.amount) })),
      fee: e.fee ? { ...e.fee, amount: h.amount(e.fee.assetRef, e.fee.amount) } : null,
      feeUnknown: e.feeUnknown,
      counterparty: e.counterparty,
      note: e.note,
      override: e.override ?? null,
    })),
    issues: report.issues,
    sources: ctx.sources,
  };
  const text = JSON.stringify(bigintSafe(body));
  const digest = await sha256Hex(text);
  return JSON.stringify({ ...(bigintSafe(body) as object), digest: { sha256: digest } }, null, 2);
}

export async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  return [...hash].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A workbook with one sheet per view, typed columns, frozen headers and filters. */
export function exportXlsx(ctx: ExportContext): Uint8Array {
  const { report } = ctx;
  const j = jurisdiction(report.settings.jurisdiction);
  const FIAT = report.settings.fiat.toUpperCase();
  const s = report.summary;
  const pct = (x: number) => Math.round(x * 1000) / 1000;
  const summaryRows: CellValue[][] = [
    ['Report', `Crypto tax report ${report.period.label}`],
    [
      'Period',
      `${iso(report.period.startMs).slice(0, 10)} to ${iso(report.period.endMs - 1).slice(0, 10)} (UTC)`,
    ],
    ['Tax residence', j.name],
    ['Cost basis method', METHOD_LABEL[report.settings.method]],
    [
      'Basis pooling',
      report.settings.pooling === 'wallet' ? 'Per wallet' : 'Universal (all wallets)',
    ],
    [
      'Network fees',
      report.settings.fees === 'dispose'
        ? 'Disposal of the fee coin at market value'
        : 'Removed without a disposal',
    ],
    ['Currency', FIAT],
    ['Scope', ctx.scopeLabel],
    ['Generated (UTC)', { date: ctx.generatedAtMs }],
    [],
    [`Proceeds (${FIAT})`, moneyCell(s.proceeds)],
    [`Cost basis (${FIAT})`, moneyCell(s.cost)],
    [`Net gain or loss (${FIAT})`, moneyCell(s.gain)],
    ...j.terms.map((t): CellValue[] => [
      `  ${TERM_LABEL[t]} gain (${FIAT})`,
      moneyCell(s.byTerm[t]?.gain ?? 0n),
    ]),
    [`Income (${FIAT})`, moneyCell(s.income)],
    [`Network fees paid (${FIAT})`, moneyCell(s.fees)],
    ['Disposals', s.disposals],
    ['  without proven basis', s.unknownBasisDisposals],
    [`  their proceeds (${FIAT})`, moneyCell(s.unknownBasisProceeds)],
    ['  without a price', s.unpricedDisposals],
    ['Transactions in period', s.events],
    ['  reviewed', s.reviewed],
    [],
    ['Readiness', pct(report.readiness.score)],
    ['  history complete', pct(report.readiness.history)],
    ['  reviewed', pct(report.readiness.reviewed)],
    ['  priced', pct(report.readiness.priced)],
    ['  basis proven', pct(report.readiness.basis)],
    [],
    ['Notes', DISCLAIMER],
    ...j.notes.map((n): CellValue[] => ['', n]),
  ];
  const table = (
    preset: CsvPreset,
    name: string,
    formats: Record<number, SheetSpec['columns'][number]['format']>,
  ): SheetSpec => {
    const t = presetTable(ctx, preset);
    return {
      name,
      columns: t.columns.map((header, i) => ({
        header,
        ...(formats[i] ? { format: formats[i] } : {}),
      })),
      rows: t.rows.map((row) =>
        row.map((c, i) =>
          formats[i] === 'money' && typeof c === 'string'
            ? c === ''
              ? null
              : Number(c)
            : formats[i] === 'decimal' && typeof c === 'string' && c !== ''
              ? amountCell(c)
              : c,
        ),
      ),
    };
  };
  const sheets: SheetSpec[] = [
    {
      name: 'Summary',
      columns: [
        { header: 'Item', width: 34 },
        { header: 'Value', width: 60 },
      ],
      rows: summaryRows,
      autoFilter: false,
    },
    table('disposals', 'Disposals', { 3: 'money', 4: 'money', 5: 'money' }),
    table('income', 'Income', { 4: 'decimal', 5: 'money' }),
    table('holdings', 'Holdings', {
      2: 'decimal',
      3: 'money',
      4: 'money',
      5: 'money',
      7: 'integer',
    }),
    table('ledger', 'Ledger', { 5: 'decimal', 7: 'decimal', 9: 'decimal', 11: 'money' }),
    {
      name: 'Issues',
      columns: [
        { header: 'Severity', width: 10 },
        { header: 'Issue', width: 18 },
        { header: 'Detail', width: 90 },
        { header: 'Event id', width: 40 },
      ],
      rows: report.issues.map((i) => [
        i.severity,
        i.code,
        i.message,
        i.eventId ?? i.accountId ?? '',
      ]),
    },
    {
      name: 'Wallets',
      columns: [
        { header: 'Wallet', width: 24 },
        { header: 'Kind', width: 10 },
        { header: 'Tags', width: 24 },
        { header: 'Chain', width: 22 },
        { header: 'Address', width: 48 },
        { header: 'Testnet' },
      ],
      rows: ctx.accounts.map((a) => [
        a.walletName,
        a.walletKind,
        ctx.wallets.find((w) => w.id === a.walletId)?.tags.join(', ') ?? '',
        a.chainName,
        a.address,
        a.testnet,
      ]),
    },
    {
      name: 'Sources',
      columns: [{ header: 'Source', width: 100 }],
      rows: ctx.sources.map((x) => [x]),
    },
  ];
  return buildXlsx({
    title: `StackWallet tax report ${report.period.label}`,
    createdMs: ctx.generatedAtMs,
    sheets,
  });
}

export function exportFileName(
  report: TaxReport,
  kind: CsvPreset | 'report',
  ext: 'csv' | 'json' | 'xlsx',
): string {
  const label = report.period.label.replace('/', '-');
  return `stackwallet-tax-${label}-${report.settings.jurisdiction}-${kind}.${ext}`;
}
