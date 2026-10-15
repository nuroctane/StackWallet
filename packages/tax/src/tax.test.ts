import type { TxRecord } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  allocate,
  buildEvents,
  buildReport,
  eventFlows,
  priceFraction,
  valueMicros,
  exportCsv,
  exportJson,
  exportXlsx,
  jurisdiction,
  money,
  resolveScope,
  taxYearOf,
  units,
  type AccountHistory,
  type AssetInfo,
  type ExportContext,
  type Overrides,
  type PricePoint,
  type ScopeAccount,
  type TaxSettings,
} from './index.js';

const ETH = 'eip155:1:native';
const USDC = 'eip155:1:erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const A = '0x' + 'a'.repeat(40);
const B = '0x' + 'b'.repeat(40);
const X = '0x' + 'c'.repeat(40);
const E = 10n ** 18n;
const day = (iso: string) => Date.parse(iso + 'T12:00:00Z');

const assets = new Map<string, AssetInfo>([
  [ETH, { ref: ETH, symbol: 'ETH', decimals: 18, priceKey: 'ethereum', testnet: false }],
  [USDC, { ref: USDC, symbol: 'USDC', decimals: 6, priceKey: 'usd-coin', testnet: false }],
]);

function series(points: [string, number][]): PricePoint[] {
  return points.map(([d, v]) => ({ t: Date.parse(d + 'T00:00:00Z'), v }));
}
const prices = new Map<string, PricePoint[]>([
  [
    'ethereum',
    series([
      ['2024-01-10', 1000],
      ['2024-02-01', 1500],
      ['2024-06-01', 2000],
      ['2025-03-01', 3000],
      ['2025-06-01', 4000],
      ['2025-12-31', 3500],
    ]),
  ],
  ['usd-coin', series([['2025-03-01', 1]])],
]);

const account = (id: string, walletId: string, address: string): ScopeAccount => ({
  accountId: id,
  walletId,
  walletName: walletId.toUpperCase(),
  walletKind: 'single',
  folderPath: '',
  chainId: 'eip155:1',
  chainName: 'Ethereum',
  address,
  testnet: false,
});

let n = 0;
function tx(
  from: string,
  to: string,
  at: string,
  deltas: [string, bigint][],
  fee: bigint | null = null,
  hash?: string,
): TxRecord {
  n += 1;
  return {
    hash: hash ?? '0x' + n.toString(16).padStart(64, '0'),
    chainId: 'eip155:1',
    timestampMs: day(at),
    from,
    to,
    assetDeltas: deltas.map(([assetRef, amount]) => ({ assetRef, amount: amount.toString() })),
    feeAssetRef: ETH,
    fee: fee === null ? null : fee.toString(),
    status: 'confirmed',
  };
}

const settings = (over: Partial<TaxSettings> = {}): TaxSettings => ({
  jurisdiction: 'us',
  method: 'fifo',
  fiat: 'usd',
  pooling: 'wallet',
  fees: 'dispose',
  year: 2025,
  includeTestnets: false,
  ...over,
});

const history = (accountId: string, records: TxRecord[]): AccountHistory => ({
  accountId,
  records,
  complete: true,
  sources: ['test'],
});

const $ = (micros: bigint | null) => (micros === null ? null : money(micros));

describe('cost basis', () => {
  const fee = E / 100n;
  const records = [
    tx(X, A, '2024-01-10', [[ETH, E]]),
    tx(X, A, '2024-06-01', [[ETH, E]]),
    // Native net changes from adapters include the fee paid.
    tx(A, X, '2025-03-01', [[ETH, -(E + E / 2n) - fee]], fee),
  ];
  const input = (over: Partial<TaxSettings> = {}, overrides: Overrides = {}) => ({
    accounts: [account('a', 'w1', A)],
    histories: [history('a', records)],
    assets,
    prices,
    overrides,
    settings: settings(over),
  });

  it('FIFO splits a sale across lots with the right terms and fee', () => {
    const r = buildReport(input());
    const sales = r.disposals.filter((d) => d.label === 'send');
    expect(sales.map((d) => [units(d.amount, 18), $(d.cost), $(d.proceeds), d.term])).toEqual([
      ['1', '1000.00', '3000.00', 'long'],
      ['0.5', '1000.00', '1500.00', 'short'],
    ]);
    const feeRow = r.disposals.find((d) => d.label === 'fee');
    expect([$(feeRow?.proceeds ?? null), $(feeRow?.cost ?? null), feeRow?.term]).toEqual([
      '30.00',
      '20.00',
      'short',
    ]);
    expect($(r.summary.gain)).toBe('2510.00');
    expect($(r.summary.fees)).toBe('30.00');
    expect(r.issues.some((i) => i.code === 'unreviewed')).toBe(true);
  });

  it('HIFO takes the most expensive lot first', () => {
    const r = buildReport(input({ method: 'hifo' }));
    const sales = r.disposals.filter((d) => d.label === 'send');
    expect(sales.map((d) => [units(d.amount, 18), $(d.cost), d.term])).toEqual([
      ['1', '2000.00', 'short'],
      ['0.5', '500.00', 'long'],
    ]);
  });

  it('average cost uses the pooled unit cost', () => {
    const r = buildReport(input({ method: 'acb', jurisdiction: 'uk', year: 2024 }));
    // UK 2024/25 runs 6 Apr 2024 to 5 Apr 2025.
    const sales = r.disposals.filter((d) => d.label === 'send');
    expect(sales.reduce((s, d) => s + (d.cost ?? 0n), 0n)).toBe(2_250_000_000n);
    expect(r.period.label).toBe('2024/25');
  });

  it('a label override turns the sale into a gift with no proceeds', () => {
    const id = `eip155:1|${records[2]!.hash}`;
    const r = buildReport(input({}, { [id]: { label: 'gift-out' } }));
    expect(r.disposals.filter((d) => d.label === 'gift-out').every((d) => d.removal)).toBe(true);
    expect(r.summary.proceeds).toBe(30_000_000n);
  });

  it('keeps lots without a proven basis out of the term totals', () => {
    const r = buildReport({
      accounts: [account('a', 'w1', A)],
      histories: [
        history('a', [
          tx(X, A, '2023-06-01', [[ETH, E]]),
          tx(X, A, '2024-06-01', [[ETH, E]]),
          tx(A, X, '2025-03-01', [[ETH, -2n * E]]),
        ]),
      ],
      assets,
      prices,
      overrides: {},
      settings: settings(),
    });
    expect(r.summary.unknownBasisDisposals).toBe(1);
    expect($(r.summary.unknownBasisProceeds)).toBe('3000.00');
    expect($(r.summary.proceeds)).toBe('6000.00');
    expect(r.summary.byTerm.long).toBeUndefined();
    const short = r.summary.byTerm.short!;
    expect([short.count, $(short.proceeds), $(short.cost), $(short.gain)]).toEqual([
      1,
      '3000.00',
      '2000.00',
      '1000.00',
    ]);
  });
});

describe('own wallets and missing basis', () => {
  it('moves basis and date between two wallets in scope', () => {
    const hash = '0x' + 'f'.repeat(64);
    const r = buildReport({
      accounts: [account('a', 'w1', A), account('b', 'w2', B)],
      histories: [
        history('a', [
          tx(X, A, '2024-01-10', [[ETH, E]]),
          tx(A, B, '2024-02-01', [[ETH, -E]], 0n, hash),
        ]),
        history('b', [
          tx(A, B, '2024-02-01', [[ETH, E]], 0n, hash),
          tx(B, X, '2025-06-01', [[ETH, -E]], 0n),
        ]),
      ],
      assets,
      prices,
      overrides: {},
      settings: settings(),
    });
    const sale = r.disposals.find((d) => d.label === 'send');
    expect(sale?.walletId).toBe('w2');
    expect($(sale?.cost ?? null)).toBe('1000.00');
    expect(sale?.term).toBe('long');
    expect(r.events.length).toBe(1);
  });

  it('reports basis missing instead of inventing zero', () => {
    const r = buildReport({
      accounts: [account('a', 'w1', A)],
      histories: [history('a', [tx(A, X, '2025-03-01', [[ETH, -E]], 0n)])],
      assets,
      prices,
      overrides: {},
      settings: settings(),
    });
    expect(r.disposals[0]?.cost).toBeNull();
    expect(r.disposals[0]?.gain).toBeNull();
    expect(r.issues[0]?.code).toBe('missing-basis');
    expect(r.readiness.basis).toBe(0);
  });

  it('a transfer-in with entered basis proves the later sale', () => {
    const inbound = tx(X, A, '2025-01-05', [[ETH, E]]);
    const r = buildReport({
      accounts: [account('a', 'w1', A)],
      histories: [history('a', [inbound, tx(A, X, '2025-03-01', [[ETH, -E]], 0n)])],
      assets,
      prices,
      overrides: {
        [`eip155:1|${inbound.hash}`]: {
          label: 'transfer-in',
          basis: '800',
          acquiredAtMs: Date.UTC(2022, 0, 1),
        },
      },
      settings: settings(),
    });
    const sale = r.disposals.find((d) => d.label === 'send');
    expect([$(sale?.cost ?? null), sale?.term]).toEqual(['800.00', 'long']);
  });
});

describe('trades and income', () => {
  it('pairs native and token deltas sharing a hash into one trade', () => {
    const hash = '0x' + 'e'.repeat(64);
    const external = tx(A, X, '2025-03-01', [[ETH, -E]], 0n, hash);
    const token: TxRecord = {
      ...tx(X, A, '2025-03-01', [[USDC, 3000n * 10n ** 6n]], null, hash),
      entryId: hash + ':4',
    };
    const r = buildReport({
      accounts: [account('a', 'w1', A)],
      histories: [history('a', [tx(X, A, '2024-01-10', [[ETH, E]]), external, token])],
      assets,
      prices,
      overrides: {},
      settings: settings(),
    });
    const trade = r.events.find((e) => e.label === 'trade');
    expect(trade).toBeDefined();
    expect(eventFlows(trade!).ins[0]?.assetRef).toBe(USDC);
    expect($(r.summary.gain)).toBe('2000.00');
    expect(r.holdings.find((h) => h.assetRef === USDC)?.cost).toBe(3_000_000_000n);
  });

  it('staking rewards are income and set basis', () => {
    const reward = tx(X, A, '2025-03-01', [[ETH, E / 10n]]);
    const r = buildReport({
      accounts: [account('a', 'w1', A)],
      histories: [history('a', [reward])],
      assets,
      prices,
      overrides: { [`eip155:1|${reward.hash}`]: { label: 'staking' } },
      settings: settings(),
    });
    expect($(r.summary.income)).toBe('300.00');
    expect(r.readiness.score).toBe(1);
  });
});

describe('jurisdictions and scope', () => {
  it('German private sales are exempt after a year', () => {
    const de = jurisdiction('de');
    expect(de.term(day('2024-01-10'), day('2025-01-11'))).toBe('exempt');
    expect(de.term(day('2024-01-10'), day('2025-01-10'))).toBe('taxable');
    expect(taxYearOf(jurisdiction('au'), day('2025-06-30'))).toBe(2024);
  });

  it('narrows by kind, directory and hand selection', () => {
    const folders = [
      { id: 'root', parentId: null, name: 'All', imported: false, exported: false },
      { id: 'set', parentId: 'root', name: 'From laptop', imported: true, exported: false },
    ];
    const wallets = [
      {
        id: 'w1',
        name: 'Watch',
        kind: 'watch',
        folderId: 'root',
        imported: false,
        exported: false,
      },
      {
        id: 'w2',
        name: 'Laptop',
        kind: 'single',
        folderId: 'set',
        imported: false,
        exported: false,
      },
      { id: 'w3', name: 'Sent', kind: 'single', folderId: 'root', imported: false, exported: true },
      {
        id: 'w4',
        name: 'Local',
        kind: 'single',
        folderId: 'root',
        imported: false,
        exported: false,
      },
    ];
    const ids = (f: Parameters<typeof resolveScope>[0]) =>
      resolveScope(f, wallets, folders).included.map((w) => w.id);
    expect(ids({ tags: ['watched'], folderIds: [], excluded: [] })).toEqual(['w1']);
    expect(ids({ tags: ['imported', 'exported'], folderIds: [], excluded: [] })).toEqual([
      'w2',
      'w3',
    ]);
    expect(ids({ tags: [], folderIds: ['set'], excluded: [] })).toEqual(['w2']);
    expect(ids({ tags: ['local'], folderIds: [], excluded: [] })).toEqual(['w4']);
    expect(ids({ tags: [], folderIds: [], excluded: ['w1', 'w4'] })).toEqual(['w2', 'w3']);
  });
});

describe('dust, spam and every chain', () => {
  const SPAM = 'eip155:1:erc20:' + '0x' + 'd'.repeat(40);
  const PEPE = 'eip155:1:erc20:' + '0x' + 'e'.repeat(40);
  const more = new Map(assets);
  more.set(SPAM, { ref: SPAM, symbol: 'SPAM·dddd', decimals: 18, priceKey: null, testnet: false });
  more.set(PEPE, { ref: PEPE, symbol: 'PEPE', decimals: 18, priceKey: 'pepe', testnet: false });
  const tiny = new Map(prices);
  tiny.set('pepe', series([['2025-03-01', 1.23e-12]]));
  const run = (records: TxRecord[], extra: Partial<AccountHistory> = {}) =>
    buildReport({
      accounts: [account('a', 'w1', A)],
      histories: [{ ...history('a', records), ...extra }],
      assets: more,
      prices: tiny,
      overrides: {},
      settings: settings(),
    });

  it('values sub-nano prices exactly instead of rounding them to zero', () => {
    expect(priceFraction(1.23e-12)).toEqual({ num: 123n, exp: -14 });
    // A trillion tokens at 1.23e-12 is 1.23 of the fiat.
    expect(valueMicros(10n ** 30n, 18, 1.23e-12)).toBe(1_230_000n);
    expect(valueMicros(1n, 0, 0.0000004)).toBe(0n);
    expect(valueMicros(1n, 0, 0.0000005)).toBe(1n);
    expect(valueMicros(1n, 18, 3500)).toBe(0n);
    expect(valueMicros(1n, 0, NaN)).toBeNull();
    const r = run([tx(X, A, '2025-03-01', [[PEPE, 10n ** 30n]])]);
    expect(r.holdings.find((h) => h.assetRef === PEPE)?.cost).toBe(1_230_000n);
  });

  it('a one-wei sale is priced at zero, not missing', () => {
    const r = run([tx(X, A, '2025-03-01', [[ETH, E]]), tx(A, X, '2025-03-01', [[ETH, -1n]])]);
    const sale = r.disposals.find((d) => d.label === 'send' && d.amount === 1n);
    expect(sale?.proceeds).toBe(0n);
    expect(sale?.cost).toBe(0n);
    expect(r.issues.some((i) => i.code === 'missing-price')).toBe(false);
  });

  it('allocates known values first and never weighs raw amounts of different assets', () => {
    const legs = (...refs: [string, bigint][]) =>
      refs.map(([assetRef, amount]) => ({ assetRef, amount }));
    expect(allocate(100n, [60n, null], legs([USDC, 1n], [SPAM, 10n ** 27n]))).toEqual([60n, 40n]);
    expect(allocate(100n, [null, null], legs([ETH, 1n], [ETH, 3n]))).toEqual([25n, 75n]);
    expect(allocate(100n, [null, null], legs([ETH, 1n], [SPAM, 3n]))).toEqual([50n, 50n]);
    expect(allocate(100n, [150n, 50n, null], legs([ETH, 1n], [USDC, 1n], [SPAM, 1n]))).toEqual([
      75n,
      25n,
      0n,
    ]);
  });

  it('a swap that also drops spam keeps the basis on the real token', () => {
    const r = run([
      tx(X, A, '2024-01-10', [[ETH, E]]),
      tx(
        A,
        X,
        '2025-03-01',
        [
          [ETH, -E],
          [USDC, 3_000_000_000n],
          [SPAM, 10n ** 27n],
        ],
        null,
      ),
    ]);
    const usdc = r.holdings.find((h) => h.assetRef === USDC);
    expect($(usdc?.cost ?? null)).toBe('3000.00');
    expect(r.holdings.find((h) => h.assetRef === SPAM)?.cost).toBe(0n);
  });

  it('a partly priced trade uses the priced part as a floor and says so', () => {
    const OTHER = 'eip155:1:erc20:0x' + 'f'.repeat(40);
    const r = run([
      tx(
        A,
        X,
        '2025-03-01',
        [
          [OTHER, -5n],
          [USDC, 3_000_000_000n],
          [SPAM, 1n],
        ],
        null,
      ),
    ]);
    const sale = r.disposals.find((d) => d.assetRef === OTHER);
    expect($(sale?.proceeds ?? null)).toBe('3000.00');
    expect(r.issues.find((i) => i.code === 'missing-price')?.severity).toBe('warn');
  });

  it('flags a history that does not add up to the live balance', () => {
    const records = [tx(X, A, '2025-03-01', [[ETH, E]])];
    const ok = run(records, { balances: [{ assetRef: ETH, amount: E.toString() }] });
    expect(ok.issues.some((i) => i.code === 'balance-mismatch')).toBe(false);
    const off = run(records, { balances: [{ assetRef: ETH, amount: (E + 5n).toString() }] });
    const issue = off.issues.find((i) => i.code === 'balance-mismatch');
    expect(issue?.message).toContain('adds up to 1 ETH');
    expect(issue?.message).toContain('holds 1.000000000000000005');
  });

  it('a coinjoin fee is capped at what this address actually paid', () => {
    const BTC_CHAIN = 'bip122:000000000019d6689c085ae165831e93';
    const BTC = BTC_CHAIN + ':native';
    const me = 'bc1qme';
    const events = buildEvents(
      [{ ...account('b', 'w1', me), chainId: BTC_CHAIN, chainName: 'Bitcoin' }],
      [
        history('b', [
          {
            hash: 'f'.repeat(64),
            chainId: BTC_CHAIN,
            timestampMs: day('2025-03-01'),
            from: me,
            assetDeltas: [{ assetRef: BTC, amount: '-1000' }],
            feeAssetRef: BTC,
            fee: '5000',
            status: 'confirmed',
          },
        ]),
      ],
      {},
    );
    expect(events[0]?.fee?.amount).toBe(1000n);
    expect(events[0]?.legs).toEqual([]);
  });
});

describe('exports', () => {
  const records = [
    tx(X, A, '2024-01-10', [[ETH, E]]),
    tx(A, X, '2025-03-01', [[ETH, -E / 2n - E / 100n]], E / 100n),
  ];
  const report = buildReport({
    accounts: [account('a', 'w1', A)],
    histories: [history('a', records)],
    assets,
    prices,
    overrides: {},
    settings: settings(),
  });
  const ctx: ExportContext = {
    report,
    accounts: [account('a', 'w1', A)],
    assets,
    scopeLabel: 'all wallets',
    wallets: [{ id: 'w1', name: 'W1', kind: 'single', tags: ['local'] }],
    generatedAtMs: Date.UTC(2026, 0, 2),
    sources: ['https://api.coingecko.com'],
  };

  it('writes the CoinTracker and Blockpit templates', () => {
    const ct = exportCsv(ctx, 'cointracker').split('\r\n');
    expect(ct[0]).toBe(
      'Date,Received Quantity,Received Currency,Sent Quantity,Sent Currency,Fee Amount,Fee Currency,Tag',
    );
    expect(ct[1]).toBe('03/01/2025 12:00:00,,,0.5,ETH,0.01,ETH,');
    const bp = exportCsv(ctx, 'blockpit').split('\r\n');
    expect(bp[1]).toContain('01.03.2025 12:00:00');
    expect(bp[1]).toContain('Withdrawal');
  });

  it('writes 8949-style disposals with exact amounts', () => {
    const rows = exportCsv(ctx, 'disposals').split('\r\n');
    expect(rows[1]).toMatch(/^0\.5 ETH,2024-01-10,2025-03-01,1500\.00,500\.00,1000\.00,long-term/);
  });

  it('JSON carries a digest over its body', async () => {
    const doc = JSON.parse(await exportJson(ctx)) as Record<string, unknown> & {
      digest: { sha256: string };
      summary: { gain: string };
    };
    expect(doc['format']).toBe('stackwallet.tax-report');
    expect(doc.digest.sha256).toMatch(/^[0-9a-f]{64}$/);
    // 1000 on the sale plus 20 on the fee coin (worth 30, bought for 10).
    expect(doc.summary.gain).toBe('1020.000000');
  });

  it('the workbook is a zip and reproducible', () => {
    const a = exportXlsx(ctx);
    const b = exportXlsx(ctx);
    expect([a[0], a[1]]).toEqual([0x50, 0x4b]);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });
});
