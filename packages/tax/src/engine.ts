import { jurisdiction, taxYearLabel, taxYearRange, type Term } from './jurisdictions.js';
import {
  INCOME_LABELS,
  LABEL_TEXT,
  type AccountHistory,
  type AssetInfo,
  type Disposal,
  type Holding,
  type IncomeItem,
  type Issue,
  type Label,
  type Lot,
  type Overrides,
  type PriceBook,
  type PricePoint,
  type ScopeAccount,
  type Summary,
  type TaxEvent,
  type TaxReport,
  type TaxSettings,
} from './model.js';
import { buildEvents } from './normalize.js';

/**
 * The cost-basis engine. Everything is integer arithmetic: amounts in base
 * units, money in micro-units of the report fiat, so an 18-decimal token and
 * a long history add up exactly. A value that cannot be proven (no price, no
 * acquisition on record) stays null and is reported as missing; it is never
 * filled with zero, which would silently turn into a gain.
 */

const DAY = 86_400_000;
/** A daily price is good for the day it describes and the next. */
export const PRICE_MAX_AGE_MS = 2 * DAY + 3_600_000;

export interface ReportInput {
  accounts: readonly ScopeAccount[];
  histories: readonly AccountHistory[];
  assets: ReadonlyMap<string, AssetInfo>;
  prices: PriceBook;
  overrides: Overrides;
  settings: TaxSettings;
  now?: number;
}

export function priceAt(points: readonly PricePoint[] | undefined, t: number): number | null {
  if (!points || points.length === 0) return null;
  let lo = 0;
  let hi = points.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if ((points[mid] as PricePoint).t <= t) {
      found = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  // A coin listed after `t` has no price then; the first point is not borrowed backwards.
  if (found < 0) return null;
  const p = points[found] as PricePoint;
  return t - p.t <= PRICE_MAX_AGE_MS ? p.v : null;
}

/** Fiat decimal string ("1234.56") to micros. */
export function toMicros(text: string): bigint {
  const [whole = '0', frac = ''] = text.split('.');
  return BigInt(whole) * 1_000_000n + BigInt((frac + '000000').slice(0, 6));
}

const abs = (n: bigint) => (n < 0n ? -n : n);

function split(total: bigint, weights: readonly bigint[]): bigint[] {
  const sum = weights.reduce((a, b) => a + b, 0n);
  if (weights.length === 0) return [];
  if (sum === 0n) {
    const each = total / BigInt(weights.length);
    return weights.map((_, i) =>
      i === weights.length - 1 ? total - each * BigInt(weights.length - 1) : each,
    );
  }
  let given = 0n;
  return weights.map((w, i) => {
    if (i === weights.length - 1) return total - given;
    const part = (total * w) / sum;
    given += part;
    return part;
  });
}

interface Slice {
  lot: Lot | null;
  amount: bigint;
  cost: bigint | null;
  acquiredAtMs: number | null;
}

export function buildReport(input: ReportInput): TaxReport {
  const { settings } = input;
  const now = input.now ?? Date.now();
  const j = jurisdiction(settings.jurisdiction);
  const period = taxYearRange(j, settings.year);
  const inPeriod = (t: number) => t >= period.startMs && t < period.endMs;
  const accounts = input.accounts.filter((a) => settings.includeTestnets || !a.testnet);
  const accountIds = new Set(accounts.map((a) => a.accountId));
  const histories = input.histories.filter((h) => accountIds.has(h.accountId));
  const events = buildEvents(accounts, histories, input.overrides);
  const issues: Issue[] = [];

  const assetOf = (ref: string) => input.assets.get(ref);
  const valueOf = (ref: string, amount: bigint, at: number): bigint | null => {
    const a = assetOf(ref);
    if (!a || a.decimals === null || !a.priceKey || a.testnet) return null;
    const price = priceAt(input.prices.get(a.priceKey), at);
    if (price === null) return null;
    // Nano-precision price keeps sub-cent tokens from rounding to zero.
    const nanos = BigInt(Math.round(price * 1e9));
    return (abs(amount) * nanos) / 10n ** BigInt(a.decimals + 3);
  };
  const walletOfAccount = new Map(accounts.map((a) => [a.accountId, a.walletId]));
  const poolOf = (walletId: string) => (settings.pooling === 'wallet' ? walletId : '*');

  const pools = new Map<string, Lot[]>();
  let lotSeq = 0;
  const lotsFor = (pool: string, assetRef: string) => {
    const key = `${pool}|${assetRef}`;
    let list = pools.get(key);
    if (!list) {
      list = [];
      pools.set(key, list);
    }
    return list;
  };
  const addLot = (
    walletId: string,
    assetRef: string,
    amount: bigint,
    cost: bigint | null,
    acquiredAtMs: number,
    eventId: string,
  ) => {
    if (amount <= 0n) return;
    const pool = poolOf(walletId);
    lotsFor(pool, assetRef).push({
      id: `L${++lotSeq}`,
      pool,
      walletId,
      assetRef,
      amount,
      cost,
      acquiredAtMs,
      eventId,
    });
  };

  const take = (walletId: string, assetRef: string, amount: bigint): Slice[] => {
    const list = lotsFor(poolOf(walletId), assetRef);
    if (settings.method === 'acb') {
      const known = list.filter((l) => l.cost !== null);
      const qty = known.reduce((s, l) => s + l.amount, 0n);
      const cost = known.reduce((s, l) => s + (l.cost as bigint), 0n);
      if (qty > 0n) {
        const costs = split(
          cost,
          known.map((l) => l.amount),
        );
        known.forEach((l, i) => (l.cost = costs[i] as bigint));
      }
    }
    const order = [...list];
    if (settings.method === 'lifo') order.sort((a, b) => b.acquiredAtMs - a.acquiredAtMs);
    else if (settings.method === 'hifo')
      order.sort((a, b) => {
        if (a.cost === null || b.cost === null) return a.cost === null ? 1 : -1;
        // Compare unit costs without division: a.cost/a.amount vs b.cost/b.amount.
        const lhs = a.cost * b.amount;
        const rhs = b.cost * a.amount;
        return lhs === rhs ? a.acquiredAtMs - b.acquiredAtMs : lhs > rhs ? -1 : 1;
      });
    else order.sort((a, b) => a.acquiredAtMs - b.acquiredAtMs);

    const slices: Slice[] = [];
    let left = amount;
    for (const lot of order) {
      if (left <= 0n) break;
      const n = lot.amount < left ? lot.amount : left;
      const cost = lot.cost === null ? null : (lot.cost * n) / lot.amount;
      slices.push({ lot, amount: n, cost, acquiredAtMs: lot.acquiredAtMs });
      lot.amount -= n;
      if (lot.cost !== null && cost !== null) lot.cost -= cost;
      left -= n;
    }
    for (let i = list.length - 1; i >= 0; i--) if ((list[i] as Lot).amount <= 0n) list.splice(i, 1);
    if (left > 0n) slices.push({ lot: null, amount: left, cost: null, acquiredAtMs: null });
    return slices;
  };

  const disposals: Disposal[] = [];
  const values = new Map<string, bigint | null>();
  const total = (xs: readonly (bigint | null | undefined)[]) =>
    xs.length > 0 && xs.every((x) => x !== null && x !== undefined)
      ? xs.reduce<bigint>((s, x) => s + (x as bigint), 0n)
      : null;
  const income: IncomeItem[] = [];
  let feeTotal = 0n;
  let holdingsAt: Lot[] | null = null;
  let dSeq = 0;
  const reported = new Set<string>();
  const testnetEvents = new Set(
    events
      .filter((e) => e.legs.length > 0 && e.legs.every((l) => assetOf(l.assetRef)?.testnet))
      .map((e) => e.id),
  );
  const flag = (issue: Issue) => {
    // Test coins have no market price by definition; asking for one is noise.
    if (issue.code === 'missing-price' && issue.eventId && testnetEvents.has(issue.eventId)) return;
    const key = `${issue.code}|${issue.eventId ?? ''}|${issue.accountId ?? ''}|${issue.message}`;
    if (!reported.has(key)) {
      reported.add(key);
      issues.push(issue);
    }
  };

  const dispose = (
    e: TaxEvent,
    walletId: string,
    assetRef: string,
    amount: bigint,
    proceeds: bigint | null,
    label: Label,
    removal: boolean,
    at: number,
  ) => {
    const slices = take(walletId, assetRef, amount);
    const parts =
      proceeds === null
        ? slices.map(() => null)
        : split(
            proceeds,
            slices.map((s) => s.amount),
          );
    slices.forEach((s, i) => {
      const p = removal ? null : (parts[i] ?? null);
      const term: Term | null =
        s.acquiredAtMs === null || removal ? null : j.term(s.acquiredAtMs, at);
      disposals.push({
        id: `D${++dSeq}`,
        eventId: e.id,
        label,
        walletId,
        assetRef,
        amount: s.amount,
        acquiredAtMs: s.acquiredAtMs,
        disposedAtMs: at,
        proceeds: p,
        cost: s.cost,
        gain: !removal && p !== null && s.cost !== null ? p - s.cost : null,
        term,
        lotId: s.lot?.id ?? null,
        hash: e.hash,
        chainId: e.chainId,
        removal,
      });
      if (s.lot === null && inPeriod(at) && !removal)
        flag({
          code: 'missing-basis',
          severity: 'blocker',
          eventId: e.id,
          message: `${symbolOf(assetRef)} sold or spent beyond what this history shows was acquired${
            settings.pooling === 'wallet' ? ' in this wallet' : ''
          }. Basis is unproven, as on a 1099-DA with “basis not reported”: label the matching deposit “From my other account” and enter what you paid.`,
        });
    });
  };
  const symbolOf = (ref: string) => assetOf(ref)?.symbol ?? ref.split(':').pop() ?? ref;

  for (const e of events) {
    if (e.label === 'spam') continue;
    if (e.timestampMs === null) {
      flag({
        code: 'no-timestamp',
        severity: 'warn',
        eventId: e.id,
        message: 'The endpoint gave no time for this transaction, so it is left out of the books.',
      });
      continue;
    }
    const t = e.timestampMs;
    if (t >= period.endMs && holdingsAt === null)
      holdingsAt = [...pools.values()].flat().map((l) => ({ ...l }));
    if (t >= period.endMs) break;
    if (e.status === 'pending') {
      if (inPeriod(t))
        flag({
          code: 'pending',
          severity: 'info',
          eventId: e.id,
          message: 'Still pending on chain; left out until it confirms.',
        });
      continue;
    }
    const here = inPeriod(t);

    for (const m of e.moves) {
      const from = walletOfAccount.get(m.fromAccountId) as string;
      const to = walletOfAccount.get(m.toAccountId) as string;
      if (poolOf(from) === poolOf(to)) continue;
      for (const s of take(from, m.assetRef, m.amount))
        addLot(to, m.assetRef, s.amount, s.cost, s.acquiredAtMs ?? t, s.lot?.eventId ?? e.id);
    }

    const net = new Map<string, { walletId: string; amount: bigint }[]>();
    for (const l of e.legs) {
      const list = net.get(l.assetRef) ?? [];
      list.push({ walletId: l.walletId, amount: l.amount });
      net.set(l.assetRef, list);
    }
    // Per wallet, after own-account moves cancel out.
    const flows: { walletId: string; assetRef: string; amount: bigint }[] = [];
    for (const [assetRef, list] of net) {
      let total = list.reduce((s, x) => s + x.amount, 0n);
      if (total === 0n) continue;
      const sign = total > 0n ? 1n : -1n;
      for (const x of list) {
        if (total === 0n) break;
        if (x.amount * sign <= 0n) continue;
        const n = abs(x.amount) < abs(total) ? x.amount : total;
        flows.push({ walletId: x.walletId, assetRef, amount: n });
        total -= n;
      }
    }
    const ins = flows.filter((f) => f.amount > 0n);
    const outs = flows.filter((f) => f.amount < 0n);
    const fixed = e.override?.value !== undefined ? toMicros(e.override.value) : null;

    for (const f of [...ins, ...outs])
      if (assetOf(f.assetRef)?.decimals === null && here)
        flag({
          code: 'unknown-decimals',
          severity: 'warn',
          eventId: e.id,
          message: `${symbolOf(f.assetRef)} is not a tracked token, so its decimals and price are unknown. Track it in Tokens, or enter the value.`,
        });

    if (e.label === 'trade') {
      const inVals = ins.map((f) => valueOf(f.assetRef, f.amount, t));
      const outVals = outs.map((f) => valueOf(f.assetRef, f.amount, t));
      const sum = (xs: (bigint | null)[]) =>
        xs.length > 0 && xs.every((x) => x !== null)
          ? xs.reduce<bigint>((s, x) => s + (x as bigint), 0n)
          : null;
      const value = fixed ?? sum(inVals) ?? sum(outVals);
      values.set(e.id, value);
      if (value === null && here)
        flag({
          code: 'missing-price',
          severity: 'blocker',
          eventId: e.id,
          message: 'No market price for either side of this trade. Enter its value.',
        });
      const outParts =
        value === null
          ? outs.map(() => null)
          : split(
              value,
              outs.map((f, i) => outVals[i] ?? abs(f.amount)),
            );
      outs.forEach((f, i) =>
        dispose(e, f.walletId, f.assetRef, -f.amount, outParts[i] ?? null, 'trade', false, t),
      );
      const inParts =
        value === null
          ? ins.map(() => null)
          : split(
              value,
              ins.map((f, i) => inVals[i] ?? f.amount),
            );
      ins.forEach((f, i) => addLot(f.walletId, f.assetRef, f.amount, inParts[i] ?? null, t, e.id));
    } else {
      const inVals = ins.map((f) => valueOf(f.assetRef, f.amount, t));
      const inParts =
        fixed !== null
          ? split(
              fixed,
              ins.map((f) => f.amount),
            )
          : inVals;
      ins.forEach((f, i) => {
        const v = inParts[i] ?? null;
        if (e.label === 'transfer-in' || e.label === 'gift-in') {
          const basis =
            e.override?.basis !== undefined
              ? (split(
                  toMicros(e.override.basis),
                  ins.map((x) => x.amount),
                )[i] ?? null)
              : null;
          const acquired = e.override?.acquiredAtMs ?? t;
          addLot(f.walletId, f.assetRef, f.amount, basis, acquired, e.id);
          if (basis === null && here)
            flag({
              code: 'missing-basis',
              severity: 'warn',
              eventId: e.id,
              message: `${LABEL_TEXT[e.label]}: enter the original cost and date of these ${symbolOf(f.assetRef)}, or a later sale reports its basis as missing.`,
            });
          return;
        }
        addLot(f.walletId, f.assetRef, f.amount, v, t, e.id);
        if (v === null && here)
          flag({
            code: 'missing-price',
            severity: 'warn',
            eventId: e.id,
            message: `No market price for ${symbolOf(f.assetRef)} at this time. Enter the value received.`,
          });
        if (INCOME_LABELS.has(e.label) && here)
          income.push({
            eventId: e.id,
            label: e.label,
            walletId: f.walletId,
            assetRef: f.assetRef,
            amount: f.amount,
            atMs: t,
            value: v,
            hash: e.hash,
            chainId: e.chainId,
          });
      });
      const removal = ['gift-out', 'transfer-out', 'lost'].includes(e.label);
      const outVals = outs.map((f) => valueOf(f.assetRef, -f.amount, t));
      const outParts =
        fixed !== null
          ? split(
              fixed,
              outs.map((f) => -f.amount),
            )
          : outVals;
      values.set(e.id, ins.length > 0 ? total(inParts) : outs.length > 0 ? total(outParts) : null);
      outs.forEach((f, i) => {
        const p = outParts[i] ?? null;
        if (p === null && !removal && here)
          flag({
            code: 'missing-price',
            severity: 'blocker',
            eventId: e.id,
            message: `No market price for ${symbolOf(f.assetRef)} at this time. Enter the value of what was sent.`,
          });
        dispose(e, f.walletId, f.assetRef, -f.amount, p, e.label, removal, t);
      });
    }

    if (e.fee) {
      const v = valueOf(e.fee.assetRef, e.fee.amount, t);
      if (here && v !== null) feeTotal += v;
      dispose(
        e,
        e.fee.walletId,
        e.fee.assetRef,
        e.fee.amount,
        v,
        'fee',
        settings.fees === 'ignore',
        t,
      );
    }
    if (e.feeUnknown && here)
      flag({
        code: 'unknown-fee',
        severity: 'info',
        eventId: e.id,
        message: 'The endpoint did not report this fee; the value moved may be understated.',
      });
    if (!e.reviewed && here)
      flag({
        code: 'unreviewed',
        severity: 'warn',
        eventId: e.id,
        message:
          e.auto === 'receive'
            ? 'Incoming coins without a label are counted as bought at market value. Mark income, a gift, or coins from your own account.'
            : 'Outgoing coins without a label are counted as sold at market value. Mark a gift, a payment, or coins to your own account.',
      });
  }
  if (holdingsAt === null) holdingsAt = [...pools.values()].flat().map((l) => ({ ...l }));

  for (const a of accounts) {
    const h = histories.find((x) => x.accountId === a.accountId);
    if (!h)
      flag({
        code: 'history-incomplete',
        severity: 'blocker',
        accountId: a.accountId,
        message: `${a.walletName} · ${a.chainName}: history not read yet.`,
      });
    else if (h.error)
      flag({
        code: 'history-error',
        severity: 'blocker',
        accountId: a.accountId,
        message: `${a.walletName} · ${a.chainName}: ${h.error}`,
      });
    else if (!h.complete)
      flag({
        code: 'history-incomplete',
        severity: 'warn',
        accountId: a.accountId,
        message: `${a.walletName} · ${a.chainName}: only the newest records were read. Older acquisitions may be missing, which shows up as missing basis.`,
      });
  }

  const valuedAt = Math.min(period.endMs - 1, now);
  const holdMap = new Map<string, Holding>();
  for (const l of holdingsAt) {
    const walletId = settings.pooling === 'wallet' ? l.walletId : '*';
    const key = `${walletId}|${l.assetRef}`;
    const h = holdMap.get(key) ?? {
      walletId,
      assetRef: l.assetRef,
      amount: 0n,
      cost: 0n,
      value: null,
      earliestAtMs: null,
      lots: 0,
    };
    h.amount += l.amount;
    h.cost = h.cost === null || l.cost === null ? null : h.cost + l.cost;
    h.earliestAtMs =
      h.earliestAtMs === null ? l.acquiredAtMs : Math.min(h.earliestAtMs, l.acquiredAtMs);
    h.lots += 1;
    holdMap.set(key, h);
  }
  const holdings = [...holdMap.values()]
    .filter((h) => h.amount > 0n)
    .map((h) => ({ ...h, value: valueOf(h.assetRef, h.amount, valuedAt) }))
    .sort((a, b) => a.assetRef.localeCompare(b.assetRef) || a.walletId.localeCompare(b.walletId));

  const periodDisposals = disposals.filter((d) => inPeriod(d.disposedAtMs));
  const sales = periodDisposals.filter((d) => !d.removal);
  const summary: Summary = {
    fiat: settings.fiat,
    proceeds: 0n,
    cost: 0n,
    gain: 0n,
    byTerm: {},
    income: 0n,
    incomeByLabel: {},
    fees: feeTotal,
    disposals: sales.length,
    unknownBasisDisposals: sales.filter((d) => d.cost === null).length,
    unknownBasisProceeds: 0n,
    unpricedDisposals: sales.filter((d) => d.proceeds === null).length,
    events: 0,
    reviewed: 0,
  };
  for (const d of sales) {
    if (d.proceeds !== null) summary.proceeds += d.proceeds;
    if (d.proceeds !== null && d.cost === null) summary.unknownBasisProceeds += d.proceeds;
    if (d.cost !== null) summary.cost += d.cost;
    if (d.gain !== null) summary.gain += d.gain;
    // Only fully valued lots go into a term, so each row's proceeds minus cost is its gain.
    if (d.term && d.proceeds !== null && d.cost !== null && d.gain !== null) {
      const b = summary.byTerm[d.term] ?? { proceeds: 0n, cost: 0n, gain: 0n, count: 0 };
      b.count += 1;
      b.proceeds += d.proceeds;
      b.cost += d.cost;
      b.gain += d.gain;
      summary.byTerm[d.term] = b;
    }
  }
  for (const i of income)
    if (i.value !== null) {
      summary.income += i.value;
      summary.incomeByLabel[i.label] = (summary.incomeByLabel[i.label] ?? 0n) + i.value;
    }
  const periodEvents = events.filter((e) => e.timestampMs !== null && inPeriod(e.timestampMs));
  summary.events = periodEvents.length;
  summary.reviewed = periodEvents.filter((e) => e.reviewed || e.label === 'spam').length;

  const complete = accounts.filter((a) => {
    const h = histories.find((x) => x.accountId === a.accountId);
    return h && !h.error && h.complete;
  }).length;
  const ratio = (n: number, d: number) => (d === 0 ? 1 : n / d);
  const pricedNeed = sales.length + income.length;
  const readiness = {
    history: ratio(complete, accounts.length),
    reviewed: ratio(summary.reviewed, summary.events),
    priced: ratio(
      sales.filter((d) => d.proceeds !== null).length +
        income.filter((i) => i.value !== null).length,
      pricedNeed,
    ),
    basis: ratio(sales.length - summary.unknownBasisDisposals, sales.length),
    score: 0,
  };
  readiness.score = Math.min(
    readiness.history,
    readiness.reviewed,
    readiness.priced,
    readiness.basis,
  );

  const order = { blocker: 0, warn: 1, info: 2 } as const;
  issues.sort((a, b) => order[a.severity] - order[b.severity]);

  return {
    settings,
    period: { ...period, label: taxYearLabel(j, settings.year) },
    events: periodEvents,
    values,
    disposals: periodDisposals,
    income,
    holdings,
    issues,
    summary,
    readiness,
  };
}
