import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Badge, Button, Chip, Input, Select } from '@stackwallet/ui';
import {
  buildReport,
  CSV_PRESETS,
  describeScope,
  DISCLAIMER,
  eventFlows,
  exportCsv,
  exportFileName,
  exportJson,
  exportXlsx,
  FIAT_SYMBOL,
  FIATS,
  formatMoney,
  INCOME_LABELS,
  JURISDICTIONS,
  jurisdiction,
  LABEL_HELP,
  LABEL_TEXT,
  labelsFor,
  METHOD_LABEL,
  PRESET_TEXT,
  resolveScope,
  SCOPE_TAG_HELP,
  SCOPE_TAG_TEXT,
  SCOPE_TAGS,
  TERM_LABEL,
  taxYearLabel,
  taxYearOf,
  units,
  type AssetInfo,
  type CsvPreset,
  type ExportContext,
  type Issue,
  type Label,
  type ScopeTag,
  type TaxEvent,
  type TaxReport,
} from '@stackwallet/tax';

import { vault } from '../../core/bridge.js';
import { useVaultView } from '../../core/vault.js';
import { explorerTxUrl, findChain } from '../../lib/chains.js';
import { marketSettings, useMarketSettings } from '../../store/market.js';
import { useDirectory } from '../../store/persist.js';
import { useRegistry } from '../../store/RegistryContext.js';
import {
  assetInfoFor,
  historyKey,
  priceBookKey,
  reportedAssets,
  scopeAccounts,
  scopeWallets,
  tagsFor,
  taxStore,
  useTax,
} from '../../store/tax.js';
import { useTokens } from '../../store/tokens.js';
import type { ElementBodyProps } from './types.js';

const TABS = [
  'summary',
  'review',
  'gains',
  'income',
  'holdings',
  'scope',
  'export',
  'rules',
] as const;
type Tab = (typeof TABS)[number];

const ROW_LIMIT = 400;

const day = (ms: number | null) => (ms === null ? '—' : new Date(ms).toISOString().slice(0, 10));
const stamp = (ms: number | null) =>
  ms === null ? 'time unknown' : new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
const pct = (x: number) => `${Math.floor(x * 100)}%`;

function amountText(amount: bigint, info: AssetInfo | undefined, symbol = true): string {
  const neg = amount < 0n;
  const abs = neg ? -amount : amount;
  const sym = symbol && info ? ' ' + info.symbol : '';
  if (!info || info.decimals === null) return `${neg ? '−' : ''}${abs} base units${sym}`;
  let text = units(abs, info.decimals);
  const dot = text.indexOf('.');
  if (dot >= 0 && text.length - dot - 1 > 8) {
    const first = text.slice(dot + 1).search(/[1-9]/);
    // Dust keeps four significant digits instead of truncating to a misleading 0.
    const keep = text.startsWith('0.') && first >= 8 ? first + 4 : 8;
    text = text.slice(0, dot + 1 + keep).replace(/\.?0+$/, '');
  }
  return `${neg ? '−' : ''}${text}${sym}`;
}

function download(name: string, data: BlobPart, type: string): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([data], { type }));
  a.download = name;
  a.hidden = true;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function Section({
  title,
  aside,
  children,
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="mt-4 first:mt-0">
      <div className="mb-2 flex items-baseline justify-between gap-2">
        <h3 className="text-[10px] uppercase tracking-[0.12em] text-faint">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  );
}

function Stat({
  label,
  value,
  tone,
  sub,
}: {
  label: string;
  value: string;
  tone?: 'ok' | 'danger' | undefined;
  sub?: string | undefined;
}) {
  return (
    <div className="min-w-[9rem] flex-1 rounded-sw-sm border border-edge px-3 py-2">
      <div className="text-[10px] uppercase tracking-[0.1em] text-faint">{label}</div>
      <div
        className={`mt-1 select-text text-[15px] tabular-nums ${tone === 'danger' ? 'text-danger' : tone === 'ok' ? 'text-ok' : 'text-ink'}`}
      >
        {value}
      </div>
      {sub && <div className="mt-0.5 text-[10px] text-faint">{sub}</div>}
    </div>
  );
}

function Meter({ label, value, help }: { label: string; value: number; help: string }) {
  return (
    <div className="min-w-[6rem] flex-1" title={help}>
      <div className="flex justify-between text-[10px] text-faint">
        <span>{label}</span>
        <span className={value >= 1 ? 'text-ok' : 'text-muted'}>{pct(value)}</span>
      </div>
      <div className="mt-1 h-[3px] overflow-hidden rounded-full bg-edge">
        <div
          className={`sw-tax-meter h-full w-full origin-left rounded-full ${value >= 1 ? 'bg-ok' : 'bg-ink'}`}
          style={{ transform: `scaleX(${Math.max(0, Math.min(1, value))})` }}
        />
      </div>
    </div>
  );
}

function Table({ head, rows, empty }: { head: string[]; rows: ReactNode[][]; empty: string }) {
  if (rows.length === 0) return <p className="py-3 text-faint">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-max border-collapse text-left text-[11px] tabular-nums">
        <thead>
          <tr className="text-faint">
            {head.map((h) => (
              <th key={h} className="border-b border-edge px-2 py-1.5 font-normal">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="select-text">
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-edge/60 hover:bg-elevated">
              {r.map((c, k) => (
                <td key={k} className="px-2 py-1.5 align-top text-muted">
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A decimal input that commits on blur or Enter, so typing does not recompute the books per key. */
function DecimalField({
  label,
  value,
  placeholder,
  onCommit,
}: {
  label: string;
  value: string | undefined;
  placeholder: string;
  onCommit: (v: string | undefined) => void;
}) {
  const [text, setText] = useState(value ?? '');
  useEffect(() => setText(value ?? ''), [value]);
  const valid = text === '' || /^\d{1,30}(\.\d{1,18})?$/.test(text.replace(/,/g, ''));
  const commit = () => {
    const clean = text.replace(/,/g, '').trim();
    if (clean === (value ?? '')) return;
    if (clean === '' || /^\d{1,30}(\.\d{1,18})?$/.test(clean)) onCommit(clean || undefined);
  };
  return (
    <label className="flex min-w-[8rem] flex-1 flex-col gap-1 text-[10px] text-faint">
      {label}
      <Input
        inputMode="decimal"
        aria-invalid={!valid}
        placeholder={placeholder}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') commit();
        }}
        className={valid ? '' : 'border-danger/60'}
      />
    </label>
  );
}

interface Ctx {
  report: TaxReport;
  assets: ReadonlyMap<string, AssetInfo>;
  walletName: (id: string) => string;
  chainName: (id: string) => string;
  explorer: (chainId: string, hash: string) => string | undefined;
}

function EventCard({ e, issues, ctx }: { e: TaxEvent; issues: readonly Issue[]; ctx: Ctx }) {
  const { report, assets } = ctx;
  const fiat = report.settings.fiat;
  const flows = eventFlows(e);
  const value = report.values.get(e.id);
  const options = labelsFor(e.auto);
  const wallets = [...new Set(e.legs.map((l) => l.walletId))];
  const url = ctx.explorer(e.chainId, e.hash);
  const needsBasis = e.label === 'transfer-in' || e.label === 'gift-in';
  const o = e.override;
  const blocker = issues.some((i) => i.severity === 'blocker');
  return (
    <article
      className={`sw-tax-card rounded-sw-sm border px-3 py-2.5 ${blocker ? 'border-danger/50' : 'border-edge'}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-ink">
            {flows.ins.map((f) => (
              <span key={'i' + f.assetRef} className="tabular-nums text-ok">
                +{amountText(f.amount, assets.get(f.assetRef))}
              </span>
            ))}
            {flows.outs.map((f) => (
              <span key={'o' + f.assetRef} className="tabular-nums">
                −{amountText(f.amount, assets.get(f.assetRef))}
              </span>
            ))}
            {flows.ins.length === 0 && flows.outs.length === 0 && (
              <span className="text-muted">
                {e.moves.length > 0 ? 'moved between your accounts' : 'fee only'}
              </span>
            )}
            <span className="text-faint">
              {value === undefined
                ? ''
                : value === null
                  ? '· value unknown'
                  : '· ' + formatMoney(value, fiat)}
            </span>
          </div>
          <div className="mt-1 text-[10px] text-faint">
            {stamp(e.timestampMs)} · {ctx.chainName(e.chainId)} ·{' '}
            {wallets.map(ctx.walletName).join(', ')}
            {e.counterparty ? ` · ${e.counterparty.slice(0, 8)}…${e.counterparty.slice(-6)}` : ''}
            {e.status !== 'confirmed' ? ` · ${e.status}` : ''}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {e.reviewed ? <Badge tone="ok">reviewed</Badge> : <Badge tone="warm">to review</Badge>}
          <Select
            aria-label="Label"
            value={e.label}
            disabled={options.length <= 1}
            onChange={(ev) => {
              const label = ev.target.value as Label;
              taxStore.review(e.id, { label });
            }}
          >
            {options.map((l) => (
              <option key={l} value={l}>
                {LABEL_TEXT[l]}
              </option>
            ))}
          </Select>
        </div>
      </div>
      <p className="mt-1.5 text-[10px] leading-relaxed text-faint">{LABEL_HELP[e.label]}</p>
      {issues.length > 0 && (
        <ul className="mt-1.5 space-y-0.5 text-[11px] leading-relaxed">
          {issues.map((i, k) => (
            <li key={k} className={i.severity === 'blocker' ? 'text-danger' : 'text-muted'}>
              {i.message}
            </li>
          ))}
        </ul>
      )}
      {e.label !== 'spam' && (
        <div className="mt-2 flex flex-wrap gap-2">
          <DecimalField
            label={`value ${FIAT_SYMBOL[fiat]} (overrides market)`}
            value={o?.value}
            placeholder={value ? formatMoney(value, fiat).replace(/[^\d.]/g, '') : 'enter value'}
            onCommit={(v) => taxStore.review(e.id, { value: v })}
          />
          {needsBasis && (
            <>
              <DecimalField
                label={`original cost ${FIAT_SYMBOL[fiat]}`}
                value={o?.basis}
                placeholder="what you paid"
                onCommit={(v) => taxStore.review(e.id, { basis: v })}
              />
              <label className="flex min-w-[8rem] flex-1 flex-col gap-1 text-[10px] text-faint">
                originally acquired (UTC)
                <Input
                  type="date"
                  value={o?.acquiredAtMs === undefined ? '' : day(o.acquiredAtMs)}
                  onChange={(ev) => {
                    const ms = ev.target.value ? Date.parse(ev.target.value + 'T00:00:00Z') : NaN;
                    taxStore.review(e.id, { acquiredAtMs: Number.isFinite(ms) ? ms : undefined });
                  }}
                />
              </label>
            </>
          )}
        </div>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-3 text-[10px] text-faint">
        <input
          aria-label="Note"
          className="min-w-0 flex-1 border-b border-transparent bg-transparent py-0.5 text-muted outline-none placeholder:text-faint focus:border-edge"
          placeholder="note for your records"
          defaultValue={o?.note ?? ''}
          maxLength={500}
          onBlur={(ev) => {
            if (ev.target.value !== (o?.note ?? ''))
              taxStore.review(e.id, { note: ev.target.value || undefined });
          }}
        />
        {o && (
          <button
            type="button"
            className="sw-pressable text-faint hover:text-ink"
            onClick={() => taxStore.review(e.id, null)}
          >
            reset
          </button>
        )}
        {url && (
          <a className="text-muted underline" href={url} target="_blank" rel="noreferrer noopener">
            explorer ↗
          </a>
        )}
      </div>
    </article>
  );
}

export function TaxElement({ pane, setProps }: ElementBodyProps) {
  const state = useDirectory();
  const registry = useRegistry();
  const { provenance, status } = useVaultView(vault);
  const tax = useTax();
  const market = useMarketSettings();
  const tokens = useTokens();
  const { settings, scope } = tax.prefs;
  const j = jurisdiction(settings.jurisdiction);
  const tab: Tab = TABS.includes(pane.props['tab'] as Tab) ? (pane.props['tab'] as Tab) : 'summary';
  const [reviewFilter, setReviewFilter] = useState<'attention' | 'unreviewed' | 'all'>('attention');
  const [limit, setLimit] = useState(60);
  const [delimiter, setDelimiter] = useState<',' | ';'>(',');
  const [notice, setNotice] = useState('');

  const { wallets, folders } = useMemo(() => scopeWallets(state, provenance), [state, provenance]);
  const resolved = useMemo(() => resolveScope(scope, wallets, folders), [scope, wallets, folders]);
  const includedIds = useMemo(() => new Set(resolved.included.map((w) => w.id)), [resolved]);
  const accounts = useMemo(
    () => scopeAccounts(state, registry, includedIds, settings.includeTestnets),
    [state, registry, includedIds, settings.includeTestnets],
  );
  const histories = useMemo(
    () =>
      accounts.flatMap((a) => {
        const h = tax.histories.get(a.accountId);
        return h && h.key === historyKey(a) ? [h.history] : [];
      }),
    [accounts, tax.histories],
  );
  const assets = useMemo(() => {
    const refs = new Set<string>();
    for (const h of histories) {
      for (const r of h.records) {
        refs.add(r.feeAssetRef);
        for (const d of r.assetDeltas) refs.add(d.assetRef);
      }
      for (const b of h.balances ?? []) refs.add(b.assetRef);
    }
    const reported = reportedAssets(histories);
    return new Map([...refs].map((ref) => [ref, assetInfoFor(registry, ref, reported.get(ref))]));
    // Tracked tokens change symbols and decimals.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [histories, registry, tokens]);
  const priceKeys = useMemo(
    () =>
      [
        ...new Set(
          [...assets.values()].flatMap((a) => (a.priceKey && !a.testnet ? [a.priceKey] : [])),
        ),
      ].sort(),
    [assets],
  );
  const priceKeyList = priceKeys.join(',');
  useEffect(() => {
    if (market.coingecko && priceKeyList)
      void taxStore.loadPrices(priceKeyList.split(','), settings.fiat);
  }, [market.coingecko, priceKeyList, settings.fiat]);
  const prices = useMemo(
    () => new Map(priceKeys.map((k) => [k, tax.prices.get(priceBookKey(settings.fiat, k)) ?? []])),
    [priceKeys, tax.prices, settings.fiat],
  );
  const report = useMemo(
    () => buildReport({ accounts, histories, assets, prices, overrides: tax.overrides, settings }),
    [accounts, histories, assets, prices, tax.overrides, settings],
  );

  const walletById = useMemo(() => new Map(state.wallets.map((w) => [w.id, w])), [state.wallets]);
  const ctx: Ctx = {
    report,
    assets,
    walletName: (id) => walletById.get(id)?.name ?? id,
    chainName: (id) => findChain(registry, id)?.name ?? id,
    explorer: (chainId, hash) => {
      const chain = findChain(registry, chainId);
      // Beacon withdrawals have no transaction to link to.
      return chain && !hash.startsWith('withdrawal-') ? explorerTxUrl(chain, hash) : undefined;
    },
  };
  const inPeriod = (t: number | null) =>
    t !== null && t >= report.period.startMs && t < report.period.endMs;
  const issuesByEvent = useMemo(() => {
    const m = new Map<string, Issue[]>();
    for (const i of report.issues)
      if (i.eventId) m.set(i.eventId, [...(m.get(i.eventId) ?? []), i]);
    return m;
  }, [report.issues]);
  const accountIssues = report.issues.filter((i) => !i.eventId);
  const blockers = report.issues.filter((i) => i.severity === 'blocker').length;
  const attention = report.events.filter(
    (e) =>
      e.label !== 'spam' &&
      ((issuesByEvent.get(e.id) ?? []).some((i) => i.severity !== 'info') ||
        (!e.reviewed && inPeriod(e.timestampMs))),
  );
  const reviewList =
    reviewFilter === 'attention'
      ? attention
      : reviewFilter === 'unreviewed'
        ? report.events.filter((e) => !e.reviewed)
        : report.events.filter((e) => inPeriod(e.timestampMs));
  const spamCandidates = report.events.filter(
    (e) =>
      e.auto === 'receive' &&
      !e.override?.label &&
      e.legs.every((l) => !l.assetRef.endsWith(':native')) &&
      report.values.get(e.id) === null,
  );
  const unreviewedPeriod = report.events.filter((e) => !e.reviewed && inPeriod(e.timestampMs));

  const now = Date.now();
  const firstYear = useMemo(() => {
    const ts = report.events.map((e) => e.timestampMs).filter((t): t is number => t !== null);
    return ts.length ? taxYearOf(j, Math.min(...ts)) : taxYearOf(j, now) - 3;
  }, [report.events, j, now]);
  const lastYear = taxYearOf(j, now);
  const years: number[] = [];
  for (let y = lastYear; y >= Math.min(firstYear, settings.year); y--) years.push(y);

  const syncedCount = accounts.filter(
    (a) => tax.histories.get(a.accountId)?.key === historyKey(a),
  ).length;
  const sync = (force: boolean) =>
    void taxStore.syncHistories(
      registry,
      accounts.map((a) => ({ accountId: a.accountId, chainId: a.chainId, address: a.address })),
      force,
    );
  const scopeLabel = describeScope(
    scope,
    folders,
    resolved.included.length,
    resolved.candidates.length,
  );
  const exportCtx = (): ExportContext => ({
    report,
    accounts,
    assets,
    scopeLabel,
    wallets: resolved.included.map((w) => ({
      id: w.id,
      name: w.name,
      kind: w.kind,
      tags: tagsFor(w, folders),
    })),
    generatedAtMs: Date.now(),
    sources: [
      ...new Set(histories.flatMap((h) => h.sources)),
      ...(priceKeys.length ? ['CoinGecko public API · daily market_chart'] : []),
    ],
  });
  const toggleTag = (t: ScopeTag) =>
    taxStore.setScope({
      tags: scope.tags.includes(t) ? scope.tags.filter((x) => x !== t) : [...scope.tags, t],
    });

  const s = report.summary;
  const fiat = settings.fiat;

  return (
    <div className="sw-tax flex h-full flex-col text-[12px]">
      <header className="shrink-0 border-b border-edge px-3 pb-2 pt-3">
        <div className="flex flex-wrap items-center gap-2">
          <Select
            aria-label="Tax year"
            value={String(settings.year)}
            onChange={(e) => taxStore.setSettings({ year: Number(e.target.value) })}
          >
            {years.map((y) => (
              <option key={y} value={y}>
                {taxYearLabel(j, y)}
                {y === lastYear ? ' · in progress' : ''}
              </option>
            ))}
          </Select>
          <Select
            aria-label="Tax residence"
            value={j.id}
            onChange={(e) => {
              const next = jurisdiction(e.target.value);
              taxStore.setSettings({ jurisdiction: next.id, method: next.method, fiat: next.fiat });
            }}
          >
            {JURISDICTIONS.map((x) => (
              <option key={x.id} value={x.id}>
                {x.name}
              </option>
            ))}
          </Select>
          <span className="min-w-0 flex-1 truncate text-[11px] text-faint" title={scopeLabel}>
            {scopeLabel} · {accounts.length} account{accounts.length === 1 ? '' : 's'}
          </span>
          {tax.syncing ? (
            <Button size="sm" variant="ghost" onClick={() => taxStore.cancelSync()}>
              Reading {tax.syncing.done}/{tax.syncing.total} · stop
            </Button>
          ) : (
            <Button
              size="sm"
              variant={syncedCount < accounts.length ? 'primary' : 'default'}
              disabled={accounts.length === 0}
              title="Reads send each address to its chain's public indexer or RPC."
              onClick={() => sync(syncedCount === accounts.length)}
            >
              {syncedCount === 0
                ? 'Read history'
                : syncedCount < accounts.length
                  ? `Read ${accounts.length - syncedCount} more`
                  : 'Refresh'}
            </Button>
          )}
        </div>
        <div className="mt-2.5 flex flex-wrap items-end gap-3">
          <div className="mr-1">
            <div className="text-[10px] uppercase tracking-[0.1em] text-faint">ready</div>
            <div
              className={`text-[18px] leading-none tabular-nums ${report.readiness.score >= 1 ? 'text-ok' : 'text-ink'}`}
            >
              {pct(report.readiness.score)}
            </div>
          </div>
          <Meter
            label="history"
            value={report.readiness.history}
            help="Accounts whose full public history was read."
          />
          <Meter
            label="reviewed"
            value={report.readiness.reviewed}
            help="Transactions in this period with a confirmed label."
          />
          <Meter
            label="priced"
            value={report.readiness.priced}
            help="Taxable events with a market or entered value."
          />
          <Meter
            label="basis"
            value={report.readiness.basis}
            help="Disposals whose cost basis is proven by the history."
          />
        </div>
        <nav className="-mb-2 mt-2 flex gap-0.5 overflow-x-auto" aria-label="Tax sections">
          {TABS.map((t) => (
            <button
              key={t}
              type="button"
              aria-current={tab === t ? 'page' : undefined}
              onClick={() => setProps({ tab: t })}
              className={`sw-pressable relative whitespace-nowrap px-2 py-1.5 text-[11px] ${
                tab === t ? 'text-ink' : 'text-faint hover:text-muted'
              }`}
            >
              {t}
              {t === 'review' && attention.length > 0 && (
                <span className="ml-1 tabular-nums text-warm">{attention.length}</span>
              )}
              {tab === t && <span className="sw-tax-tab absolute inset-x-2 bottom-0 h-px bg-ink" />}
            </button>
          ))}
        </nav>
      </header>

      <div key={tab} className="sw-tax-body min-h-0 flex-1 overflow-auto px-3 py-3">
        {notice && (
          <p role="status" className="mb-3 text-[11px] text-muted">
            {notice}
          </p>
        )}
        {state.wallets.length === 0 ? (
          <p className="text-faint">
            Add or watch a wallet first; its public history becomes the books here.
          </p>
        ) : tab === 'summary' ? (
          <>
            {syncedCount === 0 && (
              <div className="mb-4 rounded-sw-sm border border-edge px-3 py-3 leading-relaxed text-muted">
                <p className="text-ink">Build your {taxYearLabel(j, settings.year)} report.</p>
                <ol className="mt-1.5 list-decimal space-y-0.5 pl-4 text-[11px]">
                  <li>
                    Pick the wallets in scope: watched, imported, exported, a directory, or by hand.
                  </li>
                  <li>
                    Read their public history. Every lot since each wallet’s first transaction is
                    rebuilt here.
                  </li>
                  <li>
                    Review what the chain cannot tell: gifts, income, and transfers from exchanges.
                  </li>
                  <li>
                    Export a workbook, a JSON report, or CSV for CoinTracker, Blockpit or Koinly.
                  </li>
                </ol>
                <p className="mt-2 text-[10px] text-faint">
                  Computed on this device. Reads send each address to its chain’s public indexer;
                  price requests name coins only.
                </p>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <Stat
                label="net gain"
                value={formatMoney(s.gain, fiat)}
                tone={s.gain < 0n ? 'danger' : undefined}
                sub={`${s.disposals} disposal${s.disposals === 1 ? '' : 's'}`}
              />
              <Stat label="proceeds" value={formatMoney(s.proceeds, fiat)} />
              <Stat
                label="cost basis"
                value={formatMoney(s.cost, fiat)}
                sub={
                  s.unknownBasisDisposals ? `${s.unknownBasisDisposals} without basis` : undefined
                }
              />
              <Stat label="income" value={formatMoney(s.income, fiat)} />
              <Stat label="fees" value={formatMoney(s.fees, fiat)} />
            </div>
            <Section title="by holding period">
              <Table
                head={['term', 'disposals', 'proceeds', 'cost', 'gain']}
                empty="No disposals in this period."
                rows={[
                  ...j.terms
                    .filter((t) => s.byTerm[t])
                    .map((t) => {
                      const b = s.byTerm[t]!;
                      return [
                        TERM_LABEL[t],
                        b.count,
                        formatMoney(b.proceeds, fiat),
                        formatMoney(b.cost, fiat),
                        formatMoney(b.gain, fiat),
                      ];
                    }),
                  ...(s.unknownBasisDisposals > 0
                    ? [
                        [
                          'basis missing',
                          s.unknownBasisDisposals,
                          formatMoney(s.unknownBasisProceeds, fiat),
                          '—',
                          'not counted',
                        ],
                      ]
                    : []),
                ]}
              />
            </Section>
            {Object.keys(s.incomeByLabel).length > 0 && (
              <Section title="income by kind">
                <Table
                  head={['kind', 'value']}
                  empty=""
                  rows={Object.entries(s.incomeByLabel).map(([l, v]) => [
                    LABEL_TEXT[l as Label],
                    formatMoney(v ?? 0n, fiat),
                  ])}
                />
              </Section>
            )}
            <Section
              title="open issues"
              aside={
                attention.length > 0 && (
                  <button
                    type="button"
                    className="text-[11px] text-muted underline"
                    onClick={() => setProps({ tab: 'review' })}
                  >
                    review {attention.length}
                  </button>
                )
              }
            >
              {report.issues.length === 0 ? (
                <p className="text-ok">Nothing flagged. Check the rules tab before you file.</p>
              ) : (
                <ul className="space-y-1 text-[11px] leading-relaxed">
                  {accountIssues.map((i, k) => (
                    <li key={k} className={i.severity === 'blocker' ? 'text-danger' : 'text-muted'}>
                      {i.message}
                    </li>
                  ))}
                  <li className="text-muted">
                    {blockers} blocking · {report.issues.length - blockers} to check · {s.reviewed}/
                    {s.events} transactions reviewed
                  </li>
                </ul>
              )}
            </Section>
            <Section title={`${j.name} · ${METHOD_LABEL[settings.method]}`}>
              <ul className="list-disc space-y-1 pl-4 text-[11px] leading-relaxed text-faint">
                {j.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </Section>
          </>
        ) : tab === 'review' ? (
          <>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Select
                aria-label="Review filter"
                value={reviewFilter}
                onChange={(e) => setReviewFilter(e.target.value as typeof reviewFilter)}
              >
                <option value="attention">Needs attention · {attention.length}</option>
                <option value="unreviewed">
                  Every unreviewed · {report.events.filter((e) => !e.reviewed).length}
                </option>
                <option value="all">All in {taxYearLabel(j, settings.year)}</option>
              </Select>
              {spamCandidates.length > 0 && (
                <Button
                  size="sm"
                  onClick={() => {
                    taxStore.reviewMany(
                      spamCandidates.map((e) => [e.id, { label: 'spam' }] as const),
                    );
                    setNotice(
                      `${spamCandidates.length} unpriced token deposits marked spam. Reset any card to undo.`,
                    );
                  }}
                >
                  Mark {spamCandidates.length} unpriced token deposits spam
                </Button>
              )}
              {unreviewedPeriod.length > 0 && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    taxStore.reviewMany(
                      unreviewedPeriod.map((e) => [e.id, { label: e.label }] as const),
                    );
                    setNotice(
                      `${unreviewedPeriod.length} transactions confirmed as shown: receipts as purchases, sends as sales.`,
                    );
                  }}
                >
                  Confirm {unreviewedPeriod.length} as shown
                </Button>
              )}
            </div>
            <p className="mb-3 text-[11px] leading-relaxed text-faint">
              The chain shows coins moving, not why. Moves between wallets in scope are matched
              automatically and are not taxable. Label the rest: a deposit from an exchange you own
              is “From my other account”, with what you paid, so its later sale has a basis.
            </p>
            {reviewList.length === 0 ? (
              <p className="text-ok">
                {syncedCount === 0 ? 'Read history first.' : 'Nothing here needs you.'}
              </p>
            ) : (
              <div className="flex flex-col gap-2">
                {reviewList.slice(0, limit).map((e) => (
                  <EventCard key={e.id} e={e} issues={issuesByEvent.get(e.id) ?? []} ctx={ctx} />
                ))}
                {reviewList.length > limit && (
                  <Button size="sm" variant="ghost" onClick={() => setLimit(limit + 60)}>
                    Show {Math.min(60, reviewList.length - limit)} more of{' '}
                    {reviewList.length - limit}
                  </Button>
                )}
              </div>
            )}
          </>
        ) : tab === 'gains' ? (
          <Table
            head={[
              'sold',
              'acquired',
              'asset',
              'amount',
              'proceeds',
              'cost',
              'gain',
              'term',
              'wallet',
            ]}
            empty="No disposals in this period."
            rows={report.disposals
              .filter((d) => inPeriod(d.disposedAtMs))
              .slice(0, ROW_LIMIT)
              .map((d) => [
                day(d.disposedAtMs),
                day(d.acquiredAtMs),
                assets.get(d.assetRef)?.symbol ?? d.assetRef,
                amountText(d.amount, assets.get(d.assetRef), false),
                d.removal ? LABEL_TEXT[d.label] : formatMoney(d.proceeds, fiat),
                formatMoney(d.cost, fiat),
                <span
                  className={
                    d.gain !== null && d.gain < 0n
                      ? 'text-danger'
                      : d.gain === null && !d.removal
                        ? 'text-warm'
                        : ''
                  }
                >
                  {d.removal ? '—' : d.gain === null ? 'basis missing' : formatMoney(d.gain, fiat)}
                </span>,
                d.term ? TERM_LABEL[d.term] : '—',
                ctx.walletName(d.walletId),
              ])}
          />
        ) : tab === 'income' ? (
          <Table
            head={['date', 'kind', 'asset', 'amount', 'value', 'wallet']}
            empty="No income in this period. Label staking rewards, airdrops or salary in review."
            rows={report.income
              .filter((i) => inPeriod(i.atMs) && INCOME_LABELS.has(i.label))
              .slice(0, ROW_LIMIT)
              .map((i) => [
                day(i.atMs),
                LABEL_TEXT[i.label],
                assets.get(i.assetRef)?.symbol ?? i.assetRef,
                amountText(i.amount, assets.get(i.assetRef), false),
                formatMoney(i.value, fiat),
                ctx.walletName(i.walletId),
              ])}
          />
        ) : tab === 'holdings' ? (
          <Table
            head={[
              'wallet',
              'asset',
              'amount',
              'cost basis',
              `value ${day(report.period.endMs - 1)}`,
              'held since',
              'lots',
            ]}
            empty="Nothing held at the end of this period."
            rows={report.holdings
              .slice(0, ROW_LIMIT)
              .map((h) => [
                ctx.walletName(h.walletId),
                assets.get(h.assetRef)?.symbol ?? h.assetRef,
                amountText(h.amount, assets.get(h.assetRef), false),
                formatMoney(h.cost, fiat),
                formatMoney(h.value, fiat),
                day(h.earliestAtMs),
                h.lots,
              ])}
          />
        ) : tab === 'scope' ? (
          <>
            <Section title="kind of wallet · any of">
              <div className="flex flex-wrap gap-1.5">
                {SCOPE_TAGS.map((t) => (
                  <Chip
                    key={t}
                    active={scope.tags.includes(t)}
                    title={SCOPE_TAG_HELP[t]}
                    onClick={() => toggleTag(t)}
                  >
                    {SCOPE_TAG_TEXT[t]} ·{' '}
                    {wallets.filter((w) => tagsFor(w, folders).includes(t)).length}
                  </Chip>
                ))}
              </div>
              {status.kind !== 'unlocked' && (
                <p className="mt-1.5 text-[10px] text-faint">
                  Unlock the vault to sort wallets by imported and exported.
                </p>
              )}
            </Section>
            <Section title="directories · any of, subfolders included">
              <div className="flex flex-wrap gap-1.5">
                {folders
                  .filter((f) => f.parentId !== null)
                  .map((f) => (
                    <Chip
                      key={f.id}
                      active={scope.folderIds.includes(f.id)}
                      onClick={() =>
                        taxStore.setScope({
                          folderIds: scope.folderIds.includes(f.id)
                            ? scope.folderIds.filter((x) => x !== f.id)
                            : [...scope.folderIds, f.id],
                        })
                      }
                    >
                      {f.name}
                      {f.imported ? ' · imported set' : ''}
                      {f.exported ? ' · exported set' : ''}
                    </Chip>
                  ))}
                {folders.every((f) => f.parentId === null) && (
                  <span className="text-faint">No directories yet.</span>
                )}
              </div>
            </Section>
            <Section
              title={`wallets · ${resolved.included.length} of ${resolved.candidates.length}`}
              aside={
                <span className="flex gap-3 text-[11px]">
                  <button
                    type="button"
                    className="text-muted underline"
                    onClick={() => taxStore.setScope({ excluded: [] })}
                  >
                    all
                  </button>
                  <button
                    type="button"
                    className="text-muted underline"
                    onClick={() =>
                      taxStore.setScope({ excluded: resolved.candidates.map((w) => w.id) })
                    }
                  >
                    none
                  </button>
                  {(scope.tags.length > 0 ||
                    scope.folderIds.length > 0 ||
                    scope.excluded.length > 0) && (
                    <button
                      type="button"
                      className="text-muted underline"
                      onClick={() => taxStore.setScope({ tags: [], folderIds: [], excluded: [] })}
                    >
                      clear filters
                    </button>
                  )}
                </span>
              }
            >
              <ul className="divide-y divide-edge/60">
                {resolved.candidates.map((w) => {
                  const on = includedIds.has(w.id);
                  const accts = state.accounts.filter((a) => a.walletId === w.id);
                  return (
                    <li key={w.id} className="flex items-center gap-2 py-1.5">
                      <input
                        type="checkbox"
                        aria-label={`include ${w.name}`}
                        checked={on}
                        className="accent-[var(--sw-ink)]"
                        onChange={(e) =>
                          taxStore.setScope({
                            excluded: e.target.checked
                              ? scope.excluded.filter((x) => x !== w.id)
                              : [...scope.excluded, w.id],
                          })
                        }
                      />
                      <span className={`min-w-0 flex-1 truncate ${on ? 'text-ink' : 'text-faint'}`}>
                        {w.name}
                      </span>
                      <span className="flex shrink-0 gap-1">
                        {tagsFor(w, folders).map((t) => (
                          <Chip key={t}>{SCOPE_TAG_TEXT[t]}</Chip>
                        ))}
                      </span>
                      <span className="w-16 shrink-0 text-right text-[10px] text-faint">
                        {accts.length} acct{accts.length === 1 ? '' : 's'}
                      </span>
                    </li>
                  );
                })}
                {resolved.candidates.length === 0 && (
                  <li className="py-2 text-faint">No wallet matches these filters.</li>
                )}
              </ul>
            </Section>
            <Section title="history per account">
              <Table
                head={['wallet', 'chain', 'records', 'status', '']}
                empty="No accounts in scope."
                rows={accounts.map((a) => {
                  const h = tax.histories.get(a.accountId);
                  const fresh = h && h.key === historyKey(a) ? h : undefined;
                  return [
                    a.walletName,
                    a.chainName,
                    fresh ? fresh.history.records.length : '—',
                    !fresh ? (
                      <span className="text-faint">not read</span>
                    ) : fresh.history.error ? (
                      <span
                        className={fresh.history.complete ? 'text-muted' : 'text-danger'}
                        title={fresh.history.error}
                      >
                        {fresh.history.complete ? 'read' : 'partial'} ·{' '}
                        {fresh.history.error.slice(0, 60)}
                      </span>
                    ) : fresh.history.complete ? (
                      <span className="text-ok">complete</span>
                    ) : (
                      <span className="text-warm">partial</span>
                    ),
                    <button
                      type="button"
                      className="text-muted underline disabled:opacity-40"
                      disabled={tax.syncing !== null}
                      onClick={() =>
                        void taxStore.syncHistories(
                          registry,
                          [{ accountId: a.accountId, chainId: a.chainId, address: a.address }],
                          true,
                        )
                      }
                    >
                      {fresh ? 're-read' : 'read'}
                    </button>,
                  ];
                })}
              />
            </Section>
          </>
        ) : tab === 'export' ? (
          <>
            <p className="mb-3 text-[11px] leading-relaxed text-muted">
              {taxYearLabel(j, settings.year)} · {j.name} · {METHOD_LABEL[settings.method]} ·{' '}
              {fiat.toUpperCase()} · {scopeLabel}
            </p>
            {blockers > 0 && (
              <p className="mb-3 text-[11px] leading-relaxed text-warm">
                {blockers} blocking issue{blockers === 1 ? '' : 's'} remain. Exports still work and
                list them, so nothing incomplete looks final.
              </p>
            )}
            <div className="grid gap-2 sm:grid-cols-2">
              <button
                type="button"
                className="sw-pressable sw-tax-card rounded-sw-sm border border-edge-strong px-3 py-2.5 text-left hover:bg-elevated"
                onClick={() =>
                  download(
                    exportFileName(report, 'report', 'xlsx'),
                    exportXlsx(exportCtx()) as BlobPart,
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                  )
                }
              >
                <div className="text-ink">Workbook · .xlsx</div>
                <div className="mt-0.5 text-[10px] text-faint">
                  Summary, disposals, income, holdings, ledger, issues, wallets and sources
                </div>
              </button>
              <button
                type="button"
                className="sw-pressable sw-tax-card rounded-sw-sm border border-edge px-3 py-2.5 text-left hover:bg-elevated"
                onClick={() =>
                  void exportJson(exportCtx()).then((text) =>
                    download(exportFileName(report, 'report', 'json'), text, 'application/json'),
                  )
                }
              >
                <div className="text-ink">Report · .json</div>
                <div className="mt-0.5 text-[10px] text-faint">
                  Exact amounts, every lot and decision, with a SHA-256 digest
                </div>
              </button>
            </div>
            <Section
              title="csv"
              aside={
                <Select
                  aria-label="CSV delimiter"
                  value={delimiter}
                  onChange={(e) => setDelimiter(e.target.value as ',' | ';')}
                >
                  <option value=",">comma</option>
                  <option value=";">semicolon · Excel EU</option>
                </Select>
              }
            >
              <ul className="divide-y divide-edge/60">
                {CSV_PRESETS.map((p: CsvPreset) => (
                  <li key={p} className="flex items-center gap-3 py-1.5">
                    <div className="min-w-0 flex-1">
                      <div className="text-ink">{PRESET_TEXT[p].name}</div>
                      <div className="text-[10px] text-faint">{PRESET_TEXT[p].detail}</div>
                    </div>
                    <Button
                      size="sm"
                      onClick={() =>
                        download(
                          exportFileName(report, p, 'csv'),
                          exportCsv(exportCtx(), p, delimiter),
                          'text/csv',
                        )
                      }
                    >
                      .csv
                    </Button>
                  </li>
                ))}
              </ul>
            </Section>
            <Section title="review decisions">
              <p className="mb-2 text-[11px] leading-relaxed text-faint">
                Your labels, values and notes, keyed by transaction. No addresses or keys. Move them
                to another device or keep them with your records.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  onClick={() =>
                    download(
                      'stackwallet-tax-review.json',
                      taxStore.exportOverrides(),
                      'application/json',
                    )
                  }
                >
                  Save {Object.keys(tax.overrides).length} decisions
                </Button>
                <label className="sw-pressable inline-flex h-7 cursor-pointer items-center rounded-sw-sm border border-edge px-2.5 text-[12px] text-ink">
                  Load decisions
                  <input
                    type="file"
                    accept="application/json,.json"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      e.target.value = '';
                      if (!file) return;
                      void file
                        .text()
                        .then((t) => setNotice(`${taxStore.importOverrides(t)} decisions loaded.`))
                        .catch(() => setNotice('That file is not a StackWallet review file.'));
                    }}
                  />
                </label>
              </div>
            </Section>
            <p className="mt-4 text-[10px] leading-relaxed text-faint">{DISCLAIMER}</p>
          </>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-[10px] text-faint">
                cost basis method
                <Select
                  value={settings.method}
                  onChange={(e) =>
                    taxStore.setSettings({ method: e.target.value as typeof settings.method })
                  }
                >
                  {j.methods.map((m) => (
                    <option key={m} value={m}>
                      {METHOD_LABEL[m]}
                    </option>
                  ))}
                </Select>
              </label>
              <label className="flex flex-col gap-1 text-[10px] text-faint">
                report currency
                <Select
                  value={fiat}
                  onChange={(e) => taxStore.setSettings({ fiat: e.target.value as typeof fiat })}
                >
                  {FIATS.map((f) => (
                    <option key={f} value={f}>
                      {f.toUpperCase()} · {FIAT_SYMBOL[f]}
                    </option>
                  ))}
                </Select>
              </label>
              <label className="flex flex-col gap-1 text-[10px] text-faint">
                lots are tracked
                <Select
                  value={settings.pooling}
                  onChange={(e) =>
                    taxStore.setSettings({ pooling: e.target.value as typeof settings.pooling })
                  }
                >
                  <option value="wallet">per wallet · US rule from 2025</option>
                  <option value="universal">across all wallets</option>
                </Select>
              </label>
              <label className="flex flex-col gap-1 text-[10px] text-faint">
                network fees
                <Select
                  value={settings.fees}
                  onChange={(e) =>
                    taxStore.setSettings({ fees: e.target.value as typeof settings.fees })
                  }
                >
                  <option value="dispose">a small disposal of the fee coin</option>
                  <option value="ignore">leave the books without gain or loss</option>
                </Select>
              </label>
            </div>
            <label className="mt-3 flex items-center gap-2 text-[11px] text-muted">
              <input
                type="checkbox"
                checked={settings.includeTestnets}
                className="accent-[var(--sw-ink)]"
                onChange={(e) => taxStore.setSettings({ includeTestnets: e.target.checked })}
              />
              include testnets (no market value; useful for trying the flow)
            </label>
            <Section title={j.name}>
              <ul className="list-disc space-y-1 pl-4 text-[11px] leading-relaxed text-faint">
                {j.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </Section>
            <Section title="prices">
              <p className="text-[11px] leading-relaxed text-faint">
                Daily closes in {fiat.toUpperCase()} from CoinGecko’s public API, which serves the
                last 365 days. Older events need a value entered in review. Requests name coins,
                never addresses.
              </p>
              {!market.coingecko && (
                <Button
                  className="mt-2"
                  size="sm"
                  onClick={() => marketSettings.toggle('coingecko', true)}
                >
                  Turn on CoinGecko prices
                </Button>
              )}
              {tax.pricing && (
                <p className="mt-2 text-[11px] text-muted">
                  Reading prices {tax.pricing.done}/{tax.pricing.total}…
                </p>
              )}
              {tax.priceErrors.size > 0 && (
                <div className="mt-2 text-[11px]">
                  <p className="text-danger">
                    {tax.priceErrors.size} price series unavailable:{' '}
                    {[...tax.priceErrors.values()][0]}
                  </p>
                  <button
                    type="button"
                    className="mt-1 text-muted underline"
                    onClick={() => {
                      taxStore.retryPrices();
                      void taxStore.loadPrices(priceKeys, fiat);
                    }}
                  >
                    retry
                  </button>
                </div>
              )}
            </Section>
          </>
        )}
      </div>
    </div>
  );
}
