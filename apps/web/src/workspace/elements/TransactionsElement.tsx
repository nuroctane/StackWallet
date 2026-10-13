import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { HistoryPage, HISTORY_INDEXERS, type Page, type TxRecord } from '@stackwallet/chains';
import { TxState } from '@stackwallet/core-client';
import { Button, Input, Select } from '@stackwallet/ui';
import { vault } from '../../core/bridge.js';
import { useVaultView } from '../../core/vault.js';
import { explorerTxUrl, findChain } from '../../lib/chains.js';
import { formatUnits } from '../../lib/format.js';
import { useDirectory } from '../../store/persist.js';
import { useRegistry } from '../../store/RegistryContext.js';
import { useHeadline } from '../../shell/ApprovalRail.js';
import { TransactionRecovery } from '../../shell/TransactionRecovery.js';
import { auditEventLabel } from '../../lib/audit.js';
import type { ElementBodyProps } from './types.js';

export function mergeHistory(
  previous: readonly TxRecord[],
  incoming: readonly TxRecord[],
): TxRecord[] {
  const all = new Map(
    previous.map((t) => [
      t.chainId +
        '|' +
        (t.entryId ?? (t.chainId.startsWith('solana:') ? t.hash : t.hash.toLowerCase())),
      t,
    ]),
  );
  for (const t of incoming)
    all.set(
      t.chainId +
        '|' +
        (t.entryId ?? (t.chainId.startsWith('solana:') ? t.hash : t.hash.toLowerCase())),
      t,
    );
  return [...all.values()].sort(
    (a, b) =>
      (b.timestampMs ?? 0) - (a.timestampMs ?? 0) || (b.blockNumber ?? 0) - (a.blockNumber ?? 0),
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-faint">{label}</dt>
      <dd className="select-text whitespace-pre-wrap break-all text-muted">{children}</dd>
    </div>
  );
}

export function TransactionsElement({ pane, setProps }: ElementBodyProps) {
  const directory = useDirectory();
  const registry = useRegistry();
  const view = useVaultView(vault);
  const headline = useHeadline();
  const walletId = typeof pane.props['walletId'] === 'string' ? pane.props['walletId'] : '';
  const accounts = directory.accounts.filter((a) => !walletId || a.walletId === walletId);
  const [selected, setSelected] = useState('');
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [mode, setMode] = useState('local');
  const account = accounts.find((a) => a.id === selected) ?? accounts[0];
  // The address participates in the key so an edited account cannot display its old history.
  const historyMethod =
    typeof pane.props['historyMethod'] === 'string'
      ? pane.props['historyMethod']
      : account && HISTORY_INDEXERS[account.chainId]
        ? 'indexed'
        : 'rpc';
  const indexer =
    typeof pane.props['indexerUrl'] === 'string' &&
    pane.props['indexerChainId'] === account?.chainId
      ? pane.props['indexerUrl']
      : account
        ? (HISTORY_INDEXERS[account.chainId] ?? '')
        : '';
  const scope = account
    ? account.id +
      '|' +
      account.chainId +
      '|' +
      account.address +
      '|' +
      historyMethod +
      '|' +
      indexer
    : '';
  const [result, setResult] = useState<{ scope: string; page: Page<TxRecord> } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const request = useRef<AbortController | null>(null);
  const epoch = useRef(0);
  useEffect(() => {
    epoch.current++;
    request.current?.abort();
    setBusy(false);
    setError('');
    setResult(null);
    return () => {
      epoch.current++;
      request.current?.abort();
    };
  }, [scope]);
  const page = result?.scope === scope ? result.page : undefined;
  const chain = account ? findChain(registry, account.chainId) : undefined;
  const load = async (older = false) => {
    if (!account || busy) return;
    const generation = ++epoch.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError('');
    try {
      const fetched = HistoryPage.parse(
        await registry
          .adapterFor(account.chainId)
          .getHistory(account.address, account.chainId, older ? page?.nextCursor : undefined, {
            signal: controller.signal,
            ...(chain?.family === 'evm' && historyMethod !== 'rpc'
              ? { indexerUrl: indexer, tokenTransfers: historyMethod === 'tokens' }
              : {}),
          }),
      );
      if (generation !== epoch.current || controller.signal.aborted) return;
      setResult({
        scope,
        page: {
          ...fetched,
          items: mergeHistory(older ? (page?.items ?? []) : [], fetched.items).slice(0, 1000),
        },
      });
    } catch (e) {
      if (generation === epoch.current && !controller.signal.aborted)
        setError(e instanceof Error ? e.message.slice(0, 1500) : 'History read failed');
    } finally {
      if (generation === epoch.current) setBusy(false);
    }
  };
  const matches = (values: unknown[]) =>
    values.join(' ').toLowerCase().includes(query.trim().toLowerCase());
  const locals = useMemo(
    () =>
      (view.ledger?.txs ?? [])
        .filter(
          (t) => (!walletId || t.intent.walletId === walletId) && (!status || t.state === status),
        )
        .sort((a, b) => b.createdAtMs - a.createdAtMs),
    [view.ledger, walletId, status],
  );
  const onchain =
    page?.items.filter(
      (t) =>
        (!status || t.status === status) &&
        matches([t.hash, t.from, t.to, t.chainId, ...t.assetDeltas.map((d) => d.assetRef)]),
    ) ?? [];
  const states = mode === 'local' ? TxState.options : ['pending', 'confirmed', 'failed'];

  return (
    <div className="sw-history h-full overflow-auto p-3 text-[12px]">
      <div className="flex flex-wrap gap-2">
        <Select
          aria-label="History source"
          value={mode}
          onChange={(e) => {
            setMode(e.target.value);
            setStatus('');
          }}
        >
          <option value="local">Local signing records</option>
          <option value="chain">Public chain history</option>
        </Select>
        <Select
          aria-label="Transaction status"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">All statuses</option>
          {states.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
        <Input
          aria-label="Filter transaction history"
          placeholder="hash, address, wallet, chain or asset"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>
      {mode === 'local' ? (
        <>
          <p className="my-3 text-[11px] leading-relaxed text-faint">
            Signing requests made in StackWallet on every supported chain. Includes denied and
            rejected requests; these are not on-chain transactions. Unlock the vault to read its
            verified audit trail.
          </p>
          {view.ledgerError && (
            <p role="alert" className="text-danger">
              Ledger integrity check failed: {view.ledgerError}
            </p>
          )}
          {view.status.kind !== 'unlocked' ? (
            <p className="text-faint">Vault locked · local signing records unavailable.</p>
          ) : locals.filter((t) =>
              matches([
                headline(t),
                t.hash,
                t.intent.chainId,
                directory.wallets.find((w) => w.id === t.intent.walletId)?.name,
                JSON.stringify(t.intent),
              ]),
            ).length === 0 ? (
            <p className="text-faint">No local signing records match this scope.</p>
          ) : (
            locals
              .filter((t) =>
                matches([
                  headline(t),
                  t.hash,
                  t.intent.chainId,
                  directory.wallets.find((w) => w.id === t.intent.walletId)?.name,
                  JSON.stringify(t.intent),
                ]),
              )
              .map((t) => (
                <details key={t.id} className="border-t border-edge py-2">
                  <summary className="cursor-pointer break-words leading-relaxed">
                    <span
                      className={
                        ['failed', 'denied'].includes(t.state) ? 'text-danger' : 'text-ink'
                      }
                    >
                      {t.state}
                    </span>{' '}
                    · {headline(t)}
                    <span className="block text-[11px] text-faint">
                      {directory.wallets.find((w) => w.id === t.intent.walletId)?.name ??
                        t.intent.walletId}{' '}
                      · {findChain(registry, t.intent.chainId)?.name ?? t.intent.chainId} ·{' '}
                      {new Date(t.createdAtMs).toLocaleString()}
                    </span>
                  </summary>
                  <dl className="mt-3 grid gap-2 text-[11px]">
                    <Field label="Record ID">{t.id}</Field>
                    <Field label="Chain">{t.intent.chainId}</Field>
                    <Field label="Transaction hash">{t.hash ?? 'Not broadcast'}</Field>
                    <Field label="Last updated">{new Date(t.updatedAtMs).toLocaleString()}</Field>
                    {t.error && <Field label="Error">{t.error}</Field>}
                    <Field label="Intent">{JSON.stringify(t.intent, null, 2)}</Field>
                    <Field label="Signer">{JSON.stringify(t.signer, null, 2)}</Field>
                    <Field label="Prepared transaction">
                      {JSON.stringify(t.unsigned, null, 2)}
                    </Field>
                    <Field label="Policy decision">{JSON.stringify(t.decision, null, 2)}</Field>
                    <Field label="Simulation">{JSON.stringify(t.simulation, null, 2)}</Field>
                  </dl>
                  <TransactionRecovery tx={t} />
                  <p className="mt-3 text-[11px] text-faint">Core-verified audit trail</p>
                  <ol className="mt-1 space-y-2 text-[11px]">
                    {(view.ledger?.audit ?? [])
                      .filter((e) => e.txId === t.id)
                      .map((e) => (
                        <li key={e.index} className="break-all">
                          {new Date(e.atMs).toLocaleString()} · {auditEventLabel(e)}
                          {e.note ? ' · ' + e.note : ''}
                          <span className="block text-faint">
                            row {e.index} · {e.hashHex}
                          </span>
                        </li>
                      ))}
                  </ol>
                </details>
              ))
          )}
        </>
      ) : (
        <>
          <div className="mt-3 flex flex-wrap gap-2">
            <Select
              aria-label="History account"
              className="min-w-0 flex-1"
              value={account?.id ?? ''}
              onChange={(e) => setSelected(e.target.value)}
            >
              {!accounts.length && <option value="">No accounts</option>}
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {directory.wallets.find((w) => w.id === a.walletId)?.name ?? a.walletId} ·{' '}
                  {findChain(registry, a.chainId)?.name ?? a.chainId} · {a.address}
                </option>
              ))}
            </Select>
            <Button size="sm" disabled={!account || busy} onClick={() => void load()}>
              {busy ? 'Reading…' : page ? 'Refresh' : 'Read history'}
            </Button>
          </div>
          {chain?.family === 'evm' && (
            <div className="mt-3 flex flex-wrap gap-2">
              <Select
                aria-label="EVM history method"
                value={historyMethod}
                onChange={(e) => setProps({ historyMethod: e.target.value })}
              >
                <option value="rpc">RPC · recent external transactions</option>
                <option value="indexed">Blockscout · indexed external transactions</option>
                <option value="tokens">Blockscout · indexed token-transfer events</option>
              </Select>
              {historyMethod !== 'rpc' && (
                <Input
                  aria-label="Blockscout history base URL"
                  placeholder="https://eth.blockscout.com"
                  value={indexer}
                  onChange={(e) =>
                    setProps({ indexerUrl: e.target.value, indexerChainId: account?.chainId ?? '' })
                  }
                />
              )}
            </div>
          )}
          {account && (
            <p className="my-2 select-text break-all text-[11px] text-muted">
              {chain?.name ?? account.chainId} · {account.address}
            </p>
          )}
          <p className="my-2 text-[11px] leading-relaxed text-faint">
            Public endpoint observations are unverified and may omit transactions. Reads send this
            public address to the configured RPC or indexer shown below. Net balance changes below
            are not a transfer amount.
          </p>
          {error && (
            <p role="alert" className="my-2 break-words text-danger">
              History unavailable: {error}. Retry or configure a compatible endpoint in network.
            </p>
          )}
          {!page && !busy && !error && (
            <p className="my-3 text-faint">Choose an account and read its public history.</p>
          )}
          {page && (
            <>
              <p className="my-2 break-words text-[11px] leading-relaxed text-muted">
                {page.coverage ?? 'Coverage not specified by this adapter.'}
              </p>
              <p className="my-2 select-text break-all text-[10px] text-faint">
                Source: {page.source ?? 'Adapter endpoint'} · {page.items.length} loaded records
              </p>
              {onchain.length === 0 && (
                <p className="py-3 text-faint">
                  No matching records in the loaded page or block range.
                </p>
              )}
              {onchain.map((t) => {
                const url = chain ? explorerTxUrl(chain, t.hash) : null;
                return (
                  <details
                    key={t.chainId + '|' + (t.entryId ?? t.hash)}
                    className="border-t border-edge py-2"
                  >
                    <summary className="cursor-pointer break-all leading-relaxed">
                      <span className={t.status === 'failed' ? 'text-danger' : 'text-ink'}>
                        {t.status}
                      </span>{' '}
                      · {t.hash}
                      <span className="block text-[11px] text-faint">
                        {t.timestampMs === undefined
                          ? 'Timestamp unavailable'
                          : new Date(t.timestampMs).toLocaleString()}{' '}
                        ·{' '}
                        {t.blockNumber === undefined
                          ? 'Unmined'
                          : (chain?.family === 'solana' ? 'slot ' : 'block ') + t.blockNumber}
                      </span>
                    </summary>
                    <dl className="mt-3 grid gap-2 text-[11px]">
                      <Field label="Hash">{t.hash}</Field>
                      {t.entryId && <Field label="Transfer event">{t.entryId}</Field>}
                      <Field label="Chain">{t.chainId}</Field>
                      {t.description && <Field label="Event">{t.description}</Field>}
                      <Field label="From / fee payer">{t.from || 'Unknown'}</Field>
                      <Field label="To">
                        {t.to ?? 'Multiple outputs, program call or unknown'}
                      </Field>
                      <Field label="Fee">
                        {t.fee === null
                          ? 'Unknown'
                          : chain
                            ? formatUnits(t.fee, chain.nativeAsset.decimals) +
                              ' ' +
                              chain.nativeAsset.symbol +
                              ' (' +
                              t.fee +
                              ' base units)'
                            : t.fee + ' base units'}
                      </Field>
                      <Field label="Observed net balance changes">
                        {t.assetDeltas.length
                          ? t.assetDeltas
                              .map((d) => d.assetRef + ': ' + d.amount + ' base units')
                              .join('\n')
                          : 'Unknown / not decoded'}
                      </Field>
                    </dl>
                    {url && (
                      <a
                        className="mt-3 inline-block min-h-8 text-muted underline"
                        href={url}
                        target="_blank"
                        rel="noreferrer noopener"
                      >
                        View in explorer ↗
                      </a>
                    )}
                  </details>
                );
              })}
              {page.nextCursor && (
                <Button
                  className="mt-3"
                  size="sm"
                  disabled={busy || page.items.length >= 1000}
                  onClick={() => void load(true)}
                >
                  Load older {chain?.family === 'evm' ? 'blocks' : 'records'}
                </Button>
              )}
              {page.items.length >= 1000 && (
                <p className="mt-2 text-faint">
                  1,000-record view limit reached. Refresh to return to newest records.
                </p>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
