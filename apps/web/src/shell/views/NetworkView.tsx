import { useEffect, useMemo, useReducer, useState, type FormEvent } from 'react';
import type { RpcEndpoint } from '@stackwallet/chains';
import { Badge, Button, EmptyState, Input, Kbd, useToasts } from '@stackwallet/ui';

import { FAMILY_LABEL, listChains } from '../../lib/chains.js';
import { useRegistry } from '../../store/RegistryContext.js';
import {
  endpointsFor,
  MAX_ENDPOINTS_PER_CHAIN,
  normalizeRpcUrl,
  poolFor,
  resetChainEndpoints,
  rpcSettings,
  rpcUrlProblem,
} from '../../store/rpcSettings.js';
import type { DirectoryState } from '../../store/schema.js';
import { chainIdsInUse } from '../../store/selectors.js';
import { useShell } from '../ShellContext.js';

/** Health flags change as fetches land, so the pools are re-read on a slow clock. */
const HEALTH_POLL_MS = 5_000;

export function NetworkView({ state }: { state: DirectoryState }) {
  const registry = useRegistry();
  const shell = useShell();
  const [showAll, setShowAll] = useState(false);
  const [, bump] = useReducer((n: number) => n + 1, 0);

  useEffect(() => {
    const unsub = rpcSettings.subscribe(bump);
    const id = setInterval(bump, HEALTH_POLL_MS);
    return () => {
      unsub();
      clearInterval(id);
    };
  }, []);

  const inUse = useMemo(() => new Set(chainIdsInUse(state)), [state]);
  const chains = useMemo(() => {
    const all = listChains(registry);
    const list = showAll ? all : all.filter((c) => inUse.has(c.chainId));
    return [...list].sort(
      (a, b) =>
        Number(inUse.has(b.chainId)) - Number(inUse.has(a.chainId)) ||
        Number(a.testnet) - Number(b.testnet) ||
        a.name.localeCompare(b.name),
    );
  }, [registry, showAll, inUse]);

  return (
    <div className="flex flex-col gap-5 p-5">
      <div className="flex flex-col gap-2">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-[12px] text-faint">
          <button
            type="button"
            onClick={() => shell.navigate({ kind: 'directory' })}
            className="sw-pressable rounded-sw-sm px-1 text-muted"
          >
            Overview
          </button>
          <span aria-hidden>/</span>
          <span className="px-1 text-ink">Network</span>
        </nav>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h1 className="text-[22px] font-semibold tracking-[-0.01em]">RPC endpoints</h1>
          <label className="flex cursor-pointer items-center gap-2 text-[12px] text-muted">
            <input
              type="checkbox"
              checked={showAll}
              onChange={(e) => setShowAll(e.target.checked)}
              className="accent-[var(--sw-ink)]"
            />
            show all chains
          </label>
        </div>
        <p className="text-[12px] text-faint">
          Balances are read from these endpoints and cross-checked against a second one when the
          chain has more than one. Custom lists are stored on this device only.{' '}
          <span className="inline-flex items-center gap-1">
            <Kbd>esc</Kbd> back
          </span>
        </p>
      </div>

      {chains.length === 0 ? (
        <EmptyState
          title={showAll ? 'No chain adapters loaded' : 'No chains in use'}
          description={
            showAll
              ? 'Without adapters there are no endpoints to manage.'
              : 'Add a watch wallet, or show all chains to edit defaults ahead of time.'
          }
          action={
            !showAll && (
              <Button size="sm" variant="ghost" onClick={() => setShowAll(true)}>
                Show all chains
              </Button>
            )
          }
        />
      ) : (
        <div className="flex flex-col gap-3">
          {chains.map((c) => (
            <ChainCard
              key={c.chainId}
              chainId={c.chainId}
              name={c.name}
              family={FAMILY_LABEL[c.family]}
              testnet={c.testnet}
              inUse={inUse.has(c.chainId)}
              endpoints={endpointsFor(registry, c.chainId)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ChainCard({
  chainId,
  name,
  family,
  testnet,
  inUse,
  endpoints,
}: {
  chainId: string;
  name: string;
  family: string;
  testnet: boolean;
  inUse: boolean;
  endpoints: RpcEndpoint[];
}) {
  const registry = useRegistry();
  const toasts = useToasts();
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const custom = chainId in rpcSettings.getSnapshot();

  const commit = (urls: string[]) => {
    const pool = poolFor(registry, chainId);
    if (!pool) {
      toasts.push('No adapter for this chain', 'danger');
      return;
    }
    pool.setEndpoints(chainId, urls);
    rpcSettings.setChain(chainId, urls);
  };

  const add = (e: FormEvent) => {
    e.preventDefault();
    const problem = rpcUrlProblem(draft);
    if (problem) {
      setError(problem);
      return;
    }
    const url = normalizeRpcUrl(draft);
    if (endpoints.some((ep) => ep.url === url)) {
      setError('Already listed');
      return;
    }
    if (endpoints.length >= MAX_ENDPOINTS_PER_CHAIN) {
      toasts.push(`At most ${MAX_ENDPOINTS_PER_CHAIN} endpoints per chain`, 'danger');
      return;
    }
    commit([...endpoints.map((ep) => ep.url), url]);
    setDraft('');
    setError(null);
    toasts.push(`Endpoint added to ${name}`);
  };

  const remove = (url: string) => {
    commit(endpoints.filter((ep) => ep.url !== url).map((ep) => ep.url));
  };

  const reset = () => {
    if (!resetChainEndpoints(registry, chainId)) {
      toasts.push('No adapter for this chain', 'danger');
      return;
    }
    rpcSettings.clearChain(chainId);
    toasts.push(`${name} endpoints reset`);
  };

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <header className="flex flex-wrap items-center gap-2 border-b border-edge px-4 py-2.5">
        <span className="text-ink">{name}</span>
        <span className="text-[10px] tracking-[0.06em] text-faint uppercase">{family}</span>
        {testnet && <Badge>testnet</Badge>}
        {inUse && <Badge tone="ok">in use</Badge>}
        {custom && <Badge tone="warm">custom</Badge>}
        <span className="flex-1" />
        <span className="font-mono text-[11px] text-faint">{chainId}</span>
        <Button size="sm" variant="ghost" onClick={reset} disabled={!custom}>
          reset to defaults
        </Button>
      </header>
      {endpoints.length === 0 ? (
        <p className="px-4 py-3 text-[12px] text-faint">
          No endpoints. Balances for this chain cannot be read until one is added.
        </p>
      ) : (
        <div className="overflow-auto">
          <table className="w-full table-fixed border-collapse text-[12px]">
            <colgroup>
              <col />
              <col className="w-[6.5rem]" />
              <col className="w-[5.5rem]" />
              <col className="w-[4.5rem]" />
              <col className="w-[6rem]" />
              <col className="w-[5.5rem]" />
            </colgroup>
            <thead className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
              <tr className="h-9 border-b border-edge">
                <th className="px-4 text-left font-semibold">Endpoint</th>
                <th className="px-3 text-left font-semibold">Health</th>
                <th className="px-3 text-right font-semibold">Latency</th>
                <th className="px-3 text-right font-semibold">Errors</th>
                <th className="px-3 text-right font-semibold">Block</th>
                <th className="px-4 text-right font-semibold">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {endpoints.map((ep) => (
                <tr key={ep.url} className="h-9 hover:bg-hover">
                  {/* `w-full max-w-0` lets this cell absorb spare width yet truncate
                      instead of pushing the fixed-width columns off the pane. */}
                  <td
                    data-label="Endpoint"
                    className="w-full max-w-0 px-4 font-mono text-muted"
                    title={ep.url}
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="min-w-0 truncate">{ep.url}</span>
                      {ep.custom && (
                        <Badge tone="warm" className="shrink-0">
                          custom
                        </Badge>
                      )}
                    </span>
                  </td>
                  <td data-label="Health" className="px-3 whitespace-nowrap">
                    <span className="inline-flex items-center gap-1.5">
                      <span
                        aria-hidden
                        className={`inline-block h-1.5 w-1.5 rounded-full ${
                          ep.healthy ? 'bg-ok' : 'bg-danger'
                        }`}
                      />
                      <span className={ep.healthy ? 'text-muted' : 'text-danger'}>
                        {ep.healthy ? 'healthy' : 'failing'}
                      </span>
                    </span>
                  </td>
                  <td data-label="Latency" className="px-3 text-right text-muted tabular-nums">
                    {ep.latencyMs !== undefined ? `${Math.round(ep.latencyMs)} ms` : '—'}
                  </td>
                  <td data-label="Errors" className="px-3 text-right text-muted tabular-nums">
                    {ep.errorRate !== undefined ? `${Math.round(ep.errorRate * 100)}%` : '—'}
                  </td>
                  <td data-label="Block" className="px-3 text-right text-muted tabular-nums">
                    {ep.lastBlock !== undefined ? ep.lastBlock.toLocaleString('en-US') : '—'}
                  </td>
                  <td data-label="Actions" className="px-4 text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Remove ${ep.url}`}
                      onClick={() => remove(ep.url)}
                    >
                      remove
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <form onSubmit={add} className="flex items-start gap-2 border-t border-edge px-4 py-2.5">
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <Input
            dense
            value={draft}
            invalid={error !== null}
            onChange={(e) => {
              setDraft(e.target.value);
              setError(null);
            }}
            placeholder="https://rpc.example.org"
            aria-label={`Add endpoint for ${name}`}
            spellCheck={false}
            autoComplete="off"
          />
          {error && (
            <div role="alert" className="text-[11px] text-danger">
              {error}
            </div>
          )}
        </div>
        <Button size="sm" type="submit" disabled={draft.trim() === ''} className="h-8">
          add
        </Button>
      </form>
    </section>
  );
}
