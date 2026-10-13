import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { AgentGrant, ModelMessage, ToolTrace } from '@stackwallet/agent';
import { PROVIDERS, isProviderId, type ProviderId } from '@stackwallet/agent/catalog';

import { Button, Input, LoadingWord, Select } from '@stackwallet/ui';

import { vault } from '../../core/bridge.js';
import { useVaultView } from '../../core/vault.js';
import { createAgentHost } from '../../agent/host.js';
import { useDirectory } from '../../store/persist.js';
import { useRegistry } from '../../store/RegistryContext.js';
import type { ElementBodyProps } from './types.js';

interface Entry {
  role: 'user' | 'agent' | 'error';
  text: string;
  trace?: ToolTrace[];
}

/** One transcript as sealed in the vault (`agent-session:<id>`). */
interface SavedSession {
  id: string;
  title: string;
  provider: string;
  model: string;
  startedAtMs: number;
  updatedAtMs: number;
  entries: Entry[];
  history: ModelMessage[];
}

function parseSaved(text: string): SavedSession | null {
  try {
    const v = JSON.parse(text) as Partial<SavedSession>;
    if (typeof v.id !== 'string' || !Array.isArray(v.entries)) return null;
    return {
      id: v.id,
      title: typeof v.title === 'string' ? v.title : 'session',
      provider: String(v.provider ?? ''),
      model: String(v.model ?? ''),
      startedAtMs: Number(v.startedAtMs ?? 0),
      updatedAtMs: Number(v.updatedAtMs ?? 0),
      entries: v.entries.filter(
        (e): e is Entry =>
          !!e && typeof e.text === 'string' && ['user', 'agent', 'error'].includes(e.role),
      ),
      history: Array.isArray(v.history) ? v.history : [],
    };
  } catch {
    return null;
  }
}

/**
 * The agent console: a bring-your-own-key model with read tools over the
 * wallets the user grants, and one action, proposing a transfer into the
 * approval queue. The transcript lives in memory for this session only.
 */
export function AgentElement({ pane, setProps }: ElementBodyProps) {
  const view = useVaultView(vault);
  const registry = useRegistry();
  const { wallets } = useDirectory();
  const provider: ProviderId = isProviderId(pane.props['provider'])
    ? pane.props['provider']
    : 'anthropic';
  const modelId =
    typeof pane.props['model'] === 'string' && pane.props['model']
      ? pane.props['model']
      : PROVIDERS.find((p) => p.id === provider)!.defaultModel;
  const [granted, setGranted] = useState<string[]>([]);
  const [allowPropose, setAllowPropose] = useState(false);
  const [keyDraft, setKeyDraft] = useState('');
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [entries, setEntries] = useState<Entry[]>([]);
  const history = useRef<ModelMessage[]>([]);
  const counter = useRef({ proposals: 0 });
  const abort = useRef<AbortController | null>(null);
  const [session, setSession] = useState<{
    sessionId: string;
    grantId: string;
    startedAtMs: number;
  }>(() => ({
    sessionId: crypto.randomUUID(),
    grantId: crypto.randomUUID(),
    startedAtMs: Date.now(),
  }));
  const [past, setPast] = useState<SavedSession[] | null>(null);
  const [query, setQuery] = useState('');
  useEffect(() => () => abort.current?.abort(), []);

  if (view.status.kind !== 'unlocked')
    return (
      <p className="p-3 text-[12px] text-faint">
        Unlock the vault: provider keys are sealed in it.
      </p>
    );

  const hasKey = vault.hasProviderKey(provider);
  const grant: AgentGrant = { walletIds: granted, allowPropose, maxSteps: 8, maxProposals: 3 };

  const send = async (e: FormEvent) => {
    e.preventDefault();
    const message = input.trim();
    if (!message || busy) return;
    setInput('');
    setEntries((x) => [...x, { role: 'user', text: message }]);
    setBusy(true);
    const ctrl = new AbortController();
    abort.current = ctrl;
    try {
      const key = await vault.providerKey(provider);
      if (!key) throw new Error('No API key for this provider');
      // The model SDKs load with the first message, not with the page.
      const { languageModel, runAgentTurn } = await import('@stackwallet/agent');
      const turn = await runAgentTurn({
        model: languageModel(provider, key, modelId),
        host: createAgentHost(registry, session),
        grant,
        history: history.current,
        message,
        counter: counter.current,
        signal: ctrl.signal,
      });
      history.current = turn.messages.slice(-40);
      setEntries((x) => [
        ...x,
        { role: 'agent', text: turn.text || '(no reply)', trace: turn.trace },
      ]);
    } catch (err) {
      setEntries((x) => [
        ...x,
        { role: 'error', text: err instanceof Error ? err.message : String(err) },
      ]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-2 p-3 text-[12px]">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          aria-label="provider"
          value={provider}
          onChange={(e) => setProps({ provider: e.target.value, model: '' })}
          className="w-auto"
        >
          {PROVIDERS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
        </Select>
        <Input
          aria-label="model"
          value={modelId}
          onChange={(e) => setProps({ model: e.target.value })}
          className="w-[22ch]"
        />
        <span className="text-faint">
          {counter.current.proposals}/{grant.maxProposals} proposals
        </span>
      </div>
      {!hasKey && (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void vault.setProviderKey(provider, keyDraft).then((r) => {
              if (r.ok) setKeyDraft('');
              else setEntries((x) => [...x, { role: 'error', text: r.error }]);
            });
          }}
        >
          <Input
            type="password"
            aria-label="API key"
            placeholder={`${PROVIDERS.find((p) => p.id === provider)!.label} API key`}
            value={keyDraft}
            onChange={(e) => setKeyDraft(e.target.value)}
          />
          <Button size="sm" type="submit" disabled={keyDraft.trim().length < 8}>
            Seal key
          </Button>
        </form>
      )}
      <details
        className="rounded-sw-sm border border-edge px-2 py-1"
        onToggle={(e) => {
          if ((e.target as HTMLDetailsElement).open)
            void vault.agentSessions().then((list) =>
              setPast(
                list
                  .map(parseSaved)
                  .filter((x): x is SavedSession => x !== null)
                  .sort((a, b) => b.updatedAtMs - a.updatedAtMs),
              ),
            );
        }}
      >
        <summary className="cursor-pointer text-muted">Sessions</summary>
        <div className="flex flex-col gap-1 py-1">
          <div className="flex gap-2">
            <Input
              aria-label="search sessions"
              placeholder="search transcripts"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setSession({
                  sessionId: crypto.randomUUID(),
                  grantId: crypto.randomUUID(),
                  startedAtMs: Date.now(),
                });
                setEntries([]);
                history.current = [];
                counter.current = { proposals: 0 };
              }}
            >
              New
            </Button>
          </div>
          {past === null ? (
            <LoadingWord label="opening" />
          ) : (
            <ul className="max-h-40 overflow-auto">
              {past
                .filter(
                  (p) =>
                    !query.trim() ||
                    p.entries.some((e) =>
                      e.text.toLowerCase().includes(query.trim().toLowerCase()),
                    ),
                )
                .map((p) => (
                  <li key={p.id} className="flex items-center justify-between gap-2 py-0.5">
                    <button
                      type="button"
                      className="sw-pressable min-w-0 truncate text-left text-ink"
                      title={`${p.provider} · ${p.model}`}
                      onClick={() => {
                        setSession({
                          sessionId: p.id,
                          grantId: crypto.randomUUID(),
                          startedAtMs: p.startedAtMs,
                        });
                        setEntries(p.entries);
                        history.current = p.history;
                        counter.current = { proposals: 0 };
                      }}
                    >
                      {p.title}
                      <span className="ml-2 text-faint">
                        {new Date(p.updatedAtMs).toISOString().slice(0, 16).replace('T', ' ')}
                      </span>
                    </button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        void vault
                          .deleteAgentSession(p.id)
                          .then(() => setPast((x) => (x ? x.filter((y) => y.id !== p.id) : x)))
                      }
                    >
                      Delete
                    </Button>
                  </li>
                ))}
            </ul>
          )}
        </div>
      </details>
      <details className="rounded-sw-sm border border-edge px-2 py-1">
        <summary className="cursor-pointer text-muted">
          Grant: {granted.length} wallet{granted.length === 1 ? '' : 's'}
          {allowPropose ? ' · may propose' : ' · read only'}
        </summary>
        <div className="flex flex-col gap-1 py-1">
          {wallets.map((w) => (
            <label key={w.id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={granted.includes(w.id)}
                onChange={(e) =>
                  setGranted((g) => (e.target.checked ? [...g, w.id] : g.filter((x) => x !== w.id)))
                }
              />
              {w.name} <span className="text-faint">{w.kind}</span>
            </label>
          ))}
          <label className="flex items-center gap-2 pt-1">
            <input
              type="checkbox"
              checked={allowPropose}
              onChange={(e) => setAllowPropose(e.target.checked)}
            />
            May propose transfers (you still approve and sign every one)
          </label>
        </div>
      </details>
      <ol className="min-h-0 flex-1 space-y-2 overflow-auto">
        {entries.length === 0 && (
          <li className="text-faint">
            Ask about balances or ask for a transfer. The agent reads only the wallets you grant and
            can never sign; its proposals wait in the approval queue.
          </li>
        )}
        {entries.map((e, i) => (
          <li
            key={i}
            className={
              e.role === 'error' ? 'text-danger' : e.role === 'user' ? 'text-ink' : 'text-muted'
            }
          >
            <span className="text-faint">
              {e.role === 'user' ? 'you' : e.role === 'agent' ? 'agent' : 'error'} ·{' '}
            </span>
            <span className="whitespace-pre-wrap">{e.text}</span>
            {e.trace && e.trace.length > 0 && (
              <details className="mt-1 text-[11px] text-faint">
                <summary className="cursor-pointer">
                  {e.trace.length} tool call{e.trace.length === 1 ? '' : 's'}
                </summary>
                <pre className="overflow-auto whitespace-pre-wrap">
                  {JSON.stringify(e.trace, null, 2)}
                </pre>
              </details>
            )}
          </li>
        ))}
        {busy && (
          <li>
            <LoadingWord label="thinking" />
          </li>
        )}
      </ol>
      <form onSubmit={(e) => void send(e)} className="flex gap-2">
        <Input
          aria-label="message"
          value={input}
          disabled={!hasKey}
          placeholder={hasKey ? 'Ask the agent…' : 'Seal an API key first'}
          onChange={(e) => setInput(e.target.value)}
        />
        {busy ? (
          <Button size="sm" type="button" onClick={() => abort.current?.abort()}>
            Stop
          </Button>
        ) : (
          <Button size="sm" type="submit" variant="primary" disabled={!hasKey || !input.trim()}>
            Send
          </Button>
        )}
      </form>
    </div>
  );
}
