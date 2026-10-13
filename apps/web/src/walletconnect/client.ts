/**
 * WalletConnect v2, wallet side, strictly opt-in. Off until the user supplies
 * their own Reown project id; the SDK loads only then, with its telemetry
 * disabled. The relay carries end-to-end encrypted messages between this tab
 * and the dapp; it is the one third-party service a session depends on.
 */
import { useSyncExternalStore } from 'react';
import type { ISignClient } from '@walletconnect/types';
import type { SignClientTypes } from '@walletconnect/types';
import type { ChainRegistry } from '@stackwallet/chains';
import type { TxRecord } from '@stackwallet/core-client';
import { z } from 'zod';

import { vault } from '../core/bridge.js';
import { EVM_SIGNING_CHAINS } from '../lib/chains.js';
import { directory } from '../store/persist.js';
import { accountsOf } from '../store/selectors.js';
import { proposeContractCall, proposeSend } from '../store/txs.js';
import { buildNamespaces, cleanText, toAction, USER_REJECTED, type WcAction } from './requests.js';

const KEY = 'stackwallet.walletconnect.v1';

function storage(): Storage | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}
const Settings = z.object({
  projectId: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .nullable()
    .default(null),
  /** Which wallet answers for each session topic. */
  sessions: z.record(z.string().max(128), z.string().max(128)).default({}),
});
type Settings = z.infer<typeof Settings>;

export interface Dapp {
  name: string;
  url: string;
  /** Reown's domain verification: `valid` only when the relay vouches for the URL. */
  verified: 'valid' | 'invalid' | 'unknown' | 'scam';
}

export interface PendingProposal {
  id: number;
  dapp: Dapp;
  requiredChains: string[];
}

export interface PendingRequest {
  id: number;
  topic: string;
  method: string;
  chainId: string;
  walletId: string;
  dapp: Dapp;
  action: WcAction;
  receivedAtMs: number;
  /** Set once the request became a proposal in the approval queue. */
  txId?: string;
}

export interface WcSession {
  topic: string;
  walletId: string;
  dapp: Dapp;
  expiryMs: number;
}

export interface WcView {
  status: 'off' | 'starting' | 'ready' | 'error';
  error: string | null;
  projectId: string | null;
  proposals: PendingProposal[];
  requests: PendingRequest[];
  sessions: WcSession[];
}

type Metadata = { name?: unknown; url?: unknown };

function dappOf(
  meta: Metadata | undefined,
  verify?: SignClientTypes.EventArguments['session_proposal']['verifyContext'],
): Dapp {
  const v = verify?.verified;
  return {
    name: cleanText(meta?.name) || 'unnamed dapp',
    url: cleanText(meta?.url, 200),
    verified: v?.isScam
      ? 'scam'
      : v?.validation === 'VALID'
        ? 'valid'
        : v?.validation === 'INVALID'
          ? 'invalid'
          : 'unknown',
  };
}

export class WalletConnectStore {
  private client: ISignClient | null = null;
  private registry: ChainRegistry | null = null;
  private settings: Settings;
  private view: WcView;
  private listeners = new Set<() => void>();
  private watching = new Map<string, number>();

  constructor() {
    let s: Settings = { projectId: null, sessions: {} };
    try {
      const raw = storage()?.getItem(KEY);
      if (raw) s = Settings.parse(JSON.parse(raw));
    } catch {
      // Unreadable settings leave WalletConnect off.
    }
    this.settings = s;
    this.view = {
      status: 'off',
      error: null,
      projectId: s.projectId,
      proposals: [],
      requests: [],
      sessions: [],
    };
    vault.subscribe(() => this.settleRequests());
  }

  readonly subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };
  readonly getSnapshot = () => this.view;

  private set(patch: Partial<WcView>) {
    this.view = { ...this.view, ...patch };
    for (const l of this.listeners) l();
  }

  private save() {
    try {
      storage()?.setItem(KEY, JSON.stringify(this.settings));
    } catch {
      // Without storage the sessions last for this tab only.
    }
  }

  /** Start the SDK if the user enabled it; called once at boot with the chain registry. */
  async start(registry: ChainRegistry): Promise<void> {
    this.registry = registry;
    if (!this.settings.projectId || this.client) return;
    this.set({ status: 'starting', error: null });
    try {
      const { SignClient } = await import('@walletconnect/sign-client');
      const client = await SignClient.init({
        projectId: this.settings.projectId,
        telemetryEnabled: false,
        customStoragePrefix: 'stackwallet',
        metadata: {
          name: 'StackWallet',
          description: 'Local-first self-custodial wallet',
          url: location.origin,
          icons: [],
        },
      });
      this.client = client as unknown as ISignClient;
      client.on('session_proposal', (e) => {
        const required = Object.values(e.params.requiredNamespaces ?? {}).flatMap(
          (n) => n.chains ?? [],
        );
        this.set({
          proposals: [
            ...this.view.proposals,
            {
              id: e.id,
              dapp: dappOf(e.params.proposer.metadata, e.verifyContext),
              requiredChains: required.filter((c) => typeof c === 'string').slice(0, 32),
            },
          ],
        });
      });
      client.on('session_request', (e) => void this.onRequest(e));
      client.on('session_delete', ({ topic }) => this.forget(topic));
      client.on('session_expire', ({ topic }) => this.forget(topic));
      this.refreshSessions();
      this.set({ status: 'ready' });
    } catch (err) {
      this.client = null;
      this.set({ status: 'error', error: err instanceof Error ? err.message : String(err) });
    }
  }

  /** Turn WalletConnect on with the user's own project id, or off with `null`. */
  async configure(projectId: string | null): Promise<void> {
    if (projectId === null) {
      for (const s of this.view.sessions) await this.disconnect(s.topic).catch(() => undefined);
      this.client = null;
      this.settings = { projectId: null, sessions: {} };
      this.save();
      this.set({ status: 'off', projectId: null, proposals: [], requests: [], sessions: [] });
      return;
    }
    const id = projectId.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(id)) throw new Error('A Reown project id is 32 hex characters');
    this.settings = { ...this.settings, projectId: id };
    this.save();
    this.set({ projectId: id });
    if (this.registry) await this.start(this.registry);
  }

  async pair(uri: string): Promise<void> {
    if (!this.client) throw new Error('WalletConnect is not running');
    if (!/^wc:[0-9a-f]{64}@2\?/.test(uri.trim())) throw new Error('Not a WalletConnect v2 link');
    await this.client.core.pairing.pair({ uri: uri.trim() });
  }

  async approveProposal(id: number, walletId: string): Promise<void> {
    const client = this.client;
    const p = this.view.proposals.find((x) => x.id === id);
    if (!client || !p) return;
    const built = buildNamespaces(
      p.requiredChains,
      accountsOf(directory.getSnapshot(), walletId),
      EVM_SIGNING_CHAINS,
    );
    if (!built.ok) throw new Error(built.error);
    const { topic, acknowledged } = await client.approve({ id, namespaces: built.namespaces });
    this.settings.sessions[topic] = walletId;
    this.save();
    this.set({ proposals: this.view.proposals.filter((x) => x.id !== id) });
    await acknowledged();
    this.refreshSessions();
  }

  async rejectProposal(id: number): Promise<void> {
    this.set({ proposals: this.view.proposals.filter((x) => x.id !== id) });
    await this.client?.reject({ id, reason: { code: 5000, message: 'User rejected.' } });
  }

  async disconnect(topic: string): Promise<void> {
    await this.client?.disconnect({ topic, reason: { code: 6000, message: 'User disconnected.' } });
    this.forget(topic);
  }

  private forget(topic: string) {
    delete this.settings.sessions[topic];
    this.save();
    for (const r of this.view.requests.filter((x) => x.topic === topic))
      this.watching.delete(String(r.id));
    this.set({ requests: this.view.requests.filter((r) => r.topic !== topic) });
    this.refreshSessions();
  }

  private refreshSessions() {
    const all = this.client?.session.getAll() ?? [];
    this.set({
      sessions: all
        .filter((s) => this.settings.sessions[s.topic])
        .map((s) => ({
          topic: s.topic,
          walletId: this.settings.sessions[s.topic]!,
          dapp: dappOf(s.peer.metadata),
          expiryMs: s.expiry * 1000,
        })),
    });
  }

  private async onRequest(e: SignClientTypes.EventArguments['session_request']) {
    const walletId = this.settings.sessions[e.topic];
    const session = this.view.sessions.find((s) => s.topic === e.topic);
    const { method, params } = e.params.request;
    const accounts = walletId
      ? accountsOf(directory.getSnapshot(), walletId).filter(
          (a) => a.family === 'evm' && a.derivationPath,
        )
      : [];
    const action = walletId
      ? toAction(method, params, e.params.chainId, accounts)
      : ({ kind: 'refuse', code: 4100, message: 'unknown session' } as const);
    if (action.kind === 'refuse') {
      await this.respondError(e.topic, e.id, action.code, action.message);
      return;
    }
    this.set({
      requests: [
        ...this.view.requests,
        {
          id: e.id,
          topic: e.topic,
          method,
          chainId: e.params.chainId,
          walletId: walletId!,
          dapp: session?.dapp ?? dappOf(undefined, e.verifyContext),
          action,
          receivedAtMs: Date.now(),
        },
      ],
    });
  }

  private async respondError(topic: string, id: number, code: number, message: string) {
    await this.client
      ?.respond({ topic, response: { id, jsonrpc: '2.0', error: { code, message } } })
      .catch(() => undefined);
  }

  private async respondResult(topic: string, id: number, result: string) {
    await this.client
      ?.respond({ topic, response: { id, jsonrpc: '2.0', result } })
      .catch(() => undefined);
  }

  private drop(id: number) {
    this.watching.delete(String(id));
    this.set({ requests: this.view.requests.filter((r) => r.id !== id) });
  }

  async decline(id: number): Promise<void> {
    const r = this.view.requests.find((x) => x.id === id);
    if (!r) return;
    this.drop(id);
    await this.respondError(r.topic, id, USER_REJECTED, 'User rejected the request.');
  }

  /** Answer a signing request with the core's signature. */
  async answerSignature(id: number, signatureHex: string): Promise<void> {
    const r = this.view.requests.find((x) => x.id === id);
    if (!r) return;
    this.drop(id);
    await this.respondResult(r.topic, id, signatureHex);
  }

  /**
   * Turn a transaction request into a proposal. The dapp gets its hash once
   * the user approves and it is broadcast, or an error if it is denied.
   */
  async propose(id: number): Promise<{ ok: true } | { ok: false; error: string }> {
    const r = this.view.requests.find((x) => x.id === id);
    if (!r || r.action.kind !== 'send' || !this.registry) return { ok: false, error: 'gone' };
    const a = r.action;
    const untrusted = [a.to];
    const result =
      a.dataHex === ''
        ? await proposeSend(this.registry, {
            account: a.account,
            to: a.to,
            asset: `${r.chainId}:native`,
            amount: a.value,
            untrustedDestinations: untrusted,
          })
        : await proposeContractCall(this.registry, {
            account: a.account,
            to: a.to,
            dataHex: a.dataHex,
            value: a.value,
            untrustedDestinations: untrusted,
          });
    if (!result.ok) return result;
    this.set({
      requests: this.view.requests.map((x) => (x.id === id ? { ...x, txId: result.value.id } : x)),
    });
    this.watching.set(String(id), id);
    this.settleRequests();
    return { ok: true };
  }

  private settleRequests() {
    const txs: readonly TxRecord[] = vault.getSnapshot().ledger?.txs ?? [];
    for (const r of this.view.requests) {
      if (!r.txId || !this.watching.has(String(r.id))) continue;
      const tx = txs.find((t) => t.id === r.txId);
      if (!tx) continue;
      if (tx.hash && ['broadcast', 'pending', 'confirmed'].includes(tx.state)) {
        this.drop(r.id);
        void this.respondResult(r.topic, r.id, tx.hash);
      } else if (
        ['denied', 'rejected', 'failed', 'expired', 'replaced', 'dropped'].includes(tx.state)
      ) {
        this.drop(r.id);
        void this.respondError(r.topic, r.id, USER_REJECTED, tx.error ?? `transaction ${tx.state}`);
      }
    }
  }
}

export const walletConnect = new WalletConnectStore();

export function useWalletConnect(): WcView {
  return useSyncExternalStore(
    walletConnect.subscribe,
    walletConnect.getSnapshot,
    walletConnect.getSnapshot,
  );
}
