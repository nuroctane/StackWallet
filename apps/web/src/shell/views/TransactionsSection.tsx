import { useState } from 'react';
import type { Wallet } from '@stackwallet/core-client';
import { Button } from '@stackwallet/ui';

import { vault } from '../../core/bridge.js';
import { useVaultView } from '../../core/vault.js';
import { explorerTxUrl, findChain } from '../../lib/chains.js';
import { relativeTime } from '../../lib/format.js';
import { auditEventLabel } from '../../lib/audit.js';
import { TransactionRecovery } from '../TransactionRecovery.js';
import { useRegistry } from '../../store/RegistryContext.js';
import { StateChip, useHeadline } from '../ApprovalRail.js';
import { useShell } from '../ShellContext.js';

/**
 * This wallet's transactions from the core's ledger, newest first. Each row
 * expands into its audit trail, which the core verified on load.
 */
export function TransactionsSection({ wallet }: { wallet: Wallet }) {
  const view = useVaultView(vault);
  const shell = useShell();
  const registry = useRegistry();
  const headline = useHeadline();
  const [open, setOpen] = useState<string | null>(null);
  const txs = (view.ledger?.txs ?? [])
    .filter((t) => t.intent.walletId === wallet.id)
    .sort((a, b) => b.createdAtMs - a.createdAtMs);
  const audit = view.ledger?.audit ?? [];

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
        <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
          Local signing records
        </h3>
        <div className="flex items-center gap-2 text-[11px] text-faint">
          {view.ledger && <span>audit chain verified by the core · {audit.length} rows</span>}
          {wallet.kind === 'single' && (
            <Button size="sm" variant="ghost" onClick={() => shell.openDialog({ kind: 'send' })}>
              Send…
            </Button>
          )}
        </div>
      </header>
      {view.ledgerError && (
        <p className="bg-danger-soft px-4 py-2 text-[12px] text-ink">
          Ledger integrity check failed: {view.ledgerError}
        </p>
      )}
      {view.status.kind !== 'unlocked' ? (
        <p className="px-4 py-3 text-[12px] text-faint">Unlock the vault to read the ledger.</p>
      ) : txs.length === 0 ? (
        <p className="px-4 py-3 text-[12px] text-faint">No transactions from this wallet yet.</p>
      ) : (
        <ul className="divide-y divide-edge text-[12px]">
          {txs.map((t) => {
            const chain = findChain(registry, t.intent.chainId);
            const url = t.hash && chain ? explorerTxUrl(chain, t.hash) : null;
            return (
              <li key={t.id} className="flex flex-col gap-1 px-4 py-2">
                <button
                  type="button"
                  className="flex flex-wrap items-center gap-2 text-left"
                  aria-expanded={open === t.id}
                  onClick={() => setOpen((cur) => (cur === t.id ? null : t.id))}
                >
                  <StateChip state={t.state} />
                  <span className="min-w-0 flex-1 break-words text-ink">{headline(t)}</span>
                  <span className="text-[11px] text-faint">{chain?.name}</span>
                  <span className="w-[48px] text-right text-[11px] text-faint">
                    {relativeTime(t.updatedAtMs, Date.now())}
                  </span>
                </button>
                {open === t.id && (
                  <div className="flex flex-col gap-1 pl-1 text-[11px]">
                    {url && (
                      <a
                        href={url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="font-mono break-all text-muted underline decoration-dotted"
                      >
                        {t.hash}
                      </a>
                    )}
                    {t.error && <span className="text-danger">{t.error}</span>}
                    <ol className="flex flex-col gap-0.5 font-mono text-faint">
                      {audit
                        .filter((e) => e.txId === t.id)
                        .map((e) => (
                          <li key={e.index} title={`row ${e.index} · ${e.hashHex}`}>
                            {new Date(e.atMs).toISOString().slice(11, 19)} {auditEventLabel(e)}
                            {e.note ? ` · ${e.note}` : ''}
                          </li>
                        ))}
                    </ol>
                    <TransactionRecovery tx={t} />
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
