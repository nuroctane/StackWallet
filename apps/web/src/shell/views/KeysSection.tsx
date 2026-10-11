import type { Wallet } from '@stackwallet/core-client';
import { Button } from '@stackwallet/ui';

import { vault } from '../../core/bridge.js';
import { useVaultView } from '../../core/vault.js';
import { walletTags } from '../../store/provenance.js';
import { useShell } from '../ShellContext.js';
import { TagChips } from '../ProvenanceTags.js';

/**
 * The key story of a single-key wallet in one place: where it came from,
 * whether it ever left, and the one door out (which marks it exposed).
 */
export function KeysSection({ wallet }: { wallet: Wallet }) {
  const shell = useShell();
  const { status, provenance } = useVaultView(vault);
  const tags = walletTags(provenance, wallet);
  const p = provenance.wallets.find((w) => w.walletId === wallet.id);
  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
        <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">Key</h3>
        <TagChips tags={tags} />
      </header>
      <div className="flex flex-col gap-2 px-4 py-3 text-[12px]">
        <ul className="flex flex-col gap-1 text-faint">
          {tags.map((t) => (
            <li key={t.kind}>{t.detail}</li>
          ))}
          {!p && (
            <li>
              {status.kind === 'unlocked'
                ? 'No key history in this vault for this wallet.'
                : 'Unlock the vault to read this key history from the core.'}
            </li>
          )}
        </ul>
        {p && p.exposures.length > 0 && (
          <ul className="flex flex-col gap-0.5 font-mono text-[11px] text-muted">
            {p.exposures.slice(-5).map((e, i) => (
              <li key={`${e.atMs}-${i}`}>
                {new Date(e.atMs).toISOString().slice(0, 19).replace('T', ' ')} ·{' '}
                {e.what.kind === 'mnemonic' ? 'phrase' : `key ${e.what.path}`} · {e.channel}
              </li>
            ))}
          </ul>
        )}
        <div className="flex gap-2 pt-1">
          <Button
            size="sm"
            variant="danger"
            disabled={status.kind !== 'unlocked'}
            title={status.kind === 'unlocked' ? undefined : 'Unlock the vault first'}
            onClick={() => shell.openDialog({ kind: 'reveal', walletId: wallet.id })}
          >
            Export phrase or key…
          </Button>
        </div>
      </div>
    </section>
  );
}
