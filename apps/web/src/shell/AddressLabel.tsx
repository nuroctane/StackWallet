import { useEffect, useMemo } from 'react';
import { chainFamilyOf, type Account } from '@stackwallet/core-client';
import type { NameRecord } from '@stackwallet/names';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { labelFor, type AddressLabel as Label } from '../lib/labels.js';
import { relativeTime } from '../lib/format.js';
import { namesStore, useNames, walletLabel } from '../store/names.js';
import { useDirectory } from '../store/persist.js';

/** Resolve labels against everything the app knows right now. */
export function useLabeler(): (address: string, chainId: string) => Label {
  const state = useDirectory();
  const names = useNames();
  const { ledger } = useVaultView(vault);
  return useMemo(() => {
    const byAddress = new Map<string, NameRecord>();
    for (const [key, entry] of Object.entries(names.entries)) {
      const first = entry.records[0];
      if (first) byAddress.set(key.slice(key.indexOf(':') + 1), first);
    }
    const inputs = {
      wallets: state.wallets,
      accounts: state.accounts,
      names: byAddress,
      ledger,
      contacts: state.contacts,
      walletText: (id: string) => {
        const w = state.wallets.find((x) => x.id === id);
        return w ? walletLabel(names, w, state.accounts).text : id;
      },
    };
    return (address: string, chainId: string) => labelFor(address, chainId, inputs);
  }, [state, names, ledger]);
}

const SOURCE_TONE: Record<Label['source'], string> = {
  wallet: 'text-ink',
  contact: 'text-ink',
  name: 'text-accent-2',
  known: 'text-muted',
  none: 'text-faint',
};

/**
 * An address as the user should read it: label and its source first, then
 * the full address underneath when `full` is set (signing screens always set
 * it). Unknown addresses say so and say whether they were ever paid before.
 */
export function AddressLabel({
  address,
  chainId,
  full = false,
}: {
  address: string;
  chainId: string;
  full?: boolean;
}) {
  const labeler = useLabeler();
  const l = labeler(address, chainId);
  useEffect(() => {
    const family = chainFamilyOf(chainId);
    if (family) namesStore.ensureAddress(family as Account['family'], chainId, address);
  }, [address, chainId]);
  return (
    <span className="inline-flex min-w-0 flex-col">
      <span className="inline-flex min-w-0 items-baseline gap-1.5">
        <span className={`truncate ${SOURCE_TONE[l.source]}`}>
          {l.label ?? (full ? 'unknown address' : `${address.slice(0, 6)}…${address.slice(-4)}`)}
        </span>
        <span className="shrink-0 text-[10px] tracking-[0.06em] text-faint uppercase">
          {l.sourceText}
        </span>
        {l.nonAscii && <span className="shrink-0 text-[10px] text-danger">non-ASCII</span>}
        {l.source !== 'wallet' && (
          <span className="shrink-0 text-[10px] text-faint">
            {l.firstSeenMs === null
              ? 'first seen now'
              : `first sent ${relativeTime(l.firstSeenMs, Date.now())} ago`}
          </span>
        )}
      </span>
      {full && <code className="font-mono text-[11px] break-all text-muted">{address}</code>}
    </span>
  );
}
