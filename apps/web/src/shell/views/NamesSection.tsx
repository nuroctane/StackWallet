import type { Account } from '@stackwallet/core-client';
import { SERVICE_LABEL } from '@stackwallet/names';
import { shortAddress } from '@stackwallet/chains';
import { Button } from '@stackwallet/ui';

import { nameKey, namesStore, useNames } from '../../store/names.js';

/**
 * Every verified name attached to this wallet's addresses, grouped by address.
 * Each one was resolved in reverse and confirmed forward before it is listed.
 */
export function NamesSection({ accounts }: { accounts: readonly Account[] }) {
  const names = useNames();
  const unique = new Map<string, Account>();
  for (const a of accounts) if (!unique.has(nameKey(a))) unique.set(nameKey(a), a);
  const rows = [...unique.values()].map((a) => ({ account: a, entry: names.entries[nameKey(a)] }));
  const pending = rows.filter((r) => !r.entry).length;
  const failed = rows.flatMap((r) => r.entry?.failed ?? []);
  const found = rows.flatMap((r) =>
    (r.entry?.records ?? []).map((rec) => ({ rec, account: r.account })),
  );

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
        <h3 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">Names</h3>
        <div className="flex items-center gap-2 text-[11px] text-faint">
          <span>
            {pending > 0
              ? `checking ${pending}…`
              : failed.length > 0
                ? `${[...new Set(failed)].join(', ')} unreachable`
                : 'ENS · SNS · ICNS · THORName'}
          </span>
          <Button
            size="sm"
            variant="ghost"
            disabled={accounts.length === 0}
            onClick={() => namesStore.ensure(accounts, true)}
          >
            recheck
          </Button>
        </div>
      </header>
      {found.length === 0 ? (
        <p className="px-4 py-3 text-[12px] text-faint">
          {pending > 0
            ? 'Looking up names for these addresses.'
            : 'No verified names point at these addresses.'}
        </p>
      ) : (
        <ul className="divide-y divide-edge text-[12px]">
          {found.map(({ rec, account }) => (
            <li
              key={`${rec.service}:${rec.name}:${account.id}`}
              className="flex items-center gap-3 px-4 py-2"
            >
              <span className="w-[72px] shrink-0 text-[10px] tracking-[0.06em] text-faint uppercase">
                {SERVICE_LABEL[rec.service]}
              </span>
              <span className="min-w-0 flex-1 truncate text-accent-2">{rec.name}</span>
              {rec.nonAscii && <span className="text-[10px] text-danger">non-ASCII</span>}
              <span className="truncate font-mono text-[11px] text-faint" title={account.address}>
                {shortAddress(account.address)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
