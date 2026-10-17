import { useMemo, useState, type ReactNode } from 'react';
import type { ChainInfo } from '@stackwallet/chains';
import { Input, Select } from '@stackwallet/ui';

import { FAMILY_LABEL, FAMILY_ORDER } from '../lib/chains.js';
import { standardPath } from '../lib/keys.js';

/** Below this many chains a plain list is quicker than typing. */
const FILTER_FROM = 12;

interface Group {
  label: string;
  chains: ChainInfo[];
}

export function groupChains(chains: readonly ChainInfo[]): Group[] {
  const groups: Group[] = [];
  for (const testnet of [false, true]) {
    for (const family of FAMILY_ORDER) {
      const list = chains
        .filter((c) => c.family === family && c.testnet === testnet)
        .sort((a, b) => a.name.localeCompare(b.name));
      if (list.length > 0)
        groups.push({
          label: `${FAMILY_LABEL[family]}${testnet ? ' · testnets' : ''}`,
          chains: list,
        });
    }
  }
  return groups;
}

export function chainMatches(c: ChainInfo, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (q === '') return true;
  return [
    c.name,
    c.nativeAsset.symbol,
    c.chainId,
    FAMILY_LABEL[c.family],
    c.layer ?? '',
    c.parent ?? '',
  ]
    .join(' ')
    .toLowerCase()
    .includes(q);
}

export function chainOptionLabel(c: ChainInfo): string {
  const parts = [c.name, c.nativeAsset.symbol];
  if (c.layer && c.layer !== 'L1') parts.push(c.parent ? `${c.layer} on ${c.parent}` : c.layer);
  if (c.halted) parts.push('halted');
  if (c.defaultRpcs.length === 0) parts.push('add an endpoint');
  // Without a derivation path the core cannot hold a key for the chain, so it only watches.
  if (standardPath(c) === null) parts.push('watch only');
  return parts.join(' · ');
}

/**
 * Chain picker that stays usable with hundreds of chains: a filter box over a
 * native select grouped by family. The current choice is always kept visible
 * so filtering never silently changes what the form submits.
 */
export function ChainSelect({
  id,
  chains,
  value,
  onChange,
  disabled,
  leading,
  label = chainOptionLabel,
}: {
  id: string;
  chains: readonly ChainInfo[];
  value: string;
  onChange: (chainId: string) => void;
  disabled?: boolean;
  /** Options placed before the chain groups, such as "Every EVM chain". */
  leading?: ReactNode;
  label?: (c: ChainInfo) => string;
}) {
  const [query, setQuery] = useState('');
  const shown = useMemo(
    () => chains.filter((c) => c.chainId === value || chainMatches(c, query)),
    [chains, query, value],
  );
  const groups = useMemo(() => groupChains(shown), [shown]);
  const matches = shown.filter((c) => chainMatches(c, query));
  return (
    <div className="flex flex-col gap-1.5">
      {chains.length > FILTER_FROM && (
        <Input
          aria-label="Filter chains"
          value={query}
          disabled={disabled}
          placeholder={`Filter ${chains.length} chains by name, symbol or id`}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => {
            const next = e.target.value;
            setQuery(next);
            const first = chains.find((c) => chainMatches(c, next));
            const current = chains.find((c) => c.chainId === value);
            if (first && next.trim() !== '' && !(current && chainMatches(current, next)))
              onChange(first.chainId);
          }}
        />
      )}
      <Select id={id} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
        {leading}
        {groups.map((g) => (
          <optgroup key={g.label} label={g.label}>
            {g.chains.map((c) => (
              <option key={c.chainId} value={c.chainId}>
                {label(c)}
              </option>
            ))}
          </optgroup>
        ))}
      </Select>
      {query.trim() !== '' && matches.length === 0 && (
        <p className="text-[11px] text-faint">No chain matches "{query.trim()}".</p>
      )}
    </div>
  );
}
