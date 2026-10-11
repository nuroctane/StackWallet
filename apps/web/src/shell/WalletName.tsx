import type { Wallet } from '@stackwallet/core-client';
import { SERVICE_LABEL } from '@stackwallet/names';

import { useDirectory } from '../store/persist.js';
import { useNames, walletLabel, type WalletLabel } from '../store/names.js';

export function useWalletLabel(wallet: Pick<Wallet, 'id' | 'name'>): WalletLabel {
  const state = useDirectory();
  const names = useNames();
  return walletLabel(names, wallet, state.accounts);
}

export function nameTitle(label: WalletLabel): string {
  if (!label.record) return label.tag;
  const r = label.record;
  return `${r.name} · ${SERVICE_LABEL[r.service]}, verified both ways on ${r.chainId}${
    r.nonAscii ? ' · contains non-ASCII characters, check for look-alikes' : ''
  } · your tag: ${label.tag}`;
}

/**
 * A wallet's name as the UI shows it: a verified name-service name in the
 * second accent when one exists, otherwise the user's tag. Non-ASCII names
 * carry a visible marker because look-alike characters are a phishing tool.
 */
export function WalletName({
  wallet,
  className = '',
  showService = false,
}: {
  wallet: Pick<Wallet, 'id' | 'name'>;
  className?: string;
  showService?: boolean;
}) {
  const label = useWalletLabel(wallet);
  return (
    <span
      className={`inline-flex min-w-0 items-baseline gap-1.5 ${className}`}
      title={nameTitle(label)}
    >
      <span className={`truncate ${label.record ? 'text-accent-2' : ''}`}>{label.text}</span>
      {label.record?.nonAscii && (
        <span className="shrink-0 text-[10px] text-danger" aria-label="non-ASCII name">
          ≠ascii
        </span>
      )}
      {showService && label.record && (
        <span className="shrink-0 text-[10px] tracking-[0.06em] text-faint uppercase">
          {SERVICE_LABEL[label.record.service]}
        </span>
      )}
    </span>
  );
}
