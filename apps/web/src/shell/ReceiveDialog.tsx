import { useId, useState } from 'react';
import { BITCOIN_SIGNET } from '@stackwallet/chains-bitcoin';
import { COSMOS_TESTNET } from '@stackwallet/chains-cosmos';
import { SOLANA_DEVNET } from '@stackwallet/chains-solana';
import { Button, Dialog, Field, Select, useToasts } from '@stackwallet/ui';

import { findChain } from '../lib/chains.js';
import { useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { accountsOf } from '../store/selectors.js';
import { QrCode } from './views/QrCode.js';

const FAUCETS: Record<string, string> = {
  'eip155:11155111': 'https://cloud.google.com/application/web3/faucet/ethereum/sepolia',
  [SOLANA_DEVNET]: 'https://faucet.solana.com/',
  [BITCOIN_SIGNET]: 'https://signetfaucet.com/',
  [COSMOS_TESTNET]: 'https://faucet.testnet.osmosis.zone/',
};

/**
 * One address to receive on, as text and as a QR code. The chain is named
 * above the code because an address on one chain family can be valid, and
 * lost, on another.
 */
export function ReceiveDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="Receive" meta="share an address">
      {walletId && <ReceiveBody walletId={walletId} />}
    </Dialog>
  );
}

function ReceiveBody({ walletId }: { walletId: string }) {
  const state = useDirectory();
  const registry = useRegistry();
  const toasts = useToasts();
  const field = useId();
  const accounts = accountsOf(state, walletId).filter((a) => !a.hidden);
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? '');
  const account = accounts.find((a) => a.id === accountId) ?? accounts[0];
  if (!account) return <p className="p-4 text-[12px] text-faint">This wallet has no accounts.</p>;
  const chain = findChain(registry, account.chainId);
  const copy = () =>
    void navigator.clipboard
      .writeText(account.address)
      .then(() => toasts.push('Address copied'))
      .catch(() => toasts.push('Clipboard unavailable', 'danger'));

  return (
    <div className="flex flex-col gap-4 p-4">
      <Field label="Account" htmlFor={field}>
        <Select id={field} value={account.id} onChange={(e) => setAccountId(e.target.value)}>
          {accounts.map((a) => (
            <option key={a.id} value={a.id}>
              {findChain(registry, a.chainId)?.name ?? a.chainId}
              {a.label ? ` · ${a.label}` : ''}
            </option>
          ))}
        </Select>
      </Field>
      <p className="text-[12px] text-muted">
        Send only <span className="text-ink">{chain?.name ?? account.chainId}</span> assets
        {chain?.testnet ? ' (a testnet; its coins have no value)' : ''} to this address.
      </p>
      <div className="mx-auto w-[220px]">
        <QrCode text={account.address} />
      </div>
      <code className="rounded-sw-sm border border-edge bg-paper p-2 text-center font-mono text-[12px] break-all text-ink select-all">
        {account.address}
      </code>
      {FAUCETS[account.chainId] && (
        <p className="text-[11px] text-faint">
          Free test coins:{' '}
          <a
            href={FAUCETS[account.chainId]}
            target="_blank"
            rel="noreferrer noopener"
            className="text-muted underline"
          >
            {new URL(FAUCETS[account.chainId]!).hostname}
          </a>{' '}
          (a third-party faucet; paste the address above).
        </p>
      )}
      <div className="flex justify-end">
        <Button variant="primary" onClick={copy}>
          Copy address
        </Button>
      </div>
    </div>
  );
}
