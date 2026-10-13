import { useState } from 'react';
import type { TxRecord } from '@stackwallet/core-client';
import { Button, Input } from '@stackwallet/ui';
import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { useRegistry } from '../store/RegistryContext.js';
import { useDirectory } from '../store/persist.js';
import { proposeReplacement, retryBroadcast } from '../store/txs.js';

export function TransactionRecovery({ tx }: { tx: TxRecord }) {
  const registry = useRegistry();
  const view = useVaultView(vault);
  const [open, setOpen] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState('');
  const { accounts } = useDirectory();
  if (!['signed', 'broadcast', 'pending'].includes(tx.state) || !tx.hash || !tx.rawSignedHex)
    return null;
  const account = accounts.find((a) => a.id === tx.intent.accountId);
  const replaceable =
    account?.family === 'evm' &&
    ['broadcast', 'pending'].includes(tx.state) &&
    tx.unsigned !== null &&
    tx.unsigned !== undefined &&
    'maxFeePerGas' in tx.unsigned;
  const replace = async (mode: 'speedUp' | 'cancel') => {
    if (!account) return;
    setWorking(true);
    setMessage('');
    const r = await proposeReplacement(registry, tx, account, mode);
    setWorking(false);
    setMessage(
      !r.ok
        ? r.error
        : r.value.state === 'awaiting'
          ? `${mode === 'cancel' ? 'Cancel' : 'Speed-up'} proposed at the same nonce with higher fees; approve it in the queue.`
          : 'The replacement was denied by policy.',
    );
  };
  const retry = async () => {
    setWorking(true);
    setMessage('');
    try {
      const result = await retryBroadcast(registry, tx.id, passphrase);
      setMessage(
        result.ok
          ? 'Original signed transaction sent again. Its saved hash remains tracked.'
          : result.error,
      );
      if (result.ok) setOpen(false);
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : 'Retry failed; check the original transaction hash.',
      );
    } finally {
      setPassphrase('');
      setWorking(false);
    }
  };
  return (
    <div className="mt-2 flex min-w-0 flex-col gap-2 border-t border-edge pt-2 text-[11px]">
      <p className="break-words text-faint">
        Broadcast interrupted or uncertain? Retry the original signed transaction using its saved
        hash. No new transaction is signed. Its reserved spend stays tracked until the chain
        resolves it.
      </p>
      {open ? (
        <form
          className="flex min-w-0 flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            void retry();
          }}
        >
          <Input
            type="password"
            aria-label="Passphrase for original broadcast retry"
            autoComplete="current-password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            disabled={working}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              type="submit"
              className="max-w-full py-1 whitespace-normal"
              style={{ height: 'auto', minHeight: 28 }}
              disabled={working || view.busy || view.status.kind !== 'unlocked' || !passphrase}
            >
              {working ? 'Retrying…' : 'Retry original broadcast'}
            </Button>
            <Button
              size="sm"
              type="button"
              className="max-w-full py-1 whitespace-normal"
              style={{ height: 'auto', minHeight: 28 }}
              variant="ghost"
              disabled={working}
              onClick={() => {
                setOpen(false);
                setPassphrase('');
              }}
            >
              Cancel retry
            </Button>
          </div>
        </form>
      ) : (
        <Button
          size="sm"
          variant="ghost"
          className="max-w-full py-1 whitespace-normal"
          style={{ height: 'auto', minHeight: 28 }}
          disabled={view.busy || view.status.kind !== 'unlocked'}
          onClick={() => {
            setMessage('');
            setOpen(true);
          }}
        >
          Retry original broadcast…
        </Button>
      )}
      {replaceable && (
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="ghost"
            disabled={working || view.busy || view.status.kind !== 'unlocked'}
            title="Same transaction, same nonce, fees raised by at least 12.5%"
            onClick={() => void replace('speedUp')}
          >
            Speed up…
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={working || view.busy || view.status.kind !== 'unlocked'}
            title="A zero-value transfer to yourself at the same nonce; if it lands first, the original never will"
            onClick={() => void replace('cancel')}
          >
            Cancel transaction…
          </Button>
        </div>
      )}
      {message && (
        <p role="status" className="break-words text-muted">
          {message}
        </p>
      )}
    </div>
  );
}
