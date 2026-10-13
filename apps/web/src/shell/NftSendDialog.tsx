import { useId, useState, type FormEvent } from 'react';
import { isValidEvmAddress } from '@stackwallet/chains-evm';
import type { TxRecord } from '@stackwallet/core-client';
import { Button, Dialog, Field, Input, LoadingWord } from '@stackwallet/ui';

import { encodeNftTransfer } from '../lib/nftCalls.js';
import { useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { proposeContractCall } from '../store/txs.js';
import { AddressLabel } from './AddressLabel.js';

export interface NftSendTarget {
  accountId: string;
  contract: string;
  tokenId: string;
  standard: string;
  name: string;
  /** Owned amount (ERC-1155). */
  held: string;
}

/**
 * Send one collectible. It becomes an ordinary contract-call proposal: the
 * core checks the calldata byte for byte, policy runs, and it waits in the
 * approval queue for a signature like any transfer.
 */
export function NftSendDialog({
  open,
  target,
  onClose,
}: {
  open: boolean;
  target?: NftSendTarget | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Send collectible"
      meta="through the approval queue"
    >
      {target && <NftSendForm target={target} onClose={onClose} />}
    </Dialog>
  );
}

function NftSendForm({ target, onClose }: { target: NftSendTarget; onClose: () => void }) {
  const state = useDirectory();
  const registry = useRegistry();
  const ids = { to: useId(), amount: useId() };
  const account = state.accounts.find((a) => a.id === target.accountId);
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('1');
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TxRecord | null>(null);
  if (!account) return <p className="p-4 text-[12px] text-faint">Account not found.</p>;
  const multi = target.standard === 'erc1155';
  const toValid = isValidEvmAddress(to.trim());
  const amountValid =
    !multi ||
    (/^\d+$/.test(amount) && BigInt(amount) > 0n && BigInt(amount) <= BigInt(target.held));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const data = encodeNftTransfer(
      target.standard,
      account.address,
      to.trim(),
      target.tokenId,
      amount,
    );
    if (!data) {
      setError('This collectible cannot be sent from here');
      return;
    }
    setWorking(true);
    setError(null);
    const r = await proposeContractCall(registry, { account, to: target.contract, dataHex: data });
    setWorking(false);
    if (!r.ok) setError(r.error);
    else setResult(r.value);
  };

  if (result) {
    return (
      <div className="flex flex-col gap-3 p-4 text-[12px]">
        <p className="text-muted">
          {result.state === 'awaiting'
            ? 'Proposed and checked by the core. Approve it in the approval queue to sign and send.'
            : 'Denied by policy; the approval card shows why.'}
        </p>
        <div className="flex justify-end">
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <p className="text-[12px] text-muted">
        <span className="text-ink">{target.name}</span> · token {target.tokenId} ·{' '}
        <AddressLabel address={target.contract} chainId={account.chainId} />
      </p>
      <Field
        label="To"
        htmlFor={ids.to}
        error={to.trim() !== '' && !toValid ? 'Not a valid EVM address (checksum included)' : null}
      >
        <Input
          id={ids.to}
          value={to}
          placeholder="0x…"
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => setTo(e.target.value)}
        />
      </Field>
      {multi && (
        <Field label="Amount" htmlFor={ids.amount} hint={`you hold ${target.held}`}>
          <Input
            id={ids.amount}
            value={amount}
            inputMode="numeric"
            onChange={(e) => setAmount(e.target.value)}
          />
        </Field>
      )}
      {toValid && <AddressLabel address={to.trim()} chainId={account.chainId} full />}
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!toValid || !amountValid || working}>
          {working ? <LoadingWord label="preparing" /> : 'Propose'}
        </Button>
      </div>
      <p className="text-[10px] text-faint">{registry.chainInfo(account.chainId)?.name}</p>
    </form>
  );
}
