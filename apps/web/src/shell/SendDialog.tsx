import { useId, useMemo, useRef, useState, type FormEvent } from 'react';
import { isValidEvmAddress, tokenInfo, type EvmAdapter } from '@stackwallet/chains-evm';
import { SOLANA_DEVNET, isValidSolanaAddress } from '@stackwallet/chains-solana';
import { COSMOS_TESTNET, isValidCosmosAddress } from '@stackwallet/chains-cosmos';
import {
  BITCOIN_SIGNET,
  isSignetRecipient,
  signetRecipient,
  type BitcoinAdapter,
  type BitcoinPrepareOptions,
} from '@stackwallet/chains-bitcoin';
import type { TxRecord } from '@stackwallet/core-client';
import { Button, Dialog, Field, Input, LoadingWord, Select } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { EVM_SIGNING_CHAINS, findChain } from '../lib/chains.js';
import { parseUnits } from '../lib/format.js';
import { useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { proposeSend } from '../store/txs.js';
import { tokenStore } from '../store/tokens.js';
import { AddressLabel } from './AddressLabel.js';
import { BitcoinCoinControl } from './BitcoinCoinControl.js';
import { SolanaMessageFormat } from './SolanaMessageFormat.js';
import { useShell } from './ShellContext.js';
import { useWalletLabel } from './WalletName.js';

/**
 * Propose a transfer from a supported single-key account. Nothing is signed here:
 * the proposal goes through the core (intent check, policy) and lands in the
 * approval queue, where signing needs the passphrase again.
 */
export function SendDialog({
  open,
  accountId,
  onClose,
}: {
  open: boolean;
  accountId?: string | undefined;
  onClose: () => void;
}) {
  const view = useVaultView(vault);
  const shell = useShell();
  return (
    <Dialog open={open} onClose={onClose} title="Send" meta="queued for approval">
      {view.status.kind === 'unlocked' ? (
        <SendForm initialAccountId={accountId} onClose={onClose} />
      ) : (
        <div className="flex flex-col gap-3 p-4 text-[12px] text-faint">
          <p>Sending needs the vault: the key and the transaction ledger both live in it.</p>
          <div>
            <Button size="sm" onClick={() => shell.openDialog({ kind: 'vault' })}>
              Unlock vault
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

function AccountOption({ walletId, walletName }: { walletId: string; walletName: string }) {
  const label = useWalletLabel({ id: walletId, name: walletName });
  return <>{label.text}</>;
}

function SendForm({
  initialAccountId,
  onClose,
}: {
  initialAccountId?: string | undefined;
  onClose: () => void;
}) {
  const state = useDirectory();
  const registry = useRegistry();
  const view = useVaultView(vault);
  const ids = { from: useId(), to: useId(), asset: useId(), token: useId(), amount: useId() };

  const accounts = useMemo(() => {
    const single = new Set(state.wallets.filter((w) => w.kind === 'single').map((w) => w.id));
    return state.accounts.filter(
      (a) =>
        ((a.family === 'evm' && EVM_SIGNING_CHAINS.has(a.chainId)) ||
          (a.family === 'solana' && a.chainId === SOLANA_DEVNET) ||
          (a.family === 'cosmos' && a.chainId === COSMOS_TESTNET) ||
          (a.family === 'bitcoin' && a.chainId === BITCOIN_SIGNET)) &&
        single.has(a.walletId) &&
        a.derivationPath,
    );
  }, [state]);
  const [accountId, setAccountId] = useState(
    accounts.find((a) => a.id === initialAccountId)?.id ?? accounts[0]?.id ?? '',
  );
  const account = accounts.find((a) => a.id === accountId);
  const chain = account ? findChain(registry, account.chainId) : undefined;

  const [to, setTo] = useState('');
  const [assetKind, setAssetKind] = useState<'native' | 'token'>('native');
  const [token, setToken] = useState('');
  const [tokenMeta, setTokenMeta] = useState<{ symbol: string; decimals: number } | null>(null);
  const tokenLookup = useRef(0);
  const [amount, setAmount] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const [result, setResult] = useState<TxRecord | null>(null);
  const [bitcoin, setBitcoin] = useState<BitcoinPrepareOptions>({});
  const [bitcoinReady, setBitcoinReady] = useState(true);
  const [messageVersion, setMessageVersion] = useState<'legacy' | 'v0'>('legacy');

  if (accounts.length === 0) {
    return (
      <p className="p-4 text-[12px] text-faint">
        Create a single-key wallet with an EVM chain, Bitcoin Signet, Solana Devnet or Osmosis
        Testnet to send here.
      </p>
    );
  }

  const decimals =
    assetKind === 'native' ? (chain?.nativeAsset.decimals ?? 18) : tokenMeta?.decimals;
  const symbol = assetKind === 'native' ? (chain?.nativeAsset.symbol ?? '') : tokenMeta?.symbol;
  const toValid =
    account?.family === 'bitcoin'
      ? isSignetRecipient(to.trim())
      : account?.family === 'solana'
        ? isValidSolanaAddress(to.trim())
        : account?.family === 'cosmos'
          ? isValidCosmosAddress(to.trim(), 'osmo') && to.trim() === to.trim().toLowerCase()
          : isValidEvmAddress(to.trim());
  const units = decimals === undefined ? null : parseUnits(amount, decimals);
  const exceedsLamports =
    (account?.family === 'solana' || account?.family === 'cosmos') &&
    units !== null &&
    BigInt(units) > 0xffffffffffffffffn;
  const canSubmit =
    !working &&
    (account?.family !== 'bitcoin' || bitcoinReady) &&
    toValid &&
    units !== null &&
    units !== '0' &&
    !exceedsLamports &&
    (assetKind === 'native' || tokenMeta);

  const lookupToken = async () => {
    const generation = ++tokenLookup.current;
    setTokenMeta(null);
    if (!account || !isValidEvmAddress(token.trim())) return;
    try {
      const adapter = registry.adapterFor(account.chainId) as unknown as EvmAdapter;
      const metadata = await tokenInfo(adapter, account.chainId, token.trim());
      if (generation !== tokenLookup.current) return;
      tokenStore.track({ chainId: account.chainId, address: token.trim(), ...metadata });
      setTokenMeta(metadata);
    } catch (err) {
      if (generation !== tokenLookup.current) return;
      setError(`Not a token on this chain: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit || !account || units === null) return;
    setWorking(true);
    setError(null);
    const asset =
      assetKind === 'native'
        ? `${account.chainId}:native`
        : `${account.chainId}:erc20:${token.trim()}`;
    const r = await proposeSend(registry, {
      account,
      to: to.trim(),
      asset,
      amount: units,
      ...(account.family === 'bitcoin' ? { bitcoin } : {}),
      ...(account.family === 'solana' ? { solana: { messageVersion } } : {}),
    });
    setWorking(false);
    if (!r.ok) setError(r.error);
    else setResult(r.value);
  };

  if (result) {
    const denied = result.decision?.decision === 'deny' ? result.decision.reasons : [];
    return (
      <div className="flex flex-col gap-3 p-4 text-[12px]">
        {result.state === 'awaiting' ? (
          <p className="text-muted">
            Proposed and checked by the core. It is waiting in the approval queue; signing asks for
            the vault passphrase again.
            {result.simulationOk === false && (
              <span className="block pt-1 text-danger">
                The simulation failed; the approval card shows why.
              </span>
            )}
          </p>
        ) : (
          <div className="text-danger">
            Denied by policy:
            <ul className="list-inside list-disc">
              {denied.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
        )}
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
      <Field label="From" htmlFor={ids.from}>
        <Select
          id={ids.from}
          value={accountId}
          disabled={working}
          onChange={(e) => {
            ++tokenLookup.current;
            setTokenMeta(null);
            setAssetKind('native');
            setBitcoin({});
            setBitcoinReady(true);
            setMessageVersion('legacy');
            setAccountId(e.target.value);
          }}
        >
          {accounts.map((a) => {
            const w = state.wallets.find((x) => x.id === a.walletId)!;
            return (
              <option key={a.id} value={a.id}>
                {findChain(registry, a.chainId)?.name ?? a.chainId} · {w.name} ·{' '}
                {a.address.slice(0, 6)}…{a.address.slice(-4)}
              </option>
            );
          })}
        </Select>
      </Field>
      {account && (
        <p className="-mt-2 text-[11px] text-faint">
          signing as{' '}
          <AccountOption
            walletId={account.walletId}
            walletName={state.wallets.find((w) => w.id === account.walletId)?.name ?? ''}
          />
        </p>
      )}
      <Field
        label="To"
        htmlFor={ids.to}
        error={
          to.trim() !== '' && !toValid
            ? account?.family === 'solana'
              ? 'Not a valid Solana public key'
              : account?.family === 'cosmos'
                ? 'Not a lowercase osmo address'
                : 'Not a valid EVM address (checksum included)'
            : null
        }
      >
        <Input
          id={ids.to}
          value={to}
          disabled={working}
          onChange={(e) => setTo(e.target.value)}
          placeholder={
            account?.family === 'solana'
              ? 'Solana public key…'
              : account?.family === 'cosmos'
                ? 'osmo1…'
                : '0x…'
          }
          spellCheck={false}
          autoComplete="off"
          list={`contacts-${ids.to}`}
        />
        <datalist id={`contacts-${ids.to}`}>
          {state.contacts
            .filter((c) =>
              account
                ? c.chainId === null
                  ? account.family === 'evm'
                  : c.chainId === account.chainId
                : false,
            )
            .map((c) => (
              <option key={c.id} value={c.address}>
                {c.name}
              </option>
            ))}
        </datalist>
      </Field>
      {toValid && account && (
        <div className="-mt-2 text-[12px]">
          <AddressLabel address={to.trim()} chainId={account.chainId} full />
        </div>
      )}
      <Field label="Asset" htmlFor={ids.asset}>
        <Select
          id={ids.asset}
          value={assetKind}
          disabled={working}
          onChange={(e) => setAssetKind(e.target.value as 'native' | 'token')}
        >
          <option value="native">{chain?.nativeAsset.symbol ?? 'native'}</option>
          {account?.family === 'evm' && <option value="token">ERC-20 token…</option>}
        </Select>
      </Field>
      {account?.family === 'solana' && (
        <SolanaMessageFormat
          value={messageVersion}
          disabled={working}
          onChange={setMessageVersion}
        />
      )}
      {account?.family === 'cosmos' && (
        <p className="text-[11px] text-faint">
          Osmosis Testnet native transfers only. A changed account sequence or expired timeout needs
          a fresh proposal.
        </p>
      )}
      {account?.family === 'bitcoin' && (
        <p className="text-[11px] text-faint">
          Signet P2WPKH sender; native SegWit or Taproot recipient. Automatic or manual confirmed
          input selection; {signetRecipient(to.trim())?.dustSats ?? '294–330'} sats minimum
          recipient output. Change returns to this sender. Network simulation is unavailable;
          policies requiring it refuse this transfer.
        </p>
      )}
      {account?.family === 'bitcoin' && (
        <BitcoinCoinControl
          key={account.id}
          adapter={registry.adapterFor(account.chainId) as unknown as BitcoinAdapter}
          from={account.address}
          to={to.trim()}
          disabled={working}
          onChange={(options, valid) => {
            setBitcoin(options);
            setBitcoinReady(valid);
          }}
        />
      )}
      {assetKind === 'token' && (
        <Field
          label="Token contract"
          htmlFor={ids.token}
          hint={tokenMeta ? `${tokenMeta.symbol} · ${tokenMeta.decimals} decimals` : undefined}
        >
          <Input
            id={ids.token}
            value={token}
            disabled={working}
            onChange={(e) => {
              ++tokenLookup.current;
              setTokenMeta(null);
              setToken(e.target.value);
            }}
            onBlur={() => void lookupToken()}
            placeholder="0x…"
            spellCheck={false}
          />
        </Field>
      )}
      <Field
        label={`Amount${symbol ? ` (${symbol})` : ''}`}
        htmlFor={ids.amount}
        error={
          exceedsLamports
            ? 'Amount exceeds the transfer base-unit limit'
            : amount !== '' && units === null
              ? 'Not an amount this asset can hold'
              : null
        }
      >
        <Input
          id={ids.amount}
          value={amount}
          disabled={working}
          inputMode="decimal"
          onChange={(e) => setAmount(e.target.value)}
          placeholder="0.0"
        />
      </Field>
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!canSubmit || view.busy}>
          {working ? <LoadingWord label="preparing" /> : 'Propose'}
        </Button>
      </div>
    </form>
  );
}
