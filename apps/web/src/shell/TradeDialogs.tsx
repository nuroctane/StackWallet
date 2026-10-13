import { useEffect, useId, useState, type FormEvent } from 'react';
import {
  allowanceOf,
  encodeApprove,
  minOutFor,
  quoteSwap,
  swapAggregator,
  swapRoute,
  type EvmAdapter,
  type Quote,
} from '@stackwallet/chains-evm';
import {
  listDelegations,
  listValidators,
  type CosmosAdapter,
  type Delegation,
  type Validator,
} from '@stackwallet/chains-cosmos';
import type { Account, TxRecord } from '@stackwallet/core-client';
import { Button, Dialog, Field, Input, LoadingWord, Select } from '@stackwallet/ui';

import { findChain } from '../lib/chains.js';
import { formatUnits, parseUnits } from '../lib/format.js';
import { useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { accountsOf } from '../store/selectors.js';
import { useTokens } from '../store/tokens.js';
import { proposeContractCall, proposeStaking, proposeSwap } from '../store/txs.js';

interface Asset {
  ref: string;
  symbol: string;
  decimals: number;
  /** ERC-20 contract; null for the gas coin. */
  token: string | null;
}

function Proposed({ result, onClose }: { result: TxRecord; onClose: () => void }) {
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

function AccountPicker({
  id,
  accounts,
  value,
  onChange,
}: {
  id: string;
  accounts: Account[];
  value: string;
  onChange: (id: string) => void;
}) {
  const registry = useRegistry();
  return (
    <Field label="Account" htmlFor={id}>
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {accounts.map((a) => (
          <option key={a.id} value={a.id}>
            {findChain(registry, a.chainId)?.name ?? a.chainId} · {a.address.slice(0, 10)}…
          </option>
        ))}
      </Select>
    </Field>
  );
}

// ---------------------------------------------------------------------------
// Swap
// ---------------------------------------------------------------------------

export function SwapDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="Swap" meta="uniswap v3 · testnet">
      {walletId && <SwapForm walletId={walletId} onClose={onClose} />}
    </Dialog>
  );
}

function SwapForm({ walletId, onClose }: { walletId: string; onClose: () => void }) {
  const state = useDirectory();
  const registry = useRegistry();
  const tracked = useTokens();
  const ids = { account: useId(), sell: useId(), buy: useId(), amount: useId(), slip: useId() };
  const accounts = accountsOf(state, walletId).filter(
    (a) => a.family === 'evm' && a.derivationPath && swapRoute(a.chainId),
  );
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? '');
  const account = accounts.find((a) => a.id === accountId) ?? accounts[0];
  const [sell, setSell] = useState('');
  const [buy, setBuy] = useState('');
  const [amount, setAmount] = useState('');
  const [slippage, setSlippage] = useState('50');
  const [quote, setQuote] = useState<Quote | null>(null);
  const [needsApproval, setNeedsApproval] = useState(false);
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TxRecord | null>(null);
  if (!account)
    return (
      <p className="p-4 text-[12px] text-faint">
        This wallet has no keyed account on a chain with a known swap router (Sepolia).
      </p>
    );
  const route = swapRoute(account.chainId)!;
  const chain = findChain(registry, account.chainId);
  const native: Asset = {
    ref: `${account.chainId}:native`,
    symbol: chain?.nativeAsset.symbol ?? 'ETH',
    decimals: chain?.nativeAsset.decimals ?? 18,
    token: null,
  };
  const tokens: Asset[] = [
    {
      ref: `${account.chainId}:erc20:${route.weth.toLowerCase()}`,
      symbol: 'WETH',
      decimals: 18,
      token: route.weth,
    },
    ...tracked
      .filter(
        (t): t is Extract<typeof t, { address: string }> =>
          t.chainId === account.chainId && t.address !== route.weth.toLowerCase(),
      )
      .map((t) => ({
        ref: `${t.chainId}:erc20:${t.address}`,
        symbol: t.symbol,
        decimals: t.decimals,
        token: t.address,
      })),
  ];
  const sellAsset = [native, ...tokens].find((a) => a.ref === sell) ?? native;
  const buyAsset = tokens.find((a) => a.ref === buy && a.ref !== sellAsset.ref) ?? null;
  const amountIn = parseUnits(amount, sellAsset.decimals);
  const slip = Number(slippage);
  const slipValid = Number.isInteger(slip) && slip >= 1 && slip <= 5000;
  const adapter = registry.adapterFor(account.chainId) as unknown as EvmAdapter;
  const tokenIn = sellAsset.token ?? route.weth;
  const reset = () => {
    setQuote(null);
    setNeedsApproval(false);
    setError(null);
  };

  const getQuote = async () => {
    if (!buyAsset || !amountIn) return;
    setWorking('quoting');
    reset();
    try {
      const q = await quoteSwap(
        adapter,
        account.chainId,
        tokenIn,
        buyAsset.token!,
        BigInt(amountIn),
      );
      if (!q) setError('No pool quotes this pair on this testnet');
      setQuote(q);
      if (q && sellAsset.token) {
        const allowed = await allowanceOf(
          adapter,
          account.chainId,
          sellAsset.token,
          account.address,
          route.router,
        );
        setNeedsApproval(allowed < BigInt(amountIn));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setWorking(null);
    }
  };

  const approve = async () => {
    if (!sellAsset.token || !amountIn) return;
    setWorking('proposing');
    // Exactly this swap's amount: an unlimited allowance would outlive the swap.
    const r = await proposeContractCall(registry, {
      account,
      to: sellAsset.token,
      dataHex: encodeApprove(route.router, BigInt(amountIn)),
    });
    setWorking(null);
    if (!r.ok) setError(r.error);
    else setResult(r.value);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!quote || !buyAsset || !amountIn || !slipValid) return;
    setWorking('proposing');
    const r = await proposeSwap(registry, {
      account,
      sell: sellAsset.ref,
      sellAmount: amountIn,
      buy: buyAsset.ref,
      minBuyAmount: minOutFor(quote.amountOut, slip).toString(),
      maxSlippageBps: slip,
      aggregator: swapAggregator(quote.fee),
    });
    setWorking(null);
    if (!r.ok) setError(r.error);
    else setResult(r.value);
  };

  if (result) return <Proposed result={result} onClose={onClose} />;

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <AccountPicker
        id={ids.account}
        accounts={accounts}
        value={account.id}
        onChange={(v) => {
          setAccountId(v);
          reset();
        }}
      />
      <div className="grid grid-cols-2 gap-3">
        <Field label="Sell" htmlFor={ids.sell}>
          <Select
            id={ids.sell}
            value={sellAsset.ref}
            onChange={(e) => {
              setSell(e.target.value);
              reset();
            }}
          >
            {[native, ...tokens].map((a) => (
              <option key={a.ref} value={a.ref}>
                {a.symbol}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Buy" htmlFor={ids.buy}>
          <Select
            id={ids.buy}
            value={buyAsset?.ref ?? ''}
            onChange={(e) => {
              setBuy(e.target.value);
              reset();
            }}
          >
            <option value="">choose…</option>
            {tokens
              .filter((a) => a.ref !== sellAsset.ref)
              .map((a) => (
                <option key={a.ref} value={a.ref}>
                  {a.symbol}
                </option>
              ))}
          </Select>
        </Field>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <Field
          label="Amount"
          htmlFor={ids.amount}
          error={amount && !amountIn ? `Not a ${sellAsset.symbol} amount` : null}
        >
          <Input
            id={ids.amount}
            value={amount}
            inputMode="decimal"
            onChange={(e) => {
              setAmount(e.target.value);
              reset();
            }}
          />
        </Field>
        <Field
          label="Slippage (bps)"
          htmlFor={ids.slip}
          error={slipValid ? null : '1 to 5000'}
          hint="50 = 0.5%"
        >
          <Input
            id={ids.slip}
            value={slippage}
            inputMode="numeric"
            onChange={(e) => setSlippage(e.target.value.replace(/\D/g, ''))}
          />
        </Field>
      </div>
      {quote && buyAsset && (
        <p className="text-[12px] text-muted">
          Quote {formatUnits(quote.amountOut.toString(), buyAsset.decimals)} {buyAsset.symbol} ·
          pool fee {quote.fee / 10_000}% · at least{' '}
          <span className="text-ink">
            {slipValid
              ? formatUnits(minOutFor(quote.amountOut, slip).toString(), buyAsset.decimals)
              : '…'}{' '}
            {buyAsset.symbol}
          </span>{' '}
          or the swap reverts.
        </p>
      )}
      {needsApproval && (
        <p className="text-[12px] text-muted">
          The router may not spend this {sellAsset.symbol} yet. Propose an approval for exactly this
          amount, approve it in the queue, then come back to swap.
        </p>
      )}
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="button"
          disabled={!buyAsset || !amountIn || working !== null}
          onClick={() => void getQuote()}
        >
          {working === 'quoting' ? <LoadingWord label="quoting" /> : 'Quote'}
        </Button>
        {needsApproval ? (
          <Button
            type="button"
            variant="primary"
            disabled={working !== null}
            onClick={() => void approve()}
          >
            Propose approval
          </Button>
        ) : (
          <Button
            type="submit"
            variant="primary"
            disabled={!quote || !slipValid || working !== null}
          >
            {working === 'proposing' ? <LoadingWord label="preparing" /> : 'Propose swap'}
          </Button>
        )}
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Staking
// ---------------------------------------------------------------------------

type StakeAction = 'stake' | 'unstake' | 'claim';

export function StakeDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="Stake" meta="osmosis testnet">
      {walletId && <StakeForm walletId={walletId} onClose={onClose} />}
    </Dialog>
  );
}

function StakeForm({ walletId, onClose }: { walletId: string; onClose: () => void }) {
  const state = useDirectory();
  const registry = useRegistry();
  const ids = { account: useId(), action: useId(), validator: useId(), amount: useId() };
  const accounts = accountsOf(state, walletId).filter(
    (a) => a.family === 'cosmos' && a.derivationPath,
  );
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? '');
  const account = accounts.find((a) => a.id === accountId) ?? accounts[0];
  const [action, setAction] = useState<StakeAction>('stake');
  const [validators, setValidators] = useState<Validator[] | null>(null);
  const [delegations, setDelegations] = useState<Delegation[] | null>(null);
  const [validator, setValidator] = useState('');
  const [amount, setAmount] = useState('');
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TxRecord | null>(null);

  useEffect(() => {
    if (!account) return;
    let live = true;
    const adapter = registry.adapterFor(account.chainId) as unknown as CosmosAdapter;
    setValidators(null);
    setDelegations(null);
    Promise.all([listValidators(adapter), listDelegations(adapter, account.address)])
      .then(([v, d]) => {
        if (!live) return;
        setValidators(v);
        setDelegations(d);
      })
      .catch((err: unknown) => live && setError(err instanceof Error ? err.message : String(err)));
    return () => {
      live = false;
    };
  }, [account?.id, registry]);

  if (!account)
    return <p className="p-4 text-[12px] text-faint">This wallet has no keyed Osmosis account.</p>;
  if (!validators || !delegations)
    return (
      <div className="p-4">
        {error ? (
          <p className="text-[12px] text-danger">{error}</p>
        ) : (
          <LoadingWord label="reading validators" />
        )}
      </div>
    );

  const moniker = (op: string) => validators.find((v) => v.operator === op)?.moniker ?? op;
  const choices =
    action === 'stake'
      ? validators.map((v) => ({
          op: v.operator,
          label: `${v.moniker} · ${v.commissionBps / 100}%`,
        }))
      : delegations
          .filter((d) => action === 'unstake' || BigInt(d.rewards) > 0n)
          .map((d) => ({
            op: d.validator,
            label: `${moniker(d.validator)} · ${formatUnits(action === 'claim' ? d.rewards : d.amount, 6)} OSMO`,
          }));
  const chosen = choices.find((c) => c.op === validator)?.op ?? choices[0]?.op ?? '';
  const units = parseUnits(amount, 6);
  const staked = delegations.find((d) => d.validator === chosen)?.amount ?? '0';
  const amountValid =
    action === 'claim' ||
    (units !== null &&
      BigInt(units) > 0n &&
      (action !== 'unstake' || BigInt(units) <= BigInt(staked)));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!chosen || !amountValid) return;
    setWorking(true);
    setError(null);
    const r = await proposeStaking(
      registry,
      action === 'claim'
        ? { account, kind: 'claim', validator: chosen }
        : { account, kind: action, validator: chosen, amount: units! },
    );
    setWorking(false);
    if (!r.ok) setError(r.error);
    else setResult(r.value);
  };

  if (result) return <Proposed result={result} onClose={onClose} />;

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <AccountPicker
        id={ids.account}
        accounts={accounts}
        value={account.id}
        onChange={setAccountId}
      />
      <Field label="Action" htmlFor={ids.action}>
        <Select
          id={ids.action}
          value={action}
          onChange={(e) => {
            setAction(e.target.value as StakeAction);
            setValidator('');
          }}
        >
          <option value="stake">Delegate</option>
          <option value="unstake">Undelegate</option>
          <option value="claim">Claim rewards</option>
        </Select>
      </Field>
      <Field
        label="Validator"
        htmlFor={ids.validator}
        hint="names are chosen by validators; check the operator address"
      >
        <Select id={ids.validator} value={chosen} onChange={(e) => setValidator(e.target.value)}>
          {choices.length === 0 && <option value="">nothing to {action}</option>}
          {choices.map((c) => (
            <option key={c.op} value={c.op}>
              {c.label}
            </option>
          ))}
        </Select>
      </Field>
      {chosen && <code className="font-mono text-[11px] break-all text-faint">{chosen}</code>}
      {action !== 'claim' && (
        <Field
          label="Amount (OSMO)"
          htmlFor={ids.amount}
          error={amount && !amountValid ? 'Not an amount you can move here' : null}
          hint={
            action === 'unstake'
              ? `staked ${formatUnits(staked, 6)} · unbonding takes days`
              : undefined
          }
        >
          <Input
            id={ids.amount}
            value={amount}
            inputMode="decimal"
            onChange={(e) => setAmount(e.target.value)}
          />
        </Field>
      )}
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant="primary"
          disabled={!chosen || !amountValid || (action !== 'claim' && !amount) || working}
        >
          {working ? <LoadingWord label="preparing" /> : 'Propose'}
        </Button>
      </div>
    </form>
  );
}

/** Whether a wallet has anything these dialogs can act on. */
export function canSwap(accounts: readonly Account[]): boolean {
  return accounts.some((a) => a.family === 'evm' && a.derivationPath && swapRoute(a.chainId));
}
export function canStake(accounts: readonly Account[]): boolean {
  return accounts.some((a) => a.family === 'cosmos' && a.derivationPath);
}
