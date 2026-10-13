import { useState } from 'react';
import type { Account } from '@stackwallet/core-client';
import { revokeCalldata } from '@stackwallet/chains-evm';
import { Button, SecurityGlyph, useToasts } from '@stackwallet/ui';

import { EVM_SIGNING_CHAINS, explorerTxUrl, findChain } from '../../lib/chains.js';
import { proposeContractCall } from '../../store/txs.js';
import { relativeTime } from '../../lib/format.js';
import { ApprovalsStore, approvalsStore, useApprovalsVersion } from '../../store/approvals.js';
import { useRegistry } from '../../store/RegistryContext.js';
import { tokenStore } from '../../store/tokens.js';
import { AddressLabel } from '../AddressLabel.js';

const KIND_LABEL = { erc20: 'token allowance', nft: 'collectible', operator: 'all collectibles' };

/**
 * Every open allowance and collectible approval on the wallet's EVM
 * addresses. These drive the locked `approvals` tag; only revoking on chain
 * (and the next scan reading the contract) clears it.
 */
export function ApprovalsSection({ accounts }: { accounts: Account[] }) {
  useApprovalsVersion();
  const registry = useRegistry();
  const toasts = useToasts();
  const owners = ApprovalsStore.owners(accounts);
  if (owners.length === 0) return null;
  const chains = approvalsStore.scanChains();
  const open = approvalsStore.openFor(accounts);
  const statuses = owners.flatMap((o) => chains.map((c) => approvalsStore.statusOf(c, o)));
  const scanning = statuses.some((s) => s.scanning);
  const errors = statuses.filter((s) => s.error).length;
  const checked = owners
    .flatMap((o) => chains.map((c) => approvalsStore.get(c, o)?.checkedAtMs ?? 0))
    .filter((t) => t > 0);
  const oldest = checked.length > 0 ? Math.min(...checked) : 0;
  const truncated = owners.some((o) => chains.some((c) => approvalsStore.get(c, o)?.truncated));
  const now = Date.now();

  return (
    <section className="sw-elevated flex min-w-0 flex-col overflow-hidden">
      <header className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
        <h3 className="flex items-center gap-1.5 text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
          <SecurityGlyph glyph="approvals" size={10} />
          Approvals
        </h3>
        <div className="flex items-center gap-2 text-[11px] text-faint">
          <span>
            {oldest > 0
              ? `checked ${relativeTime(oldest, now)} on ${chains.length} chains`
              : `${chains.length} chains`}
          </span>
          <Button
            size="sm"
            variant="ghost"
            disabled={scanning || chains.length === 0}
            onClick={() => {
              for (const o of owners) void approvalsStore.scan(o, { force: true });
            }}
          >
            {scanning ? 'scanning…' : 'rescan'}
          </Button>
        </div>
      </header>
      <div className="flex flex-col gap-2 px-4 py-3 text-[12px]">
        {open.length === 0 ? (
          <p className="text-faint">
            {oldest > 0
              ? 'No open token allowances or collectible approvals were found on this wallet’s addresses.'
              : scanning
                ? 'Reading approval history…'
                : 'Not scanned yet.'}
          </p>
        ) : (
          <ul className="flex flex-col divide-y divide-edge">
            {open.map((a) => {
              const info = findChain(registry, a.chainId);
              const token = tokenStore.find(`${a.chainId}:erc20:${a.token}`);
              const tx = info ? explorerTxUrl(info, a.txHash) : undefined;
              return (
                <li
                  key={`${a.chainId}|${a.kind}|${a.token}|${a.spender}|${a.tokenId ?? ''}`}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5"
                >
                  <span className="w-[9ch] shrink-0 text-faint">{info?.name ?? a.chainId}</span>
                  <span className="text-muted">{KIND_LABEL[a.kind]}</span>
                  <span className="font-mono text-ink">
                    {token?.symbol ?? <AddressLabel address={a.token} chainId={a.chainId} />}
                    {a.tokenId !== undefined &&
                      ` #${a.tokenId.length > 10 ? `${a.tokenId.slice(0, 8)}…` : a.tokenId}`}
                  </span>
                  <span className="text-faint">to</span>
                  <AddressLabel address={a.spender} chainId={a.chainId} />
                  <span className={a.unlimited ? 'text-danger' : 'text-muted'}>
                    {a.kind === 'erc20'
                      ? a.unlimited
                        ? 'unlimited'
                        : `${a.amount ?? '?'} base units`
                      : a.kind === 'operator'
                        ? 'every item'
                        : 'one item'}
                  </span>
                  {!a.verified && (
                    <span
                      className="text-faint"
                      title="The contract could not be read; the indexer's record is kept until it can be"
                    >
                      unverified
                    </span>
                  )}
                  <RevokeButton
                    approval={a}
                    accounts={accounts}
                    onDone={(m, bad) => toasts.push(m, bad ? 'danger' : undefined)}
                  />
                  {tx && (
                    <a
                      href={tx}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-faint underline-offset-2 hover:underline"
                    >
                      granted
                    </a>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {(errors > 0 || truncated) && (
          <p className="text-[11px] text-faint">
            {errors > 0 &&
              `${errors} chain scan${errors === 1 ? '' : 's'} failed; earlier results are kept. `}
            {truncated && 'The indexer returned a full page; older approvals may be missing.'}
          </p>
        )}
        {open.length > 0 && (
          <p className="text-[11px] text-faint">
            Revoke an approval by setting the allowance to zero (or the operator to false) from this
            address; the tag clears on the next scan that reads the contract.
          </p>
        )}
      </div>
    </section>
  );
}

type Approval = ReturnType<typeof approvalsStore.openFor>[number];

/**
 * Revoke through the approval queue: allowance to zero, operator to false,
 * or the token's approved address to nobody. Only where this wallet holds
 * the owner's key on that chain and the core signs there.
 */
function RevokeButton({
  approval,
  accounts,
  onDone,
}: {
  approval: Approval;
  accounts: Account[];
  onDone: (message: string, bad?: boolean) => void;
}) {
  const registry = useRegistry();
  const [busy, setBusy] = useState(false);
  const signer = accounts.find(
    (acc) =>
      acc.chainId === approval.chainId &&
      Boolean(acc.derivationPath) &&
      acc.address.toLowerCase() === approval.owner,
  );
  if (!signer || !EVM_SIGNING_CHAINS.has(approval.chainId)) return null;
  return (
    <Button
      size="sm"
      variant="ghost"
      disabled={busy}
      onClick={() => {
        setBusy(true);
        void proposeContractCall(registry, {
          account: signer,
          to: approval.token,
          dataHex: revokeCalldata(approval),
        }).then((r) => {
          setBusy(false);
          if (!r.ok) onDone(r.error, true);
          else
            onDone(
              r.value.state === 'awaiting'
                ? 'Revoke proposed; approve it in the approval queue'
                : 'The revoke was denied by policy',
              r.value.state !== 'awaiting',
            );
        });
      }}
    >
      {busy ? 'preparing…' : 'Revoke'}
    </Button>
  );
}
