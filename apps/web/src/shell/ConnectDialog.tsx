import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import type { ChainInfo } from '@stackwallet/chains';
import { Badge, Button, Chip, Dialog, Field, Input, Select, useToasts } from '@stackwallet/ui';

import {
  ConnectRejected,
  discoverWallets,
  requestAddresses,
  type InjectedWallet,
} from '../lib/injected.js';
import { listChains, POPULAR_EVM } from '../lib/chains.js';
import { directory, useDirectory } from '../store/persist.js';
import { rootOf } from '../store/reducers.js';
import { useRegistry } from '../store/RegistryContext.js';
import { openDirectoryItem } from '../workspace/open.js';
import { AddressAvatar } from './AddressAvatar.js';
import { FolderOptions } from './FolderOptions.js';
import { useShell, type ShellDialog } from './ShellContext.js';

/**
 * One door for every way a wallet arrives: keys made here, a Ledger, a
 * shared wallet, an address to watch, or the accounts of a browser
 * extension. Extensions are only asked for addresses; what they share is
 * watched, never signed with, so the extension stays the only place its keys
 * live.
 */

type Step =
  | { kind: 'home' }
  | { kind: 'connecting'; wallet: InjectedWallet; error?: string }
  | { kind: 'pick'; wallet: InjectedWallet; addresses: string[]; chainId: string | null }
  | { kind: 'done'; walletIds: string[]; chains: number };

export function ConnectDialog({
  open,
  folderId,
  onClose,
}: {
  open: boolean;
  folderId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add a wallet"
      meta="keys stay where they are"
      width="w-[min(94vw,460px)]"
    >
      <ConnectHub folderId={folderId} onClose={onClose} />
    </Dialog>
  );
}

function Glyph({ d }: { d: string }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 18 18"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.2"
      aria-hidden="true"
    >
      <path d={d} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const GLYPH = {
  create: 'M9 3v12M3 9h12',
  ledger: 'M4 2.5h6v13H4zM10 6.5h4v5h-4M7 12.5h0',
  shared:
    'M6 6.5a2.5 2.5 0 1 0 0 .01M12 6.5a2.5 2.5 0 1 0 0 .01M2.5 15c.5-2.5 2-3.5 3.5-3.5s3 1 3.5 3.5M8.5 15c.5-2.5 2-3.5 3.5-3.5s3 1 3.5 3.5',
  watch:
    'M1.5 9s2.75-5 7.5-5 7.5 5 7.5 5-2.75 5-7.5 5-7.5-5-7.5-5zM9 11a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  import: 'M9 2.5v8M5.5 7 9 10.5 12.5 7M3 12.5v3h12v-3',
  dapps:
    'M6.5 11.5 11.5 6.5M7.5 4.5l1-1a3.5 3.5 0 0 1 5 5l-1 1M10.5 13.5l-1 1a3.5 3.5 0 0 1-5-5l1-1',
};

function WalletIcon({ wallet, size = 28 }: { wallet: InjectedWallet; size?: number }) {
  return wallet.icon ? (
    <img
      src={wallet.icon}
      alt=""
      width={size}
      height={size}
      className="shrink-0 rounded-[6px]"
      draggable={false}
    />
  ) : (
    <span
      style={{ width: size, height: size }}
      className="inline-flex shrink-0 items-center justify-center rounded-[6px] border border-edge text-[12px] text-muted"
    >
      {wallet.name.slice(0, 1).toUpperCase()}
    </span>
  );
}

function Option({
  icon,
  title,
  detail,
  badge,
  onClick,
  delay,
}: {
  icon: ReactNode;
  title: string;
  detail: string;
  badge?: string;
  onClick: () => void;
  delay: number;
}) {
  return (
    <li className="sw-connect-item" style={{ animationDelay: `${delay}ms` }}>
      <button
        type="button"
        onClick={onClick}
        className="sw-pressable group flex w-full items-center gap-3 rounded-sw-sm border border-transparent px-2.5 py-2 text-left hover:border-edge hover:bg-elevated focus-visible:border-edge-strong"
      >
        <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center text-muted group-hover:text-ink">
          {icon}
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2 text-[13px] text-ink">
            {title}
            {badge && <Badge>{badge}</Badge>}
          </span>
          <span className="block truncate text-[11px] text-faint">{detail}</span>
        </span>
        <span className="sw-connect-arrow text-faint group-hover:text-ink" aria-hidden="true">
          →
        </span>
      </button>
    </li>
  );
}

function Heading({ children }: { children: ReactNode }) {
  return (
    <h3 className="mb-1 mt-3 px-2.5 text-[10px] uppercase tracking-[0.12em] text-faint first:mt-0">
      {children}
    </h3>
  );
}

function ConnectHub({ folderId, onClose }: { folderId?: string | undefined; onClose: () => void }) {
  const shell = useShell();
  const [step, setStep] = useState<Step>({ kind: 'home' });
  const [injected, setInjected] = useState<InjectedWallet[]>([]);
  useEffect(() => discoverWallets(setInjected), []);

  const go = (d: ShellDialog) => shell.openDialog(d);
  const connect = async (wallet: InjectedWallet) => {
    setStep({ kind: 'connecting', wallet });
    try {
      const { addresses, chainId } = await requestAddresses(wallet);
      if (addresses.length === 0) {
        setStep({ kind: 'connecting', wallet, error: 'The wallet shared no accounts.' });
        return;
      }
      setStep({ kind: 'pick', wallet, addresses, chainId });
    } catch (e) {
      setStep({
        kind: 'connecting',
        wallet,
        error:
          e instanceof ConnectRejected || e instanceof Error
            ? e.message
            : 'The wallet did not answer.',
      });
    }
  };

  let delay = 0;
  const next = () => (delay += 35);

  return (
    <div key={step.kind} className="sw-connect-step p-2">
      {step.kind === 'home' && (
        <>
          <Heading>in this browser</Heading>
          <ul>
            {injected.map((w) => (
              <Option
                key={w.uuid}
                icon={<WalletIcon wallet={w} size={22} />}
                title={w.name}
                detail="Share its addresses to watch here; it keeps its keys"
                badge="watch"
                delay={next()}
                onClick={() => void connect(w)}
              />
            ))}
          </ul>
          {injected.length === 0 && (
            <p className="px-2.5 py-1 text-[11px] leading-relaxed text-faint">
              No browser wallet found. Extensions such as MetaMask, Rabby or Coinbase Wallet appear
              here.
            </p>
          )}
          <Heading>keys on this device</Heading>
          <ul>
            <Option
              icon={<Glyph d={GLYPH.create} />}
              title="Create or restore"
              detail="A new phrase, or one you already have"
              delay={next()}
              onClick={() => go({ kind: 'newWallet', ...(folderId ? { folderId } : {}) })}
            />
            <Option
              icon={<Glyph d={GLYPH.ledger} />}
              title="Ledger"
              detail="The key stays on the device; you approve on its screen"
              delay={next()}
              onClick={() => go({ kind: 'hardwareWallet', ...(folderId ? { folderId } : {}) })}
            />
            <Option
              icon={<Glyph d={GLYPH.shared} />}
              title="Shared wallet"
              detail="Split between this device and a paired one"
              delay={next()}
              onClick={() =>
                go({
                  kind: 'threshold',
                  target: {
                    mode: 'create',
                    folderId: folderId ?? rootOf(directory.getSnapshot()).id,
                  },
                })
              }
            />
          </ul>
          <Heading>no keys</Heading>
          <ul>
            <Option
              icon={<Glyph d={GLYPH.watch} />}
              title="Watch an address"
              detail="Balances and history for any address, on one chain or many"
              delay={next()}
              onClick={() => go({ kind: 'watch', ...(folderId ? { folderId } : {}) })}
            />
            <Option
              icon={<Glyph d={GLYPH.import} />}
              title="Open a sealed set"
              detail="A directory or wallet exported from another StackWallet"
              delay={next()}
              onClick={() => go({ kind: 'importSet' })}
            />
            <Option
              icon={<Glyph d={GLYPH.dapps} />}
              title="Connect to a dapp"
              detail="WalletConnect: use these wallets inside web apps"
              delay={next()}
              onClick={() => go({ kind: 'walletConnect' })}
            />
          </ul>
        </>
      )}

      {step.kind === 'connecting' && (
        <div className="flex flex-col items-center px-4 pb-4 pt-6 text-center">
          <WalletIcon wallet={step.wallet} size={44} />
          <p className="mt-4 flex items-center gap-2 text-[13px] text-ink">
            {step.error ? 'Not connected' : `Approve in ${step.wallet.name}`}
            {!step.error && (
              <span
                role="status"
                aria-label="waiting for the wallet"
                className="sw-spin block h-2.5 w-2.5 rounded-full border border-edge-strong border-t-transparent"
              />
            )}
          </p>
          <p
            className={`mt-1 max-w-[30ch] text-[11px] leading-relaxed ${step.error ? 'text-danger' : 'text-faint'}`}
          >
            {step.error ??
              'StackWallet asks only for addresses. Nothing will be signed, and no permission to spend is requested.'}
          </p>
          <div className="mt-5 flex gap-2">
            <Button size="sm" variant="ghost" onClick={() => setStep({ kind: 'home' })}>
              Back
            </Button>
            {step.error && (
              <Button size="sm" variant="primary" onClick={() => void connect(step.wallet)}>
                Try again
              </Button>
            )}
          </div>
        </div>
      )}

      {step.kind === 'pick' && (
        <PickAccounts
          step={step}
          initialFolderId={folderId}
          onBack={() => setStep({ kind: 'home' })}
          onDone={(walletIds, chains) => setStep({ kind: 'done', walletIds, chains })}
        />
      )}

      {step.kind === 'done' && (
        <div className="flex flex-col items-center px-4 pb-4 pt-6 text-center">
          <span className="sw-connect-check inline-flex h-11 w-11 items-center justify-center rounded-full border border-edge-strong text-ink">
            <svg
              width="18"
              height="18"
              viewBox="0 0 18 18"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              aria-hidden="true"
            >
              <path d="M4 9.5 7.5 13 14 5.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <p className="mt-4 text-[13px] text-ink">
            Watching {step.walletIds.length} address{step.walletIds.length === 1 ? '' : 'es'} on{' '}
            {step.chains} chain
            {step.chains === 1 ? '' : 's'}
          </p>
          <p className="mt-1 max-w-[32ch] text-[11px] leading-relaxed text-faint">
            Refresh balances when you want them; until then nothing is sent anywhere.
          </p>
          <div className="mt-5 flex gap-2">
            <Button size="sm" variant="ghost" onClick={onClose}>
              Done
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                const first = step.walletIds[0];
                onClose();
                if (first) openDirectoryItem(first);
              }}
            >
              Open wallet
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function PickAccounts({
  step,
  initialFolderId,
  onBack,
  onDone,
}: {
  step: Extract<Step, { kind: 'pick' }>;
  initialFolderId?: string | undefined;
  onBack: () => void;
  onDone: (walletIds: string[], chains: number) => void;
}) {
  const state = useDirectory();
  const registry = useRegistry();
  const toasts = useToasts();
  const ids = { name: useId(), folder: useId() };
  const evm = useMemo(() => listChains(registry).filter((c) => c.family === 'evm'), [registry]);
  const byId = useMemo(() => new Map(evm.map((c) => [c.chainId, c])), [evm]);
  const popular = POPULAR_EVM.flatMap((id) => (byId.has(id) ? [byId.get(id) as ChainInfo] : []));
  const current = step.chainId && byId.has(step.chainId) ? step.chainId : null;
  const [chains, setChains] = useState<string[]>(() =>
    [...new Set(['eip155:1', ...(current ? [current] : [])])].filter((id) => byId.has(id)),
  );
  const [showAll, setShowAll] = useState(false);
  const [picked, setPicked] = useState<string[]>(step.addresses);
  const [name, setName] = useState(step.wallet.name);
  const [folder, setFolder] = useState(initialFolderId ?? rootOf(state).id);
  const [error, setError] = useState('');
  const watched = new Set(
    state.accounts.filter((a) => a.family === 'evm').map((a) => a.address.toLowerCase()),
  );
  const extra = evm.filter((c) => !popular.includes(c) && (showAll || chains.includes(c.chainId)));
  const toggle = (id: string) =>
    setChains(chains.includes(id) ? chains.filter((x) => x !== id) : [...chains, id]);

  const add = () => {
    const [primary, ...rest] = chains;
    if (!primary || picked.length === 0) return;
    const made: string[] = [];
    for (const [i, address] of picked.entries()) {
      const r = directory.createWatchWallet({
        name: picked.length === 1 ? name : `${name} ${i + 1}`,
        folderId: folder,
        chainId: primary,
        address,
        extraChainIds: rest,
      });
      if (!r.ok) {
        setError(r.error);
        break;
      }
      made.push(r.value);
    }
    if (made.length > 0) {
      toasts.push(
        `Watching ${made.length} address${made.length === 1 ? '' : 'es'} from ${step.wallet.name}`,
      );
      onDone(made, chains.length);
    }
  };

  return (
    <div className="flex flex-col gap-3 p-2">
      <div className="flex items-center gap-3">
        <WalletIcon wallet={step.wallet} size={28} />
        <div className="min-w-0">
          <p className="text-[13px] text-ink">
            {step.wallet.name} shared {step.addresses.length} account
            {step.addresses.length === 1 ? '' : 's'}
          </p>
          <p className="text-[11px] text-faint">
            They will be watched here. Signing stays in {step.wallet.name}.
          </p>
        </div>
      </div>
      <ul className="divide-y divide-edge/60 rounded-sw-sm border border-edge">
        {step.addresses.map((a) => {
          const on = picked.includes(a);
          return (
            <li key={a}>
              <label className="flex cursor-pointer items-center gap-2.5 px-2.5 py-2">
                <input
                  type="checkbox"
                  checked={on}
                  className="accent-[var(--sw-ink)]"
                  onChange={() => setPicked(on ? picked.filter((x) => x !== a) : [...picked, a])}
                />
                <AddressAvatar address={a} size={18} />
                <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted">
                  {a}
                </span>
                {watched.has(a.toLowerCase()) && <Badge>already here</Badge>}
              </label>
            </li>
          );
        })}
      </ul>
      <Field label="Chains to watch on">
        <div className="flex flex-wrap gap-1.5">
          {[...popular, ...extra].map((c) => (
            <Chip
              key={c.chainId}
              active={chains.includes(c.chainId)}
              onClick={() => toggle(c.chainId)}
            >
              {c.name}
              {c.chainId === current ? ' · current' : ''}
              {c.testnet ? ' · test' : ''}
            </Chip>
          ))}
          {!showAll && evm.length > popular.length && (
            <button
              type="button"
              className="text-[11px] text-muted underline"
              onClick={() => setShowAll(true)}
            >
              {evm.length - popular.length} more
            </button>
          )}
        </div>
      </Field>
      <div className="grid grid-cols-2 gap-2">
        <Field label="Name" htmlFor={ids.name}>
          <Input
            id={ids.name}
            value={name}
            maxLength={70}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field label="Folder" htmlFor={ids.folder}>
          <Select id={ids.folder} value={folder} onChange={(e) => setFolder(e.target.value)}>
            <FolderOptions state={state} />
          </Select>
        </Field>
      </div>
      {error && <p className="text-[11px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2 border-t border-edge pt-3">
        <Button variant="ghost" size="sm" onClick={onBack}>
          Back
        </Button>
        <Button
          variant="primary"
          size="sm"
          disabled={picked.length === 0 || chains.length === 0 || name.trim() === ''}
          onClick={add}
        >
          Watch {picked.length} on {chains.length} chain{chains.length === 1 ? '' : 's'}
        </Button>
      </div>
    </div>
  );
}
