import { useId, useMemo, useState, type FormEvent } from 'react';
import type { ChainInfo } from '@stackwallet/chains';
import { Button, Dialog, Field, Input, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { adapterOrNull, FAMILY_LABEL, FAMILY_ORDER, listChains } from '../lib/chains.js';
import { standardPath } from '../lib/keys.js';
import { SENDABLE_TESTNETS } from '../lib/sendable.js';
import { directory, useDirectory } from '../store/persist.js';
import { rootOf } from '../store/reducers.js';
import { useRegistry } from '../store/RegistryContext.js';
import { chainMatches, chainOptionLabel } from './ChainSelect.js';
import { FolderOptions } from './FolderOptions.js';
import { useShell } from './ShellContext.js';

const DEFAULT_CHAINS = [
  'eip155:1',
  'eip155:8453',
  'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
  'bip122:000000000019d6689c085ae165831e93',
  'cosmos:cosmoshub-4',
  'tron:0x2b6653dc',
  ...SENDABLE_TESTNETS,
];

export function NewWalletDialog({
  open,
  folderId,
  onClose,
}: {
  open: boolean;
  folderId?: string | undefined;
  onClose: () => void;
}) {
  const view = useVaultView(vault);
  const shell = useShell();
  return (
    <Dialog open={open} onClose={onClose} title="New wallet" meta="key sealed in your vault">
      {view.status.kind === 'unlocked' ? (
        <NewWalletForm initialFolderId={folderId} onClose={onClose} />
      ) : (
        <div className="flex flex-col gap-3 p-4 text-[12px] text-faint">
          <p>A wallet key lives in the vault, so the vault has to be unlocked first.</p>
          <div>
            <Button size="sm" onClick={() => shell.openDialog({ kind: 'vault' })}>
              {view.status.kind === 'absent' ? 'Create vault' : 'Unlock vault'}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

function NewWalletForm({
  initialFolderId,
  onClose,
}: {
  initialFolderId?: string | undefined;
  onClose: () => void;
}) {
  const state = useDirectory();
  const registry = useRegistry();
  const toasts = useToasts();
  const view = useVaultView(vault);
  const ids = { name: useId(), folder: useId(), phrase: useId() };

  const chains = useMemo(
    () => listChains(registry).filter((c) => standardPath(c) !== null),
    [registry],
  );
  const [name, setName] = useState(
    () => `Wallet ${state.wallets.filter((w) => w.kind !== 'watch').length + 1}`,
  );
  const [folder, setFolder] = useState(initialFolderId ?? rootOf(state).id);
  const [mode, setMode] = useState<'create' | 'restore'>('create');
  const [phrase, setPhrase] = useState('');
  const [picked, setPicked] = useState<Set<string>>(
    () => new Set(DEFAULT_CHAINS.filter((id) => chains.some((c) => c.chainId === id))),
  );
  const [showTestnets, setShowTestnets] = useState(true);
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  const words = phrase.trim().split(/\s+/).filter(Boolean).length;
  const canSubmit =
    !working &&
    name.trim() !== '' &&
    picked.size > 0 &&
    (mode === 'create' || [12, 15, 18, 21, 24].includes(words));

  const toggle = (id: string) =>
    setPicked((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setWorking(true);
    setError(null);
    const walletId = crypto.randomUUID();
    try {
      const sealed = await vault.createSingle(walletId, mode === 'restore' ? phrase : undefined);
      if (!sealed.ok) throw new Error(sealed.error);
      const accounts = [];
      for (const chain of chains.filter((c) => picked.has(c.chainId))) {
        const sp = standardPath(chain)!;
        const adapter = adapterOrNull(registry, chain.chainId);
        if (!adapter) continue;
        const hex = await vault.publicKey(walletId, sp.curve, sp.path);
        accounts.push({
          chainId: chain.chainId,
          address: adapter.deriveAddress({ curve: sp.curve, hex }, chain.chainId),
          derivationPath: sp.path,
          publicKeyHex: hex,
        });
      }
      const r = directory.createKeyedWallet({ walletId, name, folderId: folder, accounts });
      if (!r.ok) throw new Error(r.error);
      toasts.push(
        mode === 'create'
          ? `Created "${name.trim()}": local only, no backup yet`
          : `Restored "${name.trim()}" (tagged imported)`,
      );
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setWorking(false);
    }
  };

  const groups = (testnet: boolean) =>
    FAMILY_ORDER.map((family) => ({
      family,
      list: chains
        .filter(
          (c) =>
            c.family === family &&
            c.testnet === testnet &&
            (picked.has(c.chainId) || chainMatches(c, query)),
        )
        .sort((a, b) => a.name.localeCompare(b.name)),
    })).filter((g) => g.list.length > 0);

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <Field label="Name" htmlFor={ids.name}>
        <Input
          id={ids.name}
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Trading"
          maxLength={80}
        />
      </Field>
      <Field label="Folder" htmlFor={ids.folder}>
        <Select id={ids.folder} value={folder} onChange={(e) => setFolder(e.target.value)}>
          <FolderOptions state={state} />
        </Select>
      </Field>

      <div className="flex gap-1 text-[12px]" role="radiogroup" aria-label="key source">
        {(['create', 'restore'] as const).map((m) => (
          <button
            key={m}
            type="button"
            role="radio"
            aria-checked={mode === m}
            onClick={() => setMode(m)}
            className={`sw-pressable h-7 rounded-sw-sm border px-2 ${mode === m ? 'border-edge-strong text-ink' : 'border-edge text-faint'}`}
          >
            {m === 'create' ? 'new key' : 'restore a phrase'}
          </button>
        ))}
      </div>
      {mode === 'create' ? (
        <p className="text-[12px] text-faint">
          A 24-word phrase is generated inside the core and sealed in your vault. The wallet starts{' '}
          <span className="text-muted">local · no backup</span>; exporting the phrase later marks it{' '}
          <span className="text-danger">exposed</span> for good.
        </p>
      ) : (
        <Field
          label="Recovery phrase"
          htmlFor={ids.phrase}
          error={words > 0 && ![12, 15, 18, 21, 24].includes(words) ? `${words} words` : null}
        >
          <textarea
            id={ids.phrase}
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            className="h-20 resize-none rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[12px] text-ink outline-none focus:border-edge-strong"
            placeholder="12 or 24 words"
          />
        </Field>
      )}

      <fieldset className="flex flex-col gap-2">
        <legend className="pb-1 text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
          Accounts ({picked.size})
        </legend>
        <Input
          aria-label="Filter chains"
          value={query}
          placeholder={`Filter ${chains.length} chains by name, symbol or id`}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="max-h-[220px] overflow-auto rounded-sw-sm border border-edge p-2">
          {[false, ...(showTestnets ? [true] : [])].map((testnet) =>
            groups(testnet).map((g) => (
              <ChainGroup
                key={`${testnet}-${g.family}`}
                label={`${FAMILY_LABEL[g.family]}${testnet ? ' · testnets' : ''}`}
                list={g.list}
                picked={picked}
                toggle={toggle}
              />
            )),
          )}
        </div>
        <label className="flex items-center gap-2 text-[11px] text-faint">
          <input
            type="checkbox"
            checked={showTestnets}
            onChange={(e) => setShowTestnets(e.target.checked)}
          />
          show testnets
        </label>
        <p className="text-[11px] text-faint">
          Sending works on testnets in this build (Sepolia and other EVM test networks, Bitcoin
          Signet, Solana Devnet, Osmosis Testnet, Tron Nile). Mainnet accounts receive and show
          balances.
        </p>
      </fieldset>

      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!canSubmit || view.busy}>
          {working ? <LoadingWord label="sealing" /> : mode === 'create' ? 'Create' : 'Restore'}
        </Button>
      </div>
    </form>
  );
}

function ChainGroup({
  label,
  list,
  picked,
  toggle,
}: {
  label: string;
  list: ChainInfo[];
  picked: Set<string>;
  toggle: (id: string) => void;
}) {
  return (
    <div className="pb-2">
      <div className="pb-1 text-[10px] tracking-[0.08em] text-faint uppercase">{label}</div>
      <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
        {list.map((c) => (
          <label key={c.chainId} className="flex items-center gap-1.5 text-[12px] text-muted">
            <input
              type="checkbox"
              checked={picked.has(c.chainId)}
              onChange={() => toggle(c.chainId)}
            />
            <span className="truncate" title={chainOptionLabel(c)}>
              {c.name}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
}
