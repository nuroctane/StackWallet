import { useId, useState, type ReactNode } from 'react';
import type { ExportGateInput, ExportKeyScope } from '@stackwallet/core-client';
import { Button, Field, Input, Select, SecurityGlyph, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView, type SessionChoice } from '../core/vault.js';

export const MIN_EXPORT_KEY_CHARS = 8;

/**
 * "Prove it is you, now": the passphrase, or a passkey registered on this
 * device. A PIN is never offered here; it opens a session but no export.
 */
export function SessionField({
  value,
  onChange,
  hint = 'asked again for every export',
}: {
  value: SessionChoice;
  onChange: (v: SessionChoice) => void;
  hint?: string;
}) {
  const ids = { method: useId(), pass: useId() };
  const { slots } = useVaultView(vault);
  const passkeys = slots.filter((s) => s.kind === 'passkey');
  return (
    <div className="flex flex-col gap-2">
      {passkeys.length > 0 && (
        <Field label="Sign in again with" htmlFor={ids.method}>
          <Select
            id={ids.method}
            value={value.kind === 'passkey' ? value.slotId : ''}
            onChange={(e) =>
              onChange(
                e.target.value === ''
                  ? { kind: 'passphrase', passphrase: '' }
                  : { kind: 'passkey', slotId: e.target.value },
              )
            }
          >
            <option value="">Vault passphrase</option>
            {passkeys.map((s) => (
              <option key={s.id} value={s.id}>
                Passkey · {s.label}
              </option>
            ))}
          </Select>
        </Field>
      )}
      {value.kind === 'passphrase' && (
        <Field label="Vault passphrase" htmlFor={ids.pass} hint={hint}>
          <Input
            id={ids.pass}
            type="password"
            autoComplete="current-password"
            value={value.passphrase}
            onChange={(e) => onChange({ kind: 'passphrase', passphrase: e.target.value })}
          />
        </Field>
      )}
      {value.kind === 'passkey' && (
        <p className="text-[11px] text-faint">Your device asks for the passkey when you confirm.</p>
      )}
    </div>
  );
}

export function sessionReady(v: SessionChoice): boolean {
  return v.kind === 'passkey' || v.passphrase !== '';
}

const NOUN: Record<ExportKeyScope, string> = { folder: 'directory', wallet: 'wallet' };

/**
 * One export key: an input when the key is set, otherwise a short form that
 * sets it (with the same session proof) before the export can go ahead.
 */
export function ExportKeyField({
  scope,
  id,
  name,
  value,
  onChange,
  session,
}: {
  scope: ExportKeyScope;
  id: string;
  name: string;
  value: string;
  onChange: (v: string) => void;
  session: SessionChoice;
}) {
  const view = useVaultView(vault);
  const inputId = useId();
  const has = view.exportKeys.some((k) => k.scope === scope && k.id === id);
  if (has) {
    return (
      <Field
        label={`${NOUN[scope] === 'directory' ? 'Directory' : 'Wallet'} key · ${name}`}
        htmlFor={inputId}
        hint={`the export key you set for this ${NOUN[scope]}`}
      >
        <Input
          id={inputId}
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
      </Field>
    );
  }
  return <SetExportKey scope={scope} id={id} name={name} session={session} />;
}

function SetExportKey({
  scope,
  id,
  name,
  session,
  current,
  onDone,
}: {
  scope: ExportKeyScope;
  id: string;
  name: string;
  session: SessionChoice;
  current?: boolean;
  onDone?: () => void;
}) {
  const toasts = useToasts();
  const view = useVaultView(vault);
  const ids = { cur: useId(), next: useId(), confirm: useId() };
  const [old, setOld] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const noun = NOUN[scope];
  const short = next.length > 0 && next.length < MIN_EXPORT_KEY_CHARS;
  const mismatch = confirm !== '' && confirm !== next;
  const ready =
    sessionReady(session) &&
    next.length >= MIN_EXPORT_KEY_CHARS &&
    next === confirm &&
    (!current || old !== '') &&
    !view.busy;

  const save = async () => {
    setError(null);
    let proof;
    try {
      proof = await vault.proveSession(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const r = await vault.setExportKey({
      scope,
      id,
      session: proof,
      ...(current ? { current: old } : {}),
      next,
    });
    if (!r.ok) {
      setError(r.error);
      return;
    }
    setOld('');
    setNext('');
    setConfirm('');
    toasts.push(
      `${noun === 'directory' ? 'Directory' : 'Wallet'} key ${current ? 'changed' : 'set'} for ${name}`,
    );
    onDone?.();
  };

  return (
    <div className="flex flex-col gap-2 rounded-sw-sm border border-edge p-3">
      <p className="flex items-start gap-1.5 text-[11px] text-muted">
        <SecurityGlyph glyph="lock" size={10} className="mt-px shrink-0" />
        {current
          ? `Change the export key of the ${noun} “${name}”.`
          : `The ${noun} “${name}” has no export key yet. Every export through this ${noun} needs one; it stays sealed in this device's vault and is never sent anywhere.`}
      </p>
      {current && (
        <Field label={`Current ${noun} key`} htmlFor={ids.cur}>
          <Input
            id={ids.cur}
            type="password"
            autoComplete="off"
            value={old}
            onChange={(e) => setOld(e.target.value)}
          />
        </Field>
      )}
      <Field
        label={`New ${noun} key`}
        htmlFor={ids.next}
        hint={`at least ${MIN_EXPORT_KEY_CHARS} characters, different from the passphrase`}
        error={short ? `At least ${MIN_EXPORT_KEY_CHARS} characters` : undefined}
      >
        <Input
          id={ids.next}
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
      </Field>
      <Field label="Confirm" htmlFor={ids.confirm} error={mismatch ? 'Keys differ' : undefined}>
        <Input
          id={ids.confirm}
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
      </Field>
      {error && <p className="text-[11px] text-danger">{error}</p>}
      <div className="flex justify-end">
        <Button size="sm" type="button" disabled={!ready} onClick={() => void save()}>
          {current ? 'Change key' : `Set ${noun} key`}
        </Button>
      </div>
    </div>
  );
}

/** Standalone key management: set or change one directory or wallet key. */
export function ExportKeyManager({
  scope,
  id,
  name,
  onDone,
}: {
  scope: ExportKeyScope;
  id: string;
  name: string;
  onDone: () => void;
}) {
  const view = useVaultView(vault);
  const [session, setSession] = useState<SessionChoice>({ kind: 'passphrase', passphrase: '' });
  const has = view.exportKeys.some((k) => k.scope === scope && k.id === id);
  if (view.status.kind !== 'unlocked')
    return <p className="p-4 text-[12px] text-faint">Unlock the vault to manage export keys.</p>;
  return (
    <div className="flex flex-col gap-4 p-4">
      <SessionField
        value={session}
        onChange={setSession}
        hint="asked again to change any export key"
      />
      <SetExportKey
        scope={scope}
        id={id}
        name={name}
        session={session}
        current={has}
        onDone={onDone}
      />
    </div>
  );
}

/**
 * The gate an export dialog renders: session, the directory key and (for one
 * wallet) the wallet key. `build` turns it into what the core checks.
 */
export function useExportGate(opts: {
  folderId: string;
  folderName: string;
  walletId?: string;
  walletName?: string;
}): {
  fields: ReactNode;
  ready: boolean;
  build: () => Promise<ExportGateInput>;
  reset: () => void;
} {
  const view = useVaultView(vault);
  const [session, setSession] = useState<SessionChoice>({ kind: 'passphrase', passphrase: '' });
  const [folderKey, setFolderKey] = useState('');
  const [walletKey, setWalletKey] = useState('');
  const hasFolder = view.exportKeys.some((k) => k.scope === 'folder' && k.id === opts.folderId);
  const hasWallet =
    opts.walletId === undefined ||
    view.exportKeys.some((k) => k.scope === 'wallet' && k.id === opts.walletId);
  const ready =
    sessionReady(session) &&
    hasFolder &&
    hasWallet &&
    folderKey !== '' &&
    (opts.walletId === undefined || walletKey !== '');

  const fields = (
    <div className="flex flex-col gap-3">
      <SessionField value={session} onChange={setSession} />
      <ExportKeyField
        scope="folder"
        id={opts.folderId}
        name={opts.folderName}
        value={folderKey}
        onChange={setFolderKey}
        session={session}
      />
      {opts.walletId !== undefined && (
        <ExportKeyField
          scope="wallet"
          id={opts.walletId}
          name={opts.walletName ?? 'this wallet'}
          value={walletKey}
          onChange={setWalletKey}
          session={session}
        />
      )}
    </div>
  );

  return {
    fields,
    ready,
    build: async () => ({
      session: await vault.proveSession(session),
      folderId: opts.folderId,
      folderKey,
      ...(opts.walletId !== undefined ? { walletKey } : {}),
    }),
    reset: () => {
      setSession((s) => (s.kind === 'passphrase' ? { kind: 'passphrase', passphrase: '' } : s));
      setFolderKey('');
      setWalletKey('');
    },
  };
}
