import { useId, useState, type FormEvent } from 'react';
import { Badge, Button, Dialog, Field, Input, LoadingWord, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { deviceSecretSupported } from '../core/deviceSecret.js';
import { passkeySupported } from '../core/passkey.js';
import { MIN_PASSPHRASE_CHARS, passphraseProblem, useVaultView } from '../core/vault.js';
import { shortId } from './views/DevicesView.js';

export function VaultDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const view = useVaultView(vault);
  const title =
    view.status.kind === 'absent' || view.status.kind === 'corrupt'
      ? 'Create vault'
      : view.status.kind === 'locked'
        ? 'Unlock vault'
        : 'Vault';
  const meta = view.busy ? <LoadingWord label="deriving key" /> : undefined;

  return (
    <Dialog open={open} onClose={onClose} title={title} meta={meta}>
      {view.status.kind === 'loading' && (
        <p className="p-4 text-[12px] text-faint">
          <LoadingWord label="loading core" />
        </p>
      )}
      {view.status.kind === 'unavailable' && (
        <p className="p-4 text-[12px] text-faint">
          The core did not load ({view.status.reason}); the vault needs it for every operation.
        </p>
      )}
      {(view.status.kind === 'absent' || view.status.kind === 'corrupt') && (
        <CreateForm
          corruptKey={view.status.kind === 'corrupt' ? view.status.quarantinedKey : null}
          busy={view.busy}
          onClose={onClose}
        />
      )}
      {view.status.kind === 'locked' && <UnlockForm busy={view.busy} onClose={onClose} />}
      {view.status.kind === 'unlocked' && (
        <Manage
          labels={view.status.labels.length}
          deviceId={view.status.identity?.deviceId ?? null}
          busy={view.busy}
          onClose={onClose}
        />
      )}
    </Dialog>
  );
}

function Passphrase({
  id,
  label,
  value,
  onChange,
  error,
  hint,
  autoFocus,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  error?: string | null | undefined;
  hint?: string | undefined;
  autoFocus?: boolean | undefined;
}) {
  return (
    <Field label={label} htmlFor={id} error={error ?? undefined} hint={hint}>
      <Input
        id={id}
        type="password"
        autoFocus={autoFocus}
        autoComplete="off"
        spellCheck={false}
        value={value}
        invalid={Boolean(error)}
        onChange={(e) => onChange(e.target.value)}
      />
    </Field>
  );
}

function CreateForm({
  corruptKey,
  busy,
  onClose,
}: {
  corruptKey: string | null;
  busy: boolean;
  onClose: () => void;
}) {
  const toasts = useToasts();
  const ids = { pass: useId(), confirm: useId() };
  const [pass, setPass] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const mismatch = confirm !== '' && confirm !== pass;
  const canSubmit = !busy && pass !== '' && pass === confirm && passphraseProblem(pass) === null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const result = await vault.create(pass);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toasts.push('Vault created; this browser now has a device identity');
    onClose();
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <p className="text-[12px] text-faint">
        The vault encrypts this browser&apos;s device identity and any key you add, with Argon2id
        and a passphrase that never leaves this device. There is no reset: a forgotten passphrase
        means a new identity.
      </p>
      {corruptKey && (
        <p className="text-[12px] text-danger">
          The stored vault could not be read and was kept under <code>{corruptKey}</code>.
        </p>
      )}
      <Passphrase
        id={ids.pass}
        label="Passphrase"
        value={pass}
        onChange={(v) => {
          setPass(v);
          setError(null);
        }}
        error={error}
        hint={`At least ${MIN_PASSPHRASE_CHARS} characters; a few unrelated words work well.`}
        autoFocus
      />
      <Passphrase
        id={ids.confirm}
        label="Confirm"
        value={confirm}
        onChange={setConfirm}
        error={mismatch ? 'Passphrases differ' : null}
      />
      <div className="flex justify-end gap-2 border-t border-edge pt-3">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={!canSubmit}>
          Create vault
        </Button>
      </div>
    </form>
  );
}

function UnlockForm({ busy, onClose }: { busy: boolean; onClose: () => void }) {
  const id = useId();
  const pinId = useId();
  const { slots } = useVaultView(vault);
  const pinSlot = slots.find((s) => s.kind === 'pin');
  const passkeys = slots.filter((s) => s.kind === 'passkey');
  const [mode, setMode] = useState<'passphrase' | 'pin'>(pinSlot ? 'pin' : 'passphrase');
  const [pass, setPass] = useState('');
  const [pin, setPin] = useState('');
  const [error, setError] = useState<string | null>(null);

  const done = (result: { ok: boolean; error?: string }, wrong: string) => {
    if (!result.ok) {
      setError(
        /passphrase|decrypt|auth/i.test(result.error ?? '') ? wrong : (result.error ?? wrong),
      );
      setPass('');
      setPin('');
      return;
    }
    onClose();
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (mode === 'pin') done(await vault.unlockWithPin(pin), 'Wrong PIN');
    else done(await vault.unlock(pass), 'Wrong passphrase');
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      {passkeys.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {passkeys.map((k) => (
            <Button
              key={k.id}
              type="button"
              disabled={busy}
              onClick={() =>
                void vault
                  .unlockWithPasskey(k.id)
                  .then((r) => done(r, 'The passkey did not open this vault'))
              }
            >
              Unlock with {k.label}
            </Button>
          ))}
        </div>
      )}
      {mode === 'pin' && pinSlot ? (
        <Field label="PIN" htmlFor={pinId} error={error ?? undefined} hint="this device only">
          <Input
            id={pinId}
            type="password"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            autoFocus
            autoComplete="off"
            value={pin}
            invalid={Boolean(error)}
            onChange={(e) => {
              setPin(e.target.value.replace(/\D/g, '').slice(0, 6));
              setError(null);
            }}
          />
        </Field>
      ) : (
        <Passphrase
          id={id}
          label="Passphrase"
          value={pass}
          onChange={(v) => {
            setPass(v);
            setError(null);
          }}
          error={error}
          autoFocus
        />
      )}
      <div className="flex items-center justify-between gap-2 border-t border-edge pt-3">
        {pinSlot ? (
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              setMode(mode === 'pin' ? 'passphrase' : 'pin');
              setError(null);
            }}
          >
            {mode === 'pin' ? 'Use passphrase' : 'Use PIN'}
          </Button>
        ) : (
          <span />
        )}
        <div className="flex gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            disabled={busy || (mode === 'pin' ? pin.length !== 6 : pass === '')}
          >
            Unlock
          </Button>
        </div>
      </div>
    </form>
  );
}

/**
 * PIN and passkeys for this device. They open the session here and nowhere
 * else: they live in this device's vault file, never in any export, and a
 * PIN never authorises an export.
 */
function SessionMethods({ busy }: { busy: boolean }) {
  const toasts = useToasts();
  const { slots } = useVaultView(vault);
  const ids = { pass: useId(), pin: useId(), label: useId() };
  const [adding, setAdding] = useState<null | 'pin' | 'passkey'>(null);
  const [pass, setPass] = useState('');
  const [pin, setPin] = useState('');
  const [label, setLabel] = useState(defaultPasskeyLabel());
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setAdding(null);
    setPass('');
    setPin('');
    setError(null);
  };

  const add = async (e: FormEvent) => {
    e.preventDefault();
    const r =
      adding === 'pin' ? await vault.addPin(pass, pin) : await vault.addPasskey(pass, label.trim());
    if (!r.ok) {
      setError(/passphrase|decrypt|auth/i.test(r.error) ? 'Wrong passphrase' : r.error);
      setPass('');
      return;
    }
    toasts.push(adding === 'pin' ? 'PIN set for this device' : `Passkey "${label.trim()}" added`);
    reset();
  };

  return (
    <section className="flex flex-col gap-2 border-t border-edge pt-3">
      <h4 className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
        Sign-in on this device
      </h4>
      <p className="text-[11px] text-faint">
        Face ID, Touch ID, Windows Hello or a security key (passkey), or a 6-digit PIN. They open
        the session on this device only and never travel with any export. A PIN never authorises an
        export; a passkey can.
      </p>
      {slots.length > 0 && (
        <ul className="flex flex-col divide-y divide-edge text-[12px]">
          {slots.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-2 py-1.5">
              <span className="text-ink">
                {s.kind === 'pin' ? 'PIN' : `Passkey · ${s.label}`}
                <span className="ml-2 text-faint">
                  {new Date(s.createdAtMs).toISOString().slice(0, 10)}
                </span>
              </span>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() =>
                  void vault.removeSlot(s.id).then((r) => {
                    if (!r.ok) toasts.push(r.error, 'danger');
                  })
                }
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      )}
      {adding === null ? (
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setAdding('pin')}
            disabled={!deviceSecretSupported()}
          >
            {slots.some((s) => s.kind === 'pin') ? 'Replace PIN…' : 'Add PIN…'}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setAdding('passkey')}
            disabled={!passkeySupported()}
            title={passkeySupported() ? undefined : 'This browser has no WebAuthn'}
          >
            Add passkey…
          </Button>
        </div>
      ) : (
        <form onSubmit={(e) => void add(e)} className="flex flex-col gap-3">
          <Passphrase
            id={ids.pass}
            label="Vault passphrase"
            value={pass}
            onChange={(v) => {
              setPass(v);
              setError(null);
            }}
            error={error}
            hint="only the passphrase can add a sign-in method"
            autoFocus
          />
          {adding === 'pin' ? (
            <Field
              label="New PIN"
              htmlFor={ids.pin}
              hint="exactly 6 digits; 5 wrong tries retire it"
            >
              <Input
                id={ids.pin}
                type="password"
                inputMode="numeric"
                maxLength={6}
                autoComplete="off"
                value={pin}
                onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
              />
            </Field>
          ) : (
            <Field label="Name" htmlFor={ids.label} hint="shown on the unlock screen">
              <Input
                id={ids.label}
                value={label}
                maxLength={40}
                onChange={(e) => setLabel(e.target.value)}
              />
            </Field>
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={reset}>
              Back
            </Button>
            <Button
              type="submit"
              variant="primary"
              disabled={
                busy || pass === '' || (adding === 'pin' ? pin.length !== 6 : label.trim() === '')
              }
            >
              {adding === 'pin' ? 'Set PIN' : 'Create passkey'}
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}

function defaultPasskeyLabel(): string {
  const ua = typeof navigator === 'undefined' ? '' : navigator.userAgent;
  if (/Windows/.test(ua)) return 'Windows Hello';
  if (/iPhone|iPad/.test(ua)) return 'Face ID';
  if (/Mac OS X/.test(ua)) return 'Touch ID';
  if (/Android/.test(ua)) return 'Android biometrics';
  return 'Passkey';
}

function Manage({
  labels,
  deviceId,
  busy,
  onClose,
}: {
  labels: number;
  deviceId: string | null;
  busy: boolean;
  onClose: () => void;
}) {
  const toasts = useToasts();
  const ids = { current: useId(), next: useId(), confirm: useId() };
  const [changing, setChanging] = useState(false);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const mismatch = confirm !== '' && confirm !== next;
  const canChange =
    !busy && current !== '' && next !== '' && next === confirm && passphraseProblem(next) === null;

  const lock = async () => {
    const result = await vault.lock();
    if (!result.ok) toasts.push(result.error, 'danger');
    else onClose();
  };

  const change = async (e: FormEvent) => {
    e.preventDefault();
    const result = await vault.changePassphrase(current, next);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    toasts.push('Passphrase changed');
    setChanging(false);
    setCurrent('');
    setNext('');
    setConfirm('');
  };

  return (
    <div className="flex flex-col gap-4 p-4">
      <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-[12px]">
        <dt className="text-faint">State</dt>
        <dd>
          <Badge tone="ok">unlocked</Badge>
        </dd>
        <dt className="text-faint">Secrets</dt>
        <dd className="text-ink tabular-nums">{labels}</dd>
        <dt className="text-faint">Device id</dt>
        <dd className="font-mono text-muted" title={deviceId ?? undefined}>
          {deviceId ? shortId(deviceId) : 'none'}
        </dd>
      </dl>

      {!changing && <SessionMethods busy={busy} />}

      {changing ? (
        <form
          onSubmit={(e) => void change(e)}
          className="flex flex-col gap-3 border-t border-edge pt-3"
        >
          <Passphrase
            id={ids.current}
            label="Current passphrase"
            value={current}
            onChange={(v) => {
              setCurrent(v);
              setError(null);
            }}
            error={error}
            autoFocus
          />
          <Passphrase id={ids.next} label="New passphrase" value={next} onChange={setNext} />
          <Passphrase
            id={ids.confirm}
            label="Confirm"
            value={confirm}
            onChange={setConfirm}
            error={mismatch ? 'Passphrases differ' : null}
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setChanging(false)}>
              Back
            </Button>
            <Button type="submit" variant="primary" disabled={!canChange}>
              Change passphrase
            </Button>
          </div>
        </form>
      ) : (
        <div className="flex justify-between gap-2 border-t border-edge pt-3">
          <Button variant="ghost" onClick={() => setChanging(true)}>
            Change passphrase
          </Button>
          <div className="flex gap-2">
            <Button variant="ghost" onClick={onClose}>
              Close
            </Button>
            <Button variant="primary" disabled={busy} onClick={() => void lock()}>
              Lock
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
