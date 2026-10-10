import { useId, useState, type FormEvent } from 'react';
import { Badge, Button, Dialog, Field, Input, LoadingWord, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
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
  const [pass, setPass] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const result = await vault.unlock(pass);
    if (!result.ok) {
      setError(/passphrase|decrypt|auth/i.test(result.error) ? 'Wrong passphrase' : result.error);
      setPass('');
      return;
    }
    onClose();
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
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
      <div className="flex justify-end gap-2 border-t border-edge pt-3">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={busy || pass === ''}>
          Unlock
        </Button>
      </div>
    </form>
  );
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
