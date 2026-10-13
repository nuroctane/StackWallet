import { useId, useState, type FormEvent } from 'react';
import type { SignedMessage } from '@stackwallet/core-client';
import { Button, Dialog, Field, LoadingWord, Select, useToasts } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView, type SessionChoice } from '../core/vault.js';
import { useDirectory } from '../store/persist.js';
import { accountsOf } from '../store/selectors.js';
import { SessionField, sessionReady } from './ExportGateFields.js';

/**
 * Sign a message with a single wallet's EVM key: plain text (EIP-191, e.g.
 * sign-in or proof of ownership) or typed data (EIP-712, testnet domains
 * only while mainnet signing is gated). Every signature is audited.
 */
export function SignMessageDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  const view = useVaultView(vault);
  return (
    <Dialog open={open} onClose={onClose} title="Sign message" meta="audited · no transaction">
      {!walletId ? null : view.status.kind !== 'unlocked' ? (
        <p className="p-4 text-[12px] text-faint">Unlock the vault to sign.</p>
      ) : (
        <SignForm walletId={walletId} />
      )}
    </Dialog>
  );
}

export function typedSummary(text: string): string | null {
  try {
    const d = JSON.parse(text) as { primaryType?: unknown; domain?: Record<string, unknown> };
    const primary = typeof d.primaryType === 'string' ? d.primaryType : '?';
    const dom = d.domain ?? {};
    return `${primary} for ${String(dom['name'] ?? 'an unnamed app')} on chain ${String(dom['chainId'] ?? 'missing')}${
      dom['verifyingContract'] ? ` · contract ${String(dom['verifyingContract'])}` : ''
    }`;
  } catch {
    return null;
  }
}

function SignForm({ walletId }: { walletId: string }) {
  const state = useDirectory();
  const view = useVaultView(vault);
  const toasts = useToasts();
  const ids = { account: useId(), kind: useId(), text: useId() };
  const accounts = accountsOf(state, walletId).filter(
    (a) => a.family === 'evm' && a.derivationPath,
  );
  const unique = [...new Map(accounts.map((a) => [a.derivationPath, a] as const)).values()];
  const [accountId, setAccountId] = useState(unique[0]?.id ?? '');
  const [kind, setKind] = useState<'personal' | 'typedData'>('personal');
  const [text, setText] = useState('');
  const [session, setSession] = useState<SessionChoice>({ kind: 'passphrase', passphrase: '' });
  const [error, setError] = useState<string | null>(null);
  const [signed, setSigned] = useState<SignedMessage | null>(null);
  const account = unique.find((a) => a.id === accountId);
  if (!account) return <p className="p-4 text-[12px] text-faint">This wallet has no EVM key.</p>;
  const summary = kind === 'typedData' ? typedSummary(text) : null;
  const permit = kind === 'typedData' && /permit|order|approval/i.test(summary ?? '');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    let proof;
    try {
      proof = await vault.proveSession(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const r = await vault.signMessage({
      walletId,
      path: account.derivationPath!,
      address: account.address,
      session: proof,
      kind,
      payload: text,
    });
    if (session.kind === 'passphrase') setSession({ kind: 'passphrase', passphrase: '' });
    if (!r.ok) setError(r.error);
    else setSigned(r.value);
  };

  if (signed) {
    return (
      <div className="flex flex-col gap-3 p-4 text-[12px]">
        <p className="text-muted">Signed by {signed.address}. The audit log records it.</p>
        <code className="rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[11px] break-all text-ink select-all">
          {signed.signatureHex}
        </code>
        <div className="flex justify-end">
          <Button
            variant="primary"
            onClick={() =>
              void navigator.clipboard
                .writeText(signed.signatureHex)
                .then(() => toasts.push('Signature copied'))
                .catch(() => toasts.push('Clipboard unavailable', 'danger'))
            }
          >
            Copy signature
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4 p-4">
      <Field label="Address" htmlFor={ids.account}>
        <Select id={ids.account} value={account.id} onChange={(e) => setAccountId(e.target.value)}>
          {unique.map((a) => (
            <option key={a.id} value={a.id}>
              {a.address}
              {a.label ? ` · ${a.label}` : ''}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Kind" htmlFor={ids.kind}>
        <Select
          id={ids.kind}
          value={kind}
          onChange={(e) => setKind(e.target.value as 'personal' | 'typedData')}
        >
          <option value="personal">Text message (EIP-191)</option>
          <option value="typedData">Typed data (EIP-712 JSON)</option>
        </Select>
      </Field>
      <Field label={kind === 'personal' ? 'Message' : 'Typed data'} htmlFor={ids.text}>
        <textarea
          id={ids.text}
          value={text}
          spellCheck={false}
          onChange={(e) => setText(e.target.value)}
          className="h-32 resize-y rounded-sw-sm border border-edge bg-paper p-2 font-mono text-[11px] text-ink outline-none focus:border-edge-strong"
        />
      </Field>
      {summary && <p className="text-[12px] text-muted">{summary}</p>}
      {permit && (
        <p className="rounded-sw-sm border border-danger/60 bg-danger-soft p-2 text-[12px] text-ink">
          This looks like a permit or an order: signing it can let a contract move your assets
          without another transaction.
        </p>
      )}
      <SessionField value={session} onChange={setSession} hint="asked again for every signature" />
      {error && <p className="text-[12px] text-danger">{error}</p>}
      <div className="flex justify-end">
        <Button
          type="submit"
          variant="primary"
          disabled={!text || !sessionReady(session) || view.busy}
        >
          {view.busy ? <LoadingWord label="signing" /> : 'Sign'}
        </Button>
      </div>
    </form>
  );
}
