import { useState } from 'react';
import { type Policy, type Window } from '@stackwallet/core-client';
import { Button, Dialog, Field, Input, Select } from '@stackwallet/ui';
import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { draftRule, parsePolicy, RULE_LABELS, type RuleDraft } from '../lib/policyEditor.js';

interface Draft {
  id: string;
  name: string;
  mode: Policy['mode'];
  rules: RuleDraft[];
}
const newRule = (): RuleDraft => ({
  kind: 'requireSimulationPass',
  value: '',
  window: 'tx',
  atLeast: '1',
});

export function PoliciesDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const view = useVaultView(vault);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Policies"
      meta="vault-wide · enforced by the core"
      width="w-[min(92vw,760px)]"
    >
      {open && view.status.kind === 'unlocked' && view.ledger ? (
        <PolicyEditor initial={view.ledger.policies} onClose={onClose} />
      ) : (
        <p className="p-4 text-[12px] text-faint">
          Unlock the vault to edit policies. An intact ledger is required.
        </p>
      )}
    </Dialog>
  );
}

function PolicyEditor({ initial, onClose }: { initial: Policy[]; onClose: () => void }) {
  const view = useVaultView(vault);
  const [baseline] = useState(() => JSON.stringify(initial));
  const [drafts, setDrafts] = useState<Draft[]>(() =>
    initial.map((p) => ({ ...p, rules: p.rules.map(draftRule) })),
  );
  const [error, setError] = useState<string | null>(null);
  const update = (index: number, patch: Partial<Draft>) =>
    setDrafts((current) => current.map((d, i) => (i === index ? { ...d, ...patch } : d)));
  const save = async () => {
    setError(null);
    try {
      if (JSON.stringify(view.ledger?.policies) !== baseline)
        throw new Error(
          'Policies changed while this editor was open. Reopen it to load the current rules.',
        );
      const policies = drafts.map((d) => parsePolicy(d.id, d.name, d.mode, d.rules));
      const result = await vault.setPolicies(policies);
      if (!result.ok) throw new Error(result.error);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <div className="flex flex-col gap-4 p-4 text-[12px]">
      <p className="text-faint">
        Every enforcing policy applies to every transaction in this vault, including proposals
        already awaiting approval. Audit mode observes rule failures. Saving records each change in
        the sealed audit log.
      </p>
      <div className="max-h-[60vh] space-y-4 overflow-auto">
        {drafts.map((draft, i) => (
          <section key={draft.id} className="space-y-3 rounded-sw border border-edge p-3">
            <div className="flex flex-wrap items-end gap-2">
              <Field label="Name" htmlFor={`policy-${draft.id}`}>
                <Input
                  id={`policy-${draft.id}`}
                  value={draft.name}
                  maxLength={80}
                  onChange={(e) => update(i, { name: e.target.value })}
                />
              </Field>
              <Field label="Mode" htmlFor={`mode-${draft.id}`}>
                <Select
                  id={`mode-${draft.id}`}
                  value={draft.mode}
                  onChange={(e) => update(i, { mode: e.target.value as Policy['mode'] })}
                >
                  <option value="enforce">Enforce</option>
                  <option value="audit">Audit only</option>
                </Select>
              </Field>
              <Button
                size="sm"
                variant="danger"
                disabled={view.busy}
                onClick={() => setDrafts(drafts.filter((_, n) => n !== i))}
              >
                Remove policy
              </Button>
            </div>
            {draft.rules.map((rule, n) => {
              const patchRule = (patch: Partial<RuleDraft>) =>
                update(i, { rules: draft.rules.map((r, j) => (j === n ? { ...r, ...patch } : r)) });
              const list = [
                'destinationAllow',
                'destinationDeny',
                'chainAllow',
                'assetAllow',
                'requireApprovers',
              ].includes(rule.kind);
              const noValue = ['requireSimulationPass', 'refuseUntrustedDestinations'].includes(
                rule.kind,
              );
              return (
                <div key={n} className="space-y-2 border-t border-edge pt-3">
                  <div className="flex gap-2">
                    <Select
                      aria-label={`Rule ${n + 1}`}
                      value={rule.kind}
                      onChange={(e) =>
                        patchRule({ kind: e.target.value as RuleDraft['kind'], value: '' })
                      }
                    >
                      {Object.entries(RULE_LABELS).map(([kind, label]) => (
                        <option key={kind} value={kind}>
                          {label}
                        </option>
                      ))}
                    </Select>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => update(i, { rules: draft.rules.filter((_, j) => j !== n) })}
                    >
                      Remove rule
                    </Button>
                  </div>
                  {!noValue && (
                    <Field
                      label={
                        list ? 'Values (one per line or comma-separated)' : RULE_LABELS[rule.kind]
                      }
                      htmlFor={`value-${i}-${n}`}
                    >
                      {list ? (
                        <textarea
                          id={`value-${i}-${n}`}
                          value={rule.value}
                          onChange={(e) => patchRule({ value: e.target.value })}
                          rows={3}
                          className="w-full rounded-sw-sm border border-edge bg-paper p-2 font-mono text-ink"
                        />
                      ) : (
                        <Input
                          id={`value-${i}-${n}`}
                          value={rule.value}
                          onChange={(e) => patchRule({ value: e.target.value })}
                          inputMode="decimal"
                        />
                      )}
                    </Field>
                  )}
                  {rule.kind === 'spendCap' && (
                    <>
                      <Select
                        aria-label="Spend window"
                        value={rule.window}
                        onChange={(e) => patchRule({ window: e.target.value as Window })}
                      >
                        {['tx', '1h', '24h', '7d', '30d'].map((w) => (
                          <option key={w}>{w}</option>
                        ))}
                      </Select>
                      <p className="text-faint">
                        Transfers without a USD valuation are refused by a spend cap. USD valuation
                        is not available for sends yet.
                      </p>
                    </>
                  )}
                  {rule.kind === 'requireApprovers' && (
                    <>
                      <Field label="Required count" htmlFor={`count-${i}-${n}`}>
                        <Input
                          id={`count-${i}-${n}`}
                          value={rule.atLeast}
                          onChange={(e) => patchRule({ atLeast: e.target.value })}
                        />
                      </Field>
                      <p className="text-faint">
                        Use device IDs. Single-key signing can satisfy only this device's approval;
                        other-device requirements block it until multi-device approvals are
                        supported.
                      </p>
                    </>
                  )}
                  {rule.kind === 'chainAllow' && (
                    <p className="text-faint">
                      Chain IDs, such as eip155:11155111. An empty allowlist denies all chains.
                    </p>
                  )}
                  {rule.kind === 'assetAllow' && (
                    <p className="text-faint">Asset references, such as eip155:11155111:native.</p>
                  )}
                </div>
              );
            })}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => update(i, { rules: [...draft.rules, newRule()] })}
            >
              Add rule
            </Button>
          </section>
        ))}
      </div>
      {drafts.length === 0 && (
        <p className="text-danger">
          Saving an empty list removes every policy restriction. Transaction intent checks and
          passphrase approval still apply.
        </p>
      )}
      {error && (
        <p role="alert" className="text-danger">
          {error}
        </p>
      )}
      <div className="flex justify-between gap-2">
        <Button
          size="sm"
          variant="ghost"
          disabled={view.busy || drafts.length >= 256}
          onClick={() =>
            setDrafts([
              ...drafts,
              { id: crypto.randomUUID(), name: '', mode: 'enforce', rules: [newRule()] },
            ])
          }
        >
          Add policy
        </Button>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={drafts.length === 0 ? 'danger' : 'primary'}
            disabled={view.busy}
            onClick={() => void save()}
          >
            {view.busy ? 'saving…' : 'Save policies'}
          </Button>
        </div>
      </div>
    </div>
  );
}
