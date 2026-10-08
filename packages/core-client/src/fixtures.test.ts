import { describe, expect, it } from 'vitest';

import context from '../../../fixtures/context.json';
import decisionAllow from '../../../fixtures/decision-allow.json';
import decisionDeny from '../../../fixtures/decision-deny.json';
import intentSwap from '../../../fixtures/intent-swap.json';
import intentTransfer from '../../../fixtures/intent-transfer.json';
import policies from '../../../fixtures/policies.json';
import { Decision, Policy, PolicyContext, TxIntent } from './types.js';

// The Rust side proves these fixtures evaluate to the expected decisions; this
// side proves the same bytes satisfy the Zod schemas. Together they pin the wire format.
describe('shared fixtures parse with the Zod mirrors', () => {
  it('policies cover every rule variant', () => {
    const parsed = policies.map((p) => Policy.parse(p));
    const kinds = new Set(parsed.flatMap((p) => p.rules.map((r) => r.rule)));
    expect(kinds.size).toBe(11);
  });

  it('intents and context', () => {
    expect(TxIntent.parse(intentTransfer).kind).toBe('transfer');
    expect(TxIntent.parse(intentSwap).kind).toBe('swap');
    const ctx = PolicyContext.parse(context);
    expect(ctx.keyGroup?.threshold).toBe(2);
    expect(ctx.spentUsdMicros['24h']).toBe(90_000_000);
  });

  it('decisions', () => {
    const allow = Decision.parse(decisionAllow);
    expect(allow.decision).toBe('allow');
    const deny = Decision.parse(decisionDeny);
    expect(deny.decision === 'deny' && deny.reasons).toHaveLength(3);
  });
});
