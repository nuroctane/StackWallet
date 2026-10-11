import { describe, expect, it } from 'vitest';
import { draftRule, parsePolicy, parseRule, type RuleDraft } from './policyEditor.js';

const draft = (kind: RuleDraft['kind'], value = ''): RuleDraft => ({
  kind,
  value,
  window: '24h',
  atLeast: '1',
});
describe('policy editor boundary', () => {
  it('parses USD exactly without rounding and round-trips every rule', () => {
    const rules = [
      parseRule(draft('spendCap', '123.000001')),
      parseRule(draft('destinationAllow', '0xabc,0xabc\n0xdef')),
      parseRule(draft('destinationDeny', '0xabc')),
      parseRule(draft('chainAllow', 'eip155:1')),
      parseRule(draft('assetAllow', 'eip155:1:native')),
      parseRule(draft('maxSlippageBps', '50')),
      parseRule(draft('requireSimulationPass')),
      parseRule(draft('requireApprovers', 'device')),
      parseRule(draft('cooldown', '30')),
      parseRule(draft('maxPendingProposals', '2')),
      parseRule(draft('refuseUntrustedDestinations')),
    ];
    expect(rules[0]).toEqual({ rule: 'spendCap', window: '24h', usdMicros: 123000001 });
    expect(rules[1]).toEqual({ rule: 'destinationAllow', addresses: ['0xabc', '0xdef'] });
    for (const rule of rules) expect(parseRule(draftRule(rule))).toEqual(rule);
  });
  it('refuses unsafe numbers, fractional counts and unsatisfiable approvers', () => {
    for (const value of ['-1', '1.5', '1e3', '', '9007199254740992'])
      expect(() => parseRule(draft('cooldown', value))).toThrow();
    expect(() => parseRule(draft('spendCap', '0.0000001'))).toThrow();
    expect(() =>
      parseRule({ ...draft('requireApprovers', 'device,device'), atLeast: '2' }),
    ).toThrow();
    expect(() => parseRule(draft('maxPendingProposals', '4294967296'))).toThrow();
  });
  it('requires a named policy with rules while preserving intentional empty allowlists', () => {
    expect(() => parsePolicy('id', ' ', 'enforce', [draft('requireSimulationPass')])).toThrow();
    expect(() => parsePolicy('id', 'test', 'enforce', [])).toThrow();
    expect(parsePolicy('id', ' test ', 'audit', [draft('chainAllow')])).toMatchObject({
      name: 'test',
      mode: 'audit',
      rules: [{ rule: 'chainAllow', chainIds: [] }],
    });
  });
});
