import { Policy, Rule, type Window } from '@stackwallet/core-client';
import { parseUnits } from './format.js';

export const RULE_LABELS: Record<Rule['rule'], string> = {
  spendCap: 'Spend cap (USD)',
  destinationAllow: 'Allow destinations',
  destinationDeny: 'Deny destinations',
  chainAllow: 'Allow chains',
  assetAllow: 'Allow assets',
  maxSlippageBps: 'Maximum slippage (bps)',
  requireSimulationPass: 'Require passing simulation',
  requireApprovers: 'Require approvers',
  cooldown: 'Cooldown (seconds)',
  maxPendingProposals: 'Maximum pending proposals',
  refuseUntrustedDestinations: 'Refuse untrusted destinations',
};
export interface RuleDraft {
  kind: Rule['rule'];
  value: string;
  window: Window;
  atLeast: string;
}
export function draftRule(rule: Rule): RuleDraft {
  let value = '';
  switch (rule.rule) {
    case 'spendCap':
      value = `${Math.floor(rule.usdMicros / 1_000_000)}.${String(rule.usdMicros % 1_000_000).padStart(6, '0')}`;
      break;
    case 'destinationAllow':
    case 'destinationDeny':
      value = rule.addresses.join('\n');
      break;
    case 'chainAllow':
      value = rule.chainIds.join('\n');
      break;
    case 'assetAllow':
      value = rule.assets.join('\n');
      break;
    case 'requireApprovers':
      value = rule.deviceIds.join('\n');
      break;
    case 'cooldown':
      value = String(rule.seconds);
      break;
    case 'maxPendingProposals':
      value = String(rule.count);
      break;
    case 'maxSlippageBps':
      value = String(rule.bps);
      break;
  }
  return {
    kind: rule.rule,
    value,
    window: rule.rule === 'spendCap' ? rule.window : 'tx',
    atLeast: rule.rule === 'requireApprovers' ? String(rule.atLeast) : '1',
  };
}
function integer(value: string, max = Number.MAX_SAFE_INTEGER) {
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > max)
    throw new Error('Enter a non-negative whole number within range');
  return Number(value);
}
export function parseRule(draft: RuleDraft): Rule {
  const list = [
    ...new Set(
      draft.value
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  ];
  const rule = draft.kind;
  let candidate: unknown;
  switch (rule) {
    case 'spendCap': {
      const units = parseUnits(draft.value, 6);
      if (units === null)
        throw new Error('Spend cap needs a USD amount with at most six decimal places');
      candidate = { rule, window: draft.window, usdMicros: integer(units) };
      break;
    }
    case 'destinationAllow':
    case 'destinationDeny':
      candidate = { rule, addresses: list };
      break;
    case 'chainAllow':
      candidate = { rule, chainIds: list };
      break;
    case 'assetAllow':
      candidate = { rule, assets: list };
      break;
    case 'requireApprovers': {
      const atLeast = integer(draft.atLeast, 255);
      if (atLeast < 1 || atLeast > list.length)
        throw new Error('Approver count must be between one and the number of distinct devices');
      candidate = { rule, deviceIds: list, atLeast };
      break;
    }
    case 'maxSlippageBps':
      candidate = { rule, bps: integer(draft.value, 10_000) };
      break;
    case 'cooldown':
      candidate = {
        rule,
        seconds: integer(draft.value, Math.floor(Number.MAX_SAFE_INTEGER / 1000)),
      };
      break;
    case 'maxPendingProposals':
      candidate = { rule, count: integer(draft.value, 0xffffffff) };
      break;
    default:
      candidate = { rule };
  }
  return Rule.parse(candidate);
}
export function parsePolicy(
  id: string,
  name: string,
  mode: 'enforce' | 'audit',
  drafts: RuleDraft[],
): Policy {
  if (!name.trim() || name.trim().length > 80)
    throw new Error('Use a policy name of 1–80 characters');
  if (!drafts.length) throw new Error('Add at least one rule');
  return Policy.parse({ id, name: name.trim(), mode, rules: drafts.map(parseRule) });
}
