/**
 * Read-side staking on Osmosis Testnet: who can be delegated to, what is
 * delegated, and what has accrued. Delegating, undelegating and claiming go
 * through the core as `stake`, `unstake` and `claim` intents.
 */
import { z } from 'zod';

import { isValidCosmosAddress, type CosmosAdapter } from './cosmos.js';
import { COSMOS_TESTNET } from './send.js';

const Uint = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/)
  .max(40);
/** Rewards are reported as decimals (`123.4560…`); only whole micro-units can be claimed. */
const Dec = z
  .string()
  .regex(/^[0-9]+(\.[0-9]+)?$/)
  .max(80);
const Operator = z
  .string()
  .max(90)
  .refine((a) => isValidCosmosAddress(a, 'osmovaloper'));

const Validators = z.object({
  validators: z
    .array(
      z.object({
        operator_address: Operator,
        jailed: z.boolean(),
        description: z.object({ moniker: z.string().max(400) }),
        commission: z.object({ commission_rates: z.object({ rate: Dec }) }),
        tokens: Uint,
      }),
    )
    .max(500),
});
const Delegations = z.object({
  delegation_responses: z
    .array(
      z.object({
        delegation: z.object({ validator_address: Operator }),
        balance: z.object({ denom: z.string().max(128), amount: Uint }),
      }),
    )
    .max(500),
});
const Rewards = z.object({
  rewards: z
    .array(
      z.object({
        validator_address: Operator,
        reward: z.array(z.object({ denom: z.string().max(128), amount: Dec })).max(50),
      }),
    )
    .max(500),
});

export interface Validator {
  operator: string;
  /** Chosen by the validator: untrusted text, trimmed and stripped of control characters. */
  moniker: string;
  commissionBps: number;
  tokens: string;
}

export interface Delegation {
  validator: string;
  /** uosmo */
  amount: string;
  /** Whole uosmo accrued and claimable. */
  rewards: string;
}

function cleanMoniker(m: string): string {
  return m.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e]/g, '').slice(0, 64);
}

function bps(rate: string): number {
  const [whole = '0', frac = ''] = rate.split('.');
  return Number(whole) * 10_000 + Number((frac + '0000').slice(0, 4));
}

/** Bonded validators, largest first; jailed ones are left out. */
export async function listValidators(adapter: CosmosAdapter): Promise<Validator[]> {
  return adapter.withChain(COSMOS_TESTNET, async (lcd) => {
    const r = await lcd(
      '/cosmos/staking/v1beta1/validators?status=BOND_STATUS_BONDED&pagination.limit=200',
      Validators,
    );
    if (!r) throw new Error('Validator list unavailable');
    return r.validators
      .filter((v) => !v.jailed)
      .map((v) => ({
        operator: v.operator_address,
        moniker: cleanMoniker(v.description.moniker) || v.operator_address.slice(0, 18),
        commissionBps: bps(v.commission.commission_rates.rate),
        tokens: v.tokens,
      }))
      .sort((a, b) => (BigInt(b.tokens) > BigInt(a.tokens) ? 1 : -1));
  });
}

export async function listDelegations(
  adapter: CosmosAdapter,
  delegator: string,
): Promise<Delegation[]> {
  if (!isValidCosmosAddress(delegator, 'osmo')) throw new Error('Not an Osmosis address');
  return adapter.withChain(COSMOS_TESTNET, async (lcd) => {
    const addr = encodeURIComponent(delegator);
    const [d, r] = await Promise.all([
      lcd(`/cosmos/staking/v1beta1/delegations/${addr}`, Delegations),
      lcd(`/cosmos/distribution/v1beta1/delegators/${addr}/rewards`, Rewards),
    ]);
    const owed = new Map(
      (r?.rewards ?? []).map((x) => [
        x.validator_address,
        x.reward.find((c) => c.denom === 'uosmo')?.amount.split('.')[0] ?? '0',
      ]),
    );
    return (d?.delegation_responses ?? [])
      .filter((x) => x.balance.denom === 'uosmo')
      .map((x) => ({
        validator: x.delegation.validator_address,
        amount: x.balance.amount,
        rewards: owed.get(x.delegation.validator_address) ?? '0',
      }));
  });
}
