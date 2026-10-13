import { describe, expect, it } from 'vitest';

import { createCosmosAdapter, encodeCosmosAddress } from './cosmos.js';
import { listDelegations, listValidators } from './staking.js';

const op = (n: number) => encodeCosmosAddress('osmovaloper', new Uint8Array(20).fill(n));
const me = encodeCosmosAddress('osmo', new Uint8Array(20).fill(1));

function adapter(routes: Record<string, unknown>) {
  return createCosmosAdapter({
    fetch: async (input) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/node_info'))
        return new Response(JSON.stringify({ default_node_info: { network: 'osmo-test-5' } }));
      const hit = Object.entries(routes).find(([p]) => url.pathname.endsWith(p));
      return hit ? new Response(JSON.stringify(hit[1])) : new Response('{}', { status: 404 });
    },
  });
}

describe('Osmosis staking reads', () => {
  it('lists bonded validators, drops jailed ones and cleans monikers', async () => {
    const v = (n: number, moniker: string, tokens: string, jailed = false) => ({
      operator_address: op(n),
      jailed,
      description: { moniker },
      commission: { commission_rates: { rate: '0.050000000000000000' } },
      tokens,
    });
    const list = await listValidators(
      adapter({
        '/validators': {
          validators: [
            v(2, 'small', '10'),
            v(3, 'big\u202eevil', '900'),
            v(4, 'jail', '5000', true),
          ],
        },
      }),
    );
    expect(list.map((x) => x.operator)).toEqual([op(3), op(2)]);
    expect(list[0]).toMatchObject({ moniker: 'bigevil', commissionBps: 500 });
  });

  it('joins delegations with whole claimable rewards', async () => {
    const list = await listDelegations(
      adapter({
        [`/delegations/${me}`]: {
          delegation_responses: [
            {
              delegation: { validator_address: op(2) },
              balance: { denom: 'uosmo', amount: '700' },
            },
          ],
        },
        '/rewards': {
          rewards: [{ validator_address: op(2), reward: [{ denom: 'uosmo', amount: '12.75' }] }],
        },
      }),
      me,
    );
    expect(list).toEqual([{ validator: op(2), amount: '700', rewards: '12' }]);
    await expect(listDelegations(adapter({}), op(2))).rejects.toThrow();
  });
});
