import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { createEvmAdapter } from './evm.js';
import { callFor, encodeErc20Transfer, prepareEvm } from './send.js';

const FROM = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const CHAIN = 'eip155:11155111';

function intent(asset: string, amount = '1000'): TxIntent {
  return {
    id: 't',
    walletId: 'w',
    accountId: 'a',
    chainId: CHAIN,
    proposer: { kind: 'human', deviceId: 'd' },
    usdMicros: null,
    untrustedDestinations: [],
    createdAtMs: 0,
    kind: 'transfer',
    to: TO,
    asset,
    amount,
  };
}

function rpc(answers: Record<string, unknown>, failing: string[] = []): typeof fetch {
  return (async (_url: RequestInfo | URL, init?: RequestInit) => {
    const { method } = JSON.parse(String(init?.body)) as { method: string };
    const body = failing.includes(method)
      ? { jsonrpc: '2.0', id: 1, error: { code: 3, message: 'execution reverted' } }
      : { jsonrpc: '2.0', id: 1, result: answers[method] };
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
}

const ANSWERS = {
  eth_chainId: '0xaa36a7',
  eth_getTransactionCount: '0x5',
  eth_getBlockByNumber: { baseFeePerGas: '0x3b9aca00' },
  eth_getBalance: '0xde0b6b3a7640000',
  eth_getCode: '0x',
  eth_maxPriorityFeePerGas: '0x59682f00',
  eth_estimateGas: '0x5208',
};

describe('evm send', () => {
  it('maps intents to calls the core will accept', () => {
    expect(callFor(intent(`${CHAIN}:native`))).toMatchObject({ to: TO, value: 1000n, data: '0x' });
    const token = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';
    const erc = callFor(intent(`${CHAIN}:erc20:${token}`, '5000000'));
    expect(erc.to).toBe(token);
    expect(erc.value).toBe(0n);
    expect(erc.data).toBe(encodeErc20Transfer(TO, 5_000_000n));
    expect(erc.data).toBe(
      '0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8' +
        '00000000000000000000000000000000000000000000000000000000004c4b40',
    );
    expect(() => callFor(intent('eip155:1:native'))).toThrow();
  });

  it('prepares a native transfer with fees from the base fee', async () => {
    const adapter = createEvmAdapter({ fetch: rpc(ANSWERS) });
    const p = await prepareEvm(adapter, intent(`${CHAIN}:native`), FROM);
    expect(p.unsigned).toEqual({
      chainId: 11155111,
      nonce: 5,
      maxPriorityFeePerGas: '1500000000',
      maxFeePerGas: '3500000000',
      gasLimit: 21000,
      to: TO,
      value: '1000',
      dataHex: '',
    });
    expect(p.simulation.ok).toBe(true);
    expect(p.simulation.fee.amount).toBe(String(21000 * 2_500_000_000));
  });

  it('records a failed estimate or a short balance as a failed simulation', async () => {
    const reverts = createEvmAdapter({ fetch: rpc(ANSWERS, ['eth_estimateGas']) });
    const p = await prepareEvm(reverts, intent(`${CHAIN}:native`), FROM);
    expect(p.simulation.ok).toBe(false);
    expect(p.simulation.error).toMatch(/revert/);

    const poor = createEvmAdapter({ fetch: rpc({ ...ANSWERS, eth_getBalance: '0x1' }) });
    const q = await prepareEvm(poor, intent(`${CHAIN}:native`), FROM);
    expect(q.simulation.ok).toBe(false);
    expect(q.simulation.error).toMatch(/does not cover/);
  });

  it('warns when a plain transfer goes to a contract', async () => {
    const adapter = createEvmAdapter({ fetch: rpc({ ...ANSWERS, eth_getCode: '0x6080' }) });
    const p = await prepareEvm(adapter, intent(`${CHAIN}:native`), FROM);
    expect(p.simulation.warnings).toEqual([{ kind: 'destinationIsContract', address: TO }]);
  });
});
