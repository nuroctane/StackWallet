import type { Account } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { buildNamespaces, cleanText, personalText, toAction } from './requests.js';

const ME = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const SEPOLIA = 'eip155:11155111';
const account = (chainId: string, extra: Partial<Account> = {}) =>
  ({
    id: `a-${chainId}`,
    walletId: 'w',
    chainId,
    family: 'evm',
    address: ME,
    derivationPath: "m/44'/60'/0'/0/0",
    ...extra,
  }) as Account;
const accounts = [account(SEPOLIA)];

describe('walletconnect requests', () => {
  it('turns eth_sendTransaction into a send from the session account only', () => {
    expect(
      toAction(
        'eth_sendTransaction',
        [{ from: ME.toLowerCase(), to: TO, value: '0x3e8', data: '0xa9059cbb' }],
        SEPOLIA,
        accounts,
      ),
    ).toMatchObject({ kind: 'send', to: TO, value: '1000', dataHex: 'a9059cbb' });
    expect(
      toAction('eth_sendTransaction', [{ from: TO, to: ME }], SEPOLIA, accounts),
    ).toMatchObject({
      kind: 'refuse',
      code: 4100,
    });
    expect(
      toAction('eth_sendTransaction', [{ from: ME, to: TO }], 'eip155:1', accounts),
    ).toMatchObject({
      kind: 'refuse',
    });
    expect(
      toAction(
        'eth_sendTransaction',
        [{ from: ME, to: TO, data: '0x01', input: '0x02' }],
        SEPOLIA,
        accounts,
      ),
    ).toMatchObject({ kind: 'refuse' });
  });

  it('signs personal messages as text and refuses opaque bytes', () => {
    expect(personalText('0x68656c6c6f')).toBe('hello');
    expect(personalText('plain')).toBe('plain');
    expect(personalText(`0x${'ff'.repeat(32)}`)).toBeNull();
    expect(toAction('personal_sign', ['0x68656c6c6f', ME], SEPOLIA, accounts)).toMatchObject({
      kind: 'sign',
      messageKind: 'personal',
      payload: 'hello',
    });
    expect(
      toAction('personal_sign', [`0x${'ab'.repeat(32)}`, ME], SEPOLIA, accounts),
    ).toMatchObject({
      kind: 'refuse',
    });
  });

  it('accepts typed data as a string or object and refuses other methods', () => {
    const typed = { primaryType: 'Mail', domain: { chainId: 11155111 }, types: {}, message: {} };
    expect(toAction('eth_signTypedData_v4', [ME, typed], SEPOLIA, accounts)).toMatchObject({
      kind: 'sign',
      messageKind: 'typedData',
      payload: JSON.stringify(typed),
    });
    expect(toAction('eth_sign', [ME, '0x00'], SEPOLIA, accounts)).toMatchObject({
      kind: 'refuse',
      code: 4200,
    });
  });

  it('offers only signing testnets with keyed accounts', () => {
    const signing = new Set([SEPOLIA]);
    const all = [
      ...accounts,
      account('eip155:1', { id: 'main' }),
      account(SEPOLIA, { id: 'watch', derivationPath: null } as Partial<Account>),
    ];
    const ok = buildNamespaces([], all, signing);
    expect(ok).toMatchObject({
      ok: true,
      namespaces: { eip155: { chains: [SEPOLIA], accounts: [`${SEPOLIA}:${ME}`] } },
    });
    expect(buildNamespaces(['eip155:1'], all, signing)).toMatchObject({ ok: false });
  });

  it('strips dapp text to plain printable characters', () => {
    expect(cleanText('Uni‮swap\u0007')).toBe('Uniswap');
    expect(cleanText(42)).toBe('');
  });
});
