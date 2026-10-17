import { CHROMIA_TESTNET, CHROMIA_UNREGISTERED_NOTICE } from '@stackwallet/chains-chromia';
import { describe, expect, it } from 'vitest';

import { familySendFor, familySendOf, isActivationIntent } from './families.js';
import './family-sends.js';

const ACCOUNT_ID = '40e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122';
const SIGNER = '02' + 'ab'.repeat(32);

describe('family routing', () => {
  it('routes both Chromia shapes to the Chromia send path', () => {
    const transfer = {
      chainId: CHROMIA_TESTNET,
      from: ACCOUNT_ID,
      signer: SIGNER,
      to: 'cd'.repeat(32),
      uchr: '1000000',
      nonce: 'ef'.repeat(32),
    };
    const registration = {
      chainId: CHROMIA_TESTNET,
      from: ACCOUNT_ID,
      signer: SIGNER,
      register: true,
    };
    expect(familySendOf(transfer)?.family).toBe('chromia');
    expect(familySendOf(registration)?.family).toBe('chromia');
    // A registration must never fall through to another family's broadcast path.
    expect(familySendOf({ chainId: CHROMIA_TESTNET, from: ACCOUNT_ID })).toBeUndefined();
  });

  it('offers registration only while the native holding reports the account missing', () => {
    const chromia = familySendFor({ family: 'chromia' });
    expect(chromia?.activation?.label).toBe('register');
    const holding = { assetRef: `${CHROMIA_TESTNET}:native`, amount: '0', updatedAtMs: 1 };
    expect(chromia!.activation!.needed(holding)).toBe(false);
    expect(chromia!.activation!.needed({ ...holding, notice: CHROMIA_UNREGISTERED_NOTICE })).toBe(
      true,
    );
    expect(familySendFor({ family: 'stellar' })?.activation).toBeUndefined();
  });

  it('recognises the self-addressed zero transfer as the activation intent', () => {
    const account = { address: ACCOUNT_ID, chainId: CHROMIA_TESTNET };
    const base = {
      kind: 'transfer' as const,
      chainId: CHROMIA_TESTNET,
      to: ACCOUNT_ID,
      asset: `${CHROMIA_TESTNET}:native`,
      amount: '0',
    };
    expect(isActivationIntent(base, account)).toBe(true);
    expect(isActivationIntent({ ...base, amount: '1' }, account)).toBe(false);
    expect(isActivationIntent({ ...base, to: 'cd'.repeat(32) }, account)).toBe(false);
    expect(isActivationIntent({ ...base, asset: `${CHROMIA_TESTNET}:token` }, account)).toBe(false);
  });
});
