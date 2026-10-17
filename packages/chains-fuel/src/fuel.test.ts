import { MemoryRpcPool, chainsForFamily } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  FUEL_BASE_ASSET_ID,
  FUEL_CHAINS,
  FUEL_MAINNET,
  FUEL_SEPOLIA,
  FuelAdapter,
  createFuelAdapter,
  decodeTransferBytes,
  fuelAddressFromPublicKey,
  isValidFuelAddress,
} from './fuel.js';
import {
  FuelTx,
  broadcastFuel,
  encodeFuelTransaction,
  fuelApprovalValid,
  fuelMaxFee,
  fuelTransferStatus,
  fuelTxId,
  prepareFuel,
} from './send.js';

/** Key 0x07…07 (compressed SEC1) and its address, pinned from fuels@0.103.0. */
const KEY_COMPRESSED = [
  '02989c0b76cb563971fd',
  'c9bef31ec06c3560f324',
  '9d6ee9e5d83c57625596',
  'e05f6f',
].join('');
const FROM = [
  '0x63520e389b3e28d9af',
  '866d60fc41b6753a4450',
  'da0962633143ba592407',
  '7fdb28',
].join('');
const TO = ['0xd78488241aeebaf514', '4aa4c891ef681216baf9', 'bc4a2074b8bd573ffbbe', 'c41b14'].join(
  '',
);
const UTXO = `0x${'11'.repeat(32)}0000`;

const tx: FuelTx = {
  chainId: FUEL_SEPOLIA,
  from: FROM,
  to: TO,
  base: '123456789',
  inputs: [{ txId: `0x${'11'.repeat(32)}`, outputIndex: 0, amount: '10000000000' }],
  gasLimit: 0,
  maxFee: '1000000',
  expiration: 7_600_000,
};

/** Witness-stripped encoding, pinned byte for byte against fuels 0.103.0 and the Rust core. */
const ID_FORM = [
  ['00000000000000000000', '00000000000000000000', '00000000000000000000', '0000'].join(''),
  ['00000000000000000000', '00000000000000000000', '00000004000000000000', '0000'].join(''),
  ['00000000000000180000', '00000000000100000000', '00000002000000000000', '0000'].join(''),
  ['24000000000000000000', '0000000f424000000000', '0073f780000000000000', '0000'].join(''),
  ['11111111111111111111', '11111111111111111111', '11111111111111111111', '1111'].join(''),
  ['00000000000000006352', '0e389b3e28d9af866d60', 'fc41b6753a4450da0962', '6331'].join(''),
  ['43ba5924077fdb280000', '0002540be400f8f8b628', '3d7fa5b672b530cbb84f', 'cccb'].join(''),
  ['4ff8dc40f8176ef4544d', 'db1f1952ad0700000000', '00000000000000000000', '0000'].join(''),
  ['00000000000000000000', '00000000000000000000', '00000000000000000000', '0000'].join(''),
  ['00000000000000026352', '0e389b3e28d9af866d60', 'fc41b6753a4450da0962', '6331'].join(''),
  ['43ba5924077fdb280000', '000000000000f8f8b628', '3d7fa5b672b530cbb84f', 'cccb'].join(''),
  ['4ff8dc40f8176ef4544d', 'db1f1952ad0700000000', '00000000d78488241aee', 'baf5'].join(''),
  ['144aa4c891ef681216ba', 'f9bc4a2074b8bd573ffb', 'bec41b1400000000075b', 'cd15'].join(''),
  ['f8f8b6283d7fa5b672b5', '30cbb84fcccb4ff8dc40', 'f8176ef4544ddb1f1952', 'ad07'].join(''),
].join('');
const TX_ID = [
  '0xd3ee1cae6b6e9c5bd2',
  '948f7e1c01b99758d42e',
  'af591bd9a50ff3e90fc9',
  '716703',
].join('');
/** Signed wire produced by fuels 0.103.0 for these fields (and the Rust core). */
const WIRE = [
  ['00000000000000000000', '00000000000000000000', '00000000000000000000', '0000'].join(''),
  ['00000000000000000000', '00000000000000000000', '00000004000000000000', '0000'].join(''),
  ['00000000000000180000', '00000000000100000000', '00000002000000000000', '0001'].join(''),
  ['24000000000000000000', '0000000f424000000000', '0073f780000000000000', '0000'].join(''),
  ['11111111111111111111', '11111111111111111111', '11111111111111111111', '1111'].join(''),
  ['00000000000000006352', '0e389b3e28d9af866d60', 'fc41b6753a4450da0962', '6331'].join(''),
  ['43ba5924077fdb280000', '0002540be400f8f8b628', '3d7fa5b672b530cbb84f', 'cccb'].join(''),
  ['4ff8dc40f8176ef4544d', 'db1f1952ad0700000000', '00000000000000000000', '0000'].join(''),
  ['00000000000000000000', '00000000000000000000', '00000000000000000000', '0000'].join(''),
  ['00000000000000026352', '0e389b3e28d9af866d60', 'fc41b6753a4450da0962', '6331'].join(''),
  ['43ba5924077fdb280000', '000000000000f8f8b628', '3d7fa5b672b530cbb84f', 'cccb'].join(''),
  ['4ff8dc40f8176ef4544d', 'db1f1952ad0700000000', '00000000d78488241aee', 'baf5'].join(''),
  ['144aa4c891ef681216ba', 'f9bc4a2074b8bd573ffb', 'bec41b1400000000075b', 'cd15'].join(''),
  ['f8f8b6283d7fa5b672b5', '30cbb84fcccb4ff8dc40', 'f8176ef4544ddb1f1952', 'ad07'].join(''),
  ['0000000000000040f075', 'e2cd0968b06b4b2d1f06', 'ec02ef05c18f614e8c33', 'e6fe'].join(''),
  ['dbf4c54364a40673eb7b', '1a4a2cbe5d9c413a2dce', '1bc62fc86f6404ffc01b', 'd3af'].join(''),
  '5f19b0c2a9935358',
].join('');

const CHAIN_PARAMS = {
  chainId: '0',
  baseAssetId: FUEL_BASE_ASSET_ID,
  txParams: { maxInputs: '255', maxOutputs: '255', maxWitnesses: '255', maxGasPerTx: '30000000' },
  feeParams: { gasPriceFactor: '1150000', gasPerByte: '1' },
  gasCosts: {
    vmInitialization: { base: '4846', unitsPerGas: '39' },
    s256: { base: '36', unitsPerGas: '3' },
    ecr1: '31208',
  },
};

interface GqlRequest {
  query: string;
  variables?: Record<string, unknown>;
}

/** Mock GraphQL endpoint routing on the operation's query text. */
function node(routes: {
  height?: number;
  coins?: { utxoId: string; amount: string }[];
  balance?: string;
  submitId?: string;
  submitError?: string;
  txStatus?: unknown;
}) {
  const calls: string[] = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as GqlRequest;
    const q = body.query;
    const data = (d: unknown) => new Response(JSON.stringify({ data: d }), { status: 200 });
    const errors = (message: string) =>
      new Response(JSON.stringify({ data: null, errors: [{ message }] }), { status: 200 });
    if (q.includes('consensusParameters') && q.includes('gasCosts')) {
      calls.push('chainParams');
      return data({
        chain: {
          consensusParameters: {
            chainId: CHAIN_PARAMS.chainId,
            txParams: CHAIN_PARAMS.txParams,
            feeParams: CHAIN_PARAMS.feeParams,
            gasCosts: CHAIN_PARAMS.gasCosts,
          },
          latestBlock: { header: { height: String(routes.height ?? 7_600_000) } },
        },
      });
    }
    if (q.includes('consensusParameters')) {
      calls.push('networkCheck');
      return data({
        chain: {
          consensusParameters: {
            chainId: CHAIN_PARAMS.chainId,
            baseAssetId: CHAIN_PARAMS.baseAssetId,
          },
        },
      });
    }
    if (q.includes('latestGasPrice')) {
      calls.push('gasPrice');
      return data({ latestGasPrice: { gasPrice: '2000' } });
    }
    if (q.includes('latestBlock')) {
      calls.push('head');
      return data({
        chain: { latestBlock: { header: { height: String(routes.height ?? 7_600_000) } } },
      });
    }
    if (q.includes('coins(')) {
      calls.push('coins');
      return data({
        coins: {
          nodes: routes.coins ?? [{ utxoId: UTXO, amount: '10000000000' }],
          pageInfo: { hasNextPage: false, endCursor: null },
        },
      });
    }
    if (q.includes('balance(')) {
      calls.push('balance');
      return data({ balance: { amount: routes.balance ?? '10000000000' } });
    }
    if (q.includes('dryRun')) {
      calls.push('dryRun');
      return data({
        dryRun: [{ receipts: [{ receiptType: 'SCRIPT_RESULT', gasUsed: '1', result: '0' }] }],
      });
    }
    if (q.includes('submit(')) {
      calls.push('submit');
      if (routes.submitError) return errors(routes.submitError);
      return data({ submit: { id: routes.submitId ?? TX_ID } });
    }
    if (q.includes('transaction(')) {
      calls.push('tx');
      return data({
        transaction:
          routes.txStatus === null
            ? null
            : {
                status: routes.txStatus ?? {
                  __typename: 'SuccessStatus',
                  block: { height: '7600001' },
                },
              },
      });
    }
    return errors('unmocked query');
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  const chains = (chainsForFamily('fuel').length ? chainsForFamily('fuel') : FUEL_CHAINS).map(
    (c) => ({ ...c, defaultRpcs: ['https://testnet.fuel.network/v1/graphql'] }),
  );
  return new FuelAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) });
}

const intent: TxIntent = {
  id: 'tx',
  walletId: 'w',
  accountId: 'a',
  chainId: FUEL_SEPOLIA,
  proposer: { kind: 'human', deviceId: 'd' },
  kind: 'transfer',
  to: TO,
  asset: `${FUEL_SEPOLIA}:native`,
  amount: '123456789',
  untrustedDestinations: [],
  createdAtMs: 0,
} as unknown as TxIntent;

describe('fuel addresses', () => {
  it('derives the b256 address of key 0x07…07 (fuels pin)', () => {
    expect(
      fuelAddressFromPublicKey(
        Uint8Array.from(KEY_COMPRESSED.match(/../g)!.map((b) => parseInt(b, 16))),
      ),
    ).toBe(FROM);
    const a = createFuelAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: KEY_COMPRESSED }, FUEL_SEPOLIA)).toBe(FROM);
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, FUEL_SEPOLIA),
    ).toThrow();
  });

  it('validates lowercase b256 addresses and rejects the rest', () => {
    expect(isValidFuelAddress(FROM)).toBe(true);
    expect(isValidFuelAddress(FROM.toUpperCase().replace('0X', '0x'))).toBe(false);
    expect(isValidFuelAddress(`0x${'00'.repeat(32)}`)).toBe(false);
    expect(isValidFuelAddress(FROM.slice(2))).toBe(false);
    expect(
      isValidFuelAddress(['0x7E5F4552091A69125d', '5DfCb7b8C2659029395B', 'df'].join('')),
    ).toBe(false);
  });
});

describe('fuel transfers', () => {
  it('encodes the same bytes and id as the core and fuels', () => {
    expect(Buffer.from(encodeFuelTransaction(tx)).toString('hex')).toBe(ID_FORM);
    expect(fuelTxId(tx)).toBe(TX_ID);
    expect(encodeFuelTransaction(tx, [new Uint8Array(64)]).length).toBe(520);
  });

  it('refuses hostile fields', () => {
    expect(() => encodeFuelTransaction({ ...tx, base: '0' })).toThrow();
    expect(() => encodeFuelTransaction({ ...tx, base: '01' })).toThrow();
    expect(() => encodeFuelTransaction({ ...tx, to: tx.from })).toThrow();
    expect(() => encodeFuelTransaction({ ...tx, inputs: [] })).toThrow();
    expect(() =>
      encodeFuelTransaction({
        ...tx,
        inputs: [{ txId: tx.inputs[0]!.txId, outputIndex: 0, amount: '5' }],
      }),
    ).toThrow();
    expect(() => encodeFuelTransaction({ ...tx, gasLimit: 30_000_001 })).toThrow();
    expect(() => encodeFuelTransaction({ ...tx, expiration: 0 })).toThrow();
    expect(() => encodeFuelTransaction({ ...tx, maxFee: `${1_000_000_000_001}` })).toThrow();
    expect(() =>
      encodeFuelTransaction({ ...tx, chainId: FUEL_MAINNET as typeof FUEL_SEPOLIA }),
    ).toThrow();
  });

  it('computes the SDK fee model', () => {
    // 520-byte wire, 1 signed input, script gas 2 (dry-run 1 doubled), gas price 2000:
    // minGas = (4846 + 520/39) + 520 + 31208 + (36 + 520/3) = 36770; maxFee = (36770+2)*2000/1150000 + 1 = 64
    const fee = fuelMaxFee({
      gasPrice: 2000n,
      gasPriceFactor: 1_150_000n,
      gasPerByte: 1n,
      vmInit: CHAIN_PARAMS.gasCosts.vmInitialization,
      s256: CHAIN_PARAMS.gasCosts.s256,
      ecr1: 31208n,
      txBytes: 520n,
      signedInputs: 1n,
      scriptGasLimit: 2n,
    });
    expect(fee).toBe(64n);
  });

  it('prepares a transfer with exact fee math and dry-run script gas', async () => {
    const { fetchImpl, calls } = node({});
    const { unsigned, simulation } = await prepareFuel(adapter(fetchImpl), intent, FROM);
    expect(unsigned.inputs).toEqual([
      { txId: `0x${'11'.repeat(32)}`, outputIndex: 0, amount: '10000000000' },
    ]);
    expect(unsigned.gasLimit).toBe(2); // dry-run gasUsed 1 doubled
    expect(unsigned.maxFee).toBe('64');
    expect(unsigned.expiration).toBe(7_600_600);
    expect(simulation.ok).toBe(true);
    expect(calls).toContain('dryRun');
    expect(fuelTxId(unsigned)).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('flags a balance that cannot cover the transfer', async () => {
    const { fetchImpl } = node({ coins: [{ utxoId: UTXO, amount: '100' }] });
    const { simulation } = await prepareFuel(adapter(fetchImpl), intent, FROM);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/cover/);
  });

  it('gates approval on the expiration policy', async () => {
    const live = adapter(node({ height: 7_599_000 }).fetchImpl);
    await expect(fuelApprovalValid(live, tx)).resolves.toBe(true);
    const stale = adapter(node({ height: 7_600_000 }).fetchImpl);
    await expect(fuelApprovalValid(stale, { ...tx, expiration: 7_600_020 })).resolves.toBe(false);
  });

  it('accepts only the pinned wire and returns the node id', async () => {
    const { fetchImpl } = node({});
    await expect(broadcastFuel(adapter(fetchImpl), tx, `0x${WIRE}`)).resolves.toBe(TX_ID);
    const tampered = `0x${WIRE.replace('075bcd15', '075bcd16')}`;
    expect(tampered).not.toBe(`0x${WIRE}`);
    await expect(broadcastFuel(adapter(fetchImpl), tx, tampered)).rejects.toThrow(
      /not this Fuel transfer/,
    );
    const wrongSig = `0x${WIRE.slice(0, WIRE.length - 128)}${'ff'.repeat(64)}`;
    await expect(broadcastFuel(adapter(fetchImpl), tx, wrongSig)).rejects.toThrow(/recover/);
    const { fetchImpl: f2 } = node({ submitId: `0x${'22'.repeat(32)}` });
    await expect(broadcastFuel(adapter(f2), tx, `0x${WIRE}`)).rejects.toThrow(
      /different transaction id/,
    );
  });

  it('maps node statuses and detects expiry', async () => {
    const ok = adapter(node({}).fetchImpl);
    await expect(fuelTransferStatus(ok, tx, TX_ID)).resolves.toMatchObject({
      state: 'confirmed',
      blockNumber: 7_600_001,
    });
    const pending = adapter(node({ txStatus: { __typename: 'SubmittedStatus' } }).fetchImpl);
    await expect(fuelTransferStatus(pending, tx, TX_ID)).resolves.toEqual({ state: 'pending' });
    const failed = adapter(
      node({ txStatus: { __typename: 'FailureStatus', reason: 'OutOfGas' } }).fetchImpl,
    );
    await expect(fuelTransferStatus(failed, tx, TX_ID)).resolves.toMatchObject({
      state: 'failed',
      reason: 'OutOfGas',
    });
    // Unknown id before expiration stays unknown; past expiration reads as expired.
    const unknown = adapter(node({ txStatus: null, height: 7_500_000 }).fetchImpl);
    await expect(fuelTransferStatus(unknown, tx, TX_ID)).resolves.toEqual({ state: 'unknown' });
    const past = adapter(node({ txStatus: null, height: 7_600_100 }).fetchImpl);
    await expect(fuelTransferStatus(past, tx, TX_ID)).resolves.toEqual({ state: 'expired' });
  });

  it('reads balances cross-checked against the same node', async () => {
    const { fetchImpl } = node({ balance: '42000000000' });
    const holdings = await adapter(fetchImpl).getBalances(FROM, FUEL_SEPOLIA);
    expect(holdings).toHaveLength(1);
    expect(holdings[0]).toMatchObject({
      assetRef: `${FUEL_SEPOLIA}:native`,
      amount: '42000000000',
    });
    await expect(adapter(fetchImpl).getBalances(FROM, FUEL_MAINNET)).rejects.toThrow();
  });

  it('decodes a wire payload back into inputs and outputs', () => {
    const decoded = decodeTransferBytes(`0x${WIRE}`);
    expect(decoded?.maxFee).toBe(1_000_000n);
    expect(decoded?.inputs[0]).toMatchObject({
      owner: FROM,
      amount: 10_000_000_000n,
      assetId: FUEL_BASE_ASSET_ID,
    });
    expect(decoded?.outputs[0]).toMatchObject({ type: 2, to: FROM, amount: 0n });
    expect(decoded?.outputs[1]).toMatchObject({ type: 0, to: TO, amount: 123_456_789n });
  });
});
