import { MemoryRpcPool } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  STARKNET_MAINNET,
  STARKNET_SEPOLIA,
  StarknetAdapter,
  computeHashOnElements,
  createStarknetAdapter,
  getSelectorFromName,
  isValidStarknetAddress,
  normalizeStarknetAddress,
  pedersen,
  poseidonHashMany,
  starknetAddressFromPublicKey,
} from './starknet.js';
import {
  StarknetTx,
  accountAddress,
  broadcastStarknet,
  deployTxHash,
  expectedWire,
  invokeTxHash,
  prepareStarknet,
  starknetApprovalValid,
  starknetTransferStatus,
  transferCalldata,
} from './send.js';

// Reference vectors produced by starknet.js 10.8 / @scure/starknet 2.4 and
// pinned identically in crates/stackwallet-core/src/starknet.rs.
const STARK_PUBLIC = '0689f60839e8d2780333345a68dbc81424b38a8b866598f0c872c09af9c10e7b';
const ADDRESS = '0x060827ce138bbccc66ce987d602f8413eabe379a860e89f1f4192a5e936da657';
const RECIPIENT = '0x00123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde';
const INVOKE_HASH = '0x0228bdeec54524f74407845cef655f3582d51ccb273bf2d234994e9d87e04817';
const DEPLOY_HASH = '0x04d57fa49ca4b96a0b0b56ab1267524ed7277d46997d37a57a665489eda97dec';
const INVOKE7_HASH = '0x00a3d1c20800355f2bfc063dd7104b2911e681231b31b983ee08a4c1ca603a97';

const tx: StarknetTx = {
  chainId: STARKNET_SEPOLIA,
  from: ADDRESS,
  to: RECIPIENT,
  fri: '1500000000000000000',
  nonce: 1,
  deploy: true,
  tip: '0',
  l1GasMaxAmount: 0,
  l1GasMaxPrice: '50000000000000',
  l2GasMaxAmount: 2_000_000,
  l2GasMaxPrice: '12000000000',
  l1DataGasMaxAmount: 256,
  l1DataGasMaxPrice: '1000000000',
};

const intent: TxIntent = {
  id: 'tx',
  chainId: STARKNET_SEPOLIA,
  kind: 'transfer',
  to: RECIPIENT,
  asset: `${STARKNET_SEPOLIA}:native`,
  amount: tx.fri,
} as TxIntent;

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

type Route = (params: unknown) => { result?: unknown; error?: { code: number; message: string } };
function node(routes: Record<string, Route>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const body = init?.body
      ? (JSON.parse(String(init.body)) as { method: string; params: unknown })
      : { method: '', params: [] };
    calls.push(`${url.host} ${body.method}`);
    const route = routes[body.method];
    if (!route)
      return Response.json({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'nf' } });
    const out = route(body.params);
    return Response.json(
      out.error
        ? { jsonrpc: '2.0', id: 1, error: out.error }
        : { jsonrpc: '2.0', id: 1, result: out.result },
    );
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function adapter(fetchImpl: typeof fetch) {
  const urls = ['https://a.example/rpc', 'https://b.example/rpc'];
  const chains = [
    { ...createStarknetAdapter().chains()[0]!, defaultRpcs: urls },
    { ...createStarknetAdapter().chains()[1]!, defaultRpcs: urls },
  ];
  return new StarknetAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(chains) });
}

const HEAD = {
  block_number: 16678315,
  timestamp: 1792156505,
  l1_gas_price: { price_in_fri: '0x1d7ae2b4fd76' },
  l2_gas_price: { price_in_fri: '0x2b32cdd50' },
  l1_data_gas_price: { price_in_fri: '0x7e9d' },
};
const CHAIN_ID = { result: '0x534e5f5345504f4c4941' };
const FUNDED = { result: ['0x204fce5e3e2502611000000', '0x0'] }; // 150.5 STRK

describe('starknet hashes and addresses', () => {
  it('matches the starknet.js Pedersen and Poseidon vectors', () => {
    expect(pedersen(1n, 2n)).toBe(
      0x5bb9440e27889a364bcb678b1f679ecd1347acdedcbf36e83494f857cc58026n,
    );
    expect(
      pedersen(
        0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cbn,
        0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31an,
      ),
    ).toBe(0x30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662n);
    expect(poseidonHashMany([])).toBe(
      0x2272be0f580fd156823304800919530eaa97430e972d7213ee13f4fbf7a5dbcn,
    );
    expect(poseidonHashMany([1n, 2n, 3n])).toBe(
      0x2f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad082n,
    );
    expect(getSelectorFromName('transfer')).toBe(
      0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12en,
    );
    expect(() =>
      pedersen(0x800000000000011000000000000000000000000000000000000000000000001n, 0n),
    ).toThrow();
    expect(() => poseidonHashMany([-1n])).toThrow();
  });

  it('derives the OpenZeppelin account address of the ground key', () => {
    const pub = hexToBytes(STARK_PUBLIC);
    expect(starknetAddressFromPublicKey(pub)).toBe(ADDRESS);
    expect(accountAddress(BigInt(`0x${STARK_PUBLIC}`))).toBe(ADDRESS);
    expect(computeHashOnElements([BigInt(`0x${STARK_PUBLIC}`)])).toBeTypeOf('bigint');
    const a = new StarknetAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: STARK_PUBLIC }, STARKNET_SEPOLIA)).toBe(
      ADDRESS,
    );
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: `02${STARK_PUBLIC}` }, STARKNET_SEPOLIA),
    ).toThrow();
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: STARK_PUBLIC }, STARKNET_SEPOLIA),
    ).toThrow();
  });

  it('validates addresses loosely and normalizes to the padded form', () => {
    expect(isValidStarknetAddress(ADDRESS)).toBe(true);
    expect(
      isValidStarknetAddress('0x60827ce138bbccc66ce987d602f8413eabe379a860e89f1f4192a5e936da657'),
    ).toBe(true);
    expect(isValidStarknetAddress(ADDRESS.toUpperCase().replace('0X', '0x'))).toBe(true);
    expect(
      normalizeStarknetAddress('0x60827ce138bbccc66ce987d602f8413eabe379a860e89f1f4192a5e936da657'),
    ).toBe(ADDRESS);
    expect(isValidStarknetAddress('0x0')).toBe(false);
    expect(isValidStarknetAddress('0xff')).toBe(false);
    expect(
      isValidStarknetAddress('0x0800000000000000000000000000000000000000000000000000000000000000'),
    ).toBe(false);
    expect(isValidStarknetAddress('TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC')).toBe(false);
    expect(isValidStarknetAddress('0xzz')).toBe(false);
  });
});

describe('starknet transfers', () => {
  it('builds the same calldata, hashes and wire as the core', () => {
    expect(transferCalldata(tx).map((v) => `0x${v.toString(16)}`)).toEqual([
      '0x1',
      '0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
      '0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e',
      '0x3',
      '0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde',
      '0x14d1120d7b160000',
      '0x0',
    ]);
    expect(invokeTxHash(tx)).toBe(INVOKE_HASH);
    expect(deployTxHash(tx, BigInt(`0x${STARK_PUBLIC}`))).toBe(DEPLOY_HASH);
    expect(invokeTxHash({ ...tx, nonce: 7, deploy: false, tip: '1000' })).toBe(INVOKE7_HASH);
    // The Rust test asserts these exact fields in the signed wire.
    expect(expectedWire(tx).invoke_transaction).toEqual({
      type: 'INVOKE',
      sender_address: '0x60827ce138bbccc66ce987d602f8413eabe379a860e89f1f4192a5e936da657',
      calldata: [
        '0x1',
        '0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
        '0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e',
        '0x3',
        '0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde',
        '0x14d1120d7b160000',
        '0x0',
      ],
      account_deployment_data: [],
      version: '0x3',
      nonce: '0x1',
      resource_bounds: {
        l1_gas: { max_amount: '0x0', max_price_per_unit: '0x2d79883d2000' },
        l2_gas: { max_amount: '0x1e8480', max_price_per_unit: '0x2cb417800' },
        l1_data_gas: { max_amount: '0x100', max_price_per_unit: '0x3b9aca00' },
      },
      tip: '0x0',
      paymaster_data: [],
      nonce_data_availability_mode: 'L1',
      fee_data_availability_mode: 'L1',
    });
  });

  it('refuses hostile fields', () => {
    expect(() => invokeTxHash({ ...tx, fri: '0' })).toThrow();
    expect(() => invokeTxHash({ ...tx, fri: '01' })).toThrow();
    expect(() => invokeTxHash({ ...tx, nonce: 0 })).toThrow();
    expect(() => invokeTxHash({ ...tx, to: '0x1234' })).toThrow();
    expect(() =>
      invokeTxHash({ ...tx, chainId: STARKNET_MAINNET as typeof STARKNET_SEPOLIA }),
    ).toThrow();
    expect(() => invokeTxHash({ ...tx, l2GasMaxAmount: 0 })).toThrow();
  });

  it('prepares a deploying send with fallback bounds when estimation reverts', async () => {
    const { fetchImpl } = node({
      starknet_chainId: () => CHAIN_ID,
      starknet_getNonce: () => ({ error: { code: 20, message: 'Contract not found' } }),
      starknet_getBlockWithTxHashes: () => ({ result: HEAD }),
      starknet_estimateFee: () => ({ error: { code: 41, message: 'Transaction execution error' } }),
      starknet_call: () => FUNDED,
    });
    const { unsigned, simulation } = await prepareStarknet(adapter(fetchImpl), intent, ADDRESS);
    expect(unsigned.deploy).toBe(true);
    expect(unsigned.nonce).toBe(1);
    expect(unsigned.l2GasMaxAmount).toBe(4_000_000);
    expect(unsigned.l1GasMaxPrice).toBe((0x1d7ae2b4fd76n * 2n).toString());
    expect(simulation.ok).toBe(true);
    expect(simulation.warnings.some((w) => w.kind === 'other')).toBe(true);
    expect(BigInt(simulation.fee.amount)).toBe(
      2n *
        (BigInt(unsigned.l2GasMaxAmount) * BigInt(unsigned.l2GasMaxPrice) +
          BigInt(unsigned.l1DataGasMaxAmount) * BigInt(unsigned.l1DataGasMaxPrice)),
    );
  });

  it('prepares a repeat send from fee estimates', async () => {
    const { fetchImpl } = node({
      starknet_chainId: () => CHAIN_ID,
      starknet_getNonce: () => ({ result: '0x3' }),
      starknet_getBlockWithTxHashes: () => ({ result: HEAD }),
      starknet_estimateFee: () => ({
        result: [
          {
            overall_fee: '0x22d9366e902600',
            l1_gas_consumed: '0x0',
            l1_gas_price: '0x1d7ae2b4fd76',
            l2_gas_consumed: '0xce900',
            l2_gas_price: '0x2b32cdd50',
            l1_data_gas_consumed: '0x80',
            l1_data_gas_price: '0x7e9d',
          },
        ],
      }),
      starknet_call: () => FUNDED,
    });
    const { unsigned, simulation } = await prepareStarknet(
      adapter(fetchImpl),
      { ...intent, amount: '1' } as TxIntent,
      ADDRESS,
    );
    expect(unsigned.deploy).toBe(false);
    expect(unsigned.nonce).toBe(3);
    expect(unsigned.l2GasMaxAmount).toBe(Number((0xce900n * 3n) / 2n));
    expect(unsigned.l1DataGasMaxAmount).toBe(0x100);
    expect(simulation.ok).toBe(true);
    expect(simulation.warnings).toEqual([]);
  });

  it('flags a balance that cannot cover amount and fees', async () => {
    const { fetchImpl } = node({
      starknet_chainId: () => CHAIN_ID,
      starknet_getNonce: () => ({ result: '0x3' }),
      starknet_getBlockWithTxHashes: () => ({ result: HEAD }),
      starknet_estimateFee: () => ({ error: { code: 41, message: 'Transaction execution error' } }),
      starknet_call: () => ({ result: ['0x0', '0x0'] }),
    });
    const { simulation } = await prepareStarknet(adapter(fetchImpl), intent, ADDRESS);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/does not cover/);
  });

  it('refuses an endpoint serving another network', async () => {
    const { fetchImpl } = node({
      starknet_chainId: () => ({ result: '0x534e5f4d41494e' }),
    });
    await expect(prepareStarknet(adapter(fetchImpl), intent, ADDRESS)).rejects.toThrow(
      /another Starknet network|NoRpcEndpoints|failed/i,
    );
  });

  it('tracks approval by nonce and deployment state', async () => {
    const undeployed = adapter(
      node({
        starknet_chainId: () => CHAIN_ID,
        starknet_getNonce: () => ({ error: { code: 20, message: 'Contract not found' } }),
      }).fetchImpl,
    );
    expect(await starknetApprovalValid(undeployed, tx)).toBe(true);
    expect(await starknetApprovalValid(undeployed, { ...tx, deploy: false })).toBe(false);
    const at3 = adapter(
      node({
        starknet_chainId: () => CHAIN_ID,
        starknet_getNonce: () => ({ result: '0x3' }),
      }).fetchImpl,
    );
    expect(await starknetApprovalValid(at3, { ...tx, deploy: false, nonce: 3 })).toBe(true);
    expect(await starknetApprovalValid(at3, { ...tx, deploy: false, nonce: 4 })).toBe(false);
    expect(await starknetApprovalValid(at3, tx)).toBe(false);
  });

  it('broadcasts only the ledger transfer and checks the returned hashes', async () => {
    const signed = JSON.stringify({
      deploy_account_transaction: {
        ...expectedWire(tx).deploy_account_transaction!,
        contract_address_salt: `0x${STARK_PUBLIC}`,
        constructor_calldata: [`0x${STARK_PUBLIC}`],
        signature: [
          '0x5932f7bef4099ae9421b4f36a1ab2c09bc6a8224e64df27f8e2d2349303fd28',
          '0x74202fc97806cb0a6689f80865acadf86e2bb7964bf216a62b07337fd52b603',
        ],
      },
      invoke_transaction: {
        ...expectedWire(tx).invoke_transaction,
        signature: [
          '0x46e85009472358b0b54f09427b1004eeca918eea3305e5e8f126fdef31fd67',
          '0x15b67b030195236956e1f689094745b2714e2fc24fb4bbe2d49879ade4b1d68',
        ],
      },
    });
    const { fetchImpl, calls } = node({
      starknet_chainId: () => CHAIN_ID,
      starknet_addDeployAccountTransaction: () => ({
        result: { transaction_hash: DEPLOY_HASH, contract_address: ADDRESS },
      }),
      starknet_addInvokeTransaction: () => ({ result: { transaction_hash: INVOKE_HASH } }),
    });
    await expect(broadcastStarknet(adapter(fetchImpl), tx, signed)).resolves.toBe(INVOKE_HASH);
    expect(calls.some((c) => c.includes('starknet_addDeployAccountTransaction'))).toBe(true);

    const tampered = JSON.parse(signed);
    tampered.invoke_transaction.calldata[4] = '0x1';
    await expect(
      broadcastStarknet(adapter(fetchImpl), tx, JSON.stringify(tampered)),
    ).rejects.toThrow(/not this STRK transfer/);
    const wrongNonce = JSON.parse(signed);
    wrongNonce.invoke_transaction.nonce = '0x2';
    await expect(
      broadcastStarknet(adapter(fetchImpl), tx, JSON.stringify(wrongNonce)),
    ).rejects.toThrow();
    await expect(
      broadcastStarknet(adapter(fetchImpl), { ...tx, deploy: false }, signed),
    ).rejects.toThrow(/deploy flag/);
  });

  it('reports receipt status', async () => {
    const { fetchImpl } = node({
      starknet_chainId: () => CHAIN_ID,
      starknet_getTransactionReceipt: () => ({
        result: {
          execution_status: 'SUCCEEDED',
          finality_status: 'ACCEPTED_ON_L2',
          block_number: 16678320,
        },
      }),
    });
    await expect(starknetTransferStatus(adapter(fetchImpl), tx, INVOKE_HASH)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 16678320,
    });
    await expect(starknetTransferStatus(adapter(fetchImpl), tx, DEPLOY_HASH)).rejects.toThrow(
      /not this transfer/,
    );
    const reverted = adapter(
      node({
        starknet_chainId: () => CHAIN_ID,
        starknet_getTransactionReceipt: () => ({
          result: {
            execution_status: 'REVERTED',
            finality_status: 'ACCEPTED_ON_L2',
            block_number: 16678320,
            revert_reason: 'ERC20: insufficient balance',
          },
        }),
      }).fetchImpl,
    );
    await expect(starknetTransferStatus(reverted, tx, INVOKE_HASH)).resolves.toEqual({
      state: 'failed',
      reason: 'ERC20: insufficient balance',
    });
    const unseen = adapter(
      node({
        starknet_chainId: () => CHAIN_ID,
        starknet_getTransactionReceipt: () => ({ error: { code: 29, message: 'not found' } }),
        starknet_getTransactionStatus: () => ({ error: { code: 29, message: 'not found' } }),
      }).fetchImpl,
    );
    await expect(starknetTransferStatus(unseen, tx, INVOKE_HASH)).resolves.toEqual({
      state: 'unknown',
    });
    const pending = adapter(
      node({
        starknet_chainId: () => CHAIN_ID,
        starknet_getTransactionReceipt: () => ({ error: { code: 29, message: 'not found' } }),
        starknet_getTransactionStatus: () => ({ result: { finality_status: 'RECEIVED' } }),
      }).fetchImpl,
    );
    await expect(starknetTransferStatus(pending, tx, INVOKE_HASH)).resolves.toEqual({
      state: 'pending',
    });
  });

  it('reads STRK balances cross-checked across endpoints', async () => {
    const { fetchImpl } = node({
      starknet_chainId: () => CHAIN_ID,
      starknet_call: () => FUNDED,
    });
    const balances = await adapter(fetchImpl).getBalances(ADDRESS, STARKNET_SEPOLIA);
    expect(balances[0]!.assetRef).toBe(`${STARKNET_SEPOLIA}:native`);
    expect(balances[0]!.amount).toBe(0x204fce5e3e2502611000000n.toString());
    expect(balances[0]!.provenance?.kind).toBe('agreed');
    const history = await adapter(fetchImpl).getHistory(ADDRESS, STARKNET_SEPOLIA);
    expect(history.items).toEqual([]);
    expect(history.coverage).toMatch(/indexer/);
  });
});
