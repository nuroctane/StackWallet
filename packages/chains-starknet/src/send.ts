/**
 * STRK transfers on Starknet Sepolia: an INVOKE v3 that calls the STRK
 * token's `transfer`, preceded by a DEPLOY_ACCOUNT v3 when the sender's
 * OpenZeppelin account is not on-chain yet. The core rebuilds every hashed
 * felt from these fields and signs; this module only gathers nonce, prices
 * and fee estimates, and verifies the signed wire before broadcasting.
 */
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  ACCOUNT_CLASS_HASH,
  BlockHead,
  STARKNET_SEPOLIA,
  STARK_PRIME,
  STRK_TOKEN,
  computeHashOnElements,
  feltHex,
  feltPadded,
  getSelectorFromName,
  isContractNotFound,
  isHashNotFound,
  isValidStarknetAddress,
  normalizeStarknetAddress,
  poseidonHashMany,
  type StarknetAdapter,
} from './starknet.js';

export { STARKNET_SEPOLIA };

/** Mirrors the core's `StarknetTx`; every signed felt is derived from these fields. */
export const StarknetTx = z.strictObject({
  chainId: z.literal(STARKNET_SEPOLIA),
  from: z.string().regex(/^0x[0-9a-f]{64}$/),
  to: z.string().regex(/^0x[0-9a-f]{64}$/),
  fri: z.string().regex(/^[1-9][0-9]{0,38}$/),
  nonce: z
    .number()
    .int()
    .min(1)
    .max(2 ** 53),
  deploy: z.boolean(),
  tip: z.string().regex(/^(0|[1-9][0-9]{0,38})$/),
  l1GasMaxAmount: z.number().int().nonnegative().max(1_000_000),
  l1GasMaxPrice: z.string().regex(/^(0|[1-9][0-9]{0,38})$/),
  l2GasMaxAmount: z.number().int().min(1).max(1_000_000_000),
  l2GasMaxPrice: z.string().regex(/^[1-9][0-9]{0,38}$/),
  l1DataGasMaxAmount: z.number().int().nonnegative().max(1_000_000),
  l1DataGasMaxPrice: z.string().regex(/^(0|[1-9][0-9]{0,38})$/),
});
export type StarknetTx = z.infer<typeof StarknetTx>;

/** Worst-case fee the core allows one transaction to carry: 20 STRK. */
export const MAX_FEE_FRI = 20_000_000_000_000_000_000n;
const MAX_PRICE = 1_000_000_000_000_000n;
const MASK_128 = (1n << 128n) - 1n;

const textFelt = (text: string) =>
  BigInt(`0x${[...text].map((c) => c.charCodeAt(0).toString(16)).join('')}`);
const INVOKE_PREFIX = textFelt('invoke');
const DEPLOY_ACCOUNT_PREFIX = textFelt('deploy_account');
const TRANSFER_SELECTOR = getSelectorFromName('transfer');
const CHAIN_ID = textFelt('SN_SEPOLIA');
const resourceName = (name: string) => BigInt(`0x${Buffer.from(name).toString('hex')}`);

interface Bounds {
  l1: { amount: bigint; price: bigint };
  l2: { amount: bigint; price: bigint };
  l1Data: { amount: bigint; price: bigint };
}

function boundsOf(tx: StarknetTx): Bounds {
  return {
    l1: { amount: BigInt(tx.l1GasMaxAmount), price: BigInt(tx.l1GasMaxPrice) },
    l2: { amount: BigInt(tx.l2GasMaxAmount), price: BigInt(tx.l2GasMaxPrice) },
    l1Data: { amount: BigInt(tx.l1DataGasMaxAmount), price: BigInt(tx.l1DataGasMaxPrice) },
  };
}

/** `(name << 192) + (max_amount << 128) + max_price_per_unit`, as the v3 spec packs it. */
function packBound(name: bigint, amount: bigint, price: bigint): bigint {
  return (name << 192n) + (amount << 128n) + price;
}

function feeHash(tx: StarknetTx): bigint {
  const b = boundsOf(tx);
  return poseidonHashMany([
    BigInt(tx.tip),
    packBound(resourceName('L1_GAS'), b.l1.amount, b.l1.price),
    packBound(resourceName('L2_GAS'), b.l2.amount, b.l2.price),
    packBound(resourceName('L1_DATA'), b.l1Data.amount, b.l1Data.price),
  ]);
}

/** `account.__execute__` calldata for one `transfer(recipient, u256)` call. */
export function transferCalldata(tx: StarknetTx): bigint[] {
  const amount = BigInt(tx.fri);
  return [
    1n,
    BigInt(STRK_TOKEN),
    TRANSFER_SELECTOR,
    3n,
    BigInt(tx.to),
    amount & MASK_128,
    amount >> 128n,
  ];
}

/** The INVOKE v3 hash: what the account signs and what explorers show. */
export function invokeTxHash(input: StarknetTx): string {
  const tx = StarknetTx.parse(input);
  return feltPadded(
    poseidonHashMany([
      INVOKE_PREFIX,
      3n,
      BigInt(tx.from),
      feeHash(tx),
      poseidonHashMany([]),
      CHAIN_ID,
      BigInt(tx.nonce),
      0n,
      poseidonHashMany([]),
      poseidonHashMany(transferCalldata(tx)),
    ]),
  );
}

/** The DEPLOY_ACCOUNT v3 hash (salt and constructor calldata are the Stark public key). */
export function deployTxHash(input: StarknetTx, starkPublicKey: bigint): string {
  const tx = StarknetTx.parse(input);
  return feltPadded(
    poseidonHashMany([
      DEPLOY_ACCOUNT_PREFIX,
      3n,
      BigInt(tx.from),
      feeHash(tx),
      poseidonHashMany([]),
      CHAIN_ID,
      0n,
      0n,
      poseidonHashMany([starkPublicKey]),
      BigInt(ACCOUNT_CLASS_HASH),
      starkPublicKey,
    ]),
  );
}

/** Pedersen contract-address derivation, exported so tests pin it against the core. */
export function accountAddress(starkPublicKey: bigint): string {
  return feltPadded(
    computeHashOnElements([
      textFelt('STARKNET_CONTRACT_ADDRESS'),
      0n,
      starkPublicKey,
      BigInt(ACCOUNT_CLASS_HASH),
      computeHashOnElements([starkPublicKey]),
    ]) %
      (2n ** 251n - 256n),
  );
}

const ResourceBoundsJson = z.strictObject({
  l1_gas: z.strictObject({ max_amount: z.string(), max_price_per_unit: z.string() }),
  l2_gas: z.strictObject({ max_amount: z.string(), max_price_per_unit: z.string() }),
  l1_data_gas: z.strictObject({ max_amount: z.string(), max_price_per_unit: z.string() }),
});
const FeltJson = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const CommonWire = {
  version: z.literal('0x3'),
  signature: z.array(FeltJson).length(2),
  nonce: FeltJson,
  resource_bounds: ResourceBoundsJson,
  tip: FeltJson,
  paymaster_data: z.array(z.unknown()).length(0),
  nonce_data_availability_mode: z.literal('L1'),
  fee_data_availability_mode: z.literal('L1'),
};
const InvokeWire = z.strictObject({
  type: z.literal('INVOKE'),
  sender_address: FeltJson,
  calldata: z.array(FeltJson),
  account_deployment_data: z.array(z.unknown()).length(0),
  ...CommonWire,
});
const DeployWire = z.strictObject({
  type: z.literal('DEPLOY_ACCOUNT'),
  contract_address_salt: FeltJson,
  constructor_calldata: z.array(FeltJson).length(1),
  class_hash: FeltJson,
  ...CommonWire,
});
const Wire = z.strictObject({
  invoke_transaction: InvokeWire,
  deploy_account_transaction: DeployWire.optional(),
});

function expectedCommon(tx: StarknetTx, nonce: number) {
  const b = boundsOf(tx);
  const bound = (v: { amount: bigint; price: bigint }) => ({
    max_amount: feltHex(v.amount),
    max_price_per_unit: feltHex(v.price),
  });
  return {
    version: '0x3',
    nonce: feltHex(BigInt(nonce)),
    resource_bounds: { l1_gas: bound(b.l1), l2_gas: bound(b.l2), l1_data_gas: bound(b.l1Data) },
    tip: feltHex(BigInt(tx.tip)),
    paymaster_data: [],
    nonce_data_availability_mode: 'L1',
    fee_data_availability_mode: 'L1',
  };
}

/** The wire fields everything except the signature must equal. */
export function expectedWire(tx: StarknetTx) {
  return {
    invoke_transaction: {
      type: 'INVOKE',
      sender_address: feltHex(BigInt(tx.from)),
      calldata: transferCalldata(tx).map(feltHex),
      account_deployment_data: [],
      ...expectedCommon(tx, tx.nonce),
    },
    ...(tx.deploy
      ? {
          deploy_account_transaction: {
            type: 'DEPLOY_ACCOUNT',
            class_hash: feltHex(BigInt(ACCOUNT_CLASS_HASH)),
            ...expectedCommon(tx, 0),
          },
        }
      : {}),
  };
}

// ---------------------------------------------------------------------------

const FeeEstimate = z
  .object({
    overall_fee: FeltJson,
    l1_gas_consumed: FeltJson.optional(),
    l1_gas_price: FeltJson.optional(),
    l2_gas_consumed: FeltJson.optional(),
    l2_gas_price: FeltJson.optional(),
    l1_data_gas_consumed: FeltJson.optional(),
    l1_data_gas_price: FeltJson.optional(),
    gas_consumed: FeltJson.optional(),
    gas_price: FeltJson.optional(),
    data_gas_consumed: FeltJson.optional(),
    data_gas_price: FeltJson.optional(),
  })
  .loose();
const Balance = z.array(FeltJson).min(1).max(2);

const ceilDiv = (a: bigint, b: bigint) => (a + b - 1n) / b;

function checkBounds(b: Bounds): void {
  const fee =
    b.l1.amount * b.l1.price + b.l2.amount * b.l2.price + b.l1Data.amount * b.l1Data.price;
  if (
    b.l1.amount > 1_000_000n ||
    b.l2.amount > 1_000_000_000n ||
    b.l1Data.amount > 1_000_000n ||
    b.l1.price > MAX_PRICE ||
    b.l2.price > MAX_PRICE ||
    b.l1Data.price > MAX_PRICE
  )
    throw new Error('Estimated resource bound exceeds the safety caps');
  if (fee > MAX_FEE_FRI) throw new Error('Estimated fee exceeds 20 STRK');
}

export async function prepareStarknet(
  adapter: StarknetAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: StarknetTx; simulation: Simulation }> {
  if (
    intent.chainId !== STARKNET_SEPOLIA ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${STARKNET_SEPOLIA}:native`
  )
    throw new Error('Only native STRK transfers on Starknet Sepolia are enabled');
  if (!isValidStarknetAddress(from) || !isValidStarknetAddress(intent.to))
    throw new Error('Invalid Starknet sender or recipient');
  const sender = normalizeStarknetAddress(from);
  const to = normalizeStarknetAddress(intent.to);
  return adapter.withNode(intent.chainId, async (call) => {
    let nonce = 0n;
    let deploy = false;
    try {
      nonce = BigInt(await call('starknet_getNonce', ['latest', sender], FeltJson));
    } catch (err) {
      if (!isContractNotFound(err)) throw err;
      deploy = true;
    }
    const head = await call('starknet_getBlockWithTxHashes', ['latest'], BlockHead);
    const prices = {
      l1: BigInt(head.l1_gas_price.price_in_fri),
      l2: BigInt(head.l2_gas_price.price_in_fri),
      l1Data: BigInt(head.l1_data_gas_price.price_in_fri),
    };
    const placeholder: Bounds = {
      l1: { amount: 0n, price: prices.l1 * 2n || 1n },
      l2: { amount: 1_000_000n, price: prices.l2 * 2n || 1n },
      l1Data: { amount: 256n, price: prices.l1Data * 2n || 1n },
    };
    const candidate = (bounds: Bounds): StarknetTx =>
      StarknetTx.parse({
        chainId: intent.chainId,
        from: sender,
        to,
        fri: intent.amount,
        nonce: deploy ? 1 : Number(nonce),
        deploy,
        tip: '0',
        l1GasMaxAmount: Number(bounds.l1.amount),
        l1GasMaxPrice: bounds.l1.price.toString(),
        l2GasMaxAmount: Number(bounds.l2.amount),
        l2GasMaxPrice: bounds.l2.price.toString(),
        l1DataGasMaxAmount: Number(bounds.l1Data.amount),
        l1DataGasMaxPrice: bounds.l1Data.price.toString(),
      });
    // estimateFee simulates sequentially, so the deploy makes the invoke's account exist.
    const wireFor = (tx: StarknetTx) => {
      const dummy = ['0x0', '0x0'];
      const invoke = {
        ...expectedWire(tx).invoke_transaction,
        signature: dummy,
      };
      const txs = tx.deploy
        ? [
            {
              ...expectedWire(tx).deploy_account_transaction!,
              signature: dummy,
              contract_address_salt: '0x0',
              constructor_calldata: ['0x0'],
            },
            invoke,
          ]
        : [invoke];
      return txs;
    };
    let estimates: z.infer<typeof FeeEstimate>[] | undefined;
    try {
      estimates = await call(
        'starknet_estimateFee',
        [wireFor(candidate(placeholder)), ['SKIP_VALIDATE'], 'latest'],
        z.array(FeeEstimate).min(1).max(2),
      );
    } catch {
      estimates = undefined;
    }
    let bounds: Bounds;
    if (estimates) {
      const consumed = (pick: (e: z.infer<typeof FeeEstimate>) => string | undefined) =>
        estimates!.map((e) => BigInt(pick(e) ?? '0x0')).reduce((a, b) => (a > b ? a : b), 0n);
      const l2Used = consumed((e) => e.l2_gas_consumed ?? e.gas_consumed);
      const dataUsed = consumed((e) => e.l1_data_gas_consumed ?? e.data_gas_consumed);
      const l1Used = consumed((e) => e.l1_gas_consumed);
      const priceOf = (est: (e: z.infer<typeof FeeEstimate>) => string | undefined, head: bigint) =>
        [head, ...estimates!.map((e) => BigInt(est(e) ?? '0x0'))].reduce((a, b) =>
          a > b ? a : b,
        ) * 2n || 1n;
      bounds = {
        l1: { amount: l1Used * 2n, price: priceOf((e) => e.l1_gas_price, prices.l1) },
        l2: {
          amount: ceilDiv(l2Used * 3n, 2n) > 100_000n ? ceilDiv(l2Used * 3n, 2n) : 100_000n,
          price: priceOf((e) => e.l2_gas_price ?? e.gas_price, prices.l2),
        },
        l1Data: {
          amount: dataUsed * 2n > 32n ? dataUsed * 2n : 32n,
          price: priceOf((e) => e.l1_data_gas_price ?? e.data_gas_price, prices.l1Data),
        },
      };
    } else {
      // Without an estimate (e.g. an unfunded account reverts the simulated
      // transfer), fall back to bounds that covered a live deploy + transfer.
      bounds = {
        l1: { amount: 0n, price: prices.l1 * 2n || 1n },
        l2: { amount: deploy ? 4_000_000n : 1_500_000n, price: prices.l2 * 2n || 1n },
        l1Data: { amount: deploy ? 1024n : 256n, price: prices.l1Data * 2n || 1n },
      };
    }
    checkBounds(bounds);
    const unsigned = candidate(bounds);
    const feePerTx =
      bounds.l1.amount * bounds.l1.price +
      bounds.l2.amount * bounds.l2.price +
      bounds.l1Data.amount * bounds.l1Data.price;
    const fee = deploy ? feePerTx * 2n : feePerTx;
    const balance = await call(
      'starknet_call',
      [
        {
          contract_address: STRK_TOKEN,
          entry_point_selector: feltHex(getSelectorFromName('balanceOf')),
          calldata: [feltHex(BigInt(sender))],
        },
        'latest',
      ],
      Balance,
    ).then((res) => BigInt(res[0]!) + (BigInt(res[1] ?? '0x0') << 128n));
    let error: string | undefined;
    if (balance < BigInt(intent.amount) + fee)
      error = deploy
        ? 'Balance does not cover the transfer and both fees; fund the account address with STRK before its first send'
        : 'Balance does not cover the transfer and fee';
    const warnings: Simulation['warnings'] = [];
    if (to === STRK_TOKEN) warnings.push({ kind: 'destinationIsContract', address: to });
    if (deploy)
      warnings.push({
        kind: 'other',
        message:
          'First send from this account: it deploys your OpenZeppelin account contract (DEPLOY_ACCOUNT) before the transfer, and the address must already hold STRK for both fees.',
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee}` },
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Approval is refused once the on-chain nonce or deployment state moved past the prepared tx. */
export async function starknetApprovalValid(
  adapter: StarknetAdapter,
  tx: StarknetTx,
): Promise<boolean> {
  try {
    return await adapter.withNode(tx.chainId, async (call) => {
      try {
        const nonce = BigInt(await call('starknet_getNonce', ['latest', tx.from], FeltJson));
        // A deploying send is still valid while the account stays undeployed.
        return !tx.deploy && nonce === BigInt(tx.nonce);
      } catch (err) {
        if (isContractNotFound(err)) return tx.deploy;
        throw err;
      }
    });
  } catch {
    return false;
  }
}

const AddDeployResult = z.object({ transaction_hash: FeltJson, contract_address: FeltJson });
const AddInvokeResult = z.object({ transaction_hash: FeltJson });

/** Key-order-independent JSON comparison: serde and this module order fields differently. */
const canon = (value: unknown): string =>
  JSON.stringify(value, (_, v: unknown) =>
    v !== null && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );

/** Broadcast only a payload whose every field matches the ledger's transfer. */
export async function broadcastStarknet(
  adapter: StarknetAdapter,
  input: StarknetTx,
  signedWire: string,
): Promise<string> {
  const tx = StarknetTx.parse(input);
  let parsed: unknown;
  try {
    parsed = JSON.parse(signedWire);
  } catch {
    throw new Error('Signed payload is not JSON');
  }
  const wire = Wire.parse(parsed);
  const expected = expectedWire(tx);
  const checkFelts = (felts: string[]) => {
    for (const felt of felts)
      if (BigInt(felt) === 0n || BigInt(felt) >= STARK_PRIME)
        throw new Error('Signed felt outside the field');
  };
  const { signature: invokeSig, ...invoke } = wire.invoke_transaction;
  if (canon(invoke) !== canon(expected.invoke_transaction))
    throw new Error('Signed invoke transaction is not this STRK transfer');
  checkFelts(invokeSig);
  if (tx.deploy !== (wire.deploy_account_transaction !== undefined))
    throw new Error('Signed payload does not match the deploy flag');
  if (wire.deploy_account_transaction) {
    const {
      signature: deploySig,
      contract_address_salt: salt,
      constructor_calldata: constructor,
      ...deploy
    } = wire.deploy_account_transaction;
    if (salt !== constructor[0]) throw new Error('Deploy salt must be the Stark public key');
    if (canon(deploy) !== canon(expected.deploy_account_transaction))
      throw new Error('Signed deploy transaction is not this account deployment');
    checkFelts([...deploySig, salt]);
  }
  const hash = invokeTxHash(tx);
  return adapter.withNode(tx.chainId, async (call) => {
    if (wire.deploy_account_transaction) {
      const deployed = await call(
        'starknet_addDeployAccountTransaction',
        { deploy_account_transaction: wire.deploy_account_transaction },
        AddDeployResult,
      );
      if (normalizeStarknetAddress(deployed.contract_address) !== tx.from)
        throw new Error('Node deployed a different account address');
    }
    const res = await call(
      'starknet_addInvokeTransaction',
      { invoke_transaction: wire.invoke_transaction },
      AddInvokeResult,
    );
    if (BigInt(res.transaction_hash) !== BigInt(hash))
      throw new Error('Node reported a different transaction hash');
    return hash;
  });
}

/** v3 transactions do not expire; status is receipt finality, never 'expired'. */
export async function starknetTransferStatus(
  adapter: StarknetAdapter,
  tx: StarknetTx,
  hash: string,
): Promise<TxStatus> {
  if (BigInt(hash) !== BigInt(invokeTxHash(tx))) throw new Error('Hash is not this transfer');
  try {
    return await adapter.status(feltHex(BigInt(hash)), tx.chainId);
  } catch (err) {
    if (isHashNotFound(err)) return { state: 'unknown' };
    throw err;
  }
}
