import { base64, bech32 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import { CosmosTx, type TxIntent } from '@stackwallet/core-client';
import { Any } from 'cosmjs-types/google/protobuf/any';
import { MsgSend } from 'cosmjs-types/cosmos/bank/v1beta1/tx';
import { PubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys';
import { BaseAccount } from 'cosmjs-types/cosmos/auth/v1beta1/auth';
import { AuthInfo, SignDoc, TxBody, TxRaw } from 'cosmjs-types/cosmos/tx/v1beta1/tx';
import { z } from 'zod';
import {
  cosmosAccountBytes,
  encodeCosmosAddress,
  isValidCosmosAddress,
  type CosmosAdapter,
  type LcdQuery,
} from './cosmos.js';

export const COSMOS_TESTNET = 'cosmos:osmo-test-5';
const Uint64 = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/)
  .max(20)
  .refine((s) => BigInt(s) <= 0xffffffffffffffffn);
const Header = z.object({
  chain_id: z.literal('osmo-test-5'),
  height: Uint64.refine((s) => BigInt(s) > 0n && BigInt(s) <= BigInt(Number.MAX_SAFE_INTEGER - 50)),
});
const Latest = z.union([
  z.object({ block: z.object({ header: Header }) }).transform((b) => b.block.header),
  z.object({ sdk_block: z.object({ header: Header }) }).transform((b) => b.sdk_block.header),
]);
const Account = z.object({
  account: z.object({
    '@type': z.literal('/cosmos.auth.v1beta1.BaseAccount'),
    address: z.string().max(90),
    account_number: Uint64,
    sequence: Uint64,
    pub_key: z
      .object({ '@type': z.literal('/cosmos.crypto.secp256k1.PubKey'), key: z.string().max(48) })
      .nullable(),
  }),
});
const Balance = z.object({
  balance: z.object({ denom: z.literal('uosmo'), amount: Uint64 }).nullable(),
});
const Gas = z.object({ gas_info: z.object({ gas_used: Uint64 }) });
const AccountState = z.object({
  code: z.literal(0),
  height: Uint64,
  key: z.string().max(64),
  value: z.string().max(4096),
});

async function accountAt(lcd: LcdQuery, address: string, height: string) {
  const bytes = bech32.fromWords(bech32.decode(address, 90).words);
  const key = base64.encode(new Uint8Array([1, ...bytes]));
  // ABCI carries its state height in JSON; LCD metadata headers are often hidden by CORS.
  const params = new URLSearchParams({ path: '/store/acc/key', data: key, height, prove: 'false' });
  const state = await lcd(`/cosmos/base/tendermint/v1beta1/abci_query?${params}`, AccountState);
  if (!state || state.height !== height || state.key !== key || !state.value)
    throw new Error('LCD did not return the requested account state height and key');
  const packed = Any.decode(base64.decode(state.value));
  if (packed.typeUrl !== '/cosmos.auth.v1beta1.BaseAccount')
    throw new Error('Unsupported account type');
  const account = BaseAccount.decode(packed.value);
  if (account.pubKey && account.pubKey.typeUrl !== '/cosmos.crypto.secp256k1.PubKey')
    throw new Error('Unsupported account public key');
  return Account.parse({
    account: {
      '@type': packed.typeUrl,
      address: account.address,
      account_number: account.accountNumber.toString(),
      sequence: account.sequence.toString(),
      pub_key: account.pubKey
        ? {
            '@type': account.pubKey.typeUrl,
            key: base64.encode(PubKey.decode(account.pubKey.value).key),
          }
        : null,
    },
  });
}
const Response = z.object({
  tx_response: z.object({
    txhash: z.string().regex(/^[0-9a-fA-F]{64}$/),
    code: z.number().int().nonnegative(),
    height: Uint64,
    raw_log: z.string().max(4096).optional(),
  }),
});

export function cosmosBodyAuth(input: CosmosTx): {
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
} {
  const tx = CosmosTx.parse(input);
  if (
    !isValidCosmosAddress(tx.from, 'osmo') ||
    !isValidCosmosAddress(tx.to, 'osmo') ||
    tx.from !== tx.from.toLowerCase() ||
    tx.to !== tx.to.toLowerCase() ||
    tx.from === tx.to
  )
    throw new Error('Invalid canonical Osmosis sender or recipient');
  for (const value of [tx.amount, tx.accountNumber, tx.sequence, tx.feeAmount]) Uint64.parse(value);
  if (BigInt(tx.amount) === 0n || BigInt(tx.feeAmount) === 0n || BigInt(tx.feeAmount) > 1_000_000n)
    throw new Error('Amount or fee out of bounds');
  const publicBytes = Uint8Array.from(tx.publicKeyHex.match(/../g)!, (b) => parseInt(b, 16));
  if (encodeCosmosAddress('osmo', cosmosAccountBytes(publicBytes, 'secp256k1')) !== tx.from)
    throw new Error('Public key differs from sender');
  const msg = MsgSend.fromPartial({
    fromAddress: tx.from,
    toAddress: tx.to,
    amount: [{ denom: 'uosmo', amount: tx.amount }],
  });
  const bodyBytes = TxBody.encode(
    TxBody.fromPartial({
      messages: [
        Any.fromPartial({
          typeUrl: '/cosmos.bank.v1beta1.MsgSend',
          value: MsgSend.encode(msg).finish(),
        }),
      ],
      timeoutHeight: BigInt(tx.timeoutHeight),
    }),
  ).finish();
  const authInfoBytes = AuthInfo.encode(
    AuthInfo.fromPartial({
      signerInfos: [
        {
          publicKey: {
            typeUrl: '/cosmos.crypto.secp256k1.PubKey',
            value: PubKey.encode({ key: publicBytes }).finish(),
          },
          modeInfo: { single: { mode: 1 } },
          sequence: BigInt(tx.sequence),
        },
      ],
      fee: { amount: [{ denom: 'uosmo', amount: tx.feeAmount }], gasLimit: BigInt(tx.gasLimit) },
    }),
  ).finish();
  return { bodyBytes, authInfoBytes };
}

export function cosmosSignDoc(tx: CosmosTx): Uint8Array {
  return SignDoc.encode({
    ...cosmosBodyAuth(tx),
    chainId: 'osmo-test-5',
    accountNumber: BigInt(tx.accountNumber),
  }).finish();
}
function simulationWire(tx: CosmosTx): string {
  return base64.encode(
    TxRaw.encode({ ...cosmosBodyAuth(tx), signatures: [new Uint8Array(64)] }).finish(),
  );
}

export async function prepareCosmos(
  adapter: CosmosAdapter,
  intent: TxIntent,
  from: string,
  publicKeyHex: string,
): Promise<{ unsigned: CosmosTx; simulation: Simulation }> {
  if (
    intent.chainId !== COSMOS_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${COSMOS_TESTNET}:native`
  )
    throw new Error('Only native transfers on Osmosis Testnet are enabled');
  return adapter.withChain(intent.chainId, async (lcd) => {
    const latest = await lcd('/cosmos/base/tendermint/v1beta1/blocks/latest', Latest);
    const account = await lcd(`/cosmos/auth/v1beta1/accounts/${encodeURIComponent(from)}`, Account);
    if (!latest || !account)
      throw new Error('Sender account is not funded or the latest block is unavailable');
    if (
      account.account.address !== from ||
      (account.account.pub_key &&
        base64.encode(Uint8Array.from(publicKeyHex.match(/../g) ?? [], (b) => parseInt(b, 16))) !==
          account.account.pub_key.key)
    )
      throw new Error('LCD account differs from sender key');
    let unsigned = CosmosTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      amount: intent.amount,
      publicKeyHex,
      accountNumber: account.account.account_number,
      sequence: account.account.sequence,
      gasLimit: 200_000,
      feeAmount: '5000',
      timeoutHeight: Number(latest.height) + 50,
    });
    cosmosBodyAuth(unsigned);
    let error: string | undefined;
    try {
      const gas = await lcd('/cosmos/tx/v1beta1/simulate', Gas, {
        tx_bytes: simulationWire(unsigned),
      });
      if (!gas) throw new Error('Simulation returned no gas');
      const limit = (BigInt(gas.gas_info.gas_used) * 13n + 9n) / 10n;
      if (limit === 0n || limit > 1_000_000n)
        throw new Error('Estimated gas exceeds the transfer limit');
      unsigned = CosmosTx.parse({
        ...unsigned,
        gasLimit: Number(limit),
        feeAmount: ((limit * 25n + 999n) / 1000n).toString(),
      });
      // Bind the policy's simulation flag to the final fee/gas bytes presented for approval.
      const finalGas = await lcd('/cosmos/tx/v1beta1/simulate', Gas, {
        tx_bytes: simulationWire(unsigned),
      });
      if (!finalGas || BigInt(finalGas.gas_info.gas_used) > BigInt(unsigned.gasLimit))
        throw new Error('Final simulation exceeds approved gas');
    } catch (err) {
      error = (err instanceof Error ? err.message : String(err)).slice(0, 512);
    }
    const balance = await lcd(
      `/cosmos/bank/v1beta1/balances/${encodeURIComponent(from)}/by_denom?denom=uosmo`,
      Balance,
    );
    if (!balance) throw new Error('Balance endpoint unavailable');
    if (BigInt(balance.balance?.amount ?? '0') < BigInt(intent.amount) + BigInt(unsigned.feeAmount))
      error ??= 'Balance does not cover the transfer and fee';
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${unsigned.feeAmount}` },
        ],
        fee: { assetRef: intent.asset, amount: unsigned.feeAmount },
        warnings: [],
        ...(error ? { error } : {}),
      },
    };
  });
}

export async function cosmosApprovalValid(adapter: CosmosAdapter, tx: CosmosTx): Promise<boolean> {
  return adapter.withChain(tx.chainId, async (lcd) => {
    const latest = await lcd('/cosmos/base/tendermint/v1beta1/blocks/latest', Latest);
    if (!latest) throw new Error('Cannot verify the approval lifetime');
    const account = await accountAt(lcd, tx.from, latest.height);
    if (!account) throw new Error('Cannot verify the approval lifetime');
    return (
      BigInt(latest.height) <= BigInt(tx.timeoutHeight) &&
      account.account.sequence === tx.sequence &&
      account.account.account_number === tx.accountNumber &&
      account.account.address === tx.from
    );
  });
}

export async function broadcastCosmos(
  adapter: CosmosAdapter,
  tx: CosmosTx,
  rawHex: string,
): Promise<string> {
  if (!/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(rawHex))
    throw new Error('Invalid Cosmos wire transaction');
  const tx_bytes = base64.encode(
    Uint8Array.from(rawHex.slice(2).match(/../g)!, (b) => parseInt(b, 16)),
  );
  return adapter.withChain(tx.chainId, async (lcd) => {
    const result = await lcd('/cosmos/tx/v1beta1/txs', Response, {
      tx_bytes,
      mode: 'BROADCAST_MODE_SYNC',
    });
    if (!result || result.tx_response.code !== 0)
      throw new Error(result?.tx_response.raw_log?.slice(0, 512) ?? 'Broadcast rejected');
    return result.tx_response.txhash.toUpperCase();
  });
}

export async function cosmosTransferStatus(
  adapter: CosmosAdapter,
  tx: CosmosTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Cosmos transaction hash');
  return adapter.withChain<TxStatus | { state: 'expired' }>(tx.chainId, async (lcd) => {
    const latest = await lcd('/cosmos/base/tendermint/v1beta1/blocks/latest', Latest);
    const result = await lcd(`/cosmos/tx/v1beta1/txs/${hash.toUpperCase()}`, Response);
    if (!latest) throw new Error('Latest block unavailable');
    if (!result) {
      if (BigInt(latest.height) <= BigInt(tx.timeoutHeight)) return { state: 'unknown' };
      // An unindexed transfer may already have moved funds. Unchanged sequence at
      // a height-bound post-timeout state is necessary before releasing the reservation.
      const account = await accountAt(lcd, tx.from, latest.height);
      return account &&
        account.account.address === tx.from &&
        account.account.sequence === tx.sequence &&
        account.account.account_number === tx.accountNumber
        ? { state: 'expired' }
        : { state: 'unknown' };
    }
    if (result.tx_response.txhash.toUpperCase() !== hash.toUpperCase())
      throw new Error('LCD returned a different transaction');
    if (result.tx_response.height === '0') return { state: 'pending' };
    if (result.tx_response.code !== 0)
      return {
        state: 'failed',
        reason: result.tx_response.raw_log?.slice(0, 512) ?? 'Transaction failed',
      };
    if (BigInt(result.tx_response.height) > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error('Unsafe block height');
    return { state: 'confirmed', blockNumber: Number(result.tx_response.height) };
  });
}
