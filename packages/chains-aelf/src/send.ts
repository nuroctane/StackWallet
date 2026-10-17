import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  AELF_TESTNET,
  AELF_TOKEN_CONTRACTS,
  ChainStatus,
  aelfAddressBytes,
  aelfErrorMessage,
  decodeGetBalanceOutput,
  protoBytes,
  protoInt,
  transactionBytes,
  type AelfAdapter,
} from './aelf.js';

const Address = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,64}$/);
/**
 * Mirrors the Rust `AelfTx` struct exactly (serde camelCase); the lead copies
 * this schema into `@stackwallet/core-client` when wiring the family.
 */
export const AelfTx = z.strictObject({
  chainId: z.literal(AELF_TESTNET),
  from: Address,
  to: Address,
  /** Decimal elves; 1 ELF = 100,000,000 elves. */
  elves: z.string().regex(/^\d{1,19}$/),
  refBlockNumber: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  refBlockPrefix: z.string().regex(/^[0-9a-f]{8}$/),
});
export type AelfTx = z.infer<typeof AelfTx>;

/**
 * Conservative fee allowance for a native Transfer (0.01 ELF). aelf meters
 * fees per transaction size and charges whatever execution costs; the exact
 * figure needs a signed `calculateTransactionFee`, which only the core can
 * produce, so the simulation reserves this bound instead.
 */
export const FEE_ALLOWANCE_ELVES = '1000000';
/** Reference blocks beyond this many blocks behind the head are treated as stale. */
export const REF_BLOCK_WINDOW = 512;

/** The same unsigned `Transaction` protobuf the core encodes from checked fields. */
export function transferRaw(input: AelfTx): Uint8Array {
  const tx = AelfTx.parse(input);
  const from = aelfAddressBytes(tx.from);
  const to = aelfAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid ELF sender or recipient');
  const contract = AELF_TOKEN_CONTRACTS[tx.chainId];
  if (!contract || !aelfAddressBytes(contract)) throw new Error('Unknown aelf token contract');
  if (tx.to === contract) throw new Error('Recipient must not be the token contract');
  const amount = BigInt(tx.elves);
  if (amount <= 0n || amount > 0x7fffffffffffffffn || amount.toString() !== tx.elves)
    throw new Error('ELF amount must be a positive int64 of elves');
  // TransferInput { to: Address = 1, symbol: string = 2, amount: int64 = 3 }; memo omitted.
  const params = [
    ...protoBytes(1, protoBytes(1, to)),
    ...protoBytes(2, new TextEncoder().encode('ELF')),
    ...protoInt(3, amount),
  ];
  return transactionBytes({
    from: tx.from,
    to: contract,
    refBlockNumber: BigInt(tx.refBlockNumber),
    refBlockPrefix: tx.refBlockPrefix,
    methodName: 'Transfer',
    params,
  });
}

export function transferTxId(tx: AelfTx): string {
  return bytesToHex(sha256(transferRaw(tx)));
}

export async function prepareAelf(
  adapter: AelfAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: AelfTx; simulation: Simulation }> {
  if (
    intent.chainId !== AELF_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${AELF_TESTNET}:native`
  )
    throw new Error('Only native ELF transfers on tDVV are enabled');
  if (!aelfAddressBytes(from)) throw new Error('Invalid sender address');
  return adapter.withNode(intent.chainId, async (_call, url) => {
    const status = await adapter.chainStatusOf(url);
    const height = status.BestChainHeight ?? status.LongestChainHeight;
    const hash = status.BestChainHash ?? status.LongestChainHash;
    if (height === undefined || hash === undefined)
      throw new Error('Node did not report a head block');
    const unsigned = AelfTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      elves: intent.amount,
      refBlockNumber: height,
      refBlockPrefix: hash.slice(0, 8).toLowerCase(),
    });
    transferRaw(unsigned);
    const token = AELF_TOKEN_CONTRACTS[intent.chainId]!;
    const balanceBytes = await adapter.viewCall(url, {
      to: token,
      methodName: 'GetBalance',
      params: [
        ...protoBytes(1, new TextEncoder().encode('ELF')),
        ...protoBytes(2, protoBytes(1, aelfAddressBytes(from)!)),
      ],
    });
    const balance = decodeGetBalanceOutput(balanceBytes);
    const needed = BigInt(intent.amount) + BigInt(FEE_ALLOWANCE_ELVES);
    let error: string | undefined;
    if (balance < needed)
      error =
        balance < BigInt(intent.amount)
          ? 'Balance does not cover the transfer'
          : 'Balance covers the transfer but not the network fee allowance';
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${FEE_ALLOWANCE_ELVES}` },
        ],
        fee: { assetRef: intent.asset, amount: FEE_ALLOWANCE_ELVES },
        warnings: [
          {
            kind: 'other',
            message:
              'The fee is a conservative allowance; aelf charges the exact execution fee and refunds the difference by design of the balance check here.',
          },
        ],
        ...(error ? { error } : {}),
      },
    };
  });
}

/**
 * Approval is refused once the head has moved so far past the reference block
 * that the network could consider the transaction stale.
 */
export async function aelfApprovalValid(adapter: AelfAdapter, tx: AelfTx): Promise<boolean> {
  const head = await adapter.withNode(tx.chainId, (_call, url) =>
    adapter.chainStatusOf(url).then((s) => s.BestChainHeight ?? s.LongestChainHeight),
  );
  if (head === undefined) return false;
  return tx.refBlockNumber <= head && head - tx.refBlockNumber <= REF_BLOCK_WINDOW;
}

const SendResult = z.object({
  TransactionId: z.string().regex(/^[0-9a-fA-F]{64}$/),
});

/** Broadcast only bytes that are exactly the ledger's transfer plus one 65-byte signature. */
export async function broadcastAelf(
  adapter: AelfAdapter,
  tx: AelfTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== AELF_TESTNET) throw new Error('Only tDVV broadcasts are enabled');
  const raw = bytesToHex(transferRaw(tx));
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  // signature field 10000: key 82f104, length 0x41, then r||s||recovery.
  if (
    !/^[0-9a-f]+$/.test(hex) ||
    hex.length !== raw.length + 8 + 130 ||
    !hex.startsWith(`${raw}82f10441`)
  )
    throw new Error('Signed bytes are not this ELF transfer');
  const txid = transferTxId(tx);
  try {
    const res = await adapter.withNode(tx.chainId, (call) =>
      call('/api/blockChain/sendTransaction', { RawTransaction: hex }, SendResult),
    );
    if (res.TransactionId.toLowerCase() !== txid)
      throw new Error('Node reported a different transaction id');
    return txid;
  } catch (err) {
    const message = aelfErrorMessage(err);
    throw new Error(
      `Broadcast rejected: ${message ?? (err instanceof Error ? err.message : String(err))}`,
    );
  }
}

/** Expiry is reported once the head is past the reference block window and the id is absent. */
export async function aelfTransferStatus(
  adapter: AelfAdapter,
  tx: AelfTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const head = await adapter.withNode(tx.chainId, (_call, url) =>
    adapter.chainStatusOf(url).then((s) => s.BestChainHeight ?? s.LongestChainHeight),
  );
  if (head === undefined || head - tx.refBlockNumber <= REF_BLOCK_WINDOW) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
