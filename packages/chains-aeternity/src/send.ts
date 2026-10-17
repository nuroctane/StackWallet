import { bytesToHex } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import { HttpError } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  aeternityAddressBytes,
  aeternityHash,
  aeternityTxHash,
  decodeChecked,
  encodeChecked,
  parseAeJson,
  rlpDecode,
  rlpInt,
  type AeternityAdapter,
  type RlpItem,
} from './aeternity.js';

export const AETERNITY_TESTNET = 'aet:ae_uat';
const NETWORK_ID = 'ae_uat';
const SPEND_TX_TAG = 12n;
const SIGNED_TX_TAG = 11n;
const TX_VERSION = 1n;
/** Protocol minimum for an empty-payload spend at the minimum gas price, plus headroom. */
const DEFAULT_FEE = '20000000000000'; // 20,000 gas * 1e9 aettos
/** 60 key blocks (~3h) after the prepared height. */
const TTL_BLOCKS = 60;

const AeAddress = z.string().regex(/^ak_[1-9A-HJ-NP-Za-km-z]{40,60}$/);
/** Mirrors the Rust `AeternityTx` struct field for field. */
export const AeternityTx = z.strictObject({
  chainId: z.literal(AETERNITY_TESTNET),
  from: AeAddress,
  to: AeAddress,
  aettos: z.string().regex(/^[1-9][0-9]{0,29}$/),
  fee: z.string().regex(/^[1-9][0-9]{11,17}$/),
  ttl: z.number().int().nonnegative().max(0xffffffff),
  nonce: z.number().int().positive().max(0xffffffff),
});
export type AeternityTx = z.infer<typeof AeternityTx>;

// --- aeser RLP encoding (zero integer is one 0x00 byte, not the empty string) ---

function rlpHeader(offset: number, len: number): number[] {
  if (len <= 55) return [offset + len];
  const lenBytes: number[] = [];
  for (let v = len; v > 0; v >>= 8) lenBytes.unshift(v & 0xff);
  return [offset + 55 + lenBytes.length, ...lenBytes];
}

function rlpItem(payload: Uint8Array | number[]): number[] {
  const bytes = payload instanceof Uint8Array ? [...payload] : payload;
  if (bytes.length === 1 && bytes[0]! < 0x80) return bytes;
  return [...rlpHeader(0x80, bytes.length), ...bytes];
}

function rlpList(items: number[][]): number[] {
  const payload = items.flat();
  return [...rlpHeader(0xc0, payload.length), ...payload];
}

function rlpIntEncode(value: bigint): number[] {
  if (value === 0n) return [0];
  const bytes: number[] = [];
  for (let v = value; v > 0n; v >>= 8n) bytes.unshift(Number(v & 0xffn));
  return rlpItem(bytes);
}

const rlpId = (publicKey: Uint8Array): number[] => rlpItem([1, ...publicKey]);

/** The same unsigned SpendTx RLP the core encodes independently from checked fields. */
export function spendRlp(input: AeternityTx): Uint8Array {
  const tx = AeternityTx.parse(input);
  const from = aeternityAddressBytes(tx.from);
  const to = aeternityAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid AE sender or recipient');
  const amount = BigInt(tx.aettos);
  if (amount.toString() !== tx.aettos) throw new Error('AE amount must be a canonical integer');
  return Uint8Array.from(
    rlpList([
      rlpIntEncode(SPEND_TX_TAG),
      rlpIntEncode(TX_VERSION),
      rlpId(from),
      rlpId(to),
      rlpIntEncode(amount),
      rlpIntEncode(BigInt(tx.fee)),
      rlpIntEncode(BigInt(tx.ttl)),
      rlpIntEncode(BigInt(tx.nonce)),
      rlpItem([]), // payload stays empty: no calldata, no memo
    ]),
  );
}

/** `network_id || blake2b256(unsigned RLP)`, exactly what the ed25519 key signs. */
export function spendSighash(tx: AeternityTx): Uint8Array {
  return Uint8Array.from([...new TextEncoder().encode(NETWORK_ID), ...aeternityHash(spendRlp(tx))]);
}

export function spendUnsignedTx(tx: AeternityTx): string {
  return encodeChecked('tx', spendRlp(tx));
}

const BigBalance = z.union([
  z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  z.string().regex(/^\d{1,40}$/),
]);
const Account = z.object({
  balance: BigBalance,
  nonce: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
});
const NextNonce = z.object({
  next_nonce: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
const Status = z.object({
  network_id: z.string().max(64),
  top_block_height: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});

/** Account rows 404 before the address first receives AE; balance zero, next nonce one. */
async function accountOrGenesis(
  call: <T>(path: string, schema: z.ZodType<T>) => Promise<T>,
  address: string,
): Promise<{ balance: bigint; nextNonce: number }> {
  try {
    const account = await call(`/v3/accounts/${address}`, Account);
    const next = await call(`/v3/accounts/${address}/next-nonce`, NextNonce);
    return { balance: BigInt(account.balance), nextNonce: next.next_nonce };
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) return { balance: 0n, nextNonce: 1 };
    throw error;
  }
}

export async function prepareAeternity(
  adapter: AeternityAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: AeternityTx; simulation: Simulation }> {
  if (
    intent.chainId !== AETERNITY_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${AETERNITY_TESTNET}:native`
  )
    throw new Error('Only native AE transfers on testnet are enabled');
  if (!/^[1-9][0-9]{0,29}$/.test(intent.amount))
    throw new Error('AE amount must be a positive canonical integer');
  return adapter.withNode(intent.chainId, async (call) => {
    const status = await call('/v3/status', Status);
    const [sender, recipient] = await Promise.all([
      accountOrGenesis(call, from),
      accountOrGenesis(call, intent.to),
    ]);
    const unsigned = AeternityTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      aettos: intent.amount,
      fee: DEFAULT_FEE,
      ttl: status.top_block_height + TTL_BLOCKS,
      nonce: sender.nextNonce,
    });
    const fee = BigInt(unsigned.fee);
    let error: string | undefined;
    if (sender.balance === 0n) error = 'Sender account has no AE on testnet';
    else if (sender.balance < BigInt(intent.amount) + fee)
      error = 'Balance does not cover the transfer and fee';
    void recipient;
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee}` },
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings: [],
        ...(error ? { error } : {}),
      },
    };
  });
}

/** Approval is refused once the nonce moved on or the ttl height passed. */
export async function aeternityApprovalValid(
  adapter: AeternityAdapter,
  tx: AeternityTx,
): Promise<boolean> {
  return adapter.withNode(tx.chainId, async (call) => {
    const status = await call('/v3/status', Status);
    if (tx.ttl !== 0 && status.top_block_height >= tx.ttl) return false;
    const sender = await accountOrGenesis(call, tx.from);
    return sender.nextNonce === tx.nonce;
  });
}

const Posted = z.object({
  tx_hash: z.string().regex(/^th_[1-9A-HJ-NP-Za-km-z]{40,60}$/),
});

/**
 * Broadcast only a `tx_` string whose signed RLP is exactly this transfer:
 * [SignedTx tag, version, [one 64-byte signature], the unsigned SpendTx RLP].
 */
export async function broadcastAeternity(
  adapter: AeternityAdapter,
  tx: AeternityTx,
  signedTx: string,
): Promise<string> {
  if (tx.chainId !== AETERNITY_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const expected = spendRlp(tx);
  const signed = decodeChecked(signedTx, 'tx');
  if (!signed) throw new Error('Signed payload is not a tx_ string');
  const outer = rlpDecode(signed);
  if (
    !Array.isArray(outer) ||
    outer.length !== 4 ||
    rlpInt(outer[0]!) !== SIGNED_TX_TAG ||
    rlpInt(outer[1]!) !== TX_VERSION
  )
    throw new Error('Signed bytes are not an Aeternity SignedTx');
  const signatures = outer[2];
  if (!Array.isArray(signatures) || signatures.length !== 1)
    throw new Error('Expected one signature');
  const sig: RlpItem = signatures[0]!;
  if (!(sig instanceof Uint8Array) || sig.length !== 64)
    throw new Error('Signature must be 64 bytes');
  const inner = outer[3];
  if (!(inner instanceof Uint8Array) || bytesToHex(inner) !== bytesToHex(expected))
    throw new Error('Signed bytes are not this AE transfer');
  const hash = aeternityTxHash(signedTx);
  if (!hash) throw new Error('Could not hash the signed transaction');
  const res = await adapter
    .withNode(tx.chainId, (_call, url) => adapter.postTransaction(url, signedTx))
    .then((text) => Posted.parse(parseAeJson(text)))
    .catch(async (error: unknown) => {
      // A retry of an accepted transfer is not a failure.
      if (error instanceof HttpError && error.status === 400) {
        const status = await adapter.status(hash, tx.chainId);
        if (status.state !== 'unknown') return { tx_hash: hash };
      }
      throw error;
    });
  if (res.tx_hash !== hash) throw new Error('Node reported a different transaction hash');
  return hash;
}

/** Expiry is reported once the chain is past the ttl height and the hash is absent. */
export async function aeternityTransferStatus(
  adapter: AeternityAdapter,
  tx: AeternityTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown' || tx.ttl === 0) return status;
  const height = await adapter.withNode(
    tx.chainId,
    async (call) => (await call('/v3/status', Status)).top_block_height,
  );
  if (height <= tx.ttl) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
