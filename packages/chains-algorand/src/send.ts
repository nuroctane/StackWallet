import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512_256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base32nopad, base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  ALGORAND_TESTNET,
  NETWORKS,
  TxId,
  AlgodAccount,
  TxParams,
  algorandAddressBytes,
  type AlgorandAdapter,
} from './algorand.js';

const TESTNET = NETWORKS[ALGORAND_TESTNET]!;
const Address = z.string().regex(/^[A-Z2-7]{58}$/);
const Round = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);

/** Mirrors `algorand::AlgorandTx` in the core; the core re-checks every field. */
export const AlgorandTx = z.strictObject({
  chainId: z.literal(ALGORAND_TESTNET),
  from: Address,
  to: Address,
  microalgos: z.string().regex(/^[1-9][0-9]{0,16}$/),
  fee: z.number().int().min(1_000).max(1_000_000),
  firstValid: Round,
  lastValid: Round,
  genesisID: z.literal(TESTNET.genesisId),
  genesisHash: z.literal(TESTNET.genesisHash),
});
export type AlgorandTx = z.infer<typeof AlgorandTx>;

export const MIN_FEE = 1_000;
export const MAX_FEE = 1_000_000;
/** The adapter bids at most 0.1 ALGO even when congestion pricing asks for more. */
const MAX_BID = 100_000;
/** Every account must hold 0.1 ALGO; a payment that creates one must carry at least this. */
export const MIN_BALANCE = 100_000n;
export const MAX_MICROALGOS = 10_000_000_000_000_000n;
/** Consensus `MaxTxnLife`. */
export const MAX_LIFETIME_ROUNDS = 1_000;
/** Approval is refused this many rounds (about a minute) before `lastValid`. */
const APPROVAL_MARGIN_ROUNDS = 20;
/** `sig` key, bin8 header, 64-byte signature and `txn` key around the transaction. */
const SIGNED_OVERHEAD = 75;
const enc = new TextEncoder();

function str(s: string): number[] {
  const b = enc.encode(s);
  return [0xa0 | b.length, ...b];
}
function bin(b: Uint8Array): number[] {
  return [0xc4, b.length, ...b];
}
function uint(v: bigint): number[] {
  if (v < 0x80n) return [Number(v)];
  if (v <= 0xffn) return [0xcc, Number(v)];
  const be = (n: number) => {
    const out: number[] = [];
    for (let i = n - 1; i >= 0; i--) out.push(Number((v >> BigInt(8 * i)) & 0xffn));
    return out;
  };
  if (v <= 0xffffn) return [0xcd, ...be(2)];
  if (v <= 0xffffffffn) return [0xce, ...be(4)];
  return [0xcf, ...be(8)];
}

/** The same canonical msgpack `pay` transaction the core encodes independently. */
export function algorandTxnMsgpack(input: AlgorandTx): Uint8Array {
  const tx = AlgorandTx.parse(input);
  const from = algorandAddressBytes(tx.from);
  const to = algorandAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid ALGO sender or recipient');
  const amount = BigInt(tx.microalgos);
  if (amount > MAX_MICROALGOS) throw new Error('Amount exceeds the ALGO supply');
  if (tx.lastValid < tx.firstValid || tx.lastValid - tx.firstValid > MAX_LIFETIME_ROUNDS)
    throw new Error('Validity window must be at most 1000 rounds');
  return Uint8Array.from([
    0x89,
    ...str('amt'),
    ...uint(amount),
    ...str('fee'),
    ...uint(BigInt(tx.fee)),
    ...str('fv'),
    ...uint(BigInt(tx.firstValid)),
    ...str('gen'),
    ...str(tx.genesisID),
    ...str('gh'),
    ...bin(base64.decode(tx.genesisHash)),
    ...str('lv'),
    ...uint(BigInt(tx.lastValid)),
    ...str('rcv'),
    ...bin(to),
    ...str('snd'),
    ...bin(from),
    ...str('type'),
    ...str('pay'),
  ]);
}

/** `"TX" || msgpack(txn)`: the Ed25519 message. */
export function algorandSigningMessage(tx: AlgorandTx): Uint8Array {
  return Uint8Array.from([0x54, 0x58, ...algorandTxnMsgpack(tx)]);
}

export function algorandTxId(tx: AlgorandTx): string {
  return base32nopad.encode(sha512_256(algorandSigningMessage(tx)));
}

/** Bytes of the signed transaction that precede the signature. */
const SIG_PREFIX = Uint8Array.from([0x82, ...str('sig'), 0xc4, 0x40]);
const TXN_KEY = Uint8Array.from(str('txn'));

/** The flat fee: the per-byte congestion fee times the signed size, never below the minimum. */
export function feeBid(params: { fee: number; 'min-fee': number }, txnBytes: number): number {
  const fee = Math.max(MIN_FEE, params['min-fee'], params.fee * (txnBytes + SIGNED_OVERHEAD));
  if (fee > MAX_BID) throw new Error('Algorand fees are above 0.1 ALGO; try again later');
  return fee;
}

function spendable(account: AlgodAccount): bigint {
  return BigInt(account.amount) - BigInt(account['min-balance']);
}

export async function prepareAlgorand(
  adapter: AlgorandAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: AlgorandTx; simulation: Simulation }> {
  if (
    intent.chainId !== ALGORAND_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${ALGORAND_TESTNET}:native`
  )
    throw new Error('Only native ALGO transfers on testnet are enabled');
  const amount = BigInt(intent.amount);
  if (!algorandAddressBytes(from) || !algorandAddressBytes(intent.to))
    throw new Error('Invalid ALGO sender or recipient');
  const { unsigned, sender, recipient } = await adapter.withAlgod(intent.chainId, async (get) => {
    const [params, sender, recipient] = await Promise.all([
      get('/v2/transactions/params', TxParams),
      get(`/v2/accounts/${from}?exclude=all`, AlgodAccount),
      get(`/v2/accounts/${intent.to}?exclude=all`, AlgodAccount),
    ]);
    if (
      !params ||
      !sender ||
      !recipient ||
      sender.address !== from ||
      recipient.address !== intent.to
    )
      throw new Error('algod did not report the parameters or accounts');
    // A rekeyed account is controlled by another key; this key's signature would be refused.
    if (sender['auth-addr']) throw new Error('The sender account is rekeyed to another key');
    if (recipient.amount === 0 && amount < MIN_BALANCE)
      throw new Error(
        'The recipient account is empty; send at least 0.1 ALGO to meet its minimum balance',
      );
    const draft = {
      chainId: ALGORAND_TESTNET,
      from,
      to: intent.to,
      microalgos: intent.amount,
      fee: MIN_FEE,
      firstValid: params['last-round'],
      lastValid: params['last-round'] + MAX_LIFETIME_ROUNDS,
      genesisID: TESTNET.genesisId,
      genesisHash: TESTNET.genesisHash,
    } as const;
    const size = algorandTxnMsgpack(draft).length;
    const unsigned = AlgorandTx.parse({ ...draft, fee: feeBid(params, size) });
    return { unsigned, sender, recipient };
  });
  const fee = BigInt(unsigned.fee);
  let error: string | undefined;
  if (spendable(sender) < amount + fee)
    error = 'Balance above the 0.1 ALGO minimum does not cover the transfer and fee';
  const warnings: Simulation['warnings'] = [];
  try {
    const failure = await adapter.simulateTxn(unsigned.chainId, algorandTxnMsgpack(unsigned));
    if (failure && !error) error = `Simulation failed: ${failure.slice(0, 300)}`;
  } catch {
    warnings.push({
      kind: 'other',
      message: 'Network simulation was unavailable; balance checks were done locally.',
    });
  }
  if (recipient.amount === 0)
    warnings.push({
      kind: 'other',
      message: 'The recipient account is empty; this payment funds its 0.1 ALGO minimum balance.',
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
}

/**
 * Approval is refused once the validity window is nearly over, or if the
 * sender was rekeyed or the recipient's minimum-balance rule no longer holds.
 */
export async function algorandApprovalValid(
  adapter: AlgorandAdapter,
  tx: AlgorandTx,
): Promise<boolean> {
  algorandTxnMsgpack(tx);
  const [params, sender, recipient] = await adapter.withAlgod(tx.chainId, (get) =>
    Promise.all([
      get('/v2/transactions/params', TxParams),
      get(`/v2/accounts/${tx.from}?exclude=all`, AlgodAccount),
      get(`/v2/accounts/${tx.to}?exclude=all`, AlgodAccount),
    ]),
  );
  if (!params || !sender || !recipient) return false;
  return (
    sender.address === tx.from &&
    recipient.address === tx.to &&
    params['genesis-hash'] === tx.genesisHash &&
    params['last-round'] + APPROVAL_MARGIN_ROUNDS < tx.lastValid &&
    !sender['auth-addr'] &&
    (recipient.amount > 0 || BigInt(tx.microalgos) >= MIN_BALANCE)
  );
}

const SubmitOk = z.object({ txId: TxId });
const SubmitError = z.object({ message: z.string().max(65536) });

/**
 * Broadcast only bytes that are exactly the core's signed transaction: this
 * `pay` transaction plus one Ed25519 signature that verifies against the sender.
 */
export async function broadcastAlgorand(
  adapter: AlgorandAdapter,
  tx: AlgorandTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== ALGORAND_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const txn = algorandTxnMsgpack(tx);
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  const expectedLength = (SIG_PREFIX.length + 64 + TXN_KEY.length + txn.length) * 2;
  if (
    !/^[0-9a-f]+$/.test(hex) ||
    hex.length !== expectedLength ||
    !hex.startsWith(bytesToHex(SIG_PREFIX)) ||
    !hex.endsWith(bytesToHex(TXN_KEY) + bytesToHex(txn))
  )
    throw new Error('Signed bytes are not this ALGO transfer');
  const bytes = hexToBytes(hex);
  const signature = bytes.subarray(SIG_PREFIX.length, SIG_PREFIX.length + 64);
  const key = algorandAddressBytes(tx.from)!;
  if (!ed25519.verify(signature, algorandSigningMessage(tx), key, { zip215: false }))
    throw new Error('Signature does not verify against the sender');
  const id = algorandTxId(tx);
  const res = await adapter.submit(tx.chainId, bytes);
  if (res.status === 200) {
    if (SubmitOk.parse(res.body).txId !== id)
      throw new Error('algod reported a different transaction id');
    return id;
  }
  const err = SubmitError.safeParse(res.body);
  const message = err.success ? err.data.message : '';
  if (/already in (ledger|pool)/i.test(message)) {
    // A retry of a transaction that was already accepted.
    const status = await adapter.status(id, tx.chainId);
    if (status.state === 'confirmed' || status.state === 'pending') return id;
  }
  throw new Error(`Broadcast rejected: ${message || `HTTP ${res.status}`}`.slice(0, 512));
}

/** Expiry is reported once the chain is past `lastValid` and the id is still unknown. */
export async function algorandTransferStatus(
  adapter: AlgorandAdapter,
  tx: AlgorandTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const params = await adapter.params(tx.chainId);
  if (params['last-round'] <= tx.lastValid) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
