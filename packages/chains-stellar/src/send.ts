import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import { StellarTx, type TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  HorizonAccount,
  LatestLedger,
  NETWORK_PASSPHRASES,
  STELLAR_TESTNET,
  stellarAddressBytes,
  type StellarAdapter,
} from './stellar.js';

export { StellarTx };

const INT64_MAX = 0x7fffffffffffffffn;
export const MIN_FEE = 100;
export const MAX_FEE = 10_000_000;
/** The adapter bids at most 0.2 XLM even when surge pricing asks for more. */
const MAX_BID = 2_000_000;
/** Two base reserves: the minimum balance of a new account. */
export const MIN_STARTING_BALANCE = 10_000_000n;
const MAX_LIFETIME_S = 24 * 60 * 60;
/** Long enough to review and approve. */
const LIFETIME_S = 30 * 60;
const ENVELOPE_TYPE_TX = 2;

class Xdr {
  private readonly bytes: number[] = [];
  u32(v: number): this {
    this.bytes.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
    return this;
  }
  u64(v: bigint): this {
    return this.u32(Number(v >> 32n)).u32(Number(v & 0xffffffffn));
  }
  raw(b: Uint8Array): this {
    this.bytes.push(...b);
    return this;
  }
  done(): Uint8Array {
    return Uint8Array.from(this.bytes);
  }
}

function positiveInt64(value: string, what: string): bigint {
  const n = BigInt(value);
  if (n <= 0n || n > INT64_MAX || n.toString() !== value)
    throw new Error(`${what} must be a positive canonical int64`);
  return n;
}

/** The same `Transaction` XDR the core encodes independently from checked fields. */
export function stellarTxXdr(input: StellarTx): Uint8Array {
  const tx = StellarTx.parse(input);
  const from = stellarAddressBytes(tx.from);
  const to = stellarAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid XLM sender or recipient');
  const amount = positiveInt64(tx.stroops, 'XLM amount');
  if (tx.createAccount && amount < MIN_STARTING_BALANCE)
    throw new Error('A new Stellar account must start with at least 1 XLM');
  const seq = positiveInt64(tx.seqNum, 'Sequence number');
  if (tx.maxTime <= tx.builtAt || tx.maxTime - tx.builtAt > MAX_LIFETIME_S)
    throw new Error('maxTime must fall within a day of the build time');
  const w = new Xdr().u32(0).raw(from).u32(tx.fee).u64(seq);
  w.u32(1).u64(0n).u64(BigInt(tx.maxTime)); // PRECOND_TIME
  w.u32(0); // MEMO_NONE
  w.u32(1).u32(0); // one operation without its own source account
  if (tx.createAccount) w.u32(0).u32(0).raw(to).u64(amount);
  else w.u32(1).u32(0).raw(to).u32(0).u64(amount);
  return w.u32(0).done();
}

/** sha256(networkId || ENVELOPE_TYPE_TX || tx): the signed message and the explorer hash. */
export function stellarTxHashBytes(tx: StellarTx): Uint8Array {
  const passphrase = NETWORK_PASSPHRASES[tx.chainId];
  if (!passphrase) throw new Error('Unknown Stellar network');
  const networkId = sha256(new TextEncoder().encode(passphrase));
  return sha256(new Xdr().raw(networkId).u32(ENVELOPE_TYPE_TX).raw(stellarTxXdr(tx)).done());
}

export function stellarTxHash(tx: StellarTx): string {
  return bytesToHex(stellarTxHashBytes(tx));
}

const FeeStats = z.object({
  last_ledger_base_fee: z.string().regex(/^\d{1,10}$/),
  fee_charged: z.object({ p90: z.string().regex(/^\d{1,10}$/) }).loose(),
});

/** The fee bid: the 90th percentile of recently charged fees, within the accepted range. */
export function feeBid(stats: z.infer<typeof FeeStats>): number {
  const base = Number(stats.last_ledger_base_fee);
  const p90 = Number(stats.fee_charged.p90);
  return Math.min(MAX_BID, Math.max(MIN_FEE, base, p90));
}

function spendable(account: HorizonAccount, baseReserve: bigint): bigint {
  const native = account.balances.find((b) => b.asset_type === 'native');
  if (!native) return 0n;
  const entries =
    2n +
    BigInt(account.subentry_count) +
    BigInt(account.num_sponsoring ?? 0) -
    BigInt(account.num_sponsored ?? 0);
  const selling = native.selling_liabilities
    ? BigInt(native.selling_liabilities.replace('.', ''))
    : 0n;
  return BigInt(native.balance.replace('.', '')) - entries * baseReserve - selling;
}

export async function prepareStellar(
  adapter: StellarAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: StellarTx; simulation: Simulation }> {
  if (
    intent.chainId !== STELLAR_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${STELLAR_TESTNET}:native`
  )
    throw new Error('Only native XLM transfers on testnet are enabled');
  return adapter.withHorizon(intent.chainId, async (get) => {
    const [sender, recipient, stats, ledgers] = await Promise.all([
      get(`/accounts/${from}`, HorizonAccount),
      get(`/accounts/${intent.to}`, HorizonAccount),
      get('/fee_stats', FeeStats),
      get('/ledgers?order=desc&limit=1', LatestLedger),
    ]);
    if (!sender) throw new Error('Sender account is not funded on Stellar testnet');
    if (!stats || !ledgers) throw new Error('Horizon did not report fees or the latest ledger');
    const ledger = ledgers._embedded.records[0]!;
    const builtAt = Math.floor(now / 1000);
    const createAccount = recipient === null;
    if (createAccount && BigInt(intent.amount) < MIN_STARTING_BALANCE)
      throw new Error('The recipient has no Stellar account yet; send at least 1 XLM to create it');
    const unsigned = StellarTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      stroops: intent.amount,
      fee: feeBid(stats),
      seqNum: (BigInt(sender.sequence) + 1n).toString(),
      maxTime: builtAt + LIFETIME_S,
      builtAt,
      createAccount,
    });
    stellarTxXdr(unsigned);
    const fee = BigInt(unsigned.fee);
    let error: string | undefined;
    if (spendable(sender, BigInt(ledger.base_reserve_in_stroops)) < BigInt(intent.amount) + fee)
      error = 'Balance above the minimum reserve does not cover the transfer and fee';
    const warnings: Simulation['warnings'] = [];
    if (createAccount)
      warnings.push({
        kind: 'other',
        message:
          'The recipient has no Stellar account yet; this transfer creates it with the amount as its starting balance.',
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

const closedAtSeconds = (ledgers: z.infer<typeof LatestLedger>): number =>
  Math.floor(Date.parse(ledgers._embedded.records[0]!.closed_at) / 1000);

/**
 * Approval is refused once the network could drop the transaction before it
 * lands, or once the sequence number or the recipient's existence changed.
 */
export async function stellarApprovalValid(
  adapter: StellarAdapter,
  tx: StellarTx,
  now = Date.now(),
): Promise<boolean> {
  if (now / 1000 > tx.maxTime - 60) return false;
  return adapter.withHorizon(tx.chainId, async (get) => {
    const [sender, recipient, ledgers] = await Promise.all([
      get(`/accounts/${tx.from}`, HorizonAccount),
      get(`/accounts/${tx.to}`, HorizonAccount),
      get('/ledgers?order=desc&limit=1', LatestLedger),
    ]);
    if (!sender || !ledgers) return false;
    const closed = closedAtSeconds(ledgers);
    return (
      Number.isFinite(closed) &&
      closed < tx.maxTime - 60 &&
      (BigInt(sender.sequence) + 1n).toString() === tx.seqNum &&
      (recipient === null) === tx.createAccount
    );
  });
}

const SubmitOk = z.object({
  hash: z.string().regex(/^[0-9a-f]{64}$/),
  successful: z.boolean().optional(),
});
const SubmitError = z.object({
  status: z.number().int().optional(),
  title: z.string().max(256).optional(),
  extras: z
    .object({
      result_codes: z
        .object({
          transaction: z.string().max(64).optional(),
          operations: z.array(z.string().max(64)).max(100).optional(),
        })
        .optional(),
    })
    .loose()
    .optional(),
});

/**
 * Broadcast only bytes that are exactly the ledger's envelope: this
 * transaction plus one decorated signature that verifies against the sender.
 */
export async function broadcastStellar(
  adapter: StellarAdapter,
  tx: StellarTx,
  rawHex: string,
): Promise<string> {
  if (tx.chainId !== STELLAR_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  const body = stellarTxXdr(tx);
  const key = stellarAddressBytes(tx.from)!;
  const prefix = new Xdr()
    .u32(ENVELOPE_TYPE_TX)
    .raw(body)
    .u32(1)
    .raw(key.subarray(28))
    .u32(64)
    .done();
  const hex = rawHex.replace(/^0x/, '').toLowerCase();
  const expected = bytesToHex(prefix);
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== expected.length + 128 || !hex.startsWith(expected))
    throw new Error('Signed bytes are not this XLM transfer');
  const bytes = hexToBytes(hex);
  const hashBytes = stellarTxHashBytes(tx);
  if (!ed25519.verify(bytes.subarray(prefix.length), hashBytes, key))
    throw new Error('Signature does not verify against the sender');
  const hash = bytesToHex(hashBytes);
  const res = await adapter.submit(tx.chainId, base64.encode(bytes));
  if (res.status === 200) {
    const ok = SubmitOk.parse(res.body);
    if (ok.hash !== hash) throw new Error('Horizon reported a different transaction hash');
    return hash;
  }
  // Horizon gave up waiting for a ledger; the transaction may still land before maxTime.
  if (res.status === 504) return hash;
  const err = SubmitError.safeParse(res.body);
  const codes = err.success ? err.data.extras?.result_codes : undefined;
  if (codes?.transaction === 'tx_bad_seq') {
    // A retry of an accepted transfer consumed its own sequence number.
    const status = await adapter.status(hash, tx.chainId);
    if (status.state === 'confirmed') return hash;
  }
  const detail = [codes?.transaction, ...(codes?.operations ?? [])].filter(Boolean).join(' ');
  throw new Error(
    `Broadcast rejected: ${detail || (err.success ? (err.data.title ?? '') : '') || `HTTP ${res.status}`}`.slice(
      0,
      512,
    ),
  );
}

/**
 * Expiry is reported once a closed ledger is past `maxTime`, or the sender's
 * sequence moved past `seqNum`, and the hash is still absent.
 */
export async function stellarTransferStatus(
  adapter: StellarAdapter,
  tx: StellarTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  const dead = await adapter.withHorizon(tx.chainId, async (get) => {
    const [sender, ledgers] = await Promise.all([
      get(`/accounts/${tx.from}`, HorizonAccount),
      get('/ledgers?order=desc&limit=1', LatestLedger),
    ]);
    const closed = ledgers ? closedAtSeconds(ledgers) : NaN;
    const pastTime = Number.isFinite(closed) && closed > tx.maxTime;
    const seqUsed = sender !== null && BigInt(sender.sequence) >= BigInt(tx.seqNum);
    return pastTime || seqUsed;
  });
  if (!dead) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
