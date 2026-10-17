import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { ChainId, TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  CHIA_TESTNET,
  chiaAddressBytes,
  chiaNetworkPrefix,
  coinName,
  parseSexp,
  sexpTreeHash,
  CoinRecord,
  type ChiaAdapter,
} from './chia.js';

/** Decimal mojos as canonical text; 1 XCH = 10^12 mojos, so balances fit u64. */
const Mojos = z.string().regex(/^(0|[1-9]\d{0,18})$/);
const Hex32NoPrefix = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * The unsigned transfer the Rust core signs. Field-for-field the core's
 * `ChiaTx` (camelCase); the hand-off notes tell the integrator to mirror this
 * schema into `core-client` as `ChiaTx` when the core feature lands.
 */
export const ChiaUnsignedTx = z.strictObject({
  chainId: z.literal(CHIA_TESTNET),
  /** Sender bech32m address (puzzle hash of its standard puzzle). */
  from: z.string(),
  to: z.string(),
  /** Decimal mojos to move; never a floating-point number. */
  mojos: Mojos,
  /** Decimal mojos reserved as the network fee; "0" is allowed on testnet. */
  fee: Mojos,
  /** The spent coin's parent coin id, 64 lowercase hex. */
  parentCoinId: Hex32NoPrefix,
  /** The spent coin's total value in decimal mojos; change returns to the sender. */
  coinMojos: Mojos,
});
export type ChiaUnsignedTx = z.infer<typeof ChiaUnsignedTx>;

const MAX_MOJOS = (1n << 63n) - 1n;

type SExpT = Uint8Array | [SExpT, SExpT];

function listItems(sexp: SExpT): SExpT[] {
  const out: SExpT[] = [];
  let cur: SExpT = sexp;
  while (Array.isArray(cur)) {
    out.push(cur[0]);
    cur = cur[1];
  }
  if (cur.length !== 0) throw new Error('improper list');
  return out;
}

/** CLVM integer atoms are minimal big-endian two's complement. */
function atomInt(atom: Uint8Array): bigint {
  if (atom.length === 0) return 0n;
  let v = 0n;
  for (const b of atom) v = (v << 8n) | BigInt(b);
  if ((atom[0]! & 0x80) !== 0) v -= 1n << BigInt(atom.length * 8);
  return v;
}

function parseMojos(value: string, what: string, allowZero: boolean): bigint {
  const parsed = Mojos.safeParse(value);
  if (!parsed.success) throw new Error(`${what} must be canonical decimal mojos`);
  const amount = BigInt(value);
  if (amount > MAX_MOJOS) throw new Error(`${what} exceeds the mojo cap`);
  if (amount === 0n && !allowZero) throw new Error(`${what} must be positive`);
  return amount;
}

/** Checks the exact rules the Rust core re-checks before signing. */
export function validateChiaTx(tx: ChiaUnsignedTx): {
  coinId: string;
  fromPuzzleHash: Uint8Array;
  toPuzzleHash: Uint8Array;
} {
  const parsed = ChiaUnsignedTx.parse(tx);
  const prefix = chiaNetworkPrefix(parsed.chainId as ChainId);
  const fromPuzzleHash = chiaAddressBytes(parsed.from, prefix);
  const toPuzzleHash = chiaAddressBytes(parsed.to, prefix);
  if (!fromPuzzleHash || !toPuzzleHash) throw new Error('Invalid sender or recipient address');
  if (bytesToHex(fromPuzzleHash) === bytesToHex(toPuzzleHash))
    throw new Error('sender and recipient must differ');
  const amount = parseMojos(parsed.mojos, 'amount', false);
  const fee = parseMojos(parsed.fee, 'fee', true);
  const coinValue = parseMojos(parsed.coinMojos, 'coin value', false);
  if (amount + fee > coinValue) throw new Error("amount plus fee exceeds the coin's value");
  const coinId = coinName({
    parent_coin_info: `0x${parsed.parentCoinId}`,
    puzzle_hash: `0x${bytesToHex(fromPuzzleHash)}`,
    amount: parsed.coinMojos,
  });
  return { coinId, fromPuzzleHash, toPuzzleHash };
}

const RecordsByPuzzleHash = z.object({
  success: z.literal(true),
  coin_records: z.array(CoinRecord).max(100_000),
});

export interface PrepareChiaOptions {
  /** Explicit fee in decimal mojos; default 0 (testnet11 mempool is empty). */
  fee?: string;
}

export async function prepareChia(
  adapter: ChiaAdapter,
  intent: TxIntent,
  from: string,
  opts: PrepareChiaOptions = {},
): Promise<{ unsigned: ChiaUnsignedTx; simulation: Simulation }> {
  if (intent.chainId !== CHIA_TESTNET || intent.kind !== 'transfer')
    throw new Error('Only native XCH transfers on testnet11 are enabled');
  const assetRef = `${CHIA_TESTNET}:native`;
  if (intent.asset !== assetRef) throw new Error('Only the native asset can move');
  const prefix = chiaNetworkPrefix(intent.chainId);
  const fromPh = chiaAddressBytes(from, prefix);
  const toPh = chiaAddressBytes(intent.to, prefix);
  if (!fromPh || !toPh) throw new Error('Invalid sender or recipient address');
  const amount = parseMojos(intent.amount, 'amount', false);
  const fee = parseMojos(opts.fee ?? '0', 'fee', true);
  return adapter.withNode(intent.chainId, async (call) => {
    const records: z.infer<typeof RecordsByPuzzleHash> = await call(
      '/get_coin_records_by_puzzle_hash',
      { puzzle_hash: `0x${bytesToHex(fromPh)}`, include_spent_coins: false },
      RecordsByPuzzleHash,
    );
    const spendable = records.coin_records.filter((r) => !r.spent);
    // Smallest single coin that covers the spend; change returns to the sender.
    const coin = spendable
      .map((r) => ({ r, value: BigInt(r.coin.amount) }))
      .filter((c) => c.value >= amount + fee)
      .sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0))[0];
    const total = spendable.reduce((s, r) => s + BigInt(r.coin.amount), 0n);
    const unsigned = coin
      ? ChiaUnsignedTx.parse({
          chainId: intent.chainId,
          from,
          to: intent.to,
          mojos: intent.amount,
          fee: fee.toString(),
          parentCoinId: coin.r.coin.parent_coin_info.slice(2),
          coinMojos: coin.value.toString(),
        })
      : undefined;
    const error =
      spendable.length === 0
        ? 'No spendable coins for this address'
        : coin === undefined
          ? `No single coin covers ${amount + fee} mojos (balance ${total}); coin joins are not enabled`
          : undefined;
    return {
      unsigned: unsigned ?? {
        chainId: CHIA_TESTNET,
        from,
        to: intent.to,
        mojos: intent.amount,
        fee: fee.toString(),
        parentCoinId: '00'.repeat(32),
        coinMojos: '0',
      },
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef, amount: `-${intent.amount}` },
          { assetRef, amount: `-${fee}` },
        ],
        fee: { assetRef, amount: fee.toString() },
        warnings: [],
        ...(error ? { error } : {}),
      },
    };
  });
}

/**
 * Approval is refused once the selected coin is no longer unspent. The lookup
 * goes by the sender's puzzle hash because coinset's name-indexed endpoints
 * do not serve stock `get_coin_record_by_name` lookups.
 */
export async function chiaApprovalValid(adapter: ChiaAdapter, tx: ChiaUnsignedTx): Promise<boolean> {
  const { coinId, fromPuzzleHash } = validateChiaTx(tx);
  return adapter.withNode(tx.chainId, async (call) => {
    const res = await call(
      '/get_coin_records_by_puzzle_hash',
      { puzzle_hash: `0x${bytesToHex(fromPuzzleHash)}`, include_spent_coins: false },
      RecordsByPuzzleHash,
    );
    return res.coin_records.some((r) => !r.spent && coinName(r.coin) === coinId);
  });
}

const WireBundle = z.object({
  coin_spends: z
    .array(
      z.object({
        coin: z.object({
          parent_coin_info: z.string().regex(/^0x[0-9a-f]{64}$/),
          puzzle_hash: z.string().regex(/^0x[0-9a-f]{64}$/),
          amount: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
        }),
        puzzle_reveal: z.string().regex(/^0x[0-9a-f]+$/),
        solution: z.string().regex(/^0x[0-9a-f]+$/),
      }),
    )
    .length(1),
  aggregated_signature: z.string().regex(/^0x[0-9a-f]{192}$/),
});

/**
 * The bundle's consensus name: sha256 of its streamable encoding. Programs
 * stream raw (self-delimiting, no length prefix). Matches the name a live
 * testnet11 full node computed for the pinned example bundle.
 */
export function bundleName(wire: z.infer<typeof WireBundle>): string {
  const parts: Uint8Array[] = [Uint8Array.of(0, 0, 0, 1)];
  for (const spend of wire.coin_spends) {
    const amount = new Uint8Array(8);
    new DataView(amount.buffer).setBigUint64(0, BigInt(spend.coin.amount));
    parts.push(
      hexToBytes(spend.coin.parent_coin_info.slice(2)),
      hexToBytes(spend.coin.puzzle_hash.slice(2)),
      amount,
      hexToBytes(spend.puzzle_reveal.slice(2)),
      hexToBytes(spend.solution.slice(2)),
    );
  }
  parts.push(hexToBytes(wire.aggregated_signature.slice(2)));
  return bytesToHex(sha256(concatBytes(...parts)));
}

const PushTxResult = z.object({
  success: z.boolean(),
  status: z.string().max(64).optional(),
  error: z.string().max(4096).nullable().optional(),
});

/**
 * Broadcast only a bundle that is exactly this transfer: one spend of the
 * checked coin, whose reveal really hashes to the sender's puzzle hash.
 */
export async function broadcastChia(
  adapter: ChiaAdapter,
  tx: ChiaUnsignedTx,
  wireJson: string,
): Promise<string> {
  if (tx.chainId !== CHIA_TESTNET) throw new Error('Only testnet11 broadcasts are enabled');
  const { coinId, fromPuzzleHash, toPuzzleHash } = validateChiaTx(tx);
  const wire = WireBundle.parse(JSON.parse(wireJson));
  const spend = wire.coin_spends[0]!;
  const expectedParent = `0x${tx.parentCoinId}`;
  const expectedPh = `0x${bytesToHex(fromPuzzleHash)}`;
  if (spend.coin.parent_coin_info !== expectedParent || spend.coin.puzzle_hash !== expectedPh)
    throw new Error('Wire bundle spends a different coin');
  if (String(tx.coinMojos) !== String(spend.coin.amount))
    throw new Error('Wire bundle coin value differs');
  if (coinName(spend.coin) !== coinId) throw new Error('Wire bundle coin id differs');
  // The reveal must be the standard puzzle curried with *some* key whose
  // curried tree hash is the sender's puzzle hash.
  const reveal = hexToBytes(spend.puzzle_reveal.slice(2));
  const [parsed, end] = parseSexp(reveal);
  if (end !== reveal.length || bytesToHex(sexpTreeHash(parsed)) !== bytesToHex(fromPuzzleHash))
    throw new Error("Wire bundle reveal does not match the sender's puzzle hash");
  // The solution must create exactly the intent's output plus sender change
  // and the declared fee — nothing else may leave the coin.
  const [solution] = parseSexp(hexToBytes(spend.solution.slice(2)));
  const items = listItems(solution);
  if (items.length !== 3) throw new Error('Wire bundle solution is not a standard spend');
  const delegated = items[1]!;
  if (delegated instanceof Uint8Array) throw new Error('Wire bundle delegated puzzle is an atom');
  {
    if (!(delegated[0] instanceof Uint8Array) || bytesToHex(delegated[0]) !== '01')
      throw new Error('Wire bundle delegated puzzle is not a quoted condition list');
    const conditions = listItems(delegated[1]);
    let toAmount = 0n;
    let changeAmount = 0n;
    let feeAmount = 0n;
    for (const cond of conditions) {
      const c = listItems(cond);
      const opAtom = c[0];
      if (c.length === 0 || !(opAtom instanceof Uint8Array)) throw new Error('Malformed condition');
      const op = atomInt(opAtom);
      if (op === 51n) {
        const ph = c[1];
        const amt = c[2];
        if (!(ph instanceof Uint8Array) || !(amt instanceof Uint8Array))
          throw new Error('Malformed CREATE_COIN');
        if (bytesToHex(ph) === bytesToHex(toPuzzleHash)) toAmount += atomInt(amt);
        else if (bytesToHex(ph) === bytesToHex(fromPuzzleHash)) changeAmount += atomInt(amt);
        else throw new Error('Wire bundle pays an unexpected puzzle hash');
      } else if (op === 52n) {
        const amt = c[1];
        if (!(amt instanceof Uint8Array)) throw new Error('Malformed RESERVE_FEE');
        feeAmount += atomInt(amt);
      } else throw new Error(`Wire bundle carries unexpected condition ${op}`);
    }
    if (toAmount !== BigInt(tx.mojos)) throw new Error('Wire bundle amount differs');
    if (feeAmount !== BigInt(tx.fee)) throw new Error('Wire bundle fee differs');
    if (toAmount + changeAmount + feeAmount !== BigInt(tx.coinMojos))
      throw new Error('Wire bundle does not conserve the coin value');
  }
  const name = bundleName(wire);
  const res = await adapter.withNode(tx.chainId, (call) =>
    call('/push_tx', { spend_bundle: wire }, PushTxResult),
  );
  if (!res.success) {
    // A retry of an already-mempooled transfer is not a failure.
    if (res.error?.includes('ALREADY_INCLUDING_TRANSACTION')) return name;
    throw new Error(`Broadcast rejected: ${res.status ?? 'error'} ${res.error ?? ''}`.trim());
  }
  return name;
}

/**
 * Confirmation follows the spent coin's record, found via the sender's puzzle
 * hash (name-indexed lookups are not served by coinset). Chia transfers do
 * not expire; an unspent coin either keeps its mempool seat or never left.
 */
export async function chiaTransferStatus(
  adapter: ChiaAdapter,
  tx: ChiaUnsignedTx,
  _hash: string,
): Promise<TxStatus> {
  const { coinId, fromPuzzleHash } = validateChiaTx(tx);
  return adapter.withNode(tx.chainId, async (call) => {
    const res = await call(
      '/get_coin_records_by_puzzle_hash',
      { puzzle_hash: `0x${bytesToHex(fromPuzzleHash)}`, include_spent_coins: true },
      RecordsByPuzzleHash,
    );
    const record = res.coin_records.find((r) => coinName(r.coin) === coinId);
    if (!record) return { state: 'unknown' };
    if (record.spent && record.spent_block_index > 0)
      return {
        state: 'confirmed',
        blockNumber: record.spent_block_index,
        timestampMs: record.timestamp * 1000,
      };
    if (record.spent) return { state: 'pending' };
    return { state: 'unknown' };
  });
}
