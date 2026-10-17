/**
 * Prepare / approve / broadcast for the Bitcoin-fork family. `BtcForkTx`
 * mirrors the Rust `btcfork::BtcForkTx` struct field for field; the core
 * re-plans and re-checks everything before signing. Only the five testnets
 * are signable; today just Dash testnet has a working public UTXO indexer,
 * so preparation on the other networks fails with an explicit reason.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  DASH_TESTNET,
  SIGNING_CHAINS,
  ZcashChainInfo,
  decodeForkAddress,
  forkParams,
  isRpcDriver,
  type BtcForkAdapter,
  type ForkClient,
  type ForkDriver,
  type SigningChainId,
} from './btcfork.js';

const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const SafeUint = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const Sats = z.string().regex(/^\d{1,20}$/);
const FundingHex = z
  .string()
  .regex(/^(?:[0-9a-f]{2})+$/)
  .max(400_000);

/** Mirrors the Rust `BtcForkInput` struct field for field. */
export const BtcForkInput = z.strictObject({
  txid: Hash,
  vout: z.number().int().nonnegative().max(0xffffffff),
  previousTxHex: FundingHex,
});
/** Mirrors the Rust `BtcForkTx` struct field for field. */
export const BtcForkTx = z.strictObject({
  chainId: z.enum(SIGNING_CHAINS),
  from: z.string().min(25).max(100),
  to: z.string().min(25).max(100),
  satoshis: Sats,
  fee: Sats,
  inputs: z.array(BtcForkInput).min(1).max(8),
  expiryHeight: z.number().int().min(1).max(500_000_000).optional(),
  /**
   * Zcash only: the ZIP-143 consensus branch id the node reports for the next
   * block, so a network upgrade needs no wallet release. The core falls back
   * to its last known id when absent and refuses other forks' ids.
   */
  consensusBranchId: z
    .string()
    .regex(/^[0-9a-f]{8}$/)
    .optional(),
});
export type BtcForkTx = z.infer<typeof BtcForkTx>;

const InsightUtxos = z
  .array(
    z.looseObject({
      txid: Hash,
      vout: z.number().int().nonnegative().max(0xffffffff),
      satoshis: SafeUint,
      confirmations: z.number().int().nonnegative(),
    }),
  )
  .max(10_000);
const InsightRawTx = z.object({ rawtx: FundingHex });
const InsightBroadcast = z.object({ txid: Hash });
const InsightTip = z.object({ info: z.looseObject({ blocks: SafeUint }) });
const VerusUtxos = z
  .array(
    z.looseObject({
      txid: Hash,
      outputIndex: z.number().int().nonnegative().max(0xffffffff),
      satoshis: SafeUint,
      height: SafeUint,
    }),
  )
  .max(10_000);
const VerusHeight = z.object({ blocks: SafeUint });
const BlockchairBroadcast = z.object({ data: z.object({ transaction_hash: Hash }) });

const DUST = 546n;
const MAX_FEE = 100_000n;
/** Signed wire from the core is `0x` hex; anything else is refused before broadcast. */
const SIGNED_WIRE = /^0x(?:[0-9a-f]{2})+$/;
const MAX_WIRE_CHARS = 20_000;

function sha256d(bytes: Uint8Array): Uint8Array {
  return sha256(sha256(bytes));
}

export function fundingTxid(raw: Uint8Array): string {
  return bytesToHex(Uint8Array.from(sha256d(raw)).reverse());
}

export function p2pkhScript(hash: Uint8Array): Uint8Array {
  return Uint8Array.from([0x76, 0xa9, 0x14, ...hash, 0x88, 0xac]);
}

class Cursor {
  private pos = 0;
  constructor(private readonly bytes: Uint8Array) {}
  take(n: number): Uint8Array {
    const end = this.pos + n;
    if (end > this.bytes.length) throw new Error('funding transaction truncated');
    const out = this.bytes.subarray(this.pos, end);
    this.pos = end;
    return out;
  }
  u32(): number {
    const b = this.take(4);
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;
  }
  u64(): bigint {
    const b = this.take(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
    return v;
  }
  varint(): bigint {
    const n = this.take(1)[0]!;
    if (n === 0xff) return this.u64();
    if (n === 0xfe) return BigInt(this.u32());
    if (n === 0xfd) {
      const b = this.take(2);
      return BigInt(b[0]! | (b[1]! << 8));
    }
    return BigInt(n);
  }
  get remaining(): number {
    return this.bytes.length - this.pos;
  }
}

/**
 * Local mirror of the Rust funding parser: returns the value and script of
 * output `vout`, refusing coinbase, DIP2 special and truncated transactions.
 */
export function parseFunding(raw: Uint8Array, vout: number): { value: bigint; script: Uint8Array } {
  const c = new Cursor(raw);
  const version = c.u32();
  const zcashV4 = version === 0x80000004;
  if ((version & 0x80000000) !== 0 && !zcashV4)
    throw new Error('unsupported funding transaction version');
  if (!zcashV4 && version >>> 16 !== 0)
    throw new Error('DIP2 special funding transactions are unsupported');
  if (zcashV4 && c.u32() !== 0x892f2085) throw new Error('unsupported funding version group');
  const inputs = c.varint();
  if (inputs === 0n || inputs > 65_535n)
    throw new Error('funding transaction has no usable inputs');
  for (let i = 0n; i < inputs; i++) {
    const prev = c.take(36);
    if (
      i === 0n &&
      prev.subarray(0, 32).every((b) => b === 0) &&
      prev.subarray(32).every((b) => b === 0xff)
    )
      throw new Error('coinbase funding is unsupported');
    const scriptLen = c.varint();
    if (scriptLen > 10_000n) throw new Error('funding input script too large');
    c.take(Number(scriptLen));
    c.take(4);
  }
  const outputs = c.varint();
  if (outputs === 0n || outputs > 65_535n || BigInt(vout) >= outputs)
    throw new Error('funding output missing');
  let found: { value: bigint; script: Uint8Array } | undefined;
  for (let i = 0n; i < outputs; i++) {
    const value = c.u64();
    const scriptLen = c.varint();
    if (scriptLen > 10_000n) throw new Error('funding output script too large');
    const script = c.take(Number(scriptLen));
    if (i === BigInt(vout)) found = { value, script };
  }
  if (!found) throw new Error('funding output missing');
  if (zcashV4) {
    if (c.remaining < 19) throw new Error('funding transaction truncated');
  } else if (c.remaining !== 4) {
    throw new Error('funding transaction has trailing data');
  }
  return found;
}

/** Validates a funding hex against the sender and the claimed value. */
function checkFunding(
  input: { txid: string; vout: number; previousTxHex: string },
  fromScript: Uint8Array,
  expectedValue: bigint,
): void {
  const raw = hexToBytes(input.previousTxHex);
  if (fundingTxid(raw) !== input.txid) throw new Error('Invalid funding transaction');
  const out = parseFunding(raw, input.vout);
  if (out.value !== expectedValue || bytesToHex(out.script) !== bytesToHex(fromScript))
    throw new Error('Funding output differs from the indexer claim');
}

interface Coin {
  txid: string;
  vout: number;
  satoshis: bigint;
  confirmed: boolean;
}

async function readCoins(client: ForkClient, driver: string, from: string): Promise<Coin[]> {
  if (driver === 'insight') {
    const utxos = await client.get(`/addr/${from}/utxo`, InsightUtxos);
    if (!utxos) throw new Error('UTXO endpoint unavailable');
    const seen = new Set<string>();
    return utxos.map((u) => {
      const key = `${u.txid}:${u.vout}`;
      if (seen.has(key)) throw new Error('Duplicate UTXO response');
      seen.add(key);
      return {
        txid: u.txid,
        vout: u.vout,
        satoshis: BigInt(u.satoshis),
        confirmed: u.confirmations >= 1,
      };
    });
  }
  if (isRpcDriver(driver as ForkDriver)) {
    const utxos = await client.rpc('getaddressutxos', [{ addresses: [from] }], VerusUtxos);
    const seen = new Set<string>();
    return utxos.map((u) => {
      const key = `${u.txid}:${u.outputIndex}`;
      if (seen.has(key)) throw new Error('Duplicate UTXO response');
      seen.add(key);
      return {
        txid: u.txid,
        vout: u.outputIndex,
        satoshis: BigInt(u.satoshis),
        confirmed: u.height >= 1,
      };
    });
  }
  throw new Error(`No UTXO indexer driver for ${driver}`);
}

async function fundingHex(client: ForkClient, driver: string, txid: string): Promise<string> {
  if (driver === 'insight') {
    const res = await client.get(`/rawtx/${txid}`, InsightRawTx);
    if (!res) throw new Error('Cannot fetch the funding transaction');
    return res.rawtx;
  }
  if (isRpcDriver(driver as ForkDriver)) {
    return FundingHex.parse(await client.rpc('getrawtransaction', [txid, 0], FundingHex));
  }
  throw new Error(`No funding fetch driver for ${driver}`);
}

async function tipHeight(client: ForkClient, driver: string): Promise<number | null> {
  if (driver === 'insight') {
    const res = await client.get('/status?q=getInfo', InsightTip);
    return res?.info.blocks ?? null;
  }
  if (driver === 'verus-rpc') {
    return (await client.rpc('getinfo', [], VerusHeight)).blocks;
  }
  if (driver === 'zcash-rpc') {
    return (await client.rpc('getblockchaininfo', [], ZcashChainInfo)).blocks;
  }
  return null;
}

/**
 * The ZIP-143 branch id for a transaction mined after the current tip. Only
 * a Zcash node knows it; the other v4 fork (Verus) pins its id in the core.
 */
async function consensusBranchId(client: ForkClient, driver: string): Promise<string | undefined> {
  if (driver !== 'zcash-rpc') return undefined;
  return (await client.rpc('getblockchaininfo', [], ZcashChainInfo)).consensus.nextblock;
}

/** Whether a driver can select inputs and watch them (prepare, approval, expiry). */
function canSelectInputs(driver: ForkDriver): driver is 'insight' | 'verus-rpc' | 'zcash-rpc' {
  return driver === 'insight' || isRpcDriver(driver);
}

/** vbytes of a P2PKH spend; v4 forks carry a small fixed framing overhead. */
function estimatedBytes(inputs: number, outputs: number, v4: boolean): number {
  return 10 + 148 * inputs + 34 * outputs + (v4 ? 27 : 0);
}

export async function prepareBtcFork(
  adapter: BtcForkAdapter,
  intent: TxIntent,
  from: string,
): Promise<{ unsigned: BtcForkTx; simulation: Simulation }> {
  if (intent.kind !== 'transfer' || intent.asset !== `${intent.chainId}:native`)
    throw new Error('Only native transfers are enabled');
  if (!(SIGNING_CHAINS as readonly string[]).includes(intent.chainId))
    throw new Error('Only Bitcoin-fork testnet sends are enabled');
  const f = forkParams(intent.chainId);
  const fromScript = decodeForkAddress(intent.chainId, from);
  const toScript = decodeForkAddress(intent.chainId, intent.to);
  if (!fromScript || fromScript.kind !== 'p2pkh') throw new Error('Sender must be P2PKH');
  if (!toScript || intent.to === from) throw new Error('Invalid recipient address');
  if (!/^[1-9][0-9]*$/.test(intent.amount) || BigInt(intent.amount) < DUST)
    throw new Error('Invalid or dust satoshi amount');
  if (f.driver === null)
    throw new Error(
      `No public ${f.name} endpoint is reachable, so inputs cannot be selected; preparation is unavailable`,
    );
  if (!canSelectInputs(f.driver))
    throw new Error(`The ${f.driver} driver cannot list UTXOs; preparation is unavailable`);
  const driver = f.driver;
  const amount = BigInt(intent.amount);
  return adapter.withNode(intent.chainId, async (client) => {
    const coins = (await readCoins(client, driver, from))
      .filter((c) => c.confirmed)
      .sort((a, b) => (b.satoshis > a.satoshis ? 1 : b.satoshis < a.satoshis ? -1 : 0));
    const height = f.v4 ? await tipHeight(client, driver) : null;
    if (f.v4 && (height === null || height < 1))
      throw new Error('Cannot determine the chain height for the expiry height');
    const branch = f.v4 ? await consensusBranchId(client, driver) : undefined;
    const selected: Coin[] = [];
    let total = 0n;
    let fee = 0n;
    for (const coin of coins) {
      if (selected.length >= 8) break;
      selected.push(coin);
      total += coin.satoshis;
      fee = (BigInt(estimatedBytes(selected.length, 2, f.v4)) * BigInt(f.feePerKb) + 999n) / 1000n;
      const change = total - amount - fee;
      if (change === 0n || change >= DUST) break;
    }
    const change = total - amount - fee;
    if (!selected.length || change < 0n || (change > 0n && change < DUST) || fee > MAX_FEE)
      throw new Error(
        'Confirmed inputs cannot cover amount, fee and non-dust change within limits',
      );
    const senderScript = p2pkhScript(fromScript.hash);
    const inputs = [];
    for (const coin of selected) {
      const previousTxHex = await fundingHex(client, driver, coin.txid);
      const input = { txid: coin.txid, vout: coin.vout, previousTxHex };
      checkFunding(input, senderScript, coin.satoshis);
      inputs.push(input);
    }
    const unsigned = BtcForkTx.parse({
      chainId: intent.chainId,
      from,
      to: intent.to,
      satoshis: intent.amount,
      fee: fee.toString(),
      inputs,
      ...(f.v4 ? { expiryHeight: height! + 100 } : {}),
      ...(branch ? { consensusBranchId: branch } : {}),
    });
    return {
      unsigned,
      simulation: {
        ok: false,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee}` },
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings: [
          {
            kind: 'other',
            message: `Local funding validation only; no network simulation. ${selected.length} input(s), flat ${f.feePerKb} sats/kB fee estimate, ${change} sats change to the sender.${f.v4 ? ` Expires at height ${unsigned.expiryHeight}.` : ''}${branch ? ` Signs under consensus branch ${branch} as the node reports it.` : ''}`,
          },
        ],
        error: 'Network simulation is unavailable',
      },
    };
  });
}

/** Approval stands while every input stays unspent and the expiry is not near. */
export async function btcForkApprovalValid(
  adapter: BtcForkAdapter,
  tx: BtcForkTx,
): Promise<boolean> {
  const f = forkParams(tx.chainId);
  if (!canSelectInputs(f.driver)) return false;
  return adapter.withNode(tx.chainId, async (client) => {
    const coins = await readCoins(client, f.driver!, tx.from);
    const unspent = new Set(coins.map((c) => `${c.txid}:${c.vout}`));
    if (!tx.inputs.every((i) => unspent.has(`${i.txid}:${i.vout}`))) return false;
    if (tx.expiryHeight !== undefined) {
      const height = await tipHeight(client, f.driver!);
      if (height === null || height + 5 >= tx.expiryHeight) return false;
    }
    return true;
  });
}

/** Broadcast only bytes shaped like a core-produced wire transaction. */
export async function broadcastBtcFork(
  adapter: BtcForkAdapter,
  tx: BtcForkTx,
  signedHex: string,
): Promise<string> {
  if (!SIGNED_WIRE.test(signedHex) || signedHex.length > MAX_WIRE_CHARS)
    throw new Error('Invalid core transaction bytes');
  const f = forkParams(tx.chainId);
  if (f.driver === null) throw new Error(`No public ${f.name} endpoint is known`);
  const raw = signedHex.slice(2);
  return adapter.withNode(tx.chainId, async (client) => {
    switch (f.driver) {
      case 'insight': {
        const res = await client.post(
          '/tx/send',
          `rawtx=${raw}`,
          'application/x-www-form-urlencoded',
          InsightBroadcast,
        );
        return res.txid;
      }
      case 'verus-rpc':
      case 'zcash-rpc': {
        return client.rpc('sendrawtransaction', [raw], Hash);
      }
      case 'blockchair': {
        const res = await client.post(
          '/push/transaction',
          JSON.stringify({ data: raw }),
          'application/json',
          BlockchairBroadcast,
        );
        return res.data.transaction_hash;
      }
      case 'ocean':
        throw new Error('The DefiChain ocean API cannot broadcast raw transactions here');
      case null:
        throw new Error('unreachable');
    }
  });
}

/** Expiry is reported once the tip is past the expiry height and the tx is absent. */
export async function btcForkTransferStatus(
  adapter: BtcForkAdapter,
  tx: BtcForkTx,
  hash: string,
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown' || tx.expiryHeight === undefined) return status;
  const f = forkParams(tx.chainId);
  if (!canSelectInputs(f.driver)) return status;
  const expired = await adapter.withNode(tx.chainId, async (client) => {
    const height = await tipHeight(client, f.driver!);
    return height !== null && height >= tx.expiryHeight!;
  });
  if (!expired) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
