import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  ClearinghouseState,
  HYPERLIQUID_TESTNET,
  Ledger,
  UserDetails,
  UserRole,
  cleanMessage,
  decimalToUnits,
  explorerStatus,
  hyperliquidAddressFromPublicKey,
  isValidHyperliquidAddress,
  type ExplorerTx,
  type HyperliquidAdapter,
} from './hyperliquid.js';

/** EIP-712 domain chain id the SDKs sign `usdSend` under; any value works, the core pins this one. */
export const SIGNATURE_CHAIN_ID = 0x66eee;
export const MAX_USD_MICRO = 1_000_000_000_000_000n;
/** Charged by the protocol when the destination has no HyperCore account yet (observed on testnet). */
export const NEW_ACCOUNT_FEE_MICRO = 1_000_000n;
const DAY_MS = 24 * 60 * 60 * 1000;
/** Nonces are accepted while within (T - 2 days, T + 1 day) of the block time T. */
const NONCE_PAST_MS = 2 * DAY_MS;
/** Approval closes a day before the nonce leaves the window, leaving time to broadcast. */
const APPROVAL_MS = DAY_MS;
const MIN_TIME_MS = 1_672_531_200_000;

const Address = z.string().regex(/^0x[0-9a-f]{40}$/);
export const HyperliquidTx = z.strictObject({
  chainId: z.literal(HYPERLIQUID_TESTNET),
  from: Address,
  to: Address,
  hlUsdMicro: z.string().regex(/^[1-9][0-9]{0,15}$/),
  time: z.number().int().min(MIN_TIME_MS).max(Number.MAX_SAFE_INTEGER),
  builtAtMs: z.number().int().min(MIN_TIME_MS).max(Number.MAX_SAFE_INTEGER),
});
export type HyperliquidTx = z.infer<typeof HyperliquidTx>;

const enc = new TextEncoder();
const k = (data: string | Uint8Array) =>
  keccak_256(typeof data === 'string' ? enc.encode(data) : data);
const word = (n: bigint) => hexToBytes(n.toString(16).padStart(64, '0'));
const DOMAIN = k(
  concatBytes(
    k('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
    k('HyperliquidSignTransaction'),
    k('1'),
    word(BigInt(SIGNATURE_CHAIN_ID)),
    word(0n),
  ),
);
const USD_SEND_TYPE = k(
  'HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)',
);

/** Micro-USDC as the shortest decimal string, as the core renders it: 1500000 is "1.5". */
export function amountString(micro: bigint): string {
  const whole = micro / 1_000_000n;
  const frac = micro % 1_000_000n;
  if (frac === 0n) return whole.toString();
  return `${whole}.${frac.toString().padStart(6, '0').replace(/0+$/, '')}`;
}

function checked(input: HyperliquidTx): { tx: HyperliquidTx; amount: string } {
  const tx = HyperliquidTx.parse(input);
  const micro = BigInt(tx.hlUsdMicro);
  if (micro > MAX_USD_MICRO) throw new Error('USDC amount exceeds the transfer bound');
  if (tx.from === tx.to || /^0x0{40}$/.test(tx.from) || /^0x0{40}$/.test(tx.to))
    throw new Error('Invalid Hyperliquid sender or recipient');
  if (Math.abs(tx.time - tx.builtAtMs) > DAY_MS)
    throw new Error('Transfer time must fall within a day of the build time');
  return { tx, amount: amountString(micro) };
}

/** The EIP-712 digest the core signs, computed independently from the same fields. */
export function usdSendDigest(input: HyperliquidTx): Uint8Array {
  const { tx, amount } = checked(input);
  const struct = k(
    concatBytes(USD_SEND_TYPE, k('Testnet'), k(tx.to), k(amount), word(BigInt(tx.time))),
  );
  return k(concatBytes(Uint8Array.of(0x19, 0x01), DOMAIN, struct));
}

/** The id the core reports for a transfer: keccak256 of the digest. */
export function usdSendLocalId(tx: HyperliquidTx): string {
  return `0x${bytesToHex(keccak_256(usdSendDigest(tx)))}`;
}

export function usdSendAction(input: HyperliquidTx): string {
  const { tx, amount } = checked(input);
  return `{"type":"usdSend","signatureChainId":"0x${SIGNATURE_CHAIN_ID.toString(16)}","hyperliquidChain":"Testnet","destination":"${tx.to}","amount":"${amount}","time":${tx.time}}`;
}

/** The `/exchange` body prefix the core emits before the signature object. */
function wirePrefix(tx: HyperliquidTx): string {
  return `{"action":${usdSendAction(tx)},"nonce":${tx.time},"signature":`;
}

export function usdSendWire(tx: HyperliquidTx, sig: { r: string; s: string; v: number }): string {
  return `${wirePrefix(tx)}{"r":"${sig.r}","s":"${sig.s}","v":${sig.v}}}`;
}

/** Recovers the signer of a wire body, refusing anything but this exact transfer. */
export function wireSigner(tx: HyperliquidTx, wire: string): string {
  const prefix = wirePrefix(tx);
  if (!wire.startsWith(prefix)) throw new Error('Signed body is not this USDC transfer');
  const m = /^\{"r":"0x([0-9a-f]{64})","s":"0x([0-9a-f]{64})","v":(27|28)\}\}$/.exec(
    wire.slice(prefix.length),
  );
  if (!m) throw new Error('Signed body carries a malformed signature');
  const sig = Uint8Array.from([Number(m[3]) - 27, ...hexToBytes(m[1]!), ...hexToBytes(m[2]!)]);
  const pub = secp256k1.recoverPublicKey(sig, usdSendDigest(tx), { prehash: false });
  return hyperliquidAddressFromPublicKey(pub);
}

export async function prepareHyperliquid(
  adapter: HyperliquidAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
): Promise<{ unsigned: HyperliquidTx; simulation: Simulation }> {
  if (
    intent.chainId !== HYPERLIQUID_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${HYPERLIQUID_TESTNET}:native`
  )
    throw new Error('Only perp USDC transfers on Hyperliquid testnet are enabled');
  if (!isValidHyperliquidAddress(intent.to) || !isValidHyperliquidAddress(from))
    throw new Error('Invalid Hyperliquid address');
  const unsigned = HyperliquidTx.parse({
    chainId: intent.chainId,
    from: from.toLowerCase(),
    to: intent.to.toLowerCase(),
    hlUsdMicro: intent.amount,
    time: now,
    builtAtMs: now,
  });
  usdSendDigest(unsigned);
  return adapter.withApi(intent.chainId, async (call) => {
    const [perp, sender, recipient] = await Promise.all([
      call({ type: 'clearinghouseState', user: unsigned.from }, ClearinghouseState),
      call({ type: 'userRole', user: unsigned.from }, UserRole),
      call({ type: 'userRole', user: unsigned.to }, UserRole),
    ]);
    const amount = BigInt(unsigned.hlUsdMicro);
    const activates = recipient.role === 'missing';
    const fee = activates ? NEW_ACCOUNT_FEE_MICRO : 0n;
    const balance = decimalToUnits(perp.withdrawable, 6, true);
    let error: string | undefined;
    if (sender.role === 'missing')
      error = 'The sender has no HyperCore account; it must deposit before it can send';
    else if (sender.role !== 'user')
      error = `A ${cleanMessage(sender.role).slice(0, 32)} account cannot sign a USDC send`;
    else if (balance < amount + fee)
      error = 'Withdrawable perp USDC does not cover the transfer and fee';
    const warnings: Simulation['warnings'] = [];
    if (activates)
      warnings.push({
        kind: 'other',
        message:
          'The recipient has no HyperCore account yet; the protocol charges 1 USDC to create it.',
      });
    else if (recipient.role !== 'user')
      warnings.push({
        kind: 'other',
        message: `The recipient is a HyperCore ${cleanMessage(recipient.role).slice(0, 32)} address, not a regular user account.`,
      });
    return {
      unsigned,
      simulation: {
        ok: error === undefined,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${amount}` },
          ...(fee > 0n ? [{ assetRef: intent.asset, amount: `-${fee}` }] : []),
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings,
        ...(error ? { error } : {}),
      },
    };
  });
}

/** The nonce is the build time, so the transfer stays acceptable only for a bounded window. */
export async function hyperliquidApprovalValid(
  _adapter: HyperliquidAdapter,
  tx: HyperliquidTx,
  now = Date.now(),
): Promise<boolean> {
  try {
    usdSendDigest(tx);
  } catch {
    return false;
  }
  return now >= tx.time - DAY_MS && now < tx.time + APPROVAL_MS;
}

const ExchangeReply = z.object({
  status: z.enum(['ok', 'err']),
  response: z.unknown(),
});

/** Broadcast only the exact body the core builds, signed by `from`; returns the local id. */
export async function broadcastHyperliquid(
  adapter: HyperliquidAdapter,
  tx: HyperliquidTx,
  wire: string,
): Promise<string> {
  if (tx.chainId !== HYPERLIQUID_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  if (wireSigner(tx, wire) !== tx.from) throw new Error('Signature does not recover to the sender');
  const body = JSON.parse(wire) as unknown;
  if (JSON.stringify(body) !== wire) throw new Error('Signed body does not round-trip');
  const id = usdSendLocalId(tx);
  const reply = await adapter.withApi(tx.chainId, (_call, url) =>
    adapter.postTo(`${url.replace(/\/$/, '')}/exchange`, body, ExchangeReply),
  );
  if (reply.status === 'ok') return id;
  const message = cleanMessage(typeof reply.response === 'string' ? reply.response : 'error');
  // A retry of an accepted transfer is refused for its spent nonce, not a failure.
  if (/nonce/i.test(message) && (await findTransfer(adapter, tx)) !== undefined) return id;
  throw new Error(`Broadcast rejected: ${message}`);
}

function matches(tx: HyperliquidTx, e: ExplorerTx): boolean {
  const a = e.action as Record<string, unknown>;
  return (
    e.user === tx.from &&
    a['type'] === 'usdSend' &&
    a['hyperliquidChain'] === 'Testnet' &&
    a['time'] === tx.time &&
    typeof a['destination'] === 'string' &&
    a['destination'].toLowerCase() === tx.to &&
    a['amount'] === amountString(BigInt(tx.hlUsdMicro))
  );
}

/**
 * The L1 transaction carrying this transfer, from the explorer RPC's recent
 * transactions of the sender. Undefined while it is not (yet) on chain.
 */
export async function findTransfer(
  adapter: HyperliquidAdapter,
  tx: HyperliquidTx,
): Promise<ExplorerTx | undefined> {
  const recent = await adapter.withKind(tx.chainId, 'explorer', (call) =>
    call({ type: 'userDetails', user: tx.from }, UserDetails),
  );
  return recent?.txs.find((e) => matches(tx, e));
}

/** The hash the Hyperliquid explorer shows, once the transfer is on chain. */
export async function hyperliquidExplorerHash(
  adapter: HyperliquidAdapter,
  tx: HyperliquidTx,
): Promise<string | undefined> {
  return (await findTransfer(adapter, tx))?.hash;
}

/**
 * Expiry is reported only once the nonce is past the acceptance window and
 * neither the explorer nor the sender's ledger shows the transfer.
 */
export async function hyperliquidTransferStatus(
  adapter: HyperliquidAdapter,
  tx: HyperliquidTx,
  hash: string,
  now = Date.now(),
): Promise<TxStatus | { state: 'expired' }> {
  if (hash.toLowerCase() !== usdSendLocalId(tx)) {
    // An explorer hash recorded after the fact is looked up directly.
    const direct = await adapter.status(hash, tx.chainId);
    if (direct.state !== 'unknown') return direct;
  }
  const found = await findTransfer(adapter, tx);
  if (found) return explorerStatus(found);
  // The explorer lists only recent transactions; the ledger keeps every successful send.
  const micro = BigInt(tx.hlUsdMicro);
  const ledger = await adapter.withApi(tx.chainId, (call) =>
    call(
      {
        type: 'userNonFundingLedgerUpdates',
        user: tx.from,
        startTime: tx.time - DAY_MS,
        endTime: tx.time + NONCE_PAST_MS + 60 * 60 * 1000,
      },
      Ledger,
    ),
  );
  const candidates = ledger.filter((e) => {
    const d = e.delta as Record<string, unknown>;
    return (
      d.type === 'internalTransfer' &&
      d['user'] === tx.from &&
      typeof d['destination'] === 'string' &&
      d['destination'].toLowerCase() === tx.to &&
      typeof d['usdc'] === 'string' &&
      decimalToUnits(d['usdc'], 6, true) === micro
    );
  });
  // Same amount to the same address can repeat; only the signed nonce identifies this one.
  for (const entry of candidates.slice(0, 20)) {
    const details = await adapter.txDetails(entry.hash, tx.chainId);
    if (details && matches(tx, details)) return explorerStatus(details);
  }
  if (candidates.length > 0) return { state: 'unknown' };
  if (now > tx.time + NONCE_PAST_MS + 10 * 60 * 1000) return { state: 'expired' };
  return { state: 'unknown' };
}
