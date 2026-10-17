import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  FetchBalancesResult,
  GALA_TESTNET,
  decimalToGunits,
  galaAddressBytes,
  gunitsToDecimal,
  isValidGalaAddress,
  type GalaAdapter,
} from './gala.js';

const EthRef = z.string().regex(/^eth\|[0-9a-fA-F]{40}$/);
/** Mirrors the Rust `GalaTx` struct field for field. */
export const GalaTx = z.strictObject({
  chainId: z.literal(GALA_TESTNET),
  from: EthRef,
  to: EthRef,
  gunits: z.string().regex(/^\d{1,20}$/),
  uniqueKey: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  dtoExpiresAt: z.number().int().min(1_577_836_800_000).max(4_102_444_800_000),
});
export type GalaTx = z.infer<typeof GalaTx>;

/** Long enough to review and approve; the chaincode refuses the DTO afterwards. */
const LIFETIME_MS = 30 * 60_000;
/** Verified live on both gateways: one GALA is burned per TransferToken call. */
export const GALA_FEE_GUNITS = 100_000_000n;

/**
 * The exact string the chaincode hashes and the core signs: sorted JSON of
 * the DTO minus `signature`. Rebuilt here so a tampered core reply can be
 * detected before broadcast.
 */
export function galaPayload(input: GalaTx): string {
  const tx = GalaTx.parse(input);
  const from = galaAddressBytes(tx.from);
  const to = galaAddressBytes(tx.to);
  if (!from || !to || tx.from === tx.to) throw new Error('Invalid GALA sender or recipient');
  const quantity = gunitsToDecimal(tx.gunits);
  return (
    `{"dtoExpiresAt":${tx.dtoExpiresAt},"from":"${tx.from}","quantity":"${quantity}",` +
    `"to":"${tx.to}","tokenInstance":{"additionalKey":"none","category":"Unit",` +
    `"collection":"GALA","instance":"0","type":"none"},"uniqueKey":"${tx.uniqueKey}"}`
  );
}

/** keccak256 of the payload: the local pre-broadcast id, 0x-prefixed. */
export function galaLocalId(tx: GalaTx): string {
  return `0x${bytesToHex(keccak_256(new TextEncoder().encode(galaPayload(tx))))}`;
}

/** The exact POST body for TransferToken: DTO plus the recovered signature. */
export function galaWireBody(tx: GalaTx, signature: string): string {
  const payload = galaPayload(tx);
  if (!/^[0-9a-f]{130}$/.test(signature))
    throw new Error('Signature is not 65 lowercase hex bytes');
  return payload.replace(/}$/, `,"signature":"${signature}"}`);
}

export async function prepareGala(
  adapter: GalaAdapter,
  intent: TxIntent,
  from: string,
  now = Date.now(),
  randomSuffix = Math.random().toString(36).slice(2, 10),
): Promise<{ unsigned: GalaTx; simulation: Simulation }> {
  if (
    intent.chainId !== GALA_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${GALA_TESTNET}:native`
  )
    throw new Error('Only native GALA transfers on the GalaChain testnet are enabled');
  if (!isValidGalaAddress(from)) throw new Error('Invalid sender address');
  if (!isValidGalaAddress(intent.to)) throw new Error('Invalid recipient address');
  const amount = BigInt(intent.amount);
  if (amount <= 0n || amount.toString() !== intent.amount)
    throw new Error('GALA amount must be a positive canonical integer of gunits');
  const unsigned = GalaTx.parse({
    chainId: intent.chainId,
    from,
    to: intent.to,
    gunits: intent.amount,
    uniqueKey: `stackwallet-${now}-${randomSuffix}`,
    dtoExpiresAt: now + LIFETIME_MS,
  });
  const fee = GALA_FEE_GUNITS;
  let error: string | undefined;
  // Network-proven balance read; a gateway failure refuses preparation.
  const balance = await adapter.withGateway(intent.chainId, async (url) => {
    const { data } = await adapter.gateway(
      url,
      'FetchBalances',
      { owner: from },
      FetchBalancesResult,
    );
    const gala = data?.find(
      (b) =>
        b.collection === 'GALA' &&
        b.category === 'Unit' &&
        b.type === 'none' &&
        b.additionalKey === 'none',
    );
    return gala ? BigInt(decimalToGunits(gala.quantity)) : 0n;
  });
  if (balance < amount + fee) error = 'Balance does not cover the transfer and the 1 GALA fee';
  return {
    unsigned,
    simulation: {
      ok: error === undefined,
      assetDeltas: [
        { assetRef: intent.asset, amount: `-${intent.amount}` },
        { assetRef: intent.asset, amount: `-${fee.toString()}` },
      ],
      fee: { assetRef: intent.asset, amount: fee.toString() },
      warnings: [
        {
          kind: 'other',
          message: 'Every TransferToken burns 1 GALA as the network fee.',
        },
      ],
      ...(error ? { error } : {}),
    },
  };
}

/** Approval is refused once the DTO expiry is near (60s clock-skew buffer). */
export function galaApprovalValid(tx: GalaTx, now = Date.now()): boolean {
  return now < tx.dtoExpiresAt - 60_000;
}

/**
 * Broadcasts exactly the checked DTO plus the signature from the core's
 * signed payload. The gateway executes TransferToken synchronously; a 2xx
 * with a `Data` payload is acceptance, anything else is a rejection whose
 * message is surfaced. Returns the gateway-assigned transaction id when the
 * response carries one, else the local keccak id.
 */
export async function broadcastGala(
  adapter: GalaAdapter,
  tx: GalaTx,
  signedPayload: string,
): Promise<string> {
  if (tx.chainId !== GALA_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  // The core returns the DTO JSON it signed; only the signature field is
  // taken from it, everything else is rebuilt from the checked tx.
  const signed = z
    .object({ signature: z.string().regex(/^[0-9a-f]{130}$/) })
    .loose()
    .parse(JSON.parse(signedPayload));
  const body = galaWireBody(tx, signed.signature);
  const result = await adapter.withGateway(tx.chainId, (url) =>
    adapter.gateway(url, 'TransferToken', JSON.parse(body), z.unknown()),
  );
  if (result.data === undefined)
    throw new Error(`TransferToken rejected: ${result.message ?? 'gateway returned no data'}`);
  const data = result.data as Record<string, unknown>;
  for (const key of ['transactionId', 'txId', 'id']) {
    const value = data[key];
    if (typeof value === 'string' && /^(0x)?[0-9a-fA-F]{1,128}$/.test(value)) return value;
  }
  return galaLocalId(tx);
}

/** Expiry is reported once wall-clock time is past dtoExpiresAt and the hash is absent. */
export async function galaTransferStatus(
  adapter: GalaAdapter,
  tx: GalaTx,
  hash: string,
  now = Date.now(),
): Promise<TxStatus | { state: 'expired' }> {
  const status = await adapter.status(hash, tx.chainId);
  if (status.state !== 'unknown') return status;
  if (now <= tx.dtoExpiresAt) return status;
  const again = await adapter.status(hash, tx.chainId);
  return again.state === 'unknown' ? { state: 'expired' } : again;
}
