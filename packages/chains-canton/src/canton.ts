/**
 * Canton Network adapter, read-only scaffold. Canton transfers are DAML
 * exercises submitted to a validator node; an external (self-custody) party
 * must first be onboarded with three signed topology transactions and every
 * transfer needs an authenticated validator, so there is no keyless public
 * write path — and the SV scan APIs currently answer 403 (RBAC) with no CORS
 * from the public internet (probed 2026-10-17; evidence in
 * `.nur/wiring/canton.md`). This adapter implements the scan read paths
 * against the official OpenAPI shapes (`/v0/dso-party-id`,
 * `/v0/state/acs/snapshot-timestamp`, `/v1/holdings/summary`,
 * `/v2/updates/hash/{hash}`) so it works the day a keyless scan answers, and
 * reports the access gap loudly until then.
 *
 * Keys are plain ed25519; a party id is `hint::fingerprint` with
 * fingerprint = `1220 || sha256(0x0000000C || public key)` hex, byte-pinned
 * against `@canton-network/wallet-sdk` (run in `.nur/canton-oracle`); the
 * Rust core (`canton.rs`) pins the same vectors.
 *
 * Wiring shim: `canton` is not yet in the `ChainFamily` enum or chain catalog
 * (the lead wires shared files from `.nur/wiring/canton.md`). Until then this
 * package carries its own `ChainInfo` (cast to the shared type) and overrides
 * `chains()`.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import {
  BaseAdapter,
  MemoryRpcPool,
  nativeHolding,
  postJsonText,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type ChainInfo,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const CANTON_MAINNET = 'canton:mainnet';
export const CANTON_TESTNET = 'canton:testnet';
/** SLIP-44 coin type (the wallet-sdk's CC_COIN_TYPE). */
export const CANTON_COIN_TYPE = 6767;
/** Canton Coin has 10 decimals; the base unit is 1e-10 CC. */
export const CANTON_DECIMALS = 10;
/** Mainnet SV scan APIs (all 403 RBAC / no CORS when probed 2026-10-17). */
export const CANTON_MAINNET_SCANS = [
  'https://scan.sv-1.global.canton.network.sync.global',
  'https://scan.sv-2.global.canton.network.digitalasset.com',
];
export const CANTON_TESTNET_SCANS = [
  'https://scan.sv-1.test.global.canton.network.sync.global',
];

const FINGERPRINT = /^1220[0-9a-f]{64}$/;
const HINT = /^[a-z0-9-]{1,64}$/;
/** DAML's public-key purpose tag hashed before the key bytes. */
const PUBLIC_KEY_PURPOSE = new Uint8Array([0, 0, 0, 0x0c]);

/** The 68-hex-char fingerprint of a 32-byte ed25519 public key. */
export function cantonFingerprint(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('Canton public key must be 32 bytes');
  const tagged = new Uint8Array(36);
  tagged.set(PUBLIC_KEY_PURPOSE, 0);
  tagged.set(publicKey, 4);
  return `1220${[...sha256(tagged)].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/** The party id `hint::fingerprint` for a hint and a 32-byte ed25519 key. */
export function cantonPartyId(hint: string, publicKey: Uint8Array): string {
  if (!HINT.test(hint)) throw new Error('hint must be 1-64 lowercase alphanumerics or dashes');
  return `${hint}::${cantonFingerprint(publicKey)}`;
}

export function isValidCantonPartyId(party: string): boolean {
  const sep = party.indexOf('::');
  if (sep <= 0 || party.indexOf('::', sep + 2) !== -1) return false;
  return HINT.test(party.slice(0, sep)) && FINGERPRINT.test(party.slice(sep + 2));
}

const PartyId = z.string().regex(/^[a-z0-9-]{1,64}::1220[0-9a-f]{64}$/);
/** The DSO's own party id carries the uppercase hint `DSO`. */
const DsoPartyId = z
  .object({ dso_party_id: z.string().regex(/^[A-Za-z0-9-]{1,64}::1220[0-9a-f]{64}$/) })
  .loose();
const SnapshotTimestamp = z.object({
  record_time: z.string().max(64),
  migration_id: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
const HoldingsSummary = z.object({
  record_time: z.string().max(64),
  migration_id: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  summaries: z
    .array(
      z.object({
        party_id: z.string().max(160),
        total_unlocked_coin: z.string().regex(/^\d{1,40}(\.\d{1,10})?$/),
        total_locked_coin: z.string().regex(/^\d{1,40}(\.\d{1,10})?$/),
        total_coin_holdings: z.string().regex(/^\d{1,40}(\.\d{1,10})?$/),
      }),
    )
    .max(256),
});
const UpdateByHash = z.object({
  update: z
    .object({
      update_id: z.string().max(160).optional(),
      record_time: z.string().max(64).optional(),
    })
    .loose()
    .optional(),
});

/**
 * Local catalog entries used until the lead wires `canton` into the shared
 * `ChainFamily` enum and catalog (see `.nur/wiring/canton.md`).
 */
export const CANTON_CHAINS: ChainInfo[] = [
  {
    chainId: CANTON_MAINNET,
    family: 'canton' as ChainInfo['family'],
    name: 'Canton Network',
    nativeAsset: { ref: `${CANTON_MAINNET}:native`, symbol: 'CC', decimals: CANTON_DECIMALS },
    testnet: false,
    explorerTxUrl: 'https://www.cantonscan.com/updates/{hash}',
    defaultRpcs: [...CANTON_MAINNET_SCANS],
    extra: { coinType: CANTON_COIN_TYPE },
    priceId: 'canton-network',
  },
  {
    chainId: CANTON_TESTNET,
    family: 'canton' as ChainInfo['family'],
    name: 'Canton Testnet',
    nativeAsset: { ref: `${CANTON_TESTNET}:native`, symbol: 'CC', decimals: CANTON_DECIMALS },
    testnet: true,
    defaultRpcs: [...CANTON_TESTNET_SCANS],
    extra: { coinType: 1 },
  },
];

export type CantonAdapterOptions = BaseAdapterOptions;

export class CantonAdapter extends BaseAdapter {
  constructor(opts: CantonAdapterOptions = {}) {
    // 'canton' enters ChainFamily with the lead's wiring; the catalog shim
    // above keeps the pool honest in the meantime.
    super('canton' as never, {
      ...opts,
      rpc: opts.rpc ?? new MemoryRpcPool(CANTON_CHAINS),
    });
  }

  override chains(): ChainInfo[] {
    const wired = super.chains();
    return wired.length > 0 ? wired : CANTON_CHAINS;
  }

  /**
   * Canton keys are plain ed25519, which the core holds; the party id's
   * fingerprint derives from the 32-byte public key. The hint is user-chosen
   * at onboarding, so derivation here returns the fingerprint form.
   */
  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    if (pub.curve !== 'ed25519')
      throw new Error(`Canton needs an ed25519 key (curve ${pub.curve})`);
    const bytes = Uint8Array.from(pub.hex.match(/../g) ?? [], (b) => parseInt(b, 16));
    return cantonFingerprint(bytes);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidCantonPartyId(addr);
  }

  /**
   * Network proof: `/v0/dso-party-id` must answer a well-formed DSO party id
   * and independent SV scans must agree on it (the cross-check in the reads
   * below is what makes that proof load-bearing).
   */
  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const res = await this.rest('/api/scan/v0/dso-party-id', DsoPartyId, [])(url);
      if (res === null) throw new Error('Endpoint does not serve the Canton scan API');
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidCantonPartyId(addr)) throw new TypeError(`invalid canton party id ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const snapshot = await this.rest(
          '/api/scan/v0/state/acs/snapshot-timestamp',
          SnapshotTimestamp,
          [],
        )(url);
        if (snapshot === null) throw new Error('snapshot-timestamp endpoint not found');
        const text = await postJsonText(
          `${url.replace(/\/$/, '')}/api/scan/v1/holdings/summary`,
          {
            migration_id: snapshot.migration_id,
            record_time: snapshot.record_time,
            record_time_match: 'at_or_before',
            owner_party_ids: [addr],
          },
          this.fetchOptions(),
        );
        const summary = HoldingsSummary.parse(JSON.parse(text));
        return summary.summaries.find((s) => s.party_id === addr)?.total_coin_holdings ?? '0';
      },
      { equal: (a, b) => a === b },
    );
    // Scan reports decimal CC strings; holdings need base units.
    const parts = value.split('.');
    const whole = parts[0] ?? '0';
    const frac = parts[1] ?? '';
    const base = (
      BigInt(whole) * 10n ** 10n +
      BigInt((frac + '0'.repeat(10)).slice(0, 10))
    ).toString();
    return [
      {
        ...nativeHolding(chain, base, provenance),
        notice:
          'Canton Coin balance from the SV scan holdings summary. The public scans answer 403 RBAC from most origins today (probed 2026-10-17); this read works wherever a keyless scan answers.',
      },
    ];
  }

  /**
   * The scan API pages the full ledger (`/v2/updates`) with no per-party
   * filter; per-party history would mean replaying the ledger. Report the
   * gap.
   */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidCantonPartyId(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'The scan API has no per-party history endpoint (the update history is global and paged), so transfer history is unavailable.',
    };
  }

  /**
   * `/v2/updates/hash/{hash}` answers the update or 404s. There is no pending
   * state visible to a scan: unconfirmed submissions never left the
   * submitting validator.
   */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-f]{1,160}$/.test(hash) && !/^[a-z0-9:-]{1,160}$/i.test(hash))
      throw new Error('Invalid Canton update id');
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const res = await this.rest(`/api/scan/v2/updates/hash/${hash}`, UpdateByHash, [404])(url);
      if (res === null || res.update === undefined) return { state: 'unknown' };
      const ms = res.update.record_time ? Date.parse(res.update.record_time) : NaN;
      return {
        state: 'confirmed',
        blockNumber: 0,
        ...(Number.isFinite(ms) ? { timestampMs: ms } : {}),
      };
    });
  }
}

export function createCantonAdapter(opts?: CantonAdapterOptions): CantonAdapter {
  return new CantonAdapter(opts);
}
