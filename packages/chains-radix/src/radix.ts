/**
 * Radix adapter. Account addresses are bech32m of a 30-byte node id
 * (`entity byte || blake2b-256(public key)[3..]` for virtual accounts); reads
 * go over the Gateway API, whose `gateway-status` reports the network name in
 * every response, so every endpoint proves which network it serves.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { bech32m } from '@scure/base';
import {
  BaseAdapter,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type Holding,
  type HistoryOptions,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const RADIX_MAINNET = 'radix:mainnet';
/** Stokenet, the permanent Radix application testnet. */
export const RADIX_STOKENET = 'radix:stokenet';

export interface RadixNetwork {
  /** Gateway API base urls, in priority order. */
  gateways: string[];
  /** The `network` string `gateway-status` must report. */
  networkName: string;
  /** Address and transaction-id bech32m HRPs. */
  accountHrp: string;
  txidHrp: string;
  /** The XRD resource address of this network. */
  xrdResource: string;
}

export const NETWORKS: Record<string, RadixNetwork> = {
  [RADIX_MAINNET]: {
    gateways: ['https://mainnet.radixdlt.com'],
    networkName: 'mainnet',
    accountHrp: 'account_rdx',
    txidHrp: 'txid_rdx',
    xrdResource: 'resource_rdx1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxradxrd',
  },
  [RADIX_STOKENET]: {
    gateways: ['https://stokenet.radixdlt.com'],
    networkName: 'stokenet',
    accountHrp: 'account_tdx_2_',
    txidHrp: 'txid_tdx_2_',
    xrdResource: 'resource_tdx_2_1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxtfd2jc',
  },
};

/** Entity type bytes an `account_…` address may carry (REP-60). */
export const ENTITY = {
  virtualEd25519Account: 0x51,
  virtualSecp256k1Account: 0xd1,
  accountComponent: 0xc1,
} as const;

/** The 30-byte node id of an `account_…` address, or undefined when invalid. */
export function radixAddressBytes(addr: string, hrp: string): Uint8Array | undefined {
  if (addr.length > 90 || !addr.startsWith(`${hrp}1`)) return undefined;
  try {
    const { prefix, words } = bech32m.decode(addr as `${string}1${string}`, 90);
    if (prefix !== hrp) return undefined;
    const bytes = Uint8Array.from(bech32m.fromWords(words));
    if (bytes.length !== 30) return undefined;
    if (
      bytes[0] !== ENTITY.virtualEd25519Account &&
      bytes[0] !== ENTITY.virtualSecp256k1Account &&
      bytes[0] !== ENTITY.accountComponent
    )
      return undefined;
    if (bech32m.encode(hrp, bech32m.toWords(bytes), 90) !== addr) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

export function isValidRadixAddress(addr: string, chainId: ChainId): boolean {
  const network = NETWORKS[chainId];
  return network !== undefined && radixAddressBytes(addr, network.accountHrp) !== undefined;
}

/** The virtual account address of a 32-byte Ed25519 public key. */
export function radixAddressFromPublicKey(ed25519: Uint8Array, chainId: ChainId): string {
  const network = NETWORKS[chainId];
  if (!network) throw new Error(`Unknown Radix network ${chainId}`);
  if (ed25519.length !== 32) throw new TypeError('Ed25519 public key must be 32 bytes');
  const hash = blake2b(ed25519, { dkLen: 32 });
  const node = new Uint8Array(30);
  node[0] = ENTITY.virtualEd25519Account;
  node.set(hash.subarray(3), 1);
  return bech32m.encode(network.accountHrp, bech32m.toWords(node), 90);
}

/** A bech32m `txid_…` / `signedintent_…` style hash string, 32-byte payload. */
export function radixHashString(hrp: string, hash: Uint8Array): string {
  if (hash.length !== 32) throw new TypeError('Radix hash must be 32 bytes');
  return bech32m.encode(hrp, bech32m.toWords(hash), 90);
}

const Bech32mId = z.string().regex(/^[a-z0-9_]+1[02-9ac-hj-np-z]{38,60}$/);
/** Gateway decimals are XRD strings with up to 18 decimal places. */
const Xrd = z.string().regex(/^-?\d{1,10}(\.\d{1,18})?$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

export const GatewayStatus = z.object({
  ledger_state: z.object({
    network: z.string().max(64),
    epoch: SafeInt.min(1),
    proposer_round_timestamp: z.string().max(64),
  }),
});
export type GatewayStatus = z.infer<typeof GatewayStatus>;

const EntityDetails = z.object({
  items: z.array(
    z.object({
      address: Bech32mId,
      fungible_resources: z
        .object({
          items: z.array(
            z.object({
              resource_address: Bech32mId,
              vaults: z.object({ items: z.array(z.object({ amount: Xrd }).loose()).max(64) }),
            }),
          ),
        })
        .optional(),
    }),
  ),
});

const TransactionStatus = z.object({
  ledger_state: z.object({ epoch: SafeInt, proposer_round_timestamp: z.string().max(64) }),
  status: z.string().max(64),
  known_payloads: z.array(z.object({ payload_status: z.string().max(64).optional() })).max(8),
  receipt: z
    .object({
      status: z.string().max(64).optional(),
      error_message: z.string().max(4096).optional(),
      fee_summary: z.object({ xrd_total_fee: Xrd.optional() }).optional(),
    })
    .optional(),
});

const StreamTransactions = z.object({
  ledger_state: z.object({ state_version: SafeInt }),
  items: z.array(
    z.object({
      intent_hash: Bech32mId,
      status: z.string().max(64),
      confirmed_at: z.string().max(64).optional(),
      receipt: z.object({
        status: z.string().max(64),
        error_message: z.string().max(4096).optional(),
        fee_summary: z.object({ xrd_total_fee: Xrd.optional() }).optional(),
      }),
      balance_changes: z
        .object({
          fungible_balance_changes: z
            .array(
              z.object({
                entity_address: Bech32mId,
                resource_address: Bech32mId,
                net_balance_change: Xrd,
              }),
            )
            .max(256),
        })
        .optional(),
      round_number: SafeInt.optional(),
    }),
  ),
  next_cursor: z
    .string()
    .regex(/^\d{1,20}$/)
    .nullish(),
});

/** Converts a gateway XRD decimal string to attos (10^-18 XRD) without floats. */
export function xrdToAttos(xrd: string): bigint {
  const m = /^(-?)(\d+)(?:\.(\d{1,18}))?$/.exec(xrd);
  if (!m) throw new Error(`Invalid XRD amount ${xrd}`);
  const frac = (m[3] ?? '').padEnd(18, '0');
  const value = BigInt(m[2]!) * 10n ** 18n + BigInt(frac === '' ? '0' : frac);
  return m[1] === '-' ? -value : value;
}

export function attosToXrd(attos: bigint): string {
  const sign = attos < 0n ? '-' : '';
  const abs = attos < 0n ? -attos : attos;
  const whole = abs / 10n ** 18n;
  const frac = (abs % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return frac === '' ? `${sign}${whole}` : `${sign}${whole}.${frac}`;
}

export type RadixAdapterOptions = BaseAdapterOptions;
export type RadixCall = <T>(path: string, body: unknown, schema: z.ZodType<T>) => Promise<T>;

export class RadixAdapter extends BaseAdapter<'radix'> {
  constructor(opts: RadixAdapterOptions = {}) {
    super('radix', opts);
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'ed25519');
    return radixAddressFromPublicKey(publicKeyBytes(pub), chainId);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidRadixAddress(addr, chainId);
  }

  private post<T>(url: string, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    return postJsonText(`${url.replace(/\/$/, '')}${path}`, body, this.fetchOptions()).then(
      (text) => schema.parse(JSON.parse(text)),
    );
  }

  /** Current epoch and network name; every read path funnels through this check. */
  async networkStatus(chainId: ChainId): Promise<GatewayStatus> {
    return this.withGateway(chainId, (call) => call('/status/gateway-status', {}, GatewayStatus));
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    const network = NETWORKS[chainId];
    if (!network) throw new Error(`Unknown Radix network ${chainId}`);
    await this.verifyEndpoint(chainId, url, async () => {
      const status = await this.post(url, '/status/gateway-status', {}, GatewayStatus);
      if (status.ledger_state.network !== network.networkName)
        throw new Error('Endpoint network does not match this Radix network');
    });
  }

  /** Keep dependent observations on one gateway that proved its network. */
  withGateway<T>(
    chainId: ChainId,
    query: (call: RadixCall, url: string) => Promise<T>,
  ): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, body, schema) => this.post(url, path, body, schema), url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidRadixAddress(addr, chainId)) throw new TypeError(`invalid radix address ${addr}`);
    const network = NETWORKS[chainId]!;
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const details = await this.post(
          url,
          '/state/entity/details',
          { addresses: [addr], aggregation_level: 'Vault' },
          EntityDetails,
        );
        // An account that never received XRD is not on-ledger yet: zero, not an error.
        const entry = details.items.find((i) => i.address === addr);
        const xrd = entry?.fungible_resources?.items.find(
          (r) => r.resource_address === network.xrdResource,
        );
        const total = (xrd?.vaults.items ?? []).reduce(
          (sum, vault) => sum + xrdToAttos(vault.amount),
          0n,
        );
        return total.toString();
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidRadixAddress(addr, chainId)) throw new Error('Invalid history address');
    if (cursor !== undefined && !/^\d{1,20}$/.test(cursor))
      throw new Error('Invalid history cursor');
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const page = StreamTransactions.parse(
        JSON.parse(
          await postJsonText(
            `${url.replace(/\/$/, '')}/stream/transactions`,
            {
              affected_global_entities_filter: [addr],
              order: 'Desc',
              limit_per_page: 20,
              ...(cursor ? { cursor } : {}),
              opt_ins: { balance_changes: true },
            },
            opts,
          ),
        ),
      );
      return {
        items: page.items.map((t) =>
          historyRecord(
            chain.chainId,
            chain.nativeAsset.ref,
            NETWORKS[chainId]!.xrdResource,
            addr,
            t,
          ),
        ),
        ...(page.next_cursor ? { nextCursor: page.next_cursor } : {}),
        coverage:
          'Gateway stream of committed transactions affecting this account. Only net XRD balance changes are reported; failed transactions and non-XRD movements appear without deltas. Fees are the XRD actually burned by execution.',
        source: url,
      };
    });
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    const network = NETWORKS[chainId];
    if (!network) throw new Error(`Unknown Radix network ${chainId}`);
    if (!hash.startsWith(`${network.txidHrp}1`)) throw new Error('Invalid Radix transaction id');
    return this.withGateway(chainId, async (call) => {
      const res = await call('/transaction/status', { intent_hash: hash }, TransactionStatus);
      if (res.status === 'CommittedSuccess') {
        const ts = Date.parse(res.ledger_state.proposer_round_timestamp);
        return {
          state: 'confirmed',
          blockNumber: res.ledger_state.epoch,
          ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
        };
      }
      if (res.status === 'CommittedFailure')
        return { state: 'failed', reason: clean(res.receipt?.error_message ?? 'CommittedFailure') };
      return { state: 'unknown' };
    });
  }
}

function clean(reason: string): string {
  return reason.replace(/[^\x20-\x7e]/g, '').slice(0, 256);
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  xrdResource: string,
  holder: string,
  t: z.infer<typeof StreamTransactions>['items'][number],
): TxRecord {
  const failed = t.receipt.status !== 'CommittedSuccess';
  let delta = 0n;
  if (!failed)
    for (const change of t.balance_changes?.fungible_balance_changes ?? [])
      if (change.entity_address === holder && change.resource_address === xrdResource)
        delta += xrdToAttos(change.net_balance_change);
  const fee = t.receipt.fee_summary?.xrd_total_fee;
  const ts = t.confirmed_at ? Date.parse(t.confirmed_at) : NaN;
  return {
    hash: t.intent_hash,
    chainId,
    from: '',
    ...(t.round_number !== undefined ? { blockNumber: t.round_number } : {}),
    ...(Number.isFinite(ts) ? { timestampMs: ts } : {}),
    assetDeltas: delta !== 0n ? [{ assetRef: nativeRef, amount: delta.toString() }] : [],
    feeAssetRef: nativeRef,
    fee: fee === undefined ? null : xrdToAttos(fee).toString(),
    status: failed ? 'failed' : 'confirmed',
  };
}

export function createRadixAdapter(opts?: RadixAdapterOptions): RadixAdapter {
  return new RadixAdapter(opts);
}
