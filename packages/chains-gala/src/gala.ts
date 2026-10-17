/**
 * Gala adapter. GalaChain is a Hyperledger Fabric network fronted by a REST
 * gateway; users are `eth|<EIP-55>` secp256k1 identities and signatures are
 * keccak256 over deterministically serialized DTO JSON (verified byte-exact
 * against `@gala-chain/api` 3.3.0 and live against both gateways). Reads go
 * through the same gateway (`FetchBalances`); the public explorer API backs
 * the bounded status lookup.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  nativeHolding,
  postJsonText,
  fetchJson,
  publicKeyBytes,
  requireCurve,
  secp256k1Uncompressed,
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
import type { ChainFamily, ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

export const GALA_MAINNET = 'gala:mainnet';
export const GALA_TESTNET = 'gala:testnet';
/** `gala` is not in core-client's ChainFamily enum yet; see .nur/wiring/gala.md. */
export const GALA_FAMILY = 'gala' as ChainFamily;
const EXPLORER_API = 'https://explorer-api.galachain.com';
export const GALA_DECIMALS = 8;

export const GALA_CHAINS: ChainInfo[] = [
  {
    chainId: GALA_MAINNET,
    family: GALA_FAMILY,
    name: 'GalaChain',
    nativeAsset: { ref: `${GALA_MAINNET}:native`, symbol: 'GALA', decimals: GALA_DECIMALS },
    testnet: false,
    defaultRpcs: ['https://gateway-mainnet.galachain.com'],
    extra: { coinType: 60 },
    priceId: 'gala',
    layer: 'appchain',
  },
  {
    chainId: GALA_TESTNET,
    family: GALA_FAMILY,
    name: 'GalaChain Testnet',
    nativeAsset: { ref: `${GALA_TESTNET}:native`, symbol: 'GALA', decimals: GALA_DECIMALS },
    testnet: true,
    defaultRpcs: ['https://gateway-testnet.galachain.com'],
    extra: { coinType: 60 },
    layer: 'appchain',
  },
];

/** EIP-55 mixed-case spelling of 20 raw bytes, without the `0x` prefix. */
export function galaChecksum(bytes: Uint8Array): string {
  if (bytes.length !== 20) throw new Error('address must be 20 bytes');
  const lower = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  const hash = keccak_256(new TextEncoder().encode(lower));
  let out = '';
  for (let i = 0; i < 40; i++) {
    const c = lower[i]!;
    out +=
      /[a-f]/.test(c) && (hash[Math.floor(i / 2)]! >> (i % 2 === 0 ? 4 : 0)) & 0x8
        ? c.toUpperCase()
        : c;
  }
  return out;
}

export function galaAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^eth\|[0-9a-fA-F]{40}$/.test(addr)) return undefined;
  const bytes = Uint8Array.from(addr.slice(4).match(/../g)!, (b) => parseInt(b, 16));
  if (bytes.every((b) => b === 0)) return undefined;
  if (galaChecksum(bytes) !== addr.slice(4)) return undefined;
  return bytes;
}

export function isValidGalaAddress(addr: string): boolean {
  return galaAddressBytes(addr) !== undefined;
}

/** keccak256 of the uncompressed key's last 20 bytes, as `eth|<EIP-55>`. */
export function galaAddressFromPublicKey(publicKey: Uint8Array): string {
  const full = secp256k1Uncompressed(publicKey);
  const hash = keccak_256(full.subarray(1));
  return `eth|${galaChecksum(hash.subarray(12))}`;
}

/** The gateway answers every DTO with `{Data}` on success, error JSON otherwise. */
const GatewayResult = <T extends z.ZodTypeAny>(data: T) =>
  z
    .object({
      Data: data.optional(),
      Message: z.string().max(2048).optional(),
      ErrorCode: z.string().max(128).optional(),
      Status: z.number().optional(),
    })
    .loose();

export const TokenBalance = z
  .object({
    collection: z.string().max(128),
    category: z.string().max(128),
    type: z.string().max(128),
    additionalKey: z.string().max(128),
    owner: z.string().max(128),
    quantity: z.string().regex(/^\d{1,30}(\.\d{1,18})?$/),
  })
  .loose();
export const FetchBalancesResult = z.array(TokenBalance);
export const TokenClass = z
  .object({
    collection: z.string().max(128),
    decimals: z.number().int().nonnegative().max(18),
  })
  .loose();
export const FetchTokenClassesResult = z.array(TokenClass);

export const ExplorerLatest = z.object({
  data: z.object({
    transactions: z.array(
      z
        .object({
          id: z.string().max(128),
          validationCode: z
            .object({ validationEnum: z.string().max(32) })
            .loose()
            .optional(),
        })
        .loose(),
    ),
  }),
});

export type GalaAdapterOptions = BaseAdapterOptions;

export class GalaAdapter extends BaseAdapter {
  constructor(opts: GalaAdapterOptions = {}) {
    super(GALA_FAMILY, { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(GALA_CHAINS) });
  }

  override chains(): ChainInfo[] {
    const catalog = chainsForFamily(GALA_FAMILY);
    return catalog.length > 0 ? catalog : GALA_CHAINS;
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return galaAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidGalaAddress(addr);
  }

  /** POST a DTO to the token contract endpoint; returns the parsed envelope. */
  async gateway<T>(
    url: string,
    method: string,
    body: unknown,
    schema: z.ZodType<T>,
  ): Promise<{ data: T | undefined; message?: string }> {
    if (!/^GalaChainToken:[A-Za-z]+$|^[A-Za-z]+$/.test(method))
      throw new Error('Invalid gateway method');
    const text = await postJsonText(
      `${url.replace(/\/$/, '')}/api/asset/token-contract/${method.replace(/^GalaChainToken:/, '')}`,
      body,
      this.fetchOptions(),
    );
    const envelope = GatewayResult(z.unknown()).parse(JSON.parse(text));
    if (envelope.Data === undefined) {
      return { data: undefined, ...(envelope.Message ? { message: envelope.Message } : {}) };
    }
    return { data: schema.parse(envelope.Data) };
  }

  /**
   * The gateways do not expose a network id; the proof that an endpoint is a
   * GalaChain asset gateway for this network is that it serves the GALA token
   * class with 8 decimals. Main/testnet separation rests on the hostnames,
   * which were probed live for this adapter.
   */
  private checkNetwork(chainId: ChainId, url: string): Promise<void> {
    return this.verifyEndpoint(chainId, url, async () => {
      const { data } = await this.gateway(
        url,
        'FetchTokenClasses',
        {
          tokenClasses: [
            { collection: 'GALA', category: 'Unit', type: 'none', additionalKey: 'none' },
          ],
        },
        FetchTokenClassesResult,
      );
      const gala = data?.find((c) => c.collection === 'GALA');
      if (!gala || gala.decimals !== GALA_DECIMALS)
        throw new Error('Endpoint does not serve the GALA token class');
    });
  }

  /** Keep dependent observations on one endpoint that proved itself. */
  withGateway<T>(chainId: ChainId, query: (url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query(url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidGalaAddress(addr)) throw new TypeError(`invalid gala address ${addr}`);
    let endpoint = '';
    const value = await withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const { data, message } = await this.gateway(
        url,
        'FetchBalances',
        { owner: addr },
        FetchBalancesResult,
      );
      if (!data) throw new Error(`FetchBalances failed: ${message ?? 'no data'}`);
      endpoint = url;
      const gala = data.find(
        (b) =>
          b.collection === 'GALA' &&
          b.category === 'Unit' &&
          b.type === 'none' &&
          b.additionalKey === 'none',
      );
      return gala ? gala.quantity : '0';
    });
    return [nativeHolding(chain, decimalToGunits(value), { kind: 'single', endpoint })];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidGalaAddress(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'No by-address history endpoint of the GalaChain explorer API is verified; history is unavailable.',
    };
  }

  /**
   * Bounded confirmation lookup: the explorer only exposes a latest page, so
   * a transfer found there with validation VALID is confirmed; anything else
   * is unknown (the gateway assigns ids synchronously at broadcast).
   */
  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid GalaChain transaction hash');
    const value = hash.replace(/^0x/, '').toLowerCase();
    this.requireChain(chainId);
    const latest = ExplorerLatest.parse(
      await fetchJson(
        `${EXPLORER_API}/v1/explorer/transactions/asset-channel/latest`,
        this.fetchOptions(),
      ),
    );
    const found = latest.data.transactions.find((t) => t.id.toLowerCase() === value);
    if (!found) return { state: 'unknown' };
    if (found.validationCode?.validationEnum === 'VALID')
      // The explorer's latest page does not carry block numbers; confirmed
      // here means validated in a recent block.
      return { state: 'confirmed', blockNumber: 0 };
    return { state: 'failed', reason: found.validationCode?.validationEnum ?? 'invalid' };
  }
}

/** Decimal GALA string (from FetchBalances) to integer gunits (8 decimals). */
export function decimalToGunits(quantity: string): string {
  const m = /^(\d{1,30})(?:\.(\d{1,18}))?$/.exec(quantity);
  if (!m) throw new Error('Invalid GALA quantity');
  const frac = (m[2] ?? '').padEnd(8, '0');
  if (frac.length > 8 && /[1-9]/.test(frac.slice(8)))
    throw new Error('GALA quantity has more than 8 decimals');
  const gunits = BigInt(m[1]!) * 100_000_000n + BigInt(frac.slice(0, 8));
  return gunits.toString();
}

/** Integer gunits to the fixed-notation decimal the chaincode signs. */
export function gunitsToDecimal(gunits: string): string {
  if (!/^\d{1,20}$/.test(gunits) || BigInt(gunits).toString() !== gunits || BigInt(gunits) === 0n)
    throw new Error('Invalid gunits');
  const value = BigInt(gunits);
  const whole = value / 100_000_000n;
  const frac = value % 100_000_000n;
  if (frac === 0n) return whole.toString();
  return `${whole}.${frac.toString().padStart(8, '0').replace(/0+$/, '')}`;
}

export function createGalaAdapter(opts?: GalaAdapterOptions): GalaAdapter {
  return new GalaAdapter(opts);
}
