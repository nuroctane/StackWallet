/**
 * Keeta adapter. Addresses are `keeta_` + lowercase base32 (no padding) of
 * `type || public key || sha3-256(type || public key)[0..5]`; accounts use
 * type 0x00 with the 33-byte compressed secp256k1 key. Reads go over the
 * representative REST API; an endpoint proves its network by serving the
 * base token account whose head block carries the network id.
 *
 * Protocol facts are pinned against `@keetanetwork/keetanet-client` 0.18.8.
 */
import { sha3_256 } from '@noble/hashes/sha3.js';
import { base32nopad } from '@scure/base';
import {
  BaseAdapter,
  MemoryRpcPool,
  chainsForFamily,
  fetchJson,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
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

export const KEETA_TEST = 'keeta:test';
export const KEETA_MAINNET = 'keeta:main';
/** Keeta has no CAIP-2 entry; these ids use the SDK network alias. */
export const NETWORK_ID: Record<string, string> = {
  [KEETA_TEST]: '0x54455354',
  [KEETA_MAINNET]: '0x5382',
};
/** Per-network KTA base token, derived from the network id by the SDK and confirmed live. */
export const BASE_TOKEN: Record<string, string> = {
  [KEETA_TEST]: 'keeta_anyiff4v34alvumupagmdyosydeq24lc4def5mrpmmyhx3j6vj2uucckeqn52',
  [KEETA_MAINNET]: 'keeta_anqdilpazdekdu4acw65fj7smltcp26wbrildkqtszqvverljpwpezmd44ssg',
};
const KTA_DECIMALS = 18;

/** Built-in chains used until the shared catalog carries Keeta entries. */
export const KEETA_CHAINS: ChainInfo[] = [
  {
    chainId: KEETA_MAINNET,
    family: 'keeta',
    name: 'Keeta',
    nativeAsset: { ref: `${KEETA_MAINNET}:native`, symbol: 'KTA', decimals: KTA_DECIMALS },
    testnet: false,
    explorerTxUrl: 'https://explorer.keeta.com/block/{hash}',
    defaultRpcs: [
      'https://rep1.main.network.api.keeta.com/api',
      'https://rep2.main.network.api.keeta.com/api',
      'https://rep3.main.network.api.keeta.com/api',
      'https://rep4.main.network.api.keeta.com/api',
    ],
    priceId: 'keeta',
  },
  {
    chainId: KEETA_TEST,
    family: 'keeta',
    name: 'Keeta Test Network',
    nativeAsset: { ref: `${KEETA_TEST}:native`, symbol: 'KTA', decimals: KTA_DECIMALS },
    testnet: true,
    explorerTxUrl: 'https://explorer.test.keeta.com/block/{hash}',
    defaultRpcs: [
      'https://rep1.test.network.api.keeta.com/api',
      'https://rep2.test.network.api.keeta.com/api',
    ],
  },
];

function keetaChains(): ChainInfo[] {
  const catalog = chainsForFamily('keeta');
  return catalog.length > 0 ? catalog : KEETA_CHAINS;
}

/** Decoded account address: `0x00 || compressed SEC1`, or undefined. */
export function keetaAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^keeta_[a-z2-7]{63}$/.test(addr)) return undefined;
  try {
    const decoded = base32nopad.decode(addr.slice(6).toUpperCase());
    if (decoded.length !== 39 || decoded[0] !== 0x00) return undefined;
    const payload = decoded.subarray(0, 34);
    const check = decoded.subarray(34);
    for (let i = 0; i < 5; i++) if (check[i] !== sha3_256(payload)[i]) return undefined;
    return payload;
  } catch {
    return undefined;
  }
}

/** Decoded token identifier address: `0x03 || 32-byte identifier`, or undefined. */
export function keetaTokenBytes(addr: string): Uint8Array | undefined {
  if (!/^keeta_[a-z2-7]{61}$/.test(addr)) return undefined;
  try {
    const decoded = base32nopad.decode(addr.slice(6).toUpperCase());
    if (decoded.length !== 38 || decoded[0] !== 0x03) return undefined;
    const payload = decoded.subarray(0, 33);
    const check = decoded.subarray(33);
    for (let i = 0; i < 5; i++) if (check[i] !== sha3_256(payload)[i]) return undefined;
    return payload;
  } catch {
    return undefined;
  }
}

export function isValidKeetaAddress(addr: string): boolean {
  return keetaAddressBytes(addr) !== undefined;
}

export function keetaAddressFromPublicKey(sec1: Uint8Array): string {
  if (sec1.length !== 33 || (sec1[0] !== 0x02 && sec1[0] !== 0x03))
    throw new Error('Keeta public keys are 33-byte compressed SEC1');
  const payload = new Uint8Array(34);
  payload[0] = 0x00;
  payload.set(sec1, 1);
  const full = new Uint8Array(39);
  full.set(payload);
  full.set(sha3_256(payload).subarray(0, 5), 34);
  return `keeta_${base32nopad.encode(full).toLowerCase()}`;
}

const Hex64 = z.string().regex(/^[0-9A-F]{64}$/);
const HexBig = z.string().regex(/^0x[0-9A-F]+$/);
const AddressStr = z.string().regex(/^keeta_[a-z2-7]{61,63}$/);

export const AccountState = z.object({
  account: AddressStr,
  currentHeadBlock: Hex64.nullable(),
  currentHeadBlockHeight: HexBig.nullable(),
  info: z
    .object({
      name: z.string().max(256).optional(),
      metadata: z.string().max(4096).optional(),
    })
    .loose()
    .optional(),
  balances: z.array(z.object({ token: AddressStr, balance: HexBig })).max(256),
});

export const BlockJSON = z
  .object({
    version: z.number().int().min(1).max(2),
    date: z.string().max(40),
    previous: Hex64,
    account: AddressStr,
    signer: z.union([AddressStr, z.unknown()]),
    network: z.string().regex(/^0x[0-9A-F]+$/),
    purpose: z.number().int().optional(),
    operations: z
      .array(
        z
          .object({
            type: z.number().int().nonnegative().max(255),
            to: AddressStr.optional(),
            amount: HexBig.optional(),
            token: AddressStr.optional(),
          })
          .loose(),
      )
      .max(64),
    $hash: Hex64.optional(),
  })
  .loose();
export type KeetaBlockJSON = z.infer<typeof BlockJSON>;

const BlockLookup = z.object({ blockhash: Hex64, block: BlockJSON.nullable() });

const Vote = z
  .object({
    issuer: AddressStr,
    $permanent: z.boolean().optional(),
    validityTo: z.string().max(40).optional(),
  })
  .loose();
const VoteLookup = z.object({ blockhash: Hex64, votes: z.array(Vote).max(64).nullable() });

const HistoryPage = z.object({
  history: z
    .array(
      z
        .object({
          voteStaple: z.object({ blocks: z.array(BlockJSON).max(64) }).loose(),
        })
        .loose(),
    )
    .max(200),
});

export type KeetaAdapterOptions = BaseAdapterOptions;
export type KeetaCall = <T>(path: string, schema: z.ZodType<T>) => Promise<T>;

/** Publish-aid endpoints collect representative votes server-side and publish the block. */
export const PUBLISH_AID: Record<string, { url: string; network: string }> = {
  [KEETA_TEST]: {
    url: 'https://publish-aid.test.network.api.keeta.com/api/publish',
    network: 'test',
  },
  [KEETA_MAINNET]: {
    url: 'https://publish-aid.main.api.keeta.com/api/publish',
    network: 'main',
  },
};
const PublishResult = z.object({ publish: z.boolean() });

export class KeetaAdapter extends BaseAdapter<'keeta'> {
  constructor(opts: KeetaAdapterOptions = {}) {
    super('keeta', { ...opts, rpc: opts.rpc ?? new MemoryRpcPool(keetaChains()) });
  }

  override chains(): ChainInfo[] {
    return keetaChains();
  }

  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    requireCurve(pub, 'secp256k1');
    return keetaAddressFromPublicKey(publicKeyBytes(pub));
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidKeetaAddress(addr);
  }

  private get<T>(url: string, path: string, schema: z.ZodType<T>): Promise<T> {
    return fetchJson(`${url.replace(/\/$/, '')}${path}`, this.fetchOptions()).then((res) =>
      schema.parse(res),
    );
  }

  /**
   * An endpoint proves its network by serving the base token account: the
   * token address is derived from the network id, its info names it KTA, and
   * its head block carries the expected network id.
   */
  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const token = BASE_TOKEN[chainId];
      const network = NETWORK_ID[chainId];
      if (!token || !network) throw new Error(`No Keeta base token for ${chainId}`);
      const state = await this.get(url, `/node/ledger/account/${token}`, AccountState);
      if (state.info?.name !== 'KTA') throw new Error('Endpoint does not serve this Keeta network');
      if (state.currentHeadBlock) {
        const head = await this.get(
          url,
          `/node/ledger/block/${state.currentHeadBlock}`,
          BlockLookup,
        );
        if (head.block === null || head.block.network !== network)
          throw new Error('Endpoint head block is from another Keeta network');
      }
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: KeetaCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      return query((path, schema) => this.get(url, path, schema), url);
    });
  }

  /** POST a signed block to the network's publish-aid; resolves to its publish verdict. */
  async publishBlock(chainId: ChainId, signedBase64: string): Promise<boolean> {
    const aid = PUBLISH_AID[chainId];
    if (!aid) throw new Error(`No publish-aid endpoint for ${chainId}`);
    const text = await postJsonText(
      aid.url,
      { network: aid.network, blocks: [signedBase64] },
      this.fetchOptions(),
    );
    return PublishResult.parse(JSON.parse(text)).publish;
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidKeetaAddress(addr)) throw new TypeError(`invalid keeta address ${addr}`);
    const token = BASE_TOKEN[chainId]!;
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const state = await this.get(url, `/node/ledger/account/${addr}`, AccountState);
        // An address that never transacted has no balance entries: zero.
        const entry = state.balances.find((b) => b.token === token);
        return entry ? BigInt(entry.balance).toString() : '0';
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, value, provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!isValidKeetaAddress(addr)) throw new Error('Invalid history address');
    const token = BASE_TOKEN[chainId]!;
    const opts = { ...this.fetchOptions(), ...(options?.signal ? { signal: options.signal } : {}) };
    let lastError: unknown;
    for (const { url } of this.rpc.endpoints(chainId)) {
      try {
        await this.checkNetwork(chainId, url);
        const page = HistoryPage.parse(
          await fetchJson(`${url.replace(/\/$/, '')}/node/ledger/account/${addr}/history`, opts),
        );
        const items: TxRecord[] = [];
        for (const entry of page.history) {
          for (const block of entry.voteStaple.blocks) {
            if (block.account !== addr && block.signer !== addr) continue;
            const record = historyRecord(chain.chainId, chain.nativeAsset.ref, addr, token, block);
            if (record) items.push(record);
          }
        }
        return {
          items,
          coverage:
            'Representative node account history (first page). Only KTA SEND operations carry balance changes; other operation types are omitted.',
          source: url,
        };
      } catch (err) {
        if (options?.signal?.aborted) throw err;
        lastError = err;
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Keeta history is unavailable');
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Invalid Keeta block hash');
    const value = hash.toUpperCase();
    return this.withNode(chainId, async (call) => {
      const lookup = await call(`/node/ledger/block/${value}`, BlockLookup);
      if (lookup.block === null) return { state: 'unknown' } as const;
      const votes = await call(`/vote/${value}`, VoteLookup);
      const permanent = (votes.votes ?? []).filter((v) => v.$permanent === true);
      if (permanent.length === 0) return { state: 'pending' } as const;
      // Keeta has no global block height; the sender's head height bounds the
      // block's account-chain position from above.
      let blockNumber = 0;
      try {
        const state = await call(`/node/ledger/account/${lookup.block.account}`, AccountState);
        if (state.currentHeadBlockHeight)
          blockNumber = Number(BigInt(state.currentHeadBlockHeight));
      } catch {
        // Height is informational; confirmation rests on the permanent votes.
      }
      return {
        state: 'confirmed',
        blockNumber,
        timestampMs: Date.parse(lookup.block.date),
      } as const;
    });
  }
}

function historyRecord(
  chainId: string,
  nativeRef: string,
  holder: string,
  baseToken: string,
  block: KeetaBlockJSON,
): TxRecord | null {
  if (!block.$hash) return null;
  let delta = 0n;
  let sawSend = false;
  let counterparty = '';
  for (const op of block.operations) {
    if (op.type !== 0 || !op.to || !op.amount || op.token !== baseToken) continue;
    sawSend = true;
    const amount = BigInt(op.amount);
    if (block.account === holder) {
      delta -= amount;
      counterparty = op.to;
    }
    if (op.to === holder) {
      delta += amount;
      if (block.account !== holder) counterparty = block.account;
    }
  }
  if (!sawSend) return null;
  return {
    hash: block.$hash,
    chainId,
    from: block.account,
    ...(counterparty ? { to: counterparty } : {}),
    timestampMs: Date.parse(block.date),
    assetDeltas: [{ assetRef: nativeRef, amount: String(delta) }],
    feeAssetRef: nativeRef,
    fee: '0',
    status: 'confirmed',
  };
}

export function createKeetaAdapter(opts?: KeetaAdapterOptions): KeetaAdapter {
  return new KeetaAdapter(opts);
}
