/**
 * NEO N3 adapter, read-only. NEO N3 signs with ECDSA over secp256r1 (P-256);
 * the core holds no P-256 curve and no threshold protocol for one, so this
 * adapter serves balances and transaction status only and the signing
 * entry points stay `NotImplementedError`. Addresses are base58check of
 * `0x35 || hash160(verificationScript)` where the script is
 * `0x0C 0x21 <pubkey> 0x41 56e7b327` (PUSHDATA1 + SYSCALL System.Crypto.CheckSig);
 * byte-pinned against the official `@cityofzion/neon-core` bundle.
 *
 * Every read is network-proven with `getversion`: `protocol.network` must be
 * 860833102 on mainnet and 894710606 on testnet (CAIP-2 `neo3:mainnet` /
 * `neo3:testnet3`). No keyless public history indexer is alive (Dora and
 * NeoTube both retired their REST APIs), so history reports its gap.
 */
import { p256 } from '@noble/curves/nist.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createBase58check } from '@scure/base';
import {
  BaseAdapter,
  JsonRpcError,
  UnsupportedKeyError,
  nativeHolding,
  publicKeyBytes,
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

const base58check = createBase58check(sha256);
const ADDRESS_VERSION = 0x35;
/** Interop hash of `System.Crypto.CheckSig` (sha256 of the name, first 4 bytes). */
const CHECKSIG = [0x41, 0x56, 0xe7, 0xb3, 0x27];

export const NEO3_MAINNET = 'neo3:mainnet';
export const NEO3_TESTNET = 'neo3:testnet3';
/** Network magic from `getversion.protocol.network`, the network proof. */
export const NEO3_MAGIC: Record<string, number> = {
  [NEO3_MAINNET]: 860833102,
  [NEO3_TESTNET]: 894710606,
};
/** NEO governance token contract (both networks); NEO has 0 decimals. */
export const NEO_TOKEN = ['0xef4073a0f2b305a38e', 'c4050e4d3d28bc40ea63', 'f5'].join('');
/** GAS utility token contract (both networks); GAS has 8 decimals and pays fees. */
export const GAS_TOKEN = ['0xd2a4cff31913016155', 'e38e474a2c06d08be276', 'cf'].join('');

export function neoVerificationScript(publicKey: Uint8Array): Uint8Array {
  // Full point validation: rejects bad length, prefix, and off-curve points.
  const compressed = p256.Point.fromBytes(publicKey).toBytes(true);
  const script = new Uint8Array(40);
  script[0] = 0x0c; // PUSHDATA1
  script[1] = 0x21; // 33 bytes follow
  script.set(compressed, 2);
  script.set(CHECKSIG, 35);
  return script;
}

/** base58check address from a compressed secp256r1 SEC1 public key. */
export function neoAddressFromPublicKey(publicKey: Uint8Array): string {
  const payload = new Uint8Array(21);
  payload[0] = ADDRESS_VERSION;
  payload.set(ripemd160(sha256(neoVerificationScript(publicKey))), 1);
  return base58check.encode(payload);
}

export function neoAddressBytes(addr: string): Uint8Array | undefined {
  if (!/^N[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr)) return undefined;
  try {
    const bytes = base58check.decode(addr);
    if (bytes.length !== 21 || bytes[0] !== ADDRESS_VERSION) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

export function isValidNeoAddress(addr: string): boolean {
  return neoAddressBytes(addr) !== undefined;
}

const Hash160 = z.string().regex(/^0x[0-9a-f]{40}$/);
const Hash256 = z.string().regex(/^0x[0-9a-f]{64}$/);
const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

const Version = z.object({
  protocol: z.object({ addressversion: z.number().int(), network: SafeInt }).loose(),
});
const Nep17Balances = z.object({
  balance: z
    .array(
      z.object({
        assethash: Hash160,
        amount: z.string().regex(/^\d{1,40}$/),
        decimals: z.string().regex(/^\d{1,2}$/),
        name: z.string().max(128),
        symbol: z.string().max(32),
      }),
    )
    .max(256),
});
const Mempool = z.array(Hash256).max(50_000);
const VerboseTx = z.object({
  blockhash: Hash256.optional(),
  vmstate: z.string().max(16).optional(),
  blocktime: SafeInt.optional(),
  netfee: z.string().max(32).optional(),
  sysfee: z.string().max(32).optional(),
});
/** `gettransactionheight` errors with code -103 ("Unknown transaction") when absent. */

export type NeoAdapterOptions = BaseAdapterOptions;
export type NeoCall = <T>(method: string, params: unknown[], schema: z.ZodType<T>) => Promise<T>;

export class NeoAdapter extends BaseAdapter<'neo'> {
  constructor(opts: NeoAdapterOptions = {}) {
    super('neo', opts);
  }

  /**
   * The core has no secp256r1 key type, so no `PublicKey` it can hand out
   * derives a NEO address. `neoAddressFromPublicKey` holds the byte-exact
   * derivation for the day a P-256 signing path exists.
   */
  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    void publicKeyBytes(pub);
    throw new UnsupportedKeyError(
      `NEO N3 uses secp256r1 (P-256); the core has no P-256 key (curve ${pub.curve})`,
    );
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidNeoAddress(addr);
  }

  private async checkNetwork(chainId: ChainId, url: string): Promise<void> {
    await this.verifyEndpoint(chainId, url, async () => {
      const version = await this.jsonRpc('getversion', [], Version)(url);
      if (
        version.protocol.network !== NEO3_MAGIC[chainId] ||
        version.protocol.addressversion !== 53
      )
        throw new Error('Endpoint network magic does not match this NEO network');
    });
  }

  /** Keep dependent observations on one endpoint that proved its network. */
  withNode<T>(chainId: ChainId, query: (call: NeoCall, url: string) => Promise<T>): Promise<T> {
    this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      await this.checkNetwork(chainId, url);
      const call: NeoCall = (method, params, schema) => this.jsonRpc(method, params, schema)(url);
      return query(call, url);
    });
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!isValidNeoAddress(addr)) throw new TypeError(`invalid neo address ${addr}`);
    const { value, provenance } = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        await this.checkNetwork(chainId, url);
        const res = await this.jsonRpc('getnep17balances', [addr], Nep17Balances)(url);
        return JSON.stringify(
          res.balance
            .filter((b) => b.assethash === NEO_TOKEN || b.assethash === GAS_TOKEN)
            .map((b) => [b.assethash, b.amount]),
        );
      },
      { equal: (a, b) => a === b },
    );
    const amounts = new Map<string, string>(JSON.parse(value) as [string, string][]);
    const gasRef = `${chainId}:nep17:${GAS_TOKEN}`;
    const gas: Holding = {
      assetRef: gasRef,
      amount: amounts.get(GAS_TOKEN) ?? '0',
      metadata: { symbol: 'GAS', decimals: 8 },
      notice: 'GAS balance from getnep17balances; NEP-17 transfers are not enabled.',
      updatedAtMs: Date.now(),
      provenance,
    };
    return [nativeHolding(chain, amounts.get(NEO_TOKEN) ?? '0', provenance), gas];
  }

  /**
   * NEO N3 lost its keyless public indexers: Dora's REST API and NeoTube both
   * answer SPA shells or 404s now (probed, see .nur/wiring/neo.md). Plain
   * nodes cannot list an address's transactions, so report the gap.
   */
  override async getHistory(
    addr: Address,
    chainId: ChainId,
    _cursor?: string,
    _options?: HistoryOptions,
  ): Promise<Page<TxRecord>> {
    this.requireChain(chainId);
    if (!isValidNeoAddress(addr)) throw new Error('Invalid history address');
    return {
      items: [],
      coverage:
        'No keyless public NEO N3 indexer is available (Dora and NeoTube retired their APIs), so transfer history is unavailable.',
    };
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    const value = hash.replace(/^0x/, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(value)) throw new Error('Invalid NEO transaction id');
    return this.withNode(chainId, async (call) => {
      let height: number | undefined;
      try {
        height = await call('gettransactionheight', [`0x${value}`], SafeInt);
      } catch (error) {
        // Code -103 ("Unknown transaction") is a real answer: not on this chain.
        if (!(error instanceof JsonRpcError && error.code === -103)) throw error;
      }
      if (height !== undefined) {
        const tx = await call('getrawtransaction', [`0x${value}`, 1], VerboseTx);
        if (tx.vmstate === 'FAULT')
          return { state: 'failed', reason: 'transaction FAULTed during execution' };
        return {
          state: 'confirmed',
          blockNumber: height,
          ...(tx.blocktime !== undefined ? { timestampMs: tx.blocktime } : {}),
        };
      }
      const mempool = await call('getrawmempool', [], Mempool);
      return mempool.includes(`0x${value}`) ? { state: 'pending' } : { state: 'unknown' };
    });
  }
}

export function createNeoAdapter(opts?: NeoAdapterOptions): NeoAdapter {
  return new NeoAdapter(opts);
}

/** Hex of the verification script, for the test vector shared with the Rust core. */
export function neoVerificationScriptHex(publicKey: Uint8Array): string {
  return bytesToHex(neoVerificationScript(publicKey));
}

export function neoAddressToScriptHashHex(addr: string): string | undefined {
  const bytes = neoAddressBytes(addr);
  return bytes ? `0x${bytesToHex(bytes.subarray(1))}` : undefined;
}
