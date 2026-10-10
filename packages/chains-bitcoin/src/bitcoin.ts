/**
 * Bitcoin-family adapter (BTC mainnet/testnet4/signet, LTC, DOGE). Address
 * derivation and validation are pure; balances and status use the
 * mempool.space REST API shape. PSBT construction, coin control and fee
 * estimation arrive with bitcoinjs-lib in a later phase.
 */
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32, bech32m, createBase58check } from '@scure/base';
import {
  BaseAdapter,
  UnsupportedKeyError,
  nativeHolding,
  preferIndexedSide,
  publicKeyBytes,
  requireCurve,
  secp256k1Compressed,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type ChainInfo,
  type Holding,
  type TxHash,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey } from '@stackwallet/core-client';
import { z } from 'zod';

const base58check = createBase58check(sha256);

export interface BitcoinNetwork {
  hrp?: string;
  p2pkhVersion: number;
  p2shVersion: number;
}

export function networkOf(chain: ChainInfo): BitcoinNetwork {
  const x = chain.extra;
  if (!x || x.p2pkhVersion === undefined || x.p2shVersion === undefined) {
    throw new Error(`${chain.chainId} is missing bitcoin version bytes in its catalog entry`);
  }
  return {
    ...(x.segwit && x.bech32Prefix !== undefined ? { hrp: x.bech32Prefix } : {}),
    p2pkhVersion: x.p2pkhVersion,
    p2shVersion: x.p2shVersion,
  };
}

export function hash160(bytes: Uint8Array): Uint8Array {
  return ripemd160(sha256(bytes));
}

/** BIP-173 / BIP-350 segwit address: version 0 uses bech32, 1..16 use bech32m. */
export function encodeSegwit(hrp: string, version: number, program: Uint8Array): string {
  if (version < 0 || version > 16) throw new RangeError('witness version out of range');
  const words = [version, ...bech32.toWords(program)];
  return version === 0 ? bech32.encode(hrp, words) : bech32m.encode(hrp, words);
}

export function decodeSegwit(
  addr: string,
): { hrp: string; version: number; program: Uint8Array } | null {
  // Mixed case is rejected by both codecs; lowercase-only input keeps the checksum meaningful.
  const v0 = bech32.decodeUnsafe(addr, 90);
  const v1 = v0 ? undefined : bech32m.decodeUnsafe(addr, 90);
  const decoded = v0 ?? v1;
  if (!decoded || decoded.words.length === 0) return null;
  const version = decoded.words[0]!;
  if (v0 && version !== 0) return null;
  if (v1 && (version < 1 || version > 16)) return null;
  const program = bech32.fromWordsUnsafe(decoded.words.slice(1));
  if (!program) return null;
  if (program.length < 2 || program.length > 40) return null;
  if (version === 0 && program.length !== 20 && program.length !== 32) return null;
  // BIP-341: a v1 output with any other program length is anyone-can-spend.
  if (version === 1 && program.length !== 32) return null;
  return { hrp: decoded.prefix, version, program };
}

export function encodeBase58Address(version: number, hash: Uint8Array): string {
  const payload = new Uint8Array(1 + hash.length);
  payload[0] = version;
  payload.set(hash, 1);
  return base58check.encode(payload);
}

export function decodeBase58Address(addr: string): { version: number; hash: Uint8Array } | null {
  try {
    const payload = base58check.decode(addr);
    if (payload.length !== 21) return null;
    return { version: payload[0]!, hash: payload.subarray(1) };
  } catch {
    return null;
  }
}

export function isValidBitcoinAddress(addr: string, net: BitcoinNetwork): boolean {
  if (net.hrp !== undefined) {
    const lower = addr.toLowerCase();
    if (lower.startsWith(`${net.hrp}1`)) {
      const sw = decodeSegwit(addr);
      return sw !== null && sw.hrp === net.hrp;
    }
  }
  const legacy = decodeBase58Address(addr);
  return (
    legacy !== null && (legacy.version === net.p2pkhVersion || legacy.version === net.p2shVersion)
  );
}

const AddressStats = z.object({
  chain_stats: z.object({ funded_txo_sum: z.number().int(), spent_txo_sum: z.number().int() }),
  mempool_stats: z.object({ funded_txo_sum: z.number().int(), spent_txo_sum: z.number().int() }),
});

const TxStatusBody = z.object({
  confirmed: z.boolean(),
  block_height: z.number().int().optional(),
  block_time: z.number().int().optional(),
});

export type BitcoinAdapterOptions = BaseAdapterOptions;

/** mempool.space answers 404 for an address or tx it has not indexed. */
const NOT_FOUND: readonly number[] = [404];

/** Spendable balance the mempool.space address stats describe: confirmed plus mempool delta. */
export function balanceFromStats(stats: z.infer<typeof AddressStats>): bigint {
  const confirmed =
    BigInt(stats.chain_stats.funded_txo_sum) - BigInt(stats.chain_stats.spent_txo_sum);
  const unconfirmed =
    BigInt(stats.mempool_stats.funded_txo_sum) - BigInt(stats.mempool_stats.spent_txo_sum);
  const total = confirmed + unconfirmed;
  return total < 0n ? 0n : total;
}

export class BitcoinAdapter extends BaseAdapter<'bitcoin'> {
  constructor(opts: BitcoinAdapterOptions = {}) {
    super('bitcoin', opts);
  }

  /**
   * `secp256k1` keys produce P2WPKH (or P2PKH where the network has no segwit).
   * `secp256k1-tr` keys are 32-byte x-only *output* keys: the taproot tweak is
   * applied by the signing core, so the adapter never sees the internal key.
   */
  deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    const net = networkOf(this.requireChain(chainId));
    requireCurve(pub, 'secp256k1', 'secp256k1-tr');
    const bytes = publicKeyBytes(pub);

    if (pub.curve === 'secp256k1-tr') {
      if (bytes.length !== 32)
        throw new UnsupportedKeyError('taproot key must be a 32-byte x-only key');
      if (net.hrp === undefined)
        throw new UnsupportedKeyError(`${chainId} has no segwit, so no taproot`);
      return encodeSegwit(net.hrp, 1, bytes);
    }

    const h160 = hash160(secp256k1Compressed(bytes));
    if (net.hrp === undefined) return encodeBase58Address(net.p2pkhVersion, h160);
    return encodeSegwit(net.hrp, 0, h160);
  }

  validateAddress(addr: string, chainId: ChainId): boolean {
    return isValidBitcoinAddress(addr, networkOf(this.requireChain(chainId)));
  }

  private get<T>(chainId: ChainId, path: string, schema: z.ZodType<T>): Promise<T | null> {
    return withFailover(this.rpc, chainId, this.rest(path, schema, NOT_FOUND));
  }

  async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    if (!this.validateAddress(addr, chainId))
      throw new TypeError(`invalid address ${addr} for ${chainId}`);
    const statsFor = this.rest(`/address/${encodeURIComponent(addr)}`, AddressStats, NOT_FOUND);
    const { value, provenance } = preferIndexedSide(
      await withCrossCheck(
        this.rpc,
        chainId,
        async (base) => {
          const stats = await statsFor(base);
          return stats === null ? null : balanceFromStats(stats).toString();
        },
        { equal: (a, b) => a === b, describe: (v) => v ?? '0' },
      ),
    );
    if (value === null) throw new Error(`address endpoint returned 404 for ${addr} on ${chainId}`);
    return [nativeHolding(chain, value, provenance)];
  }

  async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.requireChain(chainId);
    if (!/^[0-9a-fA-F]{64}$/.test(hash)) return { state: 'unknown' };
    const body = await this.get(chainId, `/tx/${hash}/status`, TxStatusBody);
    if (body === null) return { state: 'unknown' };
    if (!body.confirmed) return { state: 'pending' };
    if (body.block_height === undefined) return { state: 'unknown' };
    return {
      state: 'confirmed',
      blockNumber: body.block_height,
      ...(body.block_time !== undefined ? { timestampMs: body.block_time * 1000 } : {}),
    };
  }
}

export function createBitcoinAdapter(opts?: BitcoinAdapterOptions): BitcoinAdapter {
  return new BitcoinAdapter(opts);
}
