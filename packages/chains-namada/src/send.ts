/**
 * Namada transparent transfer: the same Borsh/protobuf wire construction the
 * Rust core implements independently from checked fields. The encoder here is
 * used to validate signed bytes byte-for-byte before broadcast and to pin the
 * core's output in tests; it never signs in production flows.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { z } from 'zod';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';

import {
  NAMADA_HOUSEFIRE,
  NATIVE_CHAIN_ID,
  NAM_TOKEN,
  namadaAddressBytes,
  type NamadaAdapter,
} from './namada.js';

const TRANSFER_TAG = 'tx_transfer.wasm';
/** Parameters internal account (`InternalAddress::Parameters`, raw disc 4). */
const PARAMETERS_ADDR = 'tnam1pyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc536j8';
const GasPriceEntry = z.object({
  token: z.string().max(64),
  minDenomAmount: z.string().regex(/^\d{1,39}$/),
});
const IndexerParameters = z.object({
  nativeTokenAddress: z.string().max(64).optional(),
  checksums: z.record(z.string().max(64), z.string().regex(/^[0-9a-f]{64}$/)),
});

const Tnam = z.string().regex(/^tnam1[02-9ac-hj-np-z]{40}$/);
const Hash32 = z.string().regex(/^[0-9a-f]{64}$/);
const Salt = z.string().regex(/^[0-9a-f]{16}$/);
const CanonicalAmount = z.string().regex(/^(0|[1-9][0-9]*)$/);

/** Mirrors the Rust `NamadaTx` (serde camelCase, deny_unknown_fields). */
export const NamadaTx = z.strictObject({
  chainId: z.literal(NAMADA_HOUSEFIRE),
  from: Tnam,
  to: Tnam,
  namnam: CanonicalAmount,
  token: Tnam,
  feeToken: Tnam,
  feePerGas: CanonicalAmount,
  gasLimit: z.number().int().positive().max(1_000_000),
  wasmCodeHash: Hash32,
  timestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}\+00:00$/),
  codeSalt: Salt,
  dataSalt: Salt,
});
export type NamadaTx = z.infer<typeof NamadaTx>;

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};
const u32le = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const u64le = (n: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
};
const borshStr = (s: string) => concat(u32le(s.length), new TextEncoder().encode(s));
/** Address borsh enum: Established = 0, Implicit = 1 (raw payload discs are 1 and 0). */
const addressBorsh = (addr: string): Uint8Array => {
  const raw = namadaAddressBytes(addr);
  if (!raw) throw new Error(`invalid namada address ${addr}`);
  return concat(Uint8Array.of(raw[0] === 0 ? 1 : 0), raw.subarray(1));
};
const amountBorsh = (v: bigint) => concat(u64le(v), new Uint8Array(24));
const denominatedBorsh = (v: bigint) => concat(amountBorsh(v), Uint8Array.of(6));

function transferData(tx: NamadaTx): Uint8Array {
  const account = (owner: string) => concat(addressBorsh(owner), addressBorsh(tx.token));
  const amt = denominatedBorsh(BigInt(tx.namnam));
  return concat(
    u32le(1),
    account(tx.from),
    amt,
    u32le(1),
    account(tx.to),
    amt,
    Uint8Array.of(0), // shielded_section_hash: None
  );
}

function codeSection(tx: NamadaTx): Uint8Array {
  return concat(
    Uint8Array.of(2),
    hexToBytes(tx.codeSalt),
    Uint8Array.of(0),
    hexToBytes(tx.wasmCodeHash),
    Uint8Array.of(1),
    borshStr(TRANSFER_TAG),
  );
}
/** The one non-borsh hash: Code hashes over salt || hash || tag bytes. */
function codeSectionHash(tx: NamadaTx): Uint8Array {
  return sha256(
    concat(
      Uint8Array.of(2),
      hexToBytes(tx.codeSalt),
      hexToBytes(tx.wasmCodeHash),
      Uint8Array.of(1),
      borshStr(TRANSFER_TAG),
    ),
  );
}
function dataSection(tx: NamadaTx): Uint8Array {
  const data = transferData(tx);
  return concat(Uint8Array.of(0), hexToBytes(tx.dataSalt), u32le(data.length), data);
}

function headerBorsh(tx: NamadaTx, wrapperPk: Uint8Array | null): Uint8Array {
  const parts = [
    borshStr(NATIVE_CHAIN_ID[tx.chainId]!),
    Uint8Array.of(0), // expiration: None
    borshStr(tx.timestamp),
    u32le(1),
    codeSectionHash(tx),
    sha256(dataSection(tx)),
    new Uint8Array(32), // memo hash of the empty memo
    Uint8Array.of(0), // atomic: false
  ];
  if (wrapperPk) {
    parts.push(
      Uint8Array.of(1), // TxType::Wrapper
      denominatedBorsh(BigInt(tx.feePerGas)),
      addressBorsh(tx.feeToken),
      Uint8Array.of(0),
      wrapperPk,
      u64le(BigInt(tx.gasLimit)),
    );
  } else {
    parts.push(Uint8Array.of(0)); // TxType::Raw
  }
  return concat(...parts);
}
const headerHash = (tx: NamadaTx, wrapperPk: Uint8Array | null) =>
  sha256(concat(Uint8Array.of(6), headerBorsh(tx, wrapperPk)));

function authBorsh(targets: Uint8Array[], signer: Uint8Array, sig64: Uint8Array): Uint8Array {
  // signatures: BTreeMap<u8, common::Signature> — one entry, key 0, value = 0x00 || sig.
  return concat(u32le(targets.length), ...targets, signer, u32le(1), Uint8Array.of(0, 0), sig64);
}
/** sha256 over the borsh Authorization with no pubkeys and no signatures. */
function rawSigHash(targets: Uint8Array[]): Uint8Array {
  return sha256(concat(u32le(targets.length), ...targets, Uint8Array.of(1), u32le(0), u32le(0)));
}

export interface SignedTransferParts {
  wire: Uint8Array;
  wrapperHash: Uint8Array;
  /** Absolute offsets of the two 64-byte signatures inside `wire`. */
  innerSigOffset: number;
  wrapperSigOffset: number;
}

/** Byte-exact mirror of the core's `NamadaTx::assemble`. */
export function encodeSignedTransfer(
  txInput: NamadaTx,
  innerSig: Uint8Array,
  wrapperSig: Uint8Array,
  pub: Uint8Array,
): SignedTransferParts {
  const tx = NamadaTx.parse(txInput);
  if (innerSig.length !== 64 || wrapperSig.length !== 64 || pub.length !== 32)
    throw new Error('signatures must be 64 bytes and the public key 32');
  if (namadaAddressBytes(tx.from) === undefined || namadaAddressBytes(tx.to) === undefined)
    throw new Error('invalid namada address');

  const rawHeaderHash = headerHash(tx, null);
  const innerAuth = concat(
    Uint8Array.of(3),
    authBorsh([rawHeaderHash], concat(Uint8Array.of(0), addressBorsh(tx.from)), innerSig),
  );
  const sectionHashes = [
    headerHash(tx, pub),
    codeSectionHash(tx),
    sha256(dataSection(tx)),
    sha256(innerAuth),
  ];
  const wrapperAuth = concat(
    Uint8Array.of(3),
    authBorsh(sectionHashes, concat(Uint8Array.of(1), u32le(1), Uint8Array.of(0), pub), wrapperSig),
  );

  const borsh = concat(
    headerBorsh(tx, pub),
    u32le(4),
    codeSection(tx),
    dataSection(tx),
    innerAuth,
    wrapperAuth,
  );
  const len = borsh.length;
  const varint: number[] = [];
  let v = len;
  do {
    let byte = v & 0x7f;
    v = Math.floor(v / 128);
    if (v > 0) byte |= 0x80;
    varint.push(byte);
  } while (v > 0);
  const wire = concat(Uint8Array.of(0x0a, ...varint), borsh);
  // Offsets: wire prefix (1 + varint) + header + sections len + code + data + 1 + auth prefix
  const wirePrefix = 1 + varint.length;
  const head = wirePrefix + headerBorsh(tx, pub).length + 4;
  const innerAuthStart = head + codeSection(tx).length + dataSection(tx).length;
  const innerSigOffset = innerAuthStart + 1 + 4 + 32 + 1 + 21 + 4 + 1 + 1;
  const wrapperSigOffset =
    innerAuthStart + innerAuth.length + 1 + 4 + 4 * 32 + 1 + 4 + 33 + 4 + 1 + 1;
  return { wire, wrapperHash: headerHash(tx, pub), innerSigOffset, wrapperSigOffset };
}

/** sha256 of the wrapper header section: the tx id Namada indexes. */
export function transferHash(tx: NamadaTx, pub: Uint8Array): string {
  return bytesToHex(headerHash(NamadaTx.parse(tx), pub));
}

/** The inner (raw-header) and wrapper sighashes the signer sees. */
export function sighashes(
  tx: NamadaTx,
  innerSig: Uint8Array,
  pub: Uint8Array,
): { inner: string; wrapper: string } {
  const parsed = NamadaTx.parse(tx);
  const rawHeaderHash = headerHash(parsed, null);
  const innerAuth = concat(
    Uint8Array.of(3),
    authBorsh([rawHeaderHash], concat(Uint8Array.of(0), addressBorsh(parsed.from)), innerSig),
  );
  const targets = [
    headerHash(parsed, pub),
    codeSectionHash(parsed),
    sha256(dataSection(parsed)),
    sha256(innerAuth),
  ];
  return {
    inner: bytesToHex(rawSigHash([rawHeaderHash])),
    wrapper: bytesToHex(rawSigHash(targets)),
  };
}

const AbciValue = z.object({
  code: z.number().int(),
  value: z.string().max(8192).nullish(),
  log: z.string().max(4096).optional(),
});

/** DateTimeUtc borsh shape: RFC3339, exactly nine fractional digits, +00:00. */
export function namadaTimestamp(now = new Date()): string {
  return now.toISOString().replace(/\.(\d{3})Z$/, '.$1000000+00:00');
}

export async function prepareNamada(
  adapter: NamadaAdapter,
  intent: TxIntent,
  from: string,
  pub: Uint8Array,
  now = new Date(),
): Promise<{ unsigned: NamadaTx; simulation: Simulation }> {
  if (
    intent.chainId !== NAMADA_HOUSEFIRE ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${NAMADA_HOUSEFIRE}:native`
  )
    throw new Error('Only native NAM transfers on housefire are enabled');
  if (intent.to === from) throw new Error('Self-transfers are refused');

  // The transfer wasm hash is chain state; read it from the chain, falling
  // back to the indexer parameters (mainnet) when the RPC cannot serve it.
  let wasmCodeHash: string | undefined;
  let indexerFeePerGas: string | undefined;
  try {
    await adapter.withNode(intent.chainId, async (call) => {
      const res = await call(
        'abci_query',
        {
          path: `/shell/value/#${PARAMETERS_ADDR}/wasm/hash/${TRANSFER_TAG}`,
          data: '',
          height: '0',
          prove: false,
        },
        AbciValue,
      );
      if (res.code !== 0 || !res.value) throw new Error('transfer wasm hash is not in storage');
      const bytes = Uint8Array.from(Buffer.from(res.value, 'base64'));
      if (bytes.length !== 32) throw new Error('unexpected wasm hash length');
      wasmCodeHash = bytesToHex(bytes);
    });
  } catch {
    const params = await adapter.indexerGet(
      intent.chainId,
      '/api/v1/chain/parameters',
      IndexerParameters,
    );
    wasmCodeHash = params.checksums[TRANSFER_TAG];
    if (params.nativeTokenAddress && params.nativeTokenAddress !== NAM_TOKEN)
      throw new Error('Unexpected native token address');
  }
  if (!wasmCodeHash) throw new Error('Could not resolve the transfer wasm hash');
  try {
    const gas = await adapter.indexerGet(
      intent.chainId,
      `/api/v1/gas-price/${NAM_TOKEN}`,
      z.array(GasPriceEntry),
    );
    const price = gas.find((g) => g.token === NAM_TOKEN)?.minDenomAmount;
    if (price !== undefined && price !== '0') indexerFeePerGas = price;
  } catch {
    // Gas price lookup is advisory; the protocol floor of 1 namnam applies.
  }
  const feePerGas = indexerFeePerGas ?? '1';
  const gasLimit = 50_000;

  const unsigned = NamadaTx.parse({
    chainId: intent.chainId,
    from,
    to: intent.to,
    namnam: intent.amount,
    token: NAM_TOKEN,
    feeToken: NAM_TOKEN,
    feePerGas,
    gasLimit,
    wasmCodeHash,
    timestamp: namadaTimestamp(now),
    codeSalt: bytesToHex(crypto.getRandomValues(new Uint8Array(8))),
    dataSalt: bytesToHex(crypto.getRandomValues(new Uint8Array(8))),
  });

  const holdings = await adapter.getBalances(from, intent.chainId);
  const balance = BigInt(holdings[0]?.amount ?? '0');
  const fee = BigInt(feePerGas) * BigInt(gasLimit);
  const total = BigInt(intent.amount) + fee;
  const error = balance < total ? 'Balance does not cover the transfer and fee' : undefined;
  return {
    unsigned,
    simulation: {
      ok: error === undefined,
      assetDeltas: [
        { assetRef: intent.asset, amount: `-${intent.amount}` },
        { assetRef: intent.asset, amount: `-${fee}` },
      ],
      fee: { assetRef: intent.asset, amount: fee.toString() },
      warnings: [],
      ...(error ? { error } : {}),
    },
  };
}

/**
 * Rebuild the expected wire from the checked fields plus the two signatures
 * spliced out of the signed bytes; any other byte that differs is tampering.
 * Also verify both ed25519 signatures against the digests the fields imply.
 */
export function namadaApprovalValid(tx: NamadaTx, wireHex: string, pub: Uint8Array): boolean {
  const parsed = NamadaTx.parse(tx);
  const hex = wireHex.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) return false;
  const template = encodeSignedTransfer(parsed, new Uint8Array(64), new Uint8Array(64), pub);
  const bytes = hexToBytes(hex);
  if (bytes.length !== template.wire.length) return false;
  const innerSig = bytes.subarray(template.innerSigOffset, template.innerSigOffset + 64);
  const wrapperSig = bytes.subarray(template.wrapperSigOffset, template.wrapperSigOffset + 64);
  const rebuilt = encodeSignedTransfer(parsed, innerSig, wrapperSig, pub);
  if (bytesToHex(rebuilt.wire) !== hex) return false;
  const hashes = sighashes(parsed, innerSig, pub);
  return (
    ed25519.verify(innerSig, hexToBytes(hashes.inner), pub) &&
    ed25519.verify(wrapperSig, hexToBytes(hashes.wrapper), pub)
  );
}

const BroadcastResult = z.object({
  code: z.number().int(),
  hash: z.string().max(128).optional(),
  height: z.string().regex(/^\d*$/).optional(),
  log: z.string().max(4096).optional(),
});
const BroadcastCommit = z.object({
  check_tx: BroadcastResult,
  tx_result: BroadcastResult,
  hash: z.string().max(128).optional(),
});

export async function broadcastNamada(
  adapter: NamadaAdapter,
  tx: NamadaTx,
  wireHex: string,
  pub: Uint8Array,
): Promise<string> {
  if (!namadaApprovalValid(tx, wireHex, pub))
    throw new Error('Signed bytes are not this NAM transfer');
  const bytes = hexToBytes(wireHex.replace(/^0x/, ''));
  const b64 = btoa(String.fromCharCode(...bytes));
  const res = await adapter.withNode(tx.chainId, (call) =>
    call('broadcast_tx_commit', { tx: b64 }, BroadcastCommit),
  );
  const check = res.check_tx;
  if (check.code !== 0)
    throw new Error(`Mempool rejected the transfer: ${check.log ?? check.code}`);
  if (res.tx_result.code !== 0)
    throw new Error(`Transfer failed on-chain: ${res.tx_result.log ?? res.tx_result.code}`);
  const hash = transferHash(tx, pub);
  if (res.hash !== undefined && res.hash.toLowerCase() !== hash)
    throw new Error('Node reported a different transaction hash');
  return hash;
}

/** Wrapper transactions carry no expiration; status is a direct lookup. */
export async function namadaTransferStatus(
  adapter: NamadaAdapter,
  tx: NamadaTx,
  hash: string,
): Promise<TxStatus> {
  return adapter.status(hash, tx.chainId);
}
