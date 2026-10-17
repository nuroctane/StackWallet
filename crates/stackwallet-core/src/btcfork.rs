//! Intent-bound P2PKH sends on the Bitcoin fork family: Bitcoin Cash, Dash,
//! Zcash (transparent t-addresses only), DefiChain and Verus (transparent
//! t-addresses only). Every fork shares Bitcoin's wire model; the per-network
//! table below carries the address prefixes, the signature hash algorithm and
//! the transaction framing. Signing is enabled on the testnets only.
use crate::{
    evm,
    intent::{TxIntent, TxIntentKind},
    CoreError, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const BCH_TESTNET: &str = "btcfork:bch-testnet";
pub const DASH_TESTNET: &str = "btcfork:dash-testnet";
pub const ZCASH_TESTNET: &str = "btcfork:zcash-testnet";
pub const DEFICHAIN_TESTNET: &str = "btcfork:defichain-testnet";
pub const VERUS_TESTNET: &str = "btcfork:verus-testnet";

const DUST: u64 = 546;
const MAX_FEE: u64 = 100_000;
const MAX_EXPIRY: u32 = 500_000_000;
/// Zcash v4 header: overwintered bit set, transaction version 4.
const ZCASH_V4_HEADER: u32 = 0x8000_0004;
const ZCASH_V4_GROUP: u32 = 0x892f_2085;
/// Consensus branch id used in the ZIP-143 personalization. NU6.3 is the
/// current Zcash network upgrade (mainnet activation 2026-07-28); the branch
/// id rotates at every network upgrade and must be bumped when Zcash ships
/// the next one. Verified against a live mainnet v4 transparent transaction.
const ZCASH_BRANCH_NU6_3: u32 = 0x37a5_165b;
/// Verus signs v4 transactions with the Sapling branch id.
const VERUS_BRANCH_SAPLING: u32 = 0x76b8_09bb;
const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_FORKID: u8 = 0x41;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sighash {
    /// Pre-SegWit SIGHASH_ALL: the modified transaction serialization is
    /// double-SHA256 hashed. Dash, DefiChain.
    Legacy,
    /// BIP-143 digest with SIGHASH_FORKID (Bitcoin Cash replay protection).
    ForkId,
    /// ZIP-143 BLAKE2b-256 digest for Zcash v4 transactions. Zcash, Verus.
    Zip143 { branch: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Bitcoin serialization: version, inputs, outputs, locktime.
    Plain { version: u32 },
    /// Zcash v4: overwintered header, version group id, expiry height and
    /// empty shielded sections appended after the outputs.
    ZcashV4 { branch: u32 },
}

#[derive(Debug, Clone, Copy)]
struct Fork {
    chain: &'static str,
    p2pkh: &'static [u8],
    p2sh: &'static [u8],
    cashaddr_hrp: Option<&'static str>,
    sighash: Sighash,
    format: Format,
    max_money: u64,
}

const FORKS: &[Fork] = &[
    Fork {
        chain: BCH_TESTNET,
        p2pkh: &[0x6f],
        p2sh: &[0xc4],
        cashaddr_hrp: Some("bchtest"),
        sighash: Sighash::ForkId,
        format: Format::Plain { version: 2 },
        max_money: 2_100_000_000_000_000,
    },
    Fork {
        chain: DASH_TESTNET,
        p2pkh: &[0x8c],
        p2sh: &[0x13],
        cashaddr_hrp: None,
        sighash: Sighash::Legacy,
        format: Format::Plain { version: 3 },
        max_money: 2_100_000_000_000_000,
    },
    Fork {
        chain: ZCASH_TESTNET,
        p2pkh: &[0x1d, 0x25],
        p2sh: &[0x1c, 0xba],
        cashaddr_hrp: None,
        sighash: Sighash::Zip143 {
            branch: ZCASH_BRANCH_NU6_3,
        },
        format: Format::ZcashV4 {
            branch: ZCASH_BRANCH_NU6_3,
        },
        max_money: 2_100_000_000_000_000,
    },
    Fork {
        chain: DEFICHAIN_TESTNET,
        p2pkh: &[0x0f],
        p2sh: &[0x80],
        cashaddr_hrp: None,
        sighash: Sighash::Legacy,
        format: Format::Plain { version: 1 },
        max_money: 120_000_000_000_000_000,
    },
    Fork {
        chain: VERUS_TESTNET,
        p2pkh: &[0x3c],
        p2sh: &[0x55],
        cashaddr_hrp: None,
        sighash: Sighash::Zip143 {
            branch: VERUS_BRANCH_SAPLING,
        },
        format: Format::ZcashV4 {
            branch: VERUS_BRANCH_SAPLING,
        },
        max_money: 2_100_000_000_000_000,
    },
];

fn fork(chain: &str) -> Result<&'static Fork> {
    FORKS
        .iter()
        .find(|f| f.chain == chain)
        .ok_or_else(|| invalid("unsupported chain; only Bitcoin-fork testnet sends are enabled"))
}

pub fn check_chain(chain: &str) -> Result<()> {
    fork(chain).map(|_| ())
}

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Bitcoin fork transfer",
        reason: reason.into(),
    }
}

fn number(text: &str, max: u64, what: &str) -> Result<u64> {
    let n = text
        .parse::<u64>()
        .map_err(|_| invalid(format!("invalid {what}")))?;
    if n.to_string() != text || n > max {
        return Err(invalid(format!("non-canonical or out-of-range {what}")));
    }
    Ok(n)
}

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(bytes)).into()
}

/// Single-shot BLAKE2b-256 with a 16-byte personalization (ZIP-143). The
/// blake2 crate's Mac variant processes a zero key block even for an empty
/// key, and its parameterized core has no public wrapper, so the compression
/// function is spelled out here; it is pinned against @noble/hashes in tests.
fn blake2b256(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    const SIGMA: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];
    let mut h = IV;
    // Parameter block: digest 32, key 0, fanout 1, depth 1; personalization.
    h[0] ^= 0x0101_0020;
    h[6] ^= u64::from_le_bytes(personal[..8].try_into().expect("8 bytes"));
    h[7] ^= u64::from_le_bytes(personal[8..].try_into().expect("8 bytes"));
    let mut t = 0u64;
    let mut blocks_vec: Vec<&[u8]> = data.chunks(128).collect();
    if blocks_vec.is_empty() {
        blocks_vec.push(&[]);
    }
    let mut blocks = blocks_vec.into_iter().peekable();
    loop {
        let block = blocks.next().expect("at least one block");
        let last = blocks.peek().is_none();
        let mut padded = [0u8; 128];
        padded[..block.len()].copy_from_slice(block);
        t = t.wrapping_add(block.len() as u64);
        let mut m = [0u64; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u64::from_le_bytes(padded[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= t;
        if last {
            v[14] = !v[14];
        }
        fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        }
        for round in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[round[0]], m[round[1]]);
            g(&mut v, 1, 5, 9, 13, m[round[2]], m[round[3]]);
            g(&mut v, 2, 6, 10, 14, m[round[4]], m[round[5]]);
            g(&mut v, 3, 7, 11, 15, m[round[6]], m[round[7]]);
            g(&mut v, 0, 5, 10, 15, m[round[8]], m[round[9]]);
            g(&mut v, 1, 6, 11, 12, m[round[10]], m[round[11]]);
            g(&mut v, 2, 7, 8, 13, m[round[12]], m[round[13]]);
            g(&mut v, 3, 4, 9, 14, m[round[14]], m[round[15]]);
        }
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
        if last {
            break;
        }
    }
    let mut out = [0u8; 32];
    for (i, w) in h[..4].iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn zip143_hash(personal: &[u8; 16], bytes: &[u8]) -> [u8; 32] {
    blake2b256(personal, bytes)
}

// ---------------------------------------------------------------- addresses

fn base58check_encode(prefix: &[u8], hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(prefix.len() + 24);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(hash);
    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}

fn base58check_decode(addr: &str) -> Option<(Vec<u8>, [u8; 20])> {
    let payload = bs58::decode(addr).into_vec().ok()?;
    if payload.len() < 25 || payload.len() > 26 {
        return None;
    }
    let (body, checksum) = payload.split_at(payload.len() - 4);
    if sha256d(body)[..4] != *checksum {
        return None;
    }
    let payload = body.to_vec();
    let split = payload.len() - 20;
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&payload[split..]);
    Some((payload[..split].to_vec(), hash))
}

const CASHADDR_ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn cashaddr_polymod(values: impl IntoIterator<Item = u8>) -> u64 {
    const GENERATORS: [u64; 5] = [
        0x98f2bc8e61,
        0x79b76d99e2,
        0xf33e5fb3c4,
        0xae2eabe2a8,
        0x1e4f43e470,
    ];
    let mut c = 1u64;
    for v in values {
        let top = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ u64::from(v);
        for (i, g) in GENERATORS.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                c ^= g;
            }
        }
    }
    c ^ 1
}

fn cashaddr_expand(hrp: &str) -> Vec<u8> {
    hrp.bytes()
        .map(|b| b & 0x1f)
        .chain(std::iter::once(0))
        .collect()
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to) - 1;
    for &b in data {
        let v = u32::from(b);
        if v >> from != 0 {
            return None;
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// CashAddr (BCH): version byte 0x00 P2PKH / 0x08 P2SH, 20-byte hash.
fn cashaddr_encode(hrp: &str, p2sh: bool, hash: &[u8; 20]) -> String {
    let version = if p2sh { 0x08 } else { 0x00 };
    let mut payload = vec![version];
    payload.extend_from_slice(hash);
    let mut five = convert_bits(&payload, 8, 5, true).expect("byte input");
    let mut checksum = cashaddr_expand(hrp);
    checksum.extend_from_slice(&five);
    checksum.extend_from_slice(&[0; 8]);
    let modulo = cashaddr_polymod(checksum);
    for i in 0..8 {
        five.push(((modulo >> (5 * (7 - i))) & 0x1f) as u8);
    }
    let body: String = five
        .iter()
        .map(|v| CASHADDR_ALPHABET[*v as usize] as char)
        .collect();
    format!("{hrp}:{body}")
}

fn cashaddr_decode(addr: &str) -> Option<(String, bool, [u8; 20])> {
    if addr.len() != addr.chars().count()
        || addr.to_lowercase() != addr && addr.to_uppercase() != addr
    {
        return None;
    }
    let addr = addr.to_lowercase();
    let (hrp, body) = addr.rsplit_once(':')?;
    if hrp.is_empty() || body.len() < 8 {
        return None;
    }
    let mut values = Vec::with_capacity(body.len());
    for c in body.bytes() {
        let v = CASHADDR_ALPHABET.iter().position(|&a| a == c)?;
        values.push(v as u8);
    }
    let mut full = cashaddr_expand(hrp);
    full.extend_from_slice(&values);
    if cashaddr_polymod(full) != 0 {
        return None;
    }
    let payload = convert_bits(&values[..values.len() - 8], 5, 8, false)?;
    if payload.len() != 21 {
        return None;
    }
    let version = payload[0];
    let p2sh = match version {
        0x00 => false,
        0x08 => true,
        _ => return None,
    };
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&payload[1..]);
    Some((hrp.to_string(), p2sh, hash))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
}

impl Script {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Script::P2pkh(h) => {
                let mut s = Vec::with_capacity(25);
                s.extend_from_slice(&[0x76, 0xa9, 0x14]);
                s.extend_from_slice(h);
                s.extend_from_slice(&[0x88, 0xac]);
                s
            }
            Script::P2sh(h) => {
                let mut s = Vec::with_capacity(23);
                s.extend_from_slice(&[0xa9, 0x14]);
                s.extend_from_slice(h);
                s.push(0x87);
                s
            }
        }
    }
}

fn decode_address(net: &Fork, addr: &str) -> Result<Script> {
    if let Some(hrp) = net.cashaddr_hrp {
        if let Some((prefix, p2sh, hash)) = cashaddr_decode(addr) {
            if prefix != hrp {
                return Err(invalid("cashaddr prefix differs from network"));
            }
            return Ok(if p2sh {
                Script::P2sh(hash)
            } else {
                Script::P2pkh(hash)
            });
        }
        // Legacy base58 stays accepted so BCH copies from any source still work.
    }
    let (prefix, hash) =
        base58check_decode(addr).ok_or_else(|| invalid("invalid address encoding"))?;
    if prefix == net.p2pkh {
        Ok(Script::P2pkh(hash))
    } else if prefix == net.p2sh {
        Ok(Script::P2sh(hash))
    } else {
        Err(invalid("address prefix differs from network"))
    }
}

/// Address for the signing network from a 33-byte compressed SEC1 key. BCH
/// returns CashAddr; every other fork returns base58check P2PKH.
pub fn address(chain: &str, public: &[u8]) -> Result<String> {
    let net = fork(chain)?;
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| invalid("invalid compressed key"))?;
    if key.to_encoded_point(true).as_bytes() != public {
        return Err(invalid("non-canonical compressed key"));
    }
    let hash: [u8; 20] = ripemd::Ripemd160::digest(Sha256::digest(public)).into();
    Ok(match net.cashaddr_hrp {
        Some(hrp) => cashaddr_encode(hrp, false, &hash),
        None => base58check_encode(net.p2pkh, &hash),
    })
}

// ------------------------------------------------------------- transactions

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BtcForkInput {
    pub txid: String,
    pub vout: u32,
    pub previous_tx_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BtcForkTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    pub satoshis: String,
    pub fee: String,
    pub inputs: Vec<BtcForkInput>,
    /// Zcash/Verus v4 expiry height; forbidden on the other forks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_height: Option<u32>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.bytes.len())
            .ok_or_else(|| invalid("funding transaction truncated"))?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn varint(&mut self) -> Result<u64> {
        match self.u8()? {
            0xff => self.u64(),
            0xfe => Ok(u64::from(self.u32()?)),
            0xfd => {
                let b = self.take(2)?;
                Ok(u64::from(u16::from_le_bytes(
                    b.try_into().expect("2 bytes"),
                )))
            }
            n => Ok(u64::from(n)),
        }
    }
}

fn varint(n: u64, out: &mut Vec<u8>) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn txid_le(txid: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(txid).map_err(|_| invalid("invalid txid"))?;
    if bytes.len() != 32 {
        return Err(invalid("invalid txid"));
    }
    let mut le = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        le[31 - i] = *b;
    }
    Ok(le)
}

fn parse_funding(raw: &[u8], vout: u32) -> Result<(u64, Vec<u8>)> {
    let mut c = Cursor { bytes: raw, pos: 0 };
    let version = c.u32()?;
    let zcash_v4 = version == ZCASH_V4_HEADER;
    if version & 0x8000_0000 != 0 && !zcash_v4 {
        return Err(invalid("unsupported funding transaction version"));
    }
    if !zcash_v4 && (version >> 16) != 0 {
        return Err(invalid("DIP2 special funding transactions are unsupported"));
    }
    if zcash_v4 && c.u32()? != ZCASH_V4_GROUP {
        return Err(invalid("unsupported funding version group"));
    }
    let inputs = c.varint()?;
    if inputs == 0 || inputs > 65_535 {
        return Err(invalid("funding transaction has no usable inputs"));
    }
    for i in 0..inputs {
        let prev = c.take(36)?;
        if i == 0 && prev[..32].iter().all(|b| *b == 0) && prev[32..] == [0xff; 4] {
            return Err(invalid("coinbase funding is unsupported"));
        }
        let script_len = c.varint()?;
        if script_len > 10_000 {
            return Err(invalid("funding input script too large"));
        }
        c.take(script_len as usize)?;
        c.take(4)?;
    }
    let outputs = c.varint()?;
    if outputs == 0 || outputs > 65_535 || u64::from(vout) >= outputs {
        return Err(invalid("funding output missing"));
    }
    let mut found = None;
    for i in 0..outputs {
        let value = c.u64()?;
        let script_len = c.varint()?;
        if script_len > 10_000 {
            return Err(invalid("funding output script too large"));
        }
        let script = c.take(script_len as usize)?.to_vec();
        if i == u64::from(vout) {
            found = Some((value, script));
        }
    }
    let found = found.ok_or_else(|| invalid("funding output missing"))?;
    // Sprout/Sapling funding transactions append a shielded trailer after the
    // locktime; the txid check in `plan` binds those bytes, so only the plain
    // forks must be consumed exactly.
    let remaining = raw.len() - c.pos;
    if zcash_v4 {
        if remaining < 4 + 4 + 8 + 3 {
            return Err(invalid("funding transaction truncated"));
        }
    } else if remaining != 4 {
        return Err(invalid("funding transaction has trailing data"));
    }
    Ok(found)
}

struct PlanOut {
    value: u64,
    script: Script,
}

struct Plan {
    net: &'static Fork,
    unsigned_prefix: Vec<u8>,
    outputs: Vec<PlanOut>,
    fundings: Vec<(u64, Vec<u8>)>,
    inputs: Vec<(String, u32)>,
    locktime: u32,
    expiry: Option<u32>,
}

impl BtcForkTx {
    fn plan(&self) -> Result<Plan> {
        let net = fork(&self.chain_id)?;
        let from = decode_address(net, &self.from)?;
        if !matches!(from, Script::P2pkh(_)) {
            return Err(invalid("sender must be P2PKH"));
        }
        let to = decode_address(net, &self.to)?;
        if to == from {
            return Err(invalid("sender and recipient must differ"));
        }
        let satoshis = number(&self.satoshis, net.max_money, "satoshi amount")?;
        if satoshis < DUST {
            return Err(invalid("dust amount"));
        }
        let fee = number(&self.fee, MAX_FEE, "satoshi fee")?;
        if fee == 0 {
            return Err(invalid("dust amount or excessive fee"));
        }
        let expiry = match (net.format, self.expiry_height) {
            (Format::ZcashV4 { .. }, Some(h)) if (1..=MAX_EXPIRY).contains(&h) => Some(h),
            (Format::ZcashV4 { .. }, _) => return Err(invalid("expiry height required")),
            (Format::Plain { .. }, Some(_)) => {
                return Err(invalid("expiry height is not valid on this fork"))
            }
            (Format::Plain { .. }, None) => None,
        };
        if self.inputs.is_empty() || self.inputs.len() > 8 {
            return Err(invalid("expected one to eight inputs"));
        }
        let from_script = from.bytes();
        let mut seen = HashSet::new();
        let mut fundings = Vec::new();
        let mut total = 0u64;
        for input in &self.inputs {
            if input.previous_tx_hex.len() > 400_000
                || input.previous_tx_hex.len() % 2 != 0
                || !input.previous_tx_hex.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid("funding transaction too large or malformed"));
            }
            let raw =
                hex::decode(&input.previous_tx_hex).map_err(|_| invalid("invalid funding hex"))?;
            if hex::encode(sha256d(&raw).iter().rev().copied().collect::<Vec<u8>>()) != input.txid {
                return Err(invalid("funding txid differs"));
            }
            if !seen.insert((input.txid.clone(), input.vout)) {
                return Err(invalid("duplicate input"));
            }
            let (value, script) = parse_funding(&raw, input.vout)?;
            if value == 0 {
                return Err(invalid("funding output is empty"));
            }
            if script != from_script {
                return Err(invalid("funding output does not belong to signer"));
            }
            total = total
                .checked_add(value)
                .filter(|n| *n <= net.max_money)
                .ok_or_else(|| invalid("input sum exceeds monetary bounds"))?;
            fundings.push((value, script));
        }
        let change = total
            .checked_sub(satoshis)
            .and_then(|n| n.checked_sub(fee))
            .ok_or_else(|| invalid("inputs do not cover amount and fee"))?;
        if change > 0 && change < DUST {
            return Err(invalid("dust change; select different inputs or amount"));
        }
        let mut outputs = vec![PlanOut {
            value: satoshis,
            script: to,
        }];
        if change > 0 {
            outputs.push(PlanOut {
                value: change,
                script: from,
            });
        }
        let mut unsigned_prefix = Vec::new();
        match net.format {
            Format::Plain { version } => unsigned_prefix.extend_from_slice(&version.to_le_bytes()),
            Format::ZcashV4 { .. } => {
                unsigned_prefix.extend_from_slice(&ZCASH_V4_HEADER.to_le_bytes());
                unsigned_prefix.extend_from_slice(&ZCASH_V4_GROUP.to_le_bytes());
            }
        }
        Ok(Plan {
            net,
            unsigned_prefix,
            outputs,
            fundings,
            inputs: self
                .inputs
                .iter()
                .map(|i| (i.txid.clone(), i.vout))
                .collect(),
            locktime: 0,
            expiry,
        })
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        self.plan()?;
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount }
                if intent.chain_id.0 == self.chain_id
                    && *to == self.to
                    && amount.0 == self.satoshis
                    && asset.0 == format!("{}:native", self.chain_id) =>
            {
                Ok(())
            }
            _ => Err(invalid("transaction differs from intent")),
        }
    }

    fn hash_prevouts(&self, plan: &Plan) -> [u8; 32] {
        let mut buf = Vec::with_capacity(36 * plan.inputs.len());
        for (txid, vout) in &plan.inputs {
            buf.extend_from_slice(&txid_le(txid).expect("checked txid"));
            buf.extend_from_slice(&vout.to_le_bytes());
        }
        match plan.net.sighash {
            Sighash::Zip143 { .. } => zip143_hash(b"ZcashPrevoutHash", &buf),
            _ => sha256d(&buf),
        }
    }

    fn hash_sequence(&self, plan: &Plan) -> [u8; 32] {
        let buf = vec![0xffu8; 4 * plan.inputs.len()];
        match plan.net.sighash {
            Sighash::Zip143 { .. } => zip143_hash(b"ZcashSequencHash", &buf),
            _ => sha256d(&buf),
        }
    }

    fn hash_outputs(&self, plan: &Plan) -> [u8; 32] {
        let mut buf = Vec::new();
        for out in &plan.outputs {
            let script = out.script.bytes();
            buf.extend_from_slice(&out.value.to_le_bytes());
            varint(script.len() as u64, &mut buf);
            buf.extend_from_slice(&script);
        }
        match plan.net.sighash {
            Sighash::Zip143 { .. } => zip143_hash(b"ZcashOutputsHash", &buf),
            _ => sha256d(&buf),
        }
    }

    /// Signature digest for one input; also the encoding a verifier rederives.
    fn sighash(&self, plan: &Plan, index: usize) -> Result<[u8; 32]> {
        let (value, script) = &plan.fundings[index];
        let (txid, vout) = &plan.inputs[index];
        match plan.net.sighash {
            Sighash::Legacy => {
                let mut buf = plan.unsigned_prefix.clone();
                varint(plan.inputs.len() as u64, &mut buf);
                for (i, ((t, v), (_, fscript))) in
                    plan.inputs.iter().zip(&plan.fundings).enumerate()
                {
                    buf.extend_from_slice(&txid_le(t)?);
                    buf.extend_from_slice(&v.to_le_bytes());
                    if i == index {
                        varint(fscript.len() as u64, &mut buf);
                        buf.extend_from_slice(fscript);
                    } else {
                        buf.push(0);
                    }
                    buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
                }
                varint(plan.outputs.len() as u64, &mut buf);
                for out in &plan.outputs {
                    let s = out.script.bytes();
                    buf.extend_from_slice(&out.value.to_le_bytes());
                    varint(s.len() as u64, &mut buf);
                    buf.extend_from_slice(&s);
                }
                buf.extend_from_slice(&plan.locktime.to_le_bytes());
                buf.extend_from_slice(&u32::from(SIGHASH_ALL).to_le_bytes());
                Ok(sha256d(&buf))
            }
            Sighash::ForkId => {
                let mut buf = plan.unsigned_prefix.clone();
                buf.extend_from_slice(&self.hash_prevouts(plan));
                buf.extend_from_slice(&self.hash_sequence(plan));
                buf.extend_from_slice(&txid_le(txid)?);
                buf.extend_from_slice(&vout.to_le_bytes());
                varint(script.len() as u64, &mut buf);
                buf.extend_from_slice(script);
                buf.extend_from_slice(&value.to_le_bytes());
                buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
                buf.extend_from_slice(&self.hash_outputs(plan));
                buf.extend_from_slice(&plan.locktime.to_le_bytes());
                buf.extend_from_slice(&u32::from(SIGHASH_FORKID).to_le_bytes());
                Ok(sha256d(&buf))
            }
            Sighash::Zip143 { branch } => {
                let mut buf = Vec::with_capacity(300);
                buf.extend_from_slice(&ZCASH_V4_HEADER.to_le_bytes());
                buf.extend_from_slice(&ZCASH_V4_GROUP.to_le_bytes());
                buf.extend_from_slice(&self.hash_prevouts(plan));
                buf.extend_from_slice(&self.hash_sequence(plan));
                buf.extend_from_slice(&self.hash_outputs(plan));
                buf.extend_from_slice(&[0u8; 32]); // hashJoinSplits
                buf.extend_from_slice(&[0u8; 32]); // hashShieldedSpends
                buf.extend_from_slice(&[0u8; 32]); // hashShieldedOutputs
                buf.extend_from_slice(&plan.locktime.to_le_bytes());
                buf.extend_from_slice(
                    &plan
                        .expiry
                        .ok_or_else(|| invalid("expiry height required"))?
                        .to_le_bytes(),
                );
                buf.extend_from_slice(&0u64.to_le_bytes()); // valueBalance
                buf.extend_from_slice(&u32::from(SIGHASH_ALL).to_le_bytes());
                buf.extend_from_slice(&txid_le(txid)?);
                buf.extend_from_slice(&vout.to_le_bytes());
                varint(script.len() as u64, &mut buf);
                buf.extend_from_slice(script);
                buf.extend_from_slice(&value.to_le_bytes());
                buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
                let mut personal = [0u8; 16];
                personal[..12].copy_from_slice(b"ZcashSigHash");
                personal[12..].copy_from_slice(&branch.to_le_bytes());
                Ok(zip143_hash(&personal, &buf))
            }
        }
    }

    fn encode(&self, plan: &Plan, scripts: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = plan.unsigned_prefix.clone();
        varint(plan.inputs.len() as u64, &mut buf);
        for ((txid, vout), script_sig) in plan.inputs.iter().zip(scripts) {
            buf.extend_from_slice(&txid_le(txid).expect("checked txid"));
            buf.extend_from_slice(&vout.to_le_bytes());
            varint(script_sig.len() as u64, &mut buf);
            buf.extend_from_slice(script_sig);
            buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        varint(plan.outputs.len() as u64, &mut buf);
        for out in &plan.outputs {
            let s = out.script.bytes();
            buf.extend_from_slice(&out.value.to_le_bytes());
            varint(s.len() as u64, &mut buf);
            buf.extend_from_slice(&s);
        }
        buf.extend_from_slice(&plan.locktime.to_le_bytes());
        if let Format::ZcashV4 { .. } = plan.net.format {
            buf.extend_from_slice(&plan.expiry.expect("v4 expiry").to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes()); // valueBalance
            buf.push(0); // nShieldedSpend
            buf.push(0); // nShieldedOutput
            buf.push(0); // nJoinSplit
        }
        buf
    }

    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let plan = self.plan()?;
        let signing = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signer"))?;
        let public = signing.verifying_key().to_encoded_point(true);
        let signer_hash: [u8; 20] =
            ripemd::Ripemd160::digest(Sha256::digest(public.as_bytes())).into();
        if !matches!(decode_address(plan.net, &self.from)?, Script::P2pkh(h) if h == signer_hash) {
            return Err(invalid("signer differs from sender"));
        }
        let hash_type = match plan.net.sighash {
            Sighash::ForkId => SIGHASH_FORKID,
            _ => SIGHASH_ALL,
        };
        let mut scripts = Vec::with_capacity(plan.inputs.len());
        for i in 0..plan.inputs.len() {
            let digest = self.sighash(&plan, i)?;
            let (_, r, s) = evm::sign_digest(secret, &digest)?;
            let signature = k256::ecdsa::Signature::from_scalars(r, s)
                .map_err(|_| invalid("invalid signature"))?;
            let der = signature.to_der();
            let mut script = Vec::with_capacity(80);
            script.push(der.as_bytes().len() as u8 + 1);
            script.extend_from_slice(der.as_bytes());
            script.push(hash_type);
            script.push(33);
            script.extend_from_slice(public.as_bytes());
            scripts.push(script);
        }
        let wire = self.encode(&plan, &scripts);
        let txid = hex::encode(sha256d(&wire).iter().rev().copied().collect::<Vec<u8>>());
        Ok((format!("0x{}", hex::encode(wire)), txid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Vector {
        chain: &'static str,
        sender: &'static str,
        recipient: &'static str,
        funding_txid: &'static str,
        funding_hex: &'static str,
        signed: &'static str,
        txid: &'static str,
        sighash: &'static str,
        unsigned: &'static str,
    }

    // Vectors produced by .nur/btcfork-oracle and cross-checked byte-exact
    // against bitcore-lib-cash (BCH), @dashevo/dashcore-lib (Dash) and
    // bitcoinjs-lib hashForSignature (legacy sighash shared with DefiChain).
    const SECRET: [u8; 32] = [1u8; 32];
    const BCH: Vector = Vector {
        chain: BCH_TESTNET,
        sender: "bchtest:qpumqqygwcnt999fz3gp5nxjy66ckg6esvmzshj478",
        recipient: "bchtest:qr4upmst92u7sfm6vqxz29r4ug4rysdpcytc853pps",
        funding_txid: "1af227fe4235dc3a68d592e7dd872818aad2d3ae695107d068273d92816e9cb7",
        funding_hex: "020000000102020202020202020202020202020202020202020202020202020202020202020100000003515151ffffffff02a0860100000000001976a91479b000887626b294a914501a4cd226b58b23598388ac01000000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
        signed: "0200000001b79c6e81923d2768d0075169aed3d2aa182887dde792d5683adc3542fe27f21a000000006a47304402206feab89dfa79b7ae4a074773a3b09d1b94a9a865ba7b7b4926827dd924d7b7b102202fd902d25c698f38ace8928d203a3633af32017e64f216d066524c18e57abce44121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
        txid: "19d5bbd81715a243c29f325d66b15039f3a3524a51edf0ee3fe380b616446a97",
        sighash: "a08e8eb438e1df78508491bb567ab1f520f892579bfc88207d5d68b2333c126b",
        unsigned: "0200000001b79c6e81923d2768d0075169aed3d2aa182887dde792d5683adc3542fe27f21a0000000000ffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
    };
    const DASH: Vector = Vector {
        chain: DASH_TESTNET,
        sender: "yXQsTFfMUkAa7j9TeKQXn8woS8umNDzGPn",
        recipient: "yhozmHU7FQB5jjRzpHw2erMSpDUmQgQNo6",
        funding_txid: "491f679fd7bda739c982f73bed7d2f3acd11db780cbf64b1048a67ddeb764c00",
        funding_hex: "030000000102020202020202020202020202020202020202020202020202020202020202020100000003515151ffffffff02a0860100000000001976a91479b000887626b294a914501a4cd226b58b23598388ac01000000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
        signed: "0300000001004c76ebdd678a04b164bf0c78db11cd3a2f7ded3bf782c939a7bdd79f671f49000000006b483045022100e6c61009d44eed684ed2612b7daf445f013e31770e4cb4af227b8010d37ac66c0220705413f0761bc8fda7c83b9f49611aea3fb533ea78cba71d74b004226d7a57b60121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
        txid: "e9922fcfe653b1df0c43db6a0bae0df773b41196bea90c3626ad4f1881692d18",
        sighash: "ff6ba7c8e055ecfbd1cc6bbe74c50a0695f7bb0e9b515652436b399ddfca5cba",
        unsigned: "0300000001004c76ebdd678a04b164bf0c78db11cd3a2f7ded3bf782c939a7bdd79f671f490000000000ffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
    };
    const ZCASH: Vector = Vector {
        chain: ZCASH_TESTNET,
        sender: "tmLomwDqZSUb1Mvsfpjtmt4cLBA7c9tGssX",
        recipient: "tmXCuFFeKD8bWywACziRGkn1yZEgcAMBabN",
        funding_txid: "0c835c3d03b2c86326248d5e3cefccc374e767a8b59ec495874865a1b8954953",
        funding_hex: "0400008085202f890102020202020202020202020202020202020202020202020202020202020202020100000003515151ffffffff02a0860100000000001976a91479b000887626b294a914501a4cd226b58b23598388ac01000000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000bfc62d000000000000000000000000",
        signed: "0400008085202f8901534995b8a165488795c49eb5a867e774c3ccef3c5e8d242663c8b2033d5c830c000000006a47304402203b12f61694b42583554d49d0328b692d78d470607f1e0b27483ad9c6a1e5710202203beeb26d970319172a8937dc1aa36b6494d5cf9751258408b73480ca6360eace0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000bfc62d000000000000000000000000",
        txid: "9db086153f3a3644aaba989e015e9b7fca68da3c56931b059de1acb7c87f3657",
        sighash: "4a874883ad478842c9065fb5ca8ef27b92395ede9822f6c695e82f016cbb3b38",
        unsigned: "0400008085202f8901534995b8a165488795c49eb5a867e774c3ccef3c5e8d242663c8b2033d5c830c0000000000ffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000bfc62d000000000000000000000000",
    };
    const DEFICHAIN: Vector = Vector {
        chain: DEFICHAIN_TESTNET,
        sender: "7EAUNgQLjCF3tYidasmhATvTm5hrXRsDHw",
        recipient: "7QZbgiD6VrFZWZ1AkrJC3BL79AGrXBVjHP",
        funding_txid: "71765d2cf44f2ab794ad62fff3bf4e345eca77af8e87cbbdad1b4c015f4e7af2",
        funding_hex: "010000000102020202020202020202020202020202020202020202020202020202020202020100000003515151ffffffff02a0860100000000001976a91479b000887626b294a914501a4cd226b58b23598388ac01000000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
        signed: "0100000001f27a4e5f014c1badbdcb878eaf77ca5e344ebff3ff62ad94b72a4ff42c5d7671000000006a4730440220298f1a190ec7a47c80b8286e2d9d605a55e16cb1b2afd2c3c37445cff908122902207c676aeb593270855e9c6e1b90925f3c5cde991a28de5e7a55a872bfe7fe34290121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
        txid: "ec74809bf7f6c5c95690db09dd20f6289a77bbec06d030d6ed651f3be1b44ffe",
        sighash: "8dc95e756a701486e3f2b47e65264ac6097788c985337c8f385ac8b4bbe7d1ac",
        unsigned: "0100000001f27a4e5f014c1badbdcb878eaf77ca5e344ebff3ff62ad94b72a4ff42c5d76710000000000ffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
    };
    const VERUS: Vector = Vector {
        chain: VERUS_TESTNET,
        sender: "RLNcgZpJgK6Uh3zXgkm2z7As5nJJVt6HXr",
        recipient: "RWmjzbd4Sy6zK4H4rjHXrpaWTrsJYRr6Nn",
        funding_txid: "0c835c3d03b2c86326248d5e3cefccc374e767a8b59ec495874865a1b8954953",
        funding_hex: "0400008085202f890102020202020202020202020202020202020202020202020202020202020202020100000003515151ffffffff02a0860100000000001976a91479b000887626b294a914501a4cd226b58b23598388ac01000000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000bfc62d000000000000000000000000",
        signed: "0400008085202f8901534995b8a165488795c49eb5a867e774c3ccef3c5e8d242663c8b2033d5c830c000000006b483045022100cfdacfa91d8f6f1559164355201a915a065b838f42803d31586110ba1a948b9902204d9695a00b86df87927af7a31515131f13eed16850a2b4bd3d8c42d8b00a5f710121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000bfc62d000000000000000000000000",
        txid: "f7bcc52331e4136da5a3442ab8eed95c6e534f573c973d4d81ded58a8de06efe",
        sighash: "d584c3cd6f07f1f81c01282abd90cc7c646d5eece865eef2dccedfd814094925",
        unsigned: "0400008085202f8901534995b8a165488795c49eb5a867e774c3ccef3c5e8d242663c8b2033d5c830c0000000000ffffffff0250c30000000000001976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac5cc10000000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000bfc62d000000000000000000000000",
    };
    const VECTORS: &[Vector] = &[BCH, DASH, ZCASH, DEFICHAIN, VERUS];

    fn fixture(v: &Vector) -> BtcForkTx {
        BtcForkTx {
            chain_id: v.chain.into(),
            from: v.sender.into(),
            to: v.recipient.into(),
            satoshis: "50000".into(),
            fee: "500".into(),
            inputs: vec![BtcForkInput {
                txid: v.funding_txid.into(),
                vout: 0,
                previous_tx_hex: v.funding_hex.into(),
            }],
            expiry_height: match fork(v.chain).unwrap().format {
                Format::ZcashV4 { .. } => Some(2_999_999),
                Format::Plain { .. } => None,
            },
        }
    }

    fn public_key() -> Vec<u8> {
        k256::ecdsa::SigningKey::from_bytes((&SECRET).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn blake2b_personalization_matches_noble() {
        assert_eq!(
            hex::encode(zip143_hash(b"ZcashPrevoutHash", &[])),
            "d53a633bbecf82fe9e9484d8a0e727c73bb9e68c96e72dec30144f6a84afa136"
        );
        assert_eq!(
            hex::encode(zip143_hash(b"ZcashSequencHash", &[1, 2, 3])),
            "e3e9d8740f4eb179a4add2a220937568f1380a06bdca0343ee29f6fb1e71f733"
        );
        let mut personal = [0u8; 16];
        personal[..12].copy_from_slice(b"ZcashSigHash");
        let multi: Vec<u8> = (0..300u32).map(|i| (i & 0xff) as u8).collect();
        assert_eq!(
            hex::encode(zip143_hash(&personal, &multi)),
            "846a1257841956ca2c8549bffa7244ad7300f44343b20bd52ae46432a35402fe"
        );
    }

    #[test]
    fn addresses_match_oracle() {
        for v in VECTORS {
            assert_eq!(
                address(v.chain, &public_key()).unwrap(),
                v.sender,
                "{}",
                v.chain
            );
        }
        // BCH legacy base58 spelling of the same key decodes to the same hash.
        let hash: [u8; 20] = ripemd::Ripemd160::digest(Sha256::digest(public_key())).into();
        let legacy = base58check_encode(&[0x6f], &hash);
        assert_eq!(
            decode_address(fork(BCH_TESTNET).unwrap(), &legacy).unwrap(),
            decode_address(fork(BCH_TESTNET).unwrap(), BCH.sender).unwrap()
        );
    }

    #[test]
    fn signed_wire_and_txid_match_oracle() {
        for v in VECTORS {
            let tx = fixture(v);
            let plan = tx.plan().unwrap();
            assert_eq!(
                hex::encode(tx.encode(&plan, &[Vec::new()])),
                v.unsigned,
                "unsigned {}",
                v.chain
            );
            assert_eq!(
                hex::encode(tx.sighash(&plan, 0).unwrap()),
                v.sighash,
                "sighash {}",
                v.chain
            );
            let (wire, txid) = tx.sign(&SECRET).unwrap();
            assert_eq!(wire, format!("0x{}", v.signed), "wire {}", v.chain);
            assert_eq!(txid, v.txid, "txid {}", v.chain);
        }
    }

    #[test]
    fn signatures_verify_against_their_own_digest() {
        for v in VECTORS {
            let tx = fixture(v);
            let plan = tx.plan().unwrap();
            let digest = tx.sighash(&plan, 0).unwrap();
            let wire = hex::decode(&tx.sign(&SECRET).unwrap().0[2..]).unwrap();
            // recover the DER signature pushed first in the scriptSig
            let mut c = Cursor {
                bytes: &wire,
                pos: plan.unsigned_prefix.len(),
            };
            c.varint().unwrap();
            c.take(36).unwrap();
            let script_len = c.varint().unwrap() as usize;
            let script = c.take(script_len).unwrap();
            let sig_len = script[0] as usize;
            let der = &script[1..1 + sig_len];
            let hash_type = *der.last().unwrap();
            let expected = if v.chain == BCH_TESTNET {
                SIGHASH_FORKID
            } else {
                SIGHASH_ALL
            };
            assert_eq!(hash_type, expected, "hash type {}", v.chain);
            let sig = k256::ecdsa::Signature::from_der(&der[..der.len() - 1]).unwrap();
            let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key()).unwrap();
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            assert!(
                key.verify_prehash(&digest, &sig).is_ok(),
                "verify {}",
                v.chain
            );
        }
    }

    #[test]
    fn rejects_hostile_inputs() {
        let tx = fixture(&BCH);
        assert!(check_chain("btcfork:bch-mainnet").is_err());
        assert!(check_chain("bip122:000000000019d6689c085ae165831e93").is_err());
        let mut t = tx.clone();
        t.chain_id = "btcfork:dash-testnet".into();
        assert!(t.plan().is_err());
        for bad in ["0", "545", "0500", "2100000000000001"] {
            let mut t = tx.clone();
            t.satoshis = bad.into();
            assert!(t.plan().is_err(), "satoshis {bad}");
        }
        for bad in ["0", "0500", "100001"] {
            let mut t = tx.clone();
            t.fee = bad.into();
            assert!(t.plan().is_err(), "fee {bad}");
        }
        let mut t = tx.clone();
        t.inputs.push(t.inputs[0].clone());
        assert!(t.plan().is_err());
        let mut t = tx.clone();
        t.inputs[0].txid = "a".repeat(64);
        assert!(t.plan().is_err());
        let mut t = tx.clone();
        t.inputs[0].vout = 1;
        assert!(t.plan().is_err());
        let mut t = tx.clone();
        t.inputs[0].previous_tx_hex = "00".into();
        assert!(t.plan().is_err());
        let mut t = tx.clone();
        t.from = t.to.clone();
        assert!(t.plan().is_err());
        let mut t = tx.clone();
        t.expiry_height = Some(7);
        assert!(t.plan().is_err());
        assert!(tx.sign(&[3u8; 32]).is_err());
        let mut t = fixture(&ZCASH);
        t.expiry_height = None;
        assert!(t.plan().is_err());
        let mut t = fixture(&ZCASH);
        t.expiry_height = Some(0);
        assert!(t.plan().is_err());
        let mut t = fixture(&ZCASH);
        t.expiry_height = Some(MAX_EXPIRY + 1);
        assert!(t.plan().is_err());
        let mut payload = serde_json::to_value(&tx).unwrap();
        payload["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<BtcForkTx>(payload).is_err());
    }

    #[test]
    fn rejects_wrong_signer_per_network() {
        for v in VECTORS {
            assert!(fixture(v).sign(&[9u8; 32]).is_err(), "{}", v.chain);
        }
    }
}
