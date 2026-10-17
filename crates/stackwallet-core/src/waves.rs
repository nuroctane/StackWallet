//! Waves family: native WAVES transfers in the version-3 protobuf scheme.
//!
//! Waves does not sign with raw Ed25519. Keys and signatures live on Curve25519
//! via the "axolotl" scheme (the libsodium-free build in `@waves/ts-lib-crypto`,
//! itself a TweetNaCl port): the 32-byte secret StackWallet holds (SLIP-10 at
//! `m/44'/5741564'/0'/0'/{i}'`) is first hashed the Waves way,
//! `sha256(keccak256(blake2b256(nonce0 || secret)))`, the clamped result is the
//! signing scalar, and the public key is its Montgomery basepoint multiple. The
//! signature is an Ed25519 signature over the Edwards image of that key, with
//! the Edwards sign bit smuggled into the top bit of `s`. The curve arithmetic
//! below is a faithful port of that reference implementation; every vector in
//! the tests was produced by `@waves/ts-lib-crypto` itself.

use blake2::digest::consts::U32;
use blake2::Blake2b;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 references are the chain-id byte: `waves:84` is testnet ('T'),
/// `waves:87` mainnet ('W', read-only, refused for signing).
pub const TESTNET: &str = "waves:84";
pub const MAINNET: &str = "waves:87";
const TESTNET_BYTE: u8 = b'T';
const VERSION: u64 = 3;
/// A plain WAVES transfer always costs 0.001 WAVES.
pub const FEE_WAVELETS: u64 = 100_000;
/// The signed timestamp must sit within an hour of when the tx was prepared.
pub const MAX_CLOCK_SKEW_MS: u64 = 60 * 60 * 1000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Waves transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Waves testnet transfers are enabled"));
    }
    Ok(())
}

/// keccak256(blake2b256(data)) — the Waves "secure hash" behind addresses and
/// key derivation.
fn secure_hash(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(Blake2b::<U32>::digest(data)).into()
}

/// The Waves account-seed hash of a core-held 32-byte secret (nonce 0).
fn seed_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 36];
    input[4..].copy_from_slice(secret);
    Sha256::digest(secure_hash(&input)).into()
}

fn clamp(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// The Waves signing scalar derived from the core-held secret.
pub fn private_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut key = seed_hash(secret);
    clamp(&mut key);
    key
}

/// The 32-byte Waves public key (Montgomery u-coordinate, sign bit cleared).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut public = curve::scalarmult_base_mont(&seed_hash(secret));
    public[31] &= 127;
    public
}

fn address_for_byte(public: &[u8], chain_byte: u8) -> Result<String> {
    let public: &[u8; 32] = public
        .try_into()
        .map_err(|_| invalid("public key must be 32 bytes"))?;
    let mut raw = Vec::with_capacity(26);
    raw.push(1u8);
    raw.push(chain_byte);
    raw.extend_from_slice(&secure_hash(public)[..20]);
    let checksum = secure_hash(&raw);
    raw.extend_from_slice(&checksum[..4]);
    Ok(bs58::encode(raw).into_string())
}

/// Testnet address of a 32-byte Waves public key.
pub fn address(public: &[u8]) -> Result<String> {
    address_for_byte(public, TESTNET_BYTE)
}

/// Testnet address of the account a core-held secret controls.
pub fn address_from_secret(secret: &[u8; 32]) -> Result<String> {
    address(&public_key(secret))
}

/// Decodes an address into its 20-byte public-key hash and chain-id byte.
pub fn parse_address(address: &str) -> Result<([u8; 20], u8)> {
    if address.len() > 36 {
        return Err(invalid("address is too long"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if bytes.len() != 26 || bytes[0] != 1 {
        return Err(invalid("not a Waves address"));
    }
    if secure_hash(&bytes[..22])[..4] != bytes[22..] {
        return Err(invalid("address checksum mismatch"));
    }
    if bs58::encode(&bytes).into_string() != address {
        return Err(invalid("non-canonical address"));
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&bytes[2..22]);
    Ok((hash, bytes[1]))
}

fn fixed_hex32(value: &str, what: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be 32 lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WavesTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal wavelets (1 WAVES = 100,000,000 wavelets); never a float.
    pub wavelets: String,
    /// Sender's 32-byte Waves public key, lowercase hex. The protobuf body
    /// carries the public key, which an address alone cannot supply.
    pub public_key_hex: String,
    /// Unix ms stamped into the transaction; nodes drop it once it is stale.
    pub timestamp: u64,
    /// Unix ms when the transaction was prepared; bounds the timestamp skew.
    pub built_at_ms: u64,
}

fn varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn int_field(out: &mut Vec<u8>, field: u64, value: u64) {
    varint(out, field << 3);
    varint(out, value);
}

fn bytes_field(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    varint(out, (field << 3) | 2);
    varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

impl WavesTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native WAVES transfers are enabled"));
                }
                if parse_address(to)? != parse_address(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.wavelets {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Waves intent")),
        }
        self.body_bytes()?;
        Ok(())
    }

    fn checked_fields(&self) -> Result<([u8; 32], [u8; 20], u64)> {
        check_chain(&self.chain_id)?;
        let (from_hash, from_byte) = parse_address(&self.from)?;
        let (to_hash, to_byte) = parse_address(&self.to)?;
        if from_byte != TESTNET_BYTE || to_byte != TESTNET_BYTE {
            return Err(invalid("addresses must be testnet addresses"));
        }
        if from_hash == to_hash {
            return Err(invalid("sender and recipient must differ"));
        }
        let public = fixed_hex32(&self.public_key_hex, "sender public key")?;
        if secure_hash(&public)[..20] != from_hash {
            return Err(invalid("public key does not match the sender address"));
        }
        let amount = self
            .wavelets
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds u64 wavelets"))?;
        if amount == 0 || amount > i64::MAX as u64 || amount.to_string() != self.wavelets {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        if self.timestamp == 0
            || self.built_at_ms == 0
            || self.timestamp > i64::MAX as u64
            || self.built_at_ms > i64::MAX as u64
            || self.timestamp.abs_diff(self.built_at_ms) > MAX_CLOCK_SKEW_MS
        {
            return Err(invalid(
                "timestamp must sit within an hour of the preparation time",
            ));
        }
        Ok((public, to_hash, amount))
    }

    /// The protobuf `waves.Transaction` body bytes; their blake2b256 is the id
    /// and the signed payload. proto3 omits the empty asset and attachment
    /// fields; verified byte-identical against a live node's own id.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        let (public, to_hash, amount) = self.checked_fields()?;
        let mut fee = Vec::new();
        int_field(&mut fee, 2, FEE_WAVELETS);
        let mut sum = Vec::new();
        int_field(&mut sum, 2, amount);
        let mut recipient = Vec::new();
        bytes_field(&mut recipient, 1, &to_hash);
        let mut transfer = Vec::new();
        bytes_field(&mut transfer, 1, &recipient);
        bytes_field(&mut transfer, 2, &sum);
        let mut body = Vec::with_capacity(128);
        int_field(&mut body, 1, TESTNET_BYTE as u64);
        bytes_field(&mut body, 2, &public);
        bytes_field(&mut body, 3, &fee);
        int_field(&mut body, 4, self.timestamp);
        int_field(&mut body, 5, VERSION);
        bytes_field(&mut body, 104, &transfer);
        Ok(body)
    }

    /// The transaction id as explorers show it: base58 of the body hash.
    pub fn txid(&self) -> Result<String> {
        Ok(bs58::encode(Blake2b::<U32>::digest(self.body_bytes()?)).into_string())
    }

    /// Returns the base64 of the protobuf `SignedTransaction` (body plus the
    /// single proof) and the transaction id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        if public_key(secret) != fixed_hex32(&self.public_key_hex, "sender public key")? {
            return Err(invalid("sender differs from signing key"));
        }
        let body = self.body_bytes()?;
        let signature = curve::axl_sign(&private_key(secret), &body);
        let mut wire = Vec::with_capacity(body.len() + 70);
        bytes_field(&mut wire, 1, &body);
        bytes_field(&mut wire, 2, &signature);
        use base64::Engine as _;
        Ok((
            base64::engine::general_purpose::STANDARD.encode(wire),
            bs58::encode(Blake2b::<U32>::digest(&body)).into_string(),
        ))
    }
}

/// TweetNaCl-derived Curve25519/Ed25519 arithmetic ported from axlsign (the
/// implementation `@waves/ts-lib-crypto` ships). Limbs are i64 where the
/// original used f64; every intermediate stays far below 2^53, so the port is
/// bit-exact. Not constant-time: fine for a local signer, never expose it to
/// attacker-chosen timing oracles.
mod curve {
    use sha2::{Digest, Sha512};

    pub type Gf = [i64; 16];
    pub type Point = [Gf; 4];
    pub const GF0: Gf = [0; 16];
    pub const GF1: Gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const A121665: Gf = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const D2: Gf = [
        0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2,
        0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
    ];
    const BASE_X: Gf = [
        0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231,
        0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
    ];
    const BASE_Y: Gf = [
        0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    ];
    /// The Ed25519 group order, little-endian bytes.
    const L: [i64; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    fn car25519(o: &mut Gf) {
        let mut c: i64 = 1;
        for limb in o.iter_mut() {
            let v = *limb + c + 65535;
            c = v.div_euclid(65536);
            *limb = v - c * 65536;
        }
        o[0] += c - 1 + 37 * (c - 1);
    }

    fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
        let c = !(b - 1);
        for i in 0..16 {
            let t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    pub fn pack25519(n: &Gf) -> [u8; 32] {
        let mut t = *n;
        let mut m = [0i64; 16];
        car25519(&mut t);
        car25519(&mut t);
        car25519(&mut t);
        for _ in 0..2 {
            m[0] = t[0] - 0xffed;
            for i in 1..15 {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            let b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            sel25519(&mut t, &mut m, 1 - b);
        }
        let mut out = [0u8; 32];
        for i in 0..16 {
            out[2 * i] = (t[i] & 0xff) as u8;
            out[2 * i + 1] = (t[i] >> 8) as u8;
        }
        out
    }

    #[cfg(test)]
    pub fn unpack25519(n: &[u8; 32]) -> Gf {
        let mut o = [0i64; 16];
        for i in 0..16 {
            o[i] = n[2 * i] as i64 + ((n[2 * i + 1] as i64) << 8);
        }
        o[15] &= 0x7fff;
        o
    }

    pub fn par25519(a: &Gf) -> u8 {
        pack25519(a)[0] & 1
    }

    pub fn add(a: &Gf, b: &Gf) -> Gf {
        let mut o = [0i64; 16];
        for i in 0..16 {
            o[i] = a[i] + b[i];
        }
        o
    }

    pub fn sub(a: &Gf, b: &Gf) -> Gf {
        let mut o = [0i64; 16];
        for i in 0..16 {
            o[i] = a[i] - b[i];
        }
        o
    }

    pub fn mul(a: &Gf, b: &Gf) -> Gf {
        let mut t = [0i64; 31];
        for i in 0..16 {
            for j in 0..16 {
                t[i + j] += a[i] * b[j];
            }
        }
        for i in 0..15 {
            t[i] += 38 * t[i + 16];
        }
        let mut o = [0i64; 16];
        o.copy_from_slice(&t[..16]);
        car25519(&mut o);
        car25519(&mut o);
        o
    }

    pub fn square(a: &Gf) -> Gf {
        mul(a, a)
    }

    pub fn inv25519(i: &Gf) -> Gf {
        let mut c = *i;
        for a in (0..=253).rev() {
            c = square(&c);
            if a != 2 && a != 4 {
                c = mul(&c, i);
            }
        }
        c
    }

    /// X25519 over the basepoint (9); clamps the scalar internally.
    pub fn scalarmult_base_mont(n: &[u8; 32]) -> [u8; 32] {
        let mut z = *n;
        z[31] = (z[31] & 127) | 64;
        z[0] &= 248;
        let x: Gf = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut a = GF0;
        let mut b = x;
        let mut c = GF0;
        let mut d = GF0;
        a[0] = 1;
        d[0] = 1;
        for i in (0..=254).rev() {
            let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
            sel25519(&mut a, &mut b, r);
            sel25519(&mut c, &mut d, r);
            let e = add(&a, &c);
            a = sub(&a, &c);
            c = add(&b, &d);
            b = sub(&b, &d);
            d = square(&e);
            let f = square(&a);
            a = mul(&c, &a);
            c = mul(&b, &e);
            let e = add(&a, &c);
            a = sub(&a, &c);
            b = square(&a);
            c = sub(&d, &f);
            a = mul(&c, &A121665);
            a = add(&a, &d);
            c = mul(&c, &a);
            a = mul(&d, &f);
            d = mul(&b, &x);
            b = square(&e);
            sel25519(&mut a, &mut b, r);
            sel25519(&mut c, &mut d, r);
        }
        let cinv = inv25519(&c);
        pack25519(&mul(&a, &cinv))
    }

    pub fn ed_add(p: &mut Point, q: &Point) {
        let mut t = sub(&q[1], &q[0]);
        let a = mul(&sub(&p[1], &p[0]), &t);
        t = add(&q[0], &q[1]);
        let b = mul(&add(&p[0], &p[1]), &t);
        let c = mul(&mul(&p[3], &q[3]), &D2);
        let dd = mul(&p[2], &q[2]);
        let d = add(&dd, &dd);
        let e = sub(&b, &a);
        let f = sub(&d, &c);
        let g = add(&d, &c);
        let h = add(&b, &a);
        p[0] = mul(&e, &f);
        p[1] = mul(&h, &g);
        p[2] = mul(&g, &f);
        p[3] = mul(&e, &h);
    }

    fn cswap(p: &mut Point, q: &mut Point, b: i64) {
        for i in 0..4 {
            sel25519(&mut p[i], &mut q[i], b);
        }
    }

    pub fn ed_pack(p: &Point) -> [u8; 32] {
        let zi = inv25519(&p[2]);
        let tx = mul(&p[0], &zi);
        let ty = mul(&p[1], &zi);
        let mut r = pack25519(&ty);
        r[31] ^= par25519(&tx) << 7;
        r
    }

    pub fn scalarmult(q: &Point, s: &[u8; 32]) -> Point {
        let mut p: Point = [GF0, GF1, GF1, GF0];
        let mut q = *q;
        for i in (0..=255).rev() {
            let b = ((s[i / 8] >> (i & 7)) & 1) as i64;
            cswap(&mut p, &mut q, b);
            ed_add(&mut q, &p);
            let pp = p;
            ed_add(&mut p, &pp);
            cswap(&mut p, &mut q, b);
        }
        p
    }

    /// Compressed Edwards point of `s` times the basepoint.
    pub fn scalarbase(s: &[u8; 32]) -> [u8; 32] {
        let q: Point = [BASE_X, BASE_Y, GF1, mul(&BASE_X, &BASE_Y)];
        ed_pack(&scalarmult(&q, s))
    }

    pub fn mod_l(x: &mut [i64; 64]) -> [u8; 32] {
        let mut carry: i64;
        for i in (32..=63).rev() {
            carry = 0;
            let k = i - 12;
            for j in (i - 32)..k {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                carry = (x[j] + 128) >> 8;
                x[j] -= carry * 256;
            }
            x[k] += carry;
            x[i] = 0;
        }
        carry = 0;
        for j in 0..32 {
            x[j] += carry - (x[31] >> 4) * L[j];
            carry = x[j] >> 8;
            x[j] &= 255;
        }
        for j in 0..32 {
            x[j] -= carry * L[j];
        }
        let mut r = [0u8; 32];
        for i in 0..32 {
            x[i + 1] += x[i] >> 8;
            r[i] = (x[i] & 255) as u8;
        }
        r
    }

    pub fn reduce(digest: &[u8; 64]) -> [u8; 32] {
        let mut x = [0i64; 64];
        for (i, b) in digest.iter().enumerate() {
            x[i] = *b as i64;
        }
        mod_l(&mut x)
    }

    /// The deterministic axolotl signature: an Ed25519 signature whose scalar
    /// is the clamped Curve25519 secret, with the Edwards sign bit of the
    /// public key folded into the top bit of `s` (bit 7 of byte 63).
    pub fn axl_sign(sk: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        let mut scalar = *sk;
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let edwards_public = scalarbase(&scalar);
        let sign_bit = edwards_public[31] & 128;

        let mut hasher = Sha512::new();
        hasher.update(scalar);
        hasher.update(msg);
        let r_digest: [u8; 64] = hasher.finalize().into();
        let r = reduce(&r_digest);
        let big_r = scalarbase(&r);

        let mut hasher = Sha512::new();
        hasher.update(big_r);
        hasher.update(edwards_public);
        hasher.update(msg);
        let h_digest: [u8; 64] = hasher.finalize().into();
        let h = reduce(&h_digest);

        let mut x = [0i64; 64];
        for i in 0..32 {
            x[i] = r[i] as i64;
        }
        for i in 0..32 {
            for j in 0..32 {
                x[i + j] += h[i] as i64 * scalar[j] as i64;
            }
        }
        let s = mod_l(&mut x);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s);
        sig[63] |= sign_bit;
        sig
    }

    /// The axolotl verification path, used by the round-trip tests only:
    /// converts the Montgomery public key to Edwards (y = (u-1)/(u+1)),
    /// restores the sign bit from the signature, checks `s*B == R + h*A`.
    #[cfg(test)]
    pub fn axl_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        const D: Gf = [
            0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079,
            0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
        ];
        const I: Gf = [
            0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099,
            0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
        ];
        fn pow2523(i: &Gf) -> Gf {
            let mut c = *i;
            for a in (0..=250).rev() {
                c = square(&c);
                if a != 1 {
                    c = mul(&c, i);
                }
            }
            c
        }
        fn unpackneg(p: &[u8; 32]) -> Option<Point> {
            let y = unpack25519(p);
            let num = sub(&square(&y), &GF1);
            let den = add(&GF1, &mul(&square(&y), &D));
            let den2 = square(&den);
            let den4 = square(&den2);
            let den6 = mul(&den4, &den2);
            let mut t = mul(&den6, &num);
            t = mul(&t, &den);
            t = pow2523(&t);
            t = mul(&t, &num);
            t = mul(&t, &den);
            t = mul(&t, &den);
            let mut x = mul(&t, &den);
            let chk = mul(&square(&x), &den);
            if pack25519(&chk) != pack25519(&num) {
                x = mul(&x, &I);
            }
            let chk = mul(&square(&x), &den);
            if pack25519(&chk) != pack25519(&num) {
                return None;
            }
            if par25519(&x) == (p[31] >> 7) {
                x = sub(&GF0, &x);
            }
            Some([x, y, GF1, mul(&x, &y)])
        }

        let mut sig = *sig;
        let u = unpack25519(pk);
        let num = sub(&u, &GF1);
        let den = add(&u, &GF1);
        let mut edpk = pack25519(&mul(&num, &inv25519(&den)));
        edpk[31] |= sig[63] & 128;
        sig[63] &= 127;
        let Some(a_point) = unpackneg(&edpk) else {
            return false;
        };
        let mut hasher = Sha512::new();
        hasher.update(&sig[..32]);
        hasher.update(edpk);
        hasher.update(msg);
        let h_digest: [u8; 64] = hasher.finalize().into();
        let h = reduce(&h_digest);
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let mut check = scalarmult(&a_point, &h);
        let sb = scalarbase_point(&s);
        ed_add(&mut check, &sb);
        ed_pack(&check)[..] == sig[..32]
    }

    #[cfg(test)]
    fn scalarbase_point(s: &[u8; 32]) -> Point {
        let q: Point = [BASE_X, BASE_Y, GF1, mul(&BASE_X, &BASE_Y)];
        scalarmult(&q, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [0x11u8; 32];
    // Vectors produced by `@waves/ts-lib-crypto` 1.5.2 (see .nur/waves-final-vectors.mjs).
    const SEED_HASH: &str = "de35e09752e45ff02004987ba44cdc20965dda673602056e409f644af41b7484";
    const PRIVATE: &str = "d835e09752e45ff02004987ba44cdc20965dda673602056e409f644af41b7444";
    const PUBLIC: &str = "8e4b17a1d571ef23420070bd3b4f3908ca0227237d455f61ef2da464f2c86123";
    const ADDRESS_T: &str = "3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z9";
    const ADDRESS_W: &str = "3PCVpavfjsxHC2VcrYLfqx1vxvipt1NYgkt";
    const RECIPIENT_T: &str = "3NBRL1d9WCia865111rFgeF6wfneJeUEj3W";
    const BODY_HEX: &str = "085412208e4b17a1d571ef23420070bd3b4f3908ca0227237d455f61ef2da464f2c861231a0410a08d06208080b3c19c332803c2061f0a160a14ebe29693861de35ec03b78d11743062defc8d082120510959aef3a";
    const TX_ID: &str = "C2rL58abTr2QstLd2cwwL8cfu9KexYhH9VLn6WkZyQbg";
    const SIG_HEX: &str = "0a9c591ac02a64df1fb0ecd932beb91009dbf86dfb021e885cd982fc57cfd4eac3ab7816071991f8beaa184532df7e47eef70f4ce6cd69df9ba5e9a8fdd4eb87";
    const SIGNED_B64: &str = "ClUIVBIgjksXodVx7yNCAHC9O085CMoCJyN9RV9h7y2kZPLIYSMaBBCgjQYggICzwZwzKAPCBh8KFgoU6+KWk4Yd417AO3jRF0MGLe/I0IISBRCVmu86EkAKnFkawCpk3x+w7NkyvrkQCdv4bfsCHohc2YL8V8/U6sOreBYHGZH4vqoYRTLffkfu9w9M5s1p35ul6aj91OuH";
    /// Deterministic axlsign signature over "stackwallet waves test".
    const MSG2_SIG: &str = "d60e6f04ba74139dfc267b70fa872897a71bc0bdda486b3e9664f44d3ffbd0952b9389327600fed98b0ceae8f4ddae03aacd276eece00ffd01967fe1d163d28d";

    fn tx() -> WavesTx {
        WavesTx {
            chain_id: TESTNET.into(),
            from: ADDRESS_T.into(),
            to: RECIPIENT_T.into(),
            wavelets: "123456789".into(),
            public_key_hex: PUBLIC.into(),
            timestamp: 1_760_000_000_000,
            built_at_ms: 1_760_000_000_000,
        }
    }

    fn intent(tx: &WavesTx) -> TxIntent {
        TxIntent {
            id: "tx".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(tx.chain_id.clone()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{}:native", tx.chain_id)),
                amount: Amount(tx.wavelets.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn edwards_scalarbase_matches_ed25519_dalek() {
        // ed25519-dalek derives its verifying key as scalarbase of the clamped
        // sha512 seed half; the ported Edwards ladder must agree exactly.
        let seed = [9u8; 32];
        let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let h: [u8; 64] = sha2::Sha512::digest(seed).into();
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&h[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        assert_eq!(curve::scalarbase(&scalar), vk.to_bytes());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(
            curve::scalarbase(&one),
            hex::decode("5866666666666666666666666666666666666666666666666666666666666666")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn keys_and_addresses_match_ts_lib_crypto() {
        assert_eq!(hex::encode(seed_hash(&SECRET)), SEED_HASH);
        assert_eq!(hex::encode(private_key(&SECRET)), PRIVATE);
        let public = public_key(&SECRET);
        assert_eq!(hex::encode(public), PUBLIC);
        assert_eq!(address(&public).unwrap(), ADDRESS_T);
        assert_eq!(address_for_byte(&public, b'W').unwrap(), ADDRESS_W);
        assert_eq!(address_from_secret(&SECRET).unwrap(), ADDRESS_T);
        assert_eq!(parse_address(ADDRESS_T).unwrap().1, b'T');
        assert_eq!(parse_address(ADDRESS_W).unwrap().1, b'W');
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(parse_address("3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z8").is_err());
        assert!(parse_address("TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC").is_err());
        assert!(parse_address("3MzV1dbmskQtZaCCbU5ftVe7c3D43qDh8z9").is_ok());
    }

    #[test]
    fn signature_matches_ts_lib_crypto_and_verifies() {
        let msg = b"stackwallet waves test";
        let sig = curve::axl_sign(&private_key(&SECRET), msg);
        assert_eq!(hex::encode(sig), MSG2_SIG);
        assert!(curve::axl_verify(&public_key(&SECRET), msg, &sig));
        let mut tampered = *b"stackwallet waves tesu";
        assert!(!curve::axl_verify(&public_key(&SECRET), &tampered, &sig));
        tampered = *msg;
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(!curve::axl_verify(&public_key(&SECRET), &tampered, &bad));
        // The other account's key must not verify this signature.
        let other = public_key(&[0x22u8; 32]);
        assert!(!curve::axl_verify(&other, msg, &sig));
    }

    #[test]
    fn body_matches_the_adapter_vector() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        assert_eq!(hex::encode(t.body_bytes().unwrap()), BODY_HEX);
        assert_eq!(t.txid().unwrap(), TX_ID);
    }

    #[test]
    fn sign_produces_the_pinned_wire_and_id() {
        let t = tx();
        let (wire, id) = t.sign(&SECRET).unwrap();
        assert_eq!(id, TX_ID);
        assert_eq!(wire, SIGNED_B64);
        // The signature over the body bytes verifies against the sender key.
        use base64::Engine as _;
        let wire_bytes = base64::engine::general_purpose::STANDARD
            .decode(wire)
            .unwrap();
        let body = t.body_bytes().unwrap();
        // wire = bytes_field(1, body) || bytes_field(2, sig)
        let body_len = wire_bytes[1] as usize;
        assert_eq!(wire_bytes[0], 0x0a);
        assert_eq!(&wire_bytes[2..2 + body_len], body.as_slice());
        let sig_at = 2 + body_len;
        assert_eq!(wire_bytes[sig_at], 0x12);
        assert_eq!(wire_bytes[sig_at + 1], 64);
        let sig: &[u8; 64] = wire_bytes[sig_at + 2..sig_at + 66].try_into().unwrap();
        assert_eq!(hex::encode(sig), SIG_HEX);
        assert!(curve::axl_verify(&public_key(&SECRET), &body, sig));
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.chain_id = "waves:1".into();
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.wavelets = "0".into();
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.wavelets = "0123".into();
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.wavelets = "9223372036854775808".into();
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.to = base.from.clone();
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.to = ADDRESS_W.into();
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.timestamp = t.built_at_ms + MAX_CLOCK_SKEW_MS + 1;
        assert!(t.body_bytes().is_err());
        let mut t = base.clone();
        t.public_key_hex = PUBLIC.to_uppercase();
        assert!(t.body_bytes().is_err());
        // A key that does not match the sender address is refused.
        let mut t = base.clone();
        t.public_key_hex = hex::encode(public_key(&[0x22u8; 32]));
        assert!(t.body_bytes().is_err());
        // Signing with a different secret is refused.
        assert!(base.sign(&[0x22u8; 32]).is_err());
        // Intent mismatches are refused.
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "123456790".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId(MAINNET.into());
        assert!(base.check_matches_intent(&i).is_err());
        // Unknown fields are refused.
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": ADDRESS_T, "to": RECIPIENT_T, "wavelets": "1",
            "publicKeyHex": PUBLIC, "timestamp": 1, "builtAtMs": 1, "attachment": "00"
        });
        assert!(serde_json::from_value::<WavesTx>(extra).is_err());
    }
}
