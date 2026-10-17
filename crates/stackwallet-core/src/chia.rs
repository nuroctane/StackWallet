//! Chia family: XCH transfers as spend bundles over the coin-set model.
//!
//! Chia uses BLS12-381 keys and signatures, not secp256k1/Ed25519. The core's
//! HD stack has no BLS support and its dependency set cannot grow, so this
//! module carries a small self-contained BLS12-381 implementation: EIP-2333
//! key derivation (HKDF-SHA-256 mod r), G1 public keys, and RFC 9380
//! hash-to-G2 (XMD:SHA-256, Simplified SWU onto the 3-isogenous curve,
//! isogeny map, cofactor clearing) for `aug_scheme_mpl` signatures with
//! Chia's AUG ciphersuite DST.
//!
//! Addresses are bech32m puzzle hashes of the standard wallet puzzle
//! (`p2_delegated_puzzle_or_hidden_puzzle` curried with the synthetic key);
//! MOD_HEX is byte-for-byte the compiled program the network runs (checked
//! against on-chain puzzle reveals). A transfer is a one-coin spend bundle
//! whose delegated puzzle quotes the conditions the core builds from checked
//! fields: RESERVE_FEE, CREATE_COIN to the recipient, CREATE_COIN of the
//! change back to the sender. The signed message is
//! `synthetic_pk || tree_hash(delegated_puzzle) || coin_id || genesis_challenge`,
//! matching chia-consensus `Condition::AggSigMe` handling (opcode 49 is
//! prepended by the standard puzzle itself).
//!
//! These routines are not constant-time; they run on local secrets for a
//! handful of signatures per session, never in a shared service.

// Multi-limb modular arithmetic indexes several arrays at once; range loops
// keep the borrow checker out of carry chains.
#![allow(clippy::needless_range_loop)]

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 references are the first 8 hex characters of the genesis challenge.
pub const TESTNET11: &str = "chia:37a90eb5";
pub const MAINNET: &str = "chia:ccd5bb71";

const GENESIS_TESTNET11: &str = "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615";
const GENESIS_MAINNET: &str = "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb";
const HRP_TESTNET: &str = "txch";
const HRP_MAINNET: &str = "xch";
/// BLS hash-to-curve DST for Chia's augmented scheme (bls-signatures schemes.cpp).
const DST_AUG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
/// m/12381'/8444'/2' per EIP-2334 (Chia wallet keys); the account index follows.
pub const WALLET_PATH: [u32; 3] = [12381, 8444, 2];
/// Condition opcodes (condition_codes.clib); AGG_SIG_ME (49) is emitted by the
/// standard puzzle, so the core only writes these two.
const RESERVE_FEE: u8 = 52;
const CREATE_COIN: u8 = 51;
/// Amounts are signed CLVM ints in conditions and u64 on the wire; cap below 2^63.
const MAX_MOJOS: u64 = i64::MAX as u64;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Chia transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET11 {
        return Err(invalid("only Chia testnet11 transfers are enabled"));
    }
    Ok(())
}

fn hex_to_bytes32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid("id must be 64 lowercase hex characters"));
    }
    let bytes = hex::decode(value).map_err(|_| invalid("id is not hex"))?;
    Ok(bytes.try_into().expect("32 bytes"))
}

fn genesis_challenge(chain: &str) -> Result<[u8; 32]> {
    let text = match chain {
        TESTNET11 => GENESIS_TESTNET11,
        MAINNET => GENESIS_MAINNET,
        _ => return Err(invalid("unknown Chia network")),
    };
    let bytes = hex::decode(text).expect("static hex");
    Ok(bytes.try_into().expect("32 bytes"))
}

fn hrp(chain: &str) -> Result<&'static str> {
    match chain {
        TESTNET11 => Ok(HRP_TESTNET),
        MAINNET => Ok(HRP_MAINNET),
        _ => Err(invalid("unknown Chia network")),
    }
}

// ---------------------------------------------------------------------------
// Scalar field Fr (group order r); only reduce and add are needed.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Scalar([u64; 4]);

impl Scalar {
    fn from_be_bytes(bytes: &[u8; 32]) -> Scalar {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            limbs[3 - i] = u64::from_be_bytes(*chunk);
        }
        let mut s = Scalar(limbs);
        s.reduce();
        s
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|l| *l == 0)
    }

    fn cmp_r(&self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&FR_MODULUS[i]) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }

    fn sub_r(&mut self) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = self.0[i].overflowing_sub(FR_MODULUS[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            self.0[i] = d;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }

    fn reduce(&mut self) {
        // A 32-byte input is below 2^256 < 2r, so one subtraction suffices.
        if self.cmp_r() != std::cmp::Ordering::Less {
            self.sub_r();
        }
    }

    fn add(&self, other: &Scalar) -> Scalar {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c1) = self.0[i].overflowing_add(other.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            out[i] = s;
            carry = (c1 as u64) + (c2 as u64);
        }
        let mut s = Scalar(out);
        if carry == 1 || s.cmp_r() != std::cmp::Ordering::Less {
            s.sub_r();
        }
        s
    }

    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }
}

/// Reduce a big-endian byte string (any length) mod r, one bit at a time.
/// The running remainder is kept below r, so each step's value is below 2r.
fn scalar_from_wide(bytes: &[u8]) -> Scalar {
    let mut rem = Scalar([0; 4]);
    for byte in bytes {
        for bit in (0..8).rev() {
            let mut carry = ((byte >> bit) & 1) as u64;
            for limb in &mut rem.0 {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            if carry == 1 {
                // The value overflowed 256 bits; since it was below 2r it is
                // now below r + 1 and the low-limb subtraction's borrow is
                // exactly absorbed by the dropped 257th bit.
                rem.sub_r();
            }
            if rem.cmp_r() != std::cmp::Ordering::Less {
                rem.sub_r();
            }
        }
    }
    rem
}

// ---------------------------------------------------------------------------
// EIP-2333 key derivation (HKDF-SHA-256 mod r, L = 48).
// ---------------------------------------------------------------------------

type HmacSha256 = hmac::Hmac<sha2_v011::Sha256>;
use hmac::digest::KeyInit;
use hmac::Mac;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hkdf_mod_r(ikm: &[u8]) -> Result<Scalar> {
    // Per ERC-2333 the salt string is hashed once before each extract attempt.
    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();
    loop {
        salt = Sha256::digest(&salt).to_vec();
        let mut ikm0 = ikm.to_vec();
        ikm0.push(0);
        let prk = hmac_sha256(&salt, &ikm0);
        // HKDF-Expand(PRK, key_info || I2OSP(48, 2), 48): two blocks, empty key_info.
        let t1 = hmac_sha256(&prk, &[0x00, 0x30, 0x01]);
        let t2 = hmac_sha256(&prk, &[&t1[..], &[0x00, 0x30, 0x02]].concat());
        let mut okm = [0u8; 48];
        okm[..32].copy_from_slice(&t1);
        okm[32..].copy_from_slice(&t2[..16]);
        let sk = scalar_from_wide(&okm);
        if !sk.is_zero() {
            return Ok(sk);
        }
    }
}

/// EIP-2333 `derive_master_SK` from a BIP-39 seed.
pub fn master_sk_from_seed(seed: &[u8]) -> Result<[u8; 32]> {
    if seed.is_empty() || seed.len() > 256 {
        return Err(invalid("seed must be 1..=256 bytes"));
    }
    Ok(hkdf_mod_r(seed)?.to_be_bytes())
}

/// EIP-2333 hardened child derivation (every step of a Chia wallet path is hardened).
pub fn derive_child_sk(secret: &[u8; 32], index: u32) -> Result<[u8; 32]> {
    let mut ikm = secret.to_vec();
    ikm.extend_from_slice(&index.to_be_bytes());
    Ok(hkdf_mod_r(&ikm)?.to_be_bytes())
}

/// The wallet secret key for account `index`: m/12381'/8444'/2'/index' (EIP-2334).
pub fn wallet_sk(master: &[u8; 32], index: u32) -> Result<[u8; 32]> {
    let mut sk = *master;
    for step in WALLET_PATH.iter().copied().chain([index]) {
        sk = derive_child_sk(&sk, step)?;
    }
    Ok(sk)
}

// ---------------------------------------------------------------------------
// Base field Fp: Montgomery arithmetic over 6 u64 limbs (SOS multiply).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Fp([u64; 6]);

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Fp {}

impl Fp {
    const fn zero() -> Fp {
        Fp([0; 6])
    }
    const fn one() -> Fp {
        Fp(FP_R)
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|l| *l == 0)
    }

    /// A normal-form 96-hex-char string into Montgomery form.
    fn from_hex(value: &str) -> Result<Fp> {
        if value.len() != 96 || value.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(invalid("field element must be 48 lowercase hex bytes"));
        }
        let bytes = hex::decode(value).map_err(|_| invalid("field element is not hex"))?;
        let mut limbs = [0u64; 6];
        for (i, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            limbs[5 - i] = u64::from_be_bytes(*chunk);
        }
        for i in (0..6).rev() {
            if limbs[i] != FP_MODULUS[i] {
                if limbs[i] > FP_MODULUS[i] {
                    return Err(invalid("field element exceeds the modulus"));
                }
                break;
            }
            if i == 0 {
                return Err(invalid("field element exceeds the modulus"));
            }
        }
        Ok(Fp(limbs).mul(&Fp(FP_R2)))
    }

    fn from_u64(v: u64) -> Fp {
        Fp([v, 0, 0, 0, 0, 0]).mul(&Fp(FP_R2))
    }

    /// x * R^-1 (Montgomery REDC of the raw limbs), then conditional subtract.
    fn to_normal(self) -> [u64; 6] {
        let mut t = [0u64; 13];
        t[..6].copy_from_slice(&self.0);
        mont_reduce(&mut t);
        let mut out = [0u64; 6];
        out.copy_from_slice(&t[..6]);
        let mut r = Fp(out);
        if t[6] != 0 {
            r.sub_p();
        }
        r.reduce_p();
        r.0
    }

    fn to_be_bytes(self) -> [u8; 48] {
        let n = self.to_normal();
        let mut out = [0u8; 48];
        for i in 0..6 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&n[5 - i].to_be_bytes());
        }
        out
    }

    fn sub_p(&mut self) {
        let mut borrow = 0u64;
        for i in 0..6 {
            let (d, b1) = self.0[i].overflowing_sub(FP_MODULUS[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            self.0[i] = d;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }

    fn ge_p(&self) -> bool {
        for i in (0..6).rev() {
            if self.0[i] != FP_MODULUS[i] {
                return self.0[i] > FP_MODULUS[i];
            }
        }
        true
    }

    fn reduce_p(&mut self) {
        if self.ge_p() {
            self.sub_p();
        }
    }

    fn mul(&self, other: &Fp) -> Fp {
        // Schoolbook into 13 limbs, then SOS reduction.
        let mut t = [0u64; 13];
        for i in 0..6 {
            let mut carry = 0u128;
            for j in 0..6 {
                let cur = t[i + j] as u128 + self.0[i] as u128 * other.0[j] as u128 + carry;
                t[i + j] = cur as u64;
                carry = cur >> 64;
            }
            let mut k = i + 6;
            let mut c = carry;
            while c > 0 {
                let cur = t[k] as u128 + c;
                t[k] = cur as u64;
                c = cur >> 64;
                k += 1;
            }
        }
        mont_reduce(&mut t);
        let mut out = [0u64; 6];
        out.copy_from_slice(&t[..6]);
        let mut r = Fp(out);
        if t[6] != 0 {
            r.sub_p();
        }
        r.reduce_p();
        r
    }

    fn add(&self, other: &Fp) -> Fp {
        let mut out = [0u64; 6];
        let mut carry = 0u64;
        for i in 0..6 {
            let (s, c1) = self.0[i].overflowing_add(other.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            out[i] = s;
            carry = (c1 as u64) + (c2 as u64);
        }
        let mut r = Fp(out);
        if carry == 1 {
            r.sub_p();
        }
        r.reduce_p();
        r
    }

    fn sub(&self, other: &Fp) -> Fp {
        let mut out = [0u64; 6];
        let mut borrow = 0u64;
        for i in 0..6 {
            let (d, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            out[i] = d;
            borrow = (b1 as u64) + (b2 as u64);
        }
        let mut r = Fp(out);
        if borrow == 1 {
            let mut carry = 0u64;
            for i in 0..6 {
                let (s, c1) = r.0[i].overflowing_add(FP_MODULUS[i]);
                let (s, c2) = s.overflowing_add(carry);
                r.0[i] = s;
                carry = (c1 as u64) + (c2 as u64);
            }
        }
        r
    }

    fn neg(&self) -> Fp {
        if self.is_zero() {
            *self
        } else {
            Fp(FP_MODULUS).sub(self)
        }
    }

    fn sqr(&self) -> Fp {
        self.mul(self)
    }

    /// self^exp with the exponent as big-endian bytes (MSB-first).
    fn pow_be(&self, exp: &[u8]) -> Fp {
        let mut r = Fp::one();
        for byte in exp {
            for bit in (0..8).rev() {
                r = r.sqr();
                if (byte >> bit) & 1 == 1 {
                    r = r.mul(self);
                }
            }
        }
        r
    }

    fn inv(&self) -> Fp {
        assert!(!self.is_zero(), "inversion of zero");
        // p - 2
        let mut exp = FP_MODULUS;
        exp[0] -= 2;
        let mut bytes = [0u8; 48];
        for i in 0..6 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&exp[5 - i].to_be_bytes());
        }
        self.pow_be(&bytes)
    }

    /// Odd/even of the normal form (RFC 9380 sgn0 for Fp).
    fn is_odd(&self) -> bool {
        self.to_normal()[0] & 1 == 1
    }

    /// value > (p-1)/2 in normal form (zcash-style compression sign).
    fn lex_largest(&self) -> bool {
        let n = self.to_normal();
        let mut half = FP_MODULUS;
        half[0] -= 1;
        for i in 0..5 {
            half[i] = (half[i] >> 1) | (half[i + 1] << 63);
        }
        half[5] >>= 1;
        for i in (0..6).rev() {
            if n[i] != half[i] {
                return n[i] > half[i];
            }
        }
        false
    }
}

/// Six SOS Montgomery reduction rounds on a 13-limb accumulator.
/// Afterwards t mod p sits in t[..6] (plus a possible bit in t[6] handled by callers).
fn mont_reduce(t: &mut [u64; 13]) {
    for i in 0..6 {
        let m = t[i].wrapping_mul(FP_INV);
        let mut carry = 0u128;
        for j in 0..6 {
            let cur = t[i + j] as u128 + m as u128 * FP_MODULUS[j] as u128 + carry;
            t[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 6;
        let mut c = carry;
        while c > 0 {
            let cur = t[k] as u128 + c;
            t[k] = cur as u64;
            c = cur >> 64;
            k += 1;
        }
    }
    // Shift the result down by six limbs, keeping the extra carry limb.
    let extra = t[12];
    t.copy_within(6..12, 0);
    t[6] = extra;
    t[7..].fill(0);
}

// ---------------------------------------------------------------------------
// Quadratic extension Fp2 = Fp[i] / (i^2 + 1); elements c0 + c1*i.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fp2 {
    c0: Fp,
    c1: Fp,
}

impl Fp2 {
    const fn zero() -> Fp2 {
        Fp2 {
            c0: Fp::zero(),
            c1: Fp::zero(),
        }
    }
    const fn one() -> Fp2 {
        Fp2 {
            c0: Fp::one(),
            c1: Fp::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    fn from_hex(re: &str, im: &str) -> Result<Fp2> {
        Ok(Fp2 {
            c0: Fp::from_hex(re)?,
            c1: Fp::from_hex(im)?,
        })
    }

    fn add(&self, o: &Fp2) -> Fp2 {
        Fp2 {
            c0: self.c0.add(&o.c0),
            c1: self.c1.add(&o.c1),
        }
    }
    fn sub(&self, o: &Fp2) -> Fp2 {
        Fp2 {
            c0: self.c0.sub(&o.c0),
            c1: self.c1.sub(&o.c1),
        }
    }
    fn neg(&self) -> Fp2 {
        Fp2 {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }
    fn mul(&self, o: &Fp2) -> Fp2 {
        let a0b0 = self.c0.mul(&o.c0);
        let a1b1 = self.c1.mul(&o.c1);
        let a0b1 = self.c0.mul(&o.c1);
        let a1b0 = self.c1.mul(&o.c0);
        Fp2 {
            c0: a0b0.sub(&a1b1),
            c1: a0b1.add(&a1b0),
        }
    }
    fn sqr(&self) -> Fp2 {
        let a2 = self.c0.sqr();
        let b2 = self.c1.sqr();
        let ab = self.c0.mul(&self.c1);
        Fp2 {
            c0: a2.sub(&b2),
            c1: ab.add(&ab),
        }
    }
    fn inv(&self) -> Fp2 {
        let denom = self.c0.sqr().add(&self.c1.sqr()).inv();
        Fp2 {
            c0: self.c0.mul(&denom),
            c1: self.c1.neg().mul(&denom),
        }
    }
    fn pow_be(&self, exp: &[u8]) -> Fp2 {
        let mut r = Fp2::one();
        for byte in exp {
            for bit in (0..8).rev() {
                r = r.sqr();
                if (byte >> bit) & 1 == 1 {
                    r = r.mul(self);
                }
            }
        }
        r
    }

    /// RFC 9380 sgn0_m_eq_2: parity of c0, falling back to c1 when c0 == 0.
    fn sgn0(&self) -> bool {
        if self.c0.is_zero() {
            self.c1.is_odd()
        } else {
            self.c0.is_odd()
        }
    }

    /// zcash/blst compression sign: c1 decides unless it is zero.
    fn lex_largest(&self) -> bool {
        if self.c1.is_zero() {
            self.c0.lex_largest()
        } else {
            self.c1.lex_largest()
        }
    }
}

// ---------------------------------------------------------------------------
// Jacobian points over a = 0 curves (G1 over Fp, G2 over Fp2).
// ---------------------------------------------------------------------------

trait Field: Copy + PartialEq {
    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;
    fn add(&self, o: &Self) -> Self;
    fn sub(&self, o: &Self) -> Self;
    fn mul(&self, o: &Self) -> Self;
    fn sqr(&self) -> Self;
    fn inv(&self) -> Self;
}
impl Field for Fp {
    fn zero() -> Self {
        Fp::zero()
    }
    fn one() -> Self {
        Fp::one()
    }
    fn is_zero(&self) -> bool {
        Fp::is_zero(self)
    }
    fn add(&self, o: &Self) -> Self {
        Fp::add(self, o)
    }
    fn sub(&self, o: &Self) -> Self {
        Fp::sub(self, o)
    }
    fn mul(&self, o: &Self) -> Self {
        Fp::mul(self, o)
    }
    fn sqr(&self) -> Self {
        Fp::sqr(self)
    }
    fn inv(&self) -> Self {
        Fp::inv(self)
    }
}
impl Field for Fp2 {
    fn zero() -> Self {
        Fp2::zero()
    }
    fn one() -> Self {
        Fp2::one()
    }
    fn is_zero(&self) -> bool {
        Fp2::is_zero(self)
    }
    fn add(&self, o: &Self) -> Self {
        Fp2::add(self, o)
    }
    fn sub(&self, o: &Self) -> Self {
        Fp2::sub(self, o)
    }
    fn mul(&self, o: &Self) -> Self {
        Fp2::mul(self, o)
    }
    fn sqr(&self) -> Self {
        Fp2::sqr(self)
    }
    fn inv(&self) -> Self {
        Fp2::inv(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Point<F: Field> {
    x: F,
    y: F,
    z: F, // zero => infinity
}

impl<F: Field> Point<F> {
    fn infinity() -> Self {
        Point {
            x: F::one(),
            y: F::one(),
            z: F::zero(),
        }
    }
    fn affine(x: F, y: F) -> Self {
        Point { x, y, z: F::one() }
    }
    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Point::infinity();
        }
        let a = self.x.sqr();
        let b = self.y.sqr();
        let c = b.sqr();
        let xb = self.x.add(&b).sqr();
        let d = xb.sub(&a).sub(&c);
        let d = d.add(&d);
        let e = a.add(&a).add(&a);
        let f = e.sqr();
        let x3 = f.sub(&d).sub(&d);
        let c2 = c.add(&c);
        let c4 = c2.add(&c2);
        let c8 = c4.add(&c4);
        let y3 = e.mul(&d.sub(&x3)).sub(&c8);
        let yz = self.y.mul(&self.z);
        let z3 = yz.add(&yz);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        let z1z1 = self.z.sqr();
        let z2z2 = other.z.sqr();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);
        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            }
            return Point::infinity();
        }
        let h = u2.sub(&u1);
        let i = h.add(&h).sqr();
        let j = h.mul(&i);
        let diff = s2.sub(&s1);
        let r = diff.add(&diff);
        let v = u1.mul(&i);
        let x3 = r.sqr().sub(&j).sub(&v).sub(&v);
        let s1j = s1.mul(&j);
        let y3 = r.mul(&v.sub(&x3)).sub(&s1j).sub(&s1j);
        let zsum = self.z.add(&other.z);
        let z3 = zsum.sqr().sub(&z1z1).sub(&z2z2).mul(&h);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// MSB-first double-and-add by a big-endian scalar.
    fn mul_be(&self, scalar: &[u8]) -> Self {
        let mut acc = Point::infinity();
        for byte in scalar {
            for bit in (0..8).rev() {
                acc = acc.double();
                if (byte >> bit) & 1 == 1 {
                    acc = acc.add(self);
                }
            }
        }
        acc
    }

    fn to_affine(self) -> Option<(F, F)> {
        if self.is_infinity() {
            return None;
        }
        let zi = self.z.inv();
        let zi2 = zi.sqr();
        let zi3 = zi2.mul(&zi);
        Some((self.x.mul(&zi2), self.y.mul(&zi3)))
    }
}

// ---------------------------------------------------------------------------
// RFC 9380 hash-to-curve for BLS12381G2_XMD:SHA-256_SSWU_RO_.
// ---------------------------------------------------------------------------

fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    assert!(dst.len() < 256);
    let ell = len.div_ceil(32);
    assert!(ell <= 255);
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);
    let mut b0_input = Vec::with_capacity(64 + msg.len() + 2 + 1 + dst_prime.len());
    b0_input.extend_from_slice(&[0u8; 64]);
    b0_input.extend_from_slice(msg);
    b0_input.extend_from_slice(&(len as u16).to_be_bytes());
    b0_input.push(0);
    b0_input.extend_from_slice(&dst_prime);
    let b0 = Sha256::digest(&b0_input);
    let mut out = Vec::with_capacity(ell * 32);
    let mut b_prev = {
        let mut input = Vec::with_capacity(32 + 1 + dst_prime.len());
        input.extend_from_slice(&b0);
        input.push(1);
        input.extend_from_slice(&dst_prime);
        let b1 = Sha256::digest(&input);
        out.extend_from_slice(&b1);
        b1
    };
    for i in 2..=ell {
        let xored: Vec<u8> = b0.iter().zip(b_prev.iter()).map(|(a, b)| a ^ b).collect();
        let mut input = Vec::with_capacity(32 + 1 + dst_prime.len());
        input.extend_from_slice(&xored);
        input.push(i as u8);
        input.extend_from_slice(&dst_prime);
        b_prev = Sha256::digest(&input);
        out.extend_from_slice(&b_prev);
    }
    out.truncate(len);
    out
}

/// hash_to_field with count = 2, m = 2, L = 64 (SHA-256 XMD).
fn hash_to_field_fp2(msg: &[u8], dst: &[u8]) -> [Fp2; 2] {
    let bytes = expand_message_xmd(msg, dst, 2 * 2 * 64);
    let mut out = [Fp2::zero(), Fp2::zero()];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut elems = [Fp::zero(), Fp::zero()];
        for (j, elem) in elems.iter_mut().enumerate() {
            let chunk = &bytes[(i * 2 + j) * 64..(i * 2 + j + 1) * 64];
            *elem = fp_from_64_bytes(chunk);
        }
        *slot = Fp2 {
            c0: elems[0],
            c1: elems[1],
        };
    }
    out
}

/// OS2IP of a 64-byte big-endian integer mod p, in Montgomery form.
fn fp_from_64_bytes(bytes: &[u8]) -> Fp {
    debug_assert_eq!(bytes.len(), 64);
    let mut rem = Fp::zero();
    for byte in bytes {
        for bit in (0..8).rev() {
            rem = rem.add(&rem);
            rem.reduce_p();
            if (byte >> bit) & 1 == 1 {
                rem = rem.add(&Fp::one());
            }
        }
    }
    rem
}

/// SWU Z = -(2 + i).
fn swu_z() -> Fp2 {
    Fp2 {
        c0: Fp::from_u64(2).neg(),
        c1: Fp::from_u64(1).neg(),
    }
}
/// E': A' = 240 i.
fn swu_a() -> Fp2 {
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_u64(240),
    }
}
/// E': B' = 1012 (1 + i).
fn swu_b() -> Fp2 {
    Fp2 {
        c0: Fp::from_u64(1012),
        c1: Fp::from_u64(1012),
    }
}

fn sqrt_ratio_c6() -> &'static Fp2 {
    static C6: OnceLock<Fp2> = OnceLock::new();
    C6.get_or_init(|| swu_z().pow_be(&hex::decode(SQRT_C2_HEX).expect("static hex")))
}

fn sqrt_ratio_c7() -> &'static Fp2 {
    static C7: OnceLock<Fp2> = OnceLock::new();
    C7.get_or_init(|| swu_z().pow_be(&hex::decode(SQRT_C2P1H_HEX).expect("static hex")))
}

/// RFC 9380 Appendix F.2.1.1 generic sqrt_ratio over Fp2 (q = p^2, c1 = 3).
fn sqrt_ratio(u: &Fp2, v: &Fp2) -> (bool, Fp2) {
    let c3 = hex::decode(SQRT_C3_HEX).expect("static hex");
    let mut tv1 = *sqrt_ratio_c6();
    let tv2 = {
        // v^c4 with c4 = 2^3 - 1 = 7
        let v2 = v.sqr();
        let v4 = v2.sqr();
        v4.mul(&v2).mul(v)
    };
    let mut tv3 = tv2.sqr().mul(v);
    let mut tv5 = u.mul(&tv3).pow_be(&c3).mul(&tv2);
    let tv2 = tv5.mul(v);
    tv3 = tv5.mul(u);
    let mut tv4 = tv3.mul(&tv2);
    tv5 = tv4.sqr().sqr(); // c5 = 2^(c1-1) = 4
    let is_qr = tv5 == Fp2::one();
    let tv3_alt = tv3.mul(sqrt_ratio_c7());
    let tv4_alt = tv4.mul(&tv1);
    if !is_qr {
        tv3 = tv3_alt;
        tv4 = tv4_alt;
    }
    for i in (2..=SQRT_C1).rev() {
        // tv5 = tv4^(2^(i-2))
        let mut t = tv4;
        for _ in 0..(i - 2) {
            t = t.sqr();
        }
        let e1 = t == Fp2::one();
        let tv3_alt = tv3.mul(&tv1);
        tv1 = tv1.sqr();
        let tv4_alt = tv4.mul(&tv1);
        // RFC F.2.1.1 steps 25-26: CMOV picks the adjusted values when NOT e1.
        if !e1 {
            tv3 = tv3_alt;
            tv4 = tv4_alt;
        }
    }
    (is_qr, tv3)
}

/// RFC 9380 Appendix F.2 straight-line Simplified SWU onto the isogenous curve E'.
fn map_to_curve_swu(u: &Fp2) -> (Fp2, Fp2) {
    let z = swu_z();
    let a = swu_a();
    let b = swu_b();
    let tv1 = z.mul(&u.sqr());
    let mut tv2 = tv1.sqr().add(&tv1);
    let tv3 = b.mul(&tv2.add(&Fp2::one()));
    let tv4 = if tv2.is_zero() { z } else { tv2.neg() }.mul(&a);
    tv2 = tv3.sqr();
    let tv6 = tv4.sqr();
    tv2 = tv2.add(&a.mul(&tv6)).mul(&tv3);
    let tv6 = tv6.mul(&tv4);
    tv2 = tv2.add(&b.mul(&tv6));
    let mut x = tv1.mul(&tv3);
    let (is_sq, y1) = sqrt_ratio(&tv2, &tv6);
    let mut y = tv1.mul(u).mul(&y1);
    if is_sq {
        x = tv3;
        y = y1;
    }
    if y.sgn0() != u.sgn0() {
        y = y.neg();
    }
    (x.mul(&tv4.inv()), y)
}

/// The 3-isogeny from E' onto E: y^2 = x^3 + 4(1 + i) (RFC 9380 Appendix E.3).
fn iso_map(x: &Fp2, y: &Fp2) -> Result<(Fp2, Fp2)> {
    fn horner(coeffs: &[Fp2], x: &Fp2) -> Fp2 {
        let mut acc = Fp2::zero();
        for c in coeffs {
            acc = acc.mul(x).add(c);
        }
        acc
    }
    let xnum: Vec<Fp2> = ISO_XNUM
        .iter()
        .map(|(re, im)| Fp2::from_hex(re, im))
        .collect::<Result<Vec<_>>>()?;
    let xden: Vec<Fp2> = ISO_XDEN
        .iter()
        .map(|(re, im)| Fp2::from_hex(re, im))
        .collect::<Result<Vec<_>>>()?;
    let ynum: Vec<Fp2> = ISO_YNUM
        .iter()
        .map(|(re, im)| Fp2::from_hex(re, im))
        .collect::<Result<Vec<_>>>()?;
    let yden: Vec<Fp2> = ISO_YDEN
        .iter()
        .map(|(re, im)| Fp2::from_hex(re, im))
        .collect::<Result<Vec<_>>>()?;
    // x_den = x^2 + k_(2,1) x + k_(2,0); y_den = x^3 + k_(4,2) x^2 + k_(4,1) x + k_(4,0).
    let xn = horner(&xnum, x);
    let xd = horner(&[Fp2::one(), xden[0], xden[1]], x);
    let yn = horner(&ynum, x);
    let yd = horner(&[Fp2::one(), yden[0], yden[1], yden[2]], x);
    Ok((xn.mul(&xd.inv()), y.mul(&yn).mul(&yd.inv())))
}

fn map_to_g2(u: &Fp2) -> Result<Point<Fp2>> {
    let (x, y) = map_to_curve_swu(u);
    let (xi, yi) = iso_map(&x, &y)?;
    Ok(Point::affine(xi, yi))
}

/// H(msg) in G2 per RFC 9380 with the given ciphersuite DST.
fn hash_to_g2(msg: &[u8], dst: &[u8]) -> Result<Point<Fp2>> {
    let [u0, u1] = hash_to_field_fp2(msg, dst);
    let q0 = map_to_g2(&u0)?;
    let q1 = map_to_g2(&u1)?;
    let r = q0.add(&q1);
    // H_EFF is emitted as minimal hex; pad to whole bytes.
    let h_eff_hex = if H_EFF.len() % 2 == 1 {
        format!("0{H_EFF}")
    } else {
        H_EFF.to_string()
    };
    let h_eff = hex::decode(h_eff_hex).expect("static hex");
    Ok(r.mul_be(&h_eff))
}

// ---------------------------------------------------------------------------
// BLS public keys and aug_scheme_mpl signatures.
// ---------------------------------------------------------------------------

fn g1_generator() -> Result<Point<Fp>> {
    Ok(Point::affine(
        Fp::from_hex(G1_GENERATOR_X)?,
        Fp::from_hex(G1_GENERATOR_Y)?,
    ))
}

/// The 48-byte compressed G1 public key for a 32-byte secret key.
pub fn public_key(secret: &[u8; 32]) -> Result<[u8; 48]> {
    let sk = Scalar::from_be_bytes(secret);
    if sk.is_zero() {
        return Err(invalid("zero secret key"));
    }
    let point = g1_generator()?.mul_be(secret);
    Ok(g1_compress(&point))
}

fn g1_compress(point: &Point<Fp>) -> [u8; 48] {
    match point.to_affine() {
        None => {
            let mut out = [0u8; 48];
            out[0] = 0xc0;
            out
        }
        Some((x, y)) => {
            let mut out = x.to_be_bytes();
            out[0] |= 0x80;
            if y.lex_largest() {
                out[0] |= 0x20;
            }
            out
        }
    }
}

fn g2_compress(point: &Point<Fp2>) -> [u8; 96] {
    match point.to_affine() {
        None => {
            let mut out = [0u8; 96];
            out[0] = 0xc0;
            out
        }
        Some((x, y)) => {
            // zcash/blst order: the imaginary limb first, then the real one.
            let mut out = [0u8; 96];
            out[..48].copy_from_slice(&x.c1.to_be_bytes());
            out[48..].copy_from_slice(&x.c0.to_be_bytes());
            out[0] |= 0x80;
            if y.lex_largest() {
                out[0] |= 0x20;
            }
            out
        }
    }
}

/// The standard wallet's synthetic secret key: sk + sha256(pk || hidden) mod r.
fn synthetic_secret(secret: &[u8; 32]) -> Result<Scalar> {
    let sk = Scalar::from_be_bytes(secret);
    if sk.is_zero() {
        return Err(invalid("zero secret key"));
    }
    let pk = public_key(secret)?;
    let hidden = hex_to_bytes32(DEFAULT_HIDDEN_PUZZLE_HASH)?;
    let digest = Sha256::digest([pk.as_slice(), hidden.as_slice()].concat());
    let mut offset_arr = [0u8; 32];
    offset_arr.copy_from_slice(&digest);
    Ok(sk.add(&Scalar::from_be_bytes(&offset_arr)))
}

/// The 48-byte compressed synthetic public key committed to by the puzzle.
pub fn synthetic_public_key(secret: &[u8; 32]) -> Result<[u8; 48]> {
    let synth = synthetic_secret(secret)?;
    let point = g1_generator()?.mul_be(&synth.to_be_bytes());
    Ok(g1_compress(&point))
}

/// aug_scheme_mpl: sig = synth_sk * H(synth_pk || msg) with the AUG DST.
fn aug_sign(msg: &[u8], secret: &[u8; 32]) -> Result<[u8; 96]> {
    let synth_sk = synthetic_secret(secret)?;
    let synth_pk = synthetic_public_key(secret)?;
    let mut full = Vec::with_capacity(48 + msg.len());
    full.extend_from_slice(&synth_pk);
    full.extend_from_slice(msg);
    let h = hash_to_g2(&full, DST_AUG)?;
    let sig = h.mul_be(&synth_sk.to_be_bytes());
    Ok(g2_compress(&sig))
}

// ---------------------------------------------------------------------------
// CLVM: minimal S-expressions, serialization and sha256 tree hashing.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum SExp {
    Atom(Vec<u8>),
    Pair(Box<SExp>, Box<SExp>),
}

impl SExp {
    fn atom(bytes: impl AsRef<[u8]>) -> SExp {
        SExp::Atom(bytes.as_ref().to_vec())
    }
    fn int(value: u64) -> SExp {
        // CLVM ints are minimal big-endian two's complement; a positive value
        // with the top bit set takes a 0x00 prefix.
        if value == 0 {
            return SExp::Atom(vec![]);
        }
        let bytes = value.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).expect("nonzero");
        let mut out = bytes[first..].to_vec();
        if out[0] & 0x80 != 0 {
            out.insert(0, 0);
        }
        SExp::Atom(out)
    }
    fn pair(l: SExp, r: SExp) -> SExp {
        SExp::Pair(Box::new(l), Box::new(r))
    }
    fn list(items: Vec<SExp>) -> SExp {
        let mut acc = SExp::Atom(vec![]);
        for item in items.into_iter().rev() {
            acc = SExp::pair(item, acc);
        }
        acc
    }

    fn parse(bytes: &[u8]) -> Result<(SExp, usize)> {
        if bytes.is_empty() {
            return Err(invalid("truncated CLVM"));
        }
        let b = bytes[0];
        if b == 0xff {
            let (l, used_l) = SExp::parse(&bytes[1..])?;
            let (r, used_r) = SExp::parse(&bytes[1 + used_l..])?;
            return Ok((SExp::pair(l, r), 1 + used_l + used_r));
        }
        if b <= 0x7f {
            return Ok((SExp::Atom(vec![b]), 1));
        }
        let (len, header) = if b < 0xc0 {
            ((b & 0x3f) as usize, 1)
        } else if b < 0xe0 {
            if bytes.len() < 2 {
                return Err(invalid("truncated CLVM atom"));
            }
            ((((b & 0x1f) as usize) << 8) | bytes[1] as usize, 2)
        } else if b < 0xf0 {
            if bytes.len() < 3 {
                return Err(invalid("truncated CLVM atom"));
            }
            (
                (((b & 0x0f) as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize,
                3,
            )
        } else {
            return Err(invalid("CLVM atom too long"));
        };
        if bytes.len() < header + len {
            return Err(invalid("truncated CLVM atom"));
        }
        Ok((
            SExp::Atom(bytes[header..header + len].to_vec()),
            header + len,
        ))
    }

    fn serialize(&self) -> Vec<u8> {
        match self {
            SExp::Atom(a) => {
                if a.is_empty() {
                    return vec![0x80];
                }
                if a.len() == 1 && a[0] < 0x80 {
                    return a.clone();
                }
                let mut out = Vec::with_capacity(a.len() + 3);
                if a.len() < 0x40 {
                    out.push(0x80 + a.len() as u8);
                } else if a.len() < 0x2000 {
                    out.push(0xc0 | (a.len() >> 8) as u8);
                    out.push((a.len() & 0xff) as u8);
                } else {
                    out.push(0xe0 | (a.len() >> 16) as u8);
                    out.push(((a.len() >> 8) & 0xff) as u8);
                    out.push((a.len() & 0xff) as u8);
                }
                out.extend_from_slice(a);
                out
            }
            SExp::Pair(l, r) => {
                let mut out = vec![0xff];
                out.extend_from_slice(&l.serialize());
                out.extend_from_slice(&r.serialize());
                out
            }
        }
    }

    fn tree_hash(&self) -> [u8; 32] {
        match self {
            SExp::Atom(a) => {
                let mut input = Vec::with_capacity(1 + a.len());
                input.push(1);
                input.extend_from_slice(a);
                Sha256::digest(&input).into()
            }
            SExp::Pair(l, r) => {
                let lh = l.tree_hash();
                let rh = r.tree_hash();
                let mut input = Vec::with_capacity(65);
                input.push(2);
                input.extend_from_slice(&lh);
                input.extend_from_slice(&rh);
                Sha256::digest(&input).into()
            }
        }
    }
}

fn standard_mod() -> Result<SExp> {
    let bytes = hex::decode(MOD_HEX).expect("static hex");
    let (sexp, used) = SExp::parse(&bytes)?;
    if used != bytes.len() {
        return Err(invalid("standard puzzle has trailing bytes"));
    }
    Ok(sexp)
}

/// `(2 (1 . MOD) (4 (1 . arg) 1))` — the curry pattern every Chia wallet uses.
fn curry_standard(arg: &[u8; 48]) -> Result<SExp> {
    Ok(SExp::list(vec![
        SExp::atom([2]),
        SExp::pair(SExp::atom([1]), standard_mod()?),
        SExp::list(vec![
            SExp::atom([4]),
            SExp::pair(SExp::atom([1]), SExp::atom(arg)),
            SExp::atom([1]),
        ]),
    ]))
}

/// The 32-byte puzzle hash behind a bech32m `xch1…`/`txch1…` address.
pub fn puzzle_hash_from_address(chain: &str, address: &str) -> Result<[u8; 32]> {
    if address.len() != 63 {
        return Err(invalid("address must be 63 characters"));
    }
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|_| invalid("invalid bech32m address"))?;
    if checked.hrp().as_str() != hrp(chain)? {
        return Err(invalid("address prefix does not match the network"));
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    if bytes.len() != 32 {
        return Err(invalid("address must hold a 32-byte puzzle hash"));
    }
    Ok(bytes.try_into().expect("32 bytes"))
}

/// The bech32m address for a puzzle hash on a network.
pub fn address_from_puzzle_hash(chain: &str, puzzle_hash: &[u8; 32]) -> Result<String> {
    bech32::encode::<Bech32m>(Hrp::parse(hrp(chain)?).expect("static hrp"), puzzle_hash)
        .map_err(|_| invalid("address encoding failed"))
}

/// Decompress a 48-byte G1 point (used to combine pubkey + synthetic offset).
fn g1_decompress(bytes: &[u8; 48]) -> Result<Point<Fp>> {
    if bytes[0] & 0x80 == 0 {
        return Err(invalid("public key is not compressed"));
    }
    if bytes[0] & 0x40 != 0 {
        return Err(invalid("infinity public key"));
    }
    let sign = bytes[0] & 0x20 != 0;
    let mut xb = *bytes;
    xb[0] &= 0x1f;
    let x = Fp::from_hex(&hex::encode(xb))?;
    // y^2 = x^3 + 4; p % 4 == 3, so the root is y2^((p+1)/4)
    let rhs = x.sqr().mul(&x).add(&Fp::from_u64(4));
    let mut exp = FP_MODULUS;
    let (v, mut carry) = exp[0].overflowing_add(1);
    exp[0] = v;
    for limb in exp.iter_mut().skip(1) {
        let (v, c) = limb.overflowing_add(carry as u64);
        *limb = v;
        carry = c;
    }
    let mut quarter = [0u64; 6];
    for i in 0..5 {
        quarter[i] = (exp[i] >> 2) | (exp[i + 1] << 62);
    }
    quarter[5] = exp[5] >> 2;
    let mut exp_bytes = [0u8; 48];
    for i in 0..6 {
        exp_bytes[i * 8..(i + 1) * 8].copy_from_slice(&quarter[5 - i].to_be_bytes());
    }
    let y = rhs.pow_be(&exp_bytes);
    if y.sqr() != rhs {
        return Err(invalid("public key is not on the curve"));
    }
    let y = if y.lex_largest() == sign { y } else { y.neg() };
    Ok(Point::affine(x, y))
}

/// The sender address (testnet prefix) for the core-held 48-byte BLS public key:
/// the synthetic key is derived, curried into the standard puzzle and hashed.
pub fn address(public: &[u8]) -> Result<String> {
    if public.len() != 48 {
        return Err(invalid("public key must be 48 bytes"));
    }
    let pk: [u8; 48] = public.try_into().expect("48 bytes");
    let hidden = hex_to_bytes32(DEFAULT_HIDDEN_PUZZLE_HASH)?;
    let digest = Sha256::digest([public, hidden.as_slice()].concat());
    let mut offset_arr = [0u8; 32];
    offset_arr.copy_from_slice(&digest);
    let offset = Scalar::from_be_bytes(&offset_arr);
    let synth_point = g1_decompress(&pk)?.add(&g1_generator()?.mul_be(&offset.to_be_bytes()));
    let synth_pk = g1_compress(&synth_point);
    let ph = curry_standard(&synth_pk)?.tree_hash();
    address_from_puzzle_hash(TESTNET11, &ph)
}

// ---------------------------------------------------------------------------
// The transaction itself.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChiaTx {
    pub chain_id: String,
    /// Sender bech32m address (puzzle hash of its standard puzzle).
    pub from: String,
    pub to: String,
    /// Decimal mojos (1 XCH = 10^12 mojos); never a JSON floating-point number.
    pub mojos: String,
    /// Decimal mojos reserved as the network fee; "0" is allowed on testnet.
    pub fee: String,
    /// The spent coin's parent coin id, 64 lowercase hex.
    pub parent_coin_id: String,
    /// The spent coin's total value in decimal mojos; change returns to the sender.
    pub coin_mojos: String,
}

struct Built {
    from_ph: [u8; 32],
    parent: [u8; 32],
    coin_value: u64,
    conditions: SExp,
    coin_id: [u8; 32],
    genesis: [u8; 32],
}

impl ChiaTx {
    fn parse_amount(value: &str, what: &str, allow_zero: bool) -> Result<u64> {
        let amount = value
            .parse::<u64>()
            .map_err(|_| invalid(format!("{what} must be a decimal integer")))?;
        if amount.to_string() != value {
            return Err(invalid(format!("{what} must be canonical decimal")));
        }
        if amount > MAX_MOJOS {
            return Err(invalid(format!("{what} exceeds the mojo cap")));
        }
        if amount == 0 && !allow_zero {
            return Err(invalid(format!("{what} must be positive")));
        }
        Ok(amount)
    }

    fn build(&self) -> Result<Built> {
        check_chain(&self.chain_id)?;
        let from_ph = puzzle_hash_from_address(&self.chain_id, &self.from)?;
        let to_ph = puzzle_hash_from_address(&self.chain_id, &self.to)?;
        if from_ph == to_ph {
            return Err(invalid("sender and recipient must differ"));
        }
        if from_ph.iter().all(|b| *b == 0) || to_ph.iter().all(|b| *b == 0) {
            return Err(invalid("zero puzzle hash"));
        }
        let amount = Self::parse_amount(&self.mojos, "amount", false)?;
        let fee = Self::parse_amount(&self.fee, "fee", true)?;
        let coin_value = Self::parse_amount(&self.coin_mojos, "coin value", false)?;
        let total = amount
            .checked_add(fee)
            .ok_or_else(|| invalid("amount plus fee overflows"))?;
        if total > coin_value {
            return Err(invalid("amount plus fee exceeds the coin's value"));
        }
        let change = coin_value - total;
        let parent = hex_to_bytes32(&self.parent_coin_id)?;
        let genesis = genesis_challenge(&self.chain_id)?;
        // The coin id hashes the amount as a minimal big-endian CLVM integer
        // (zero-prefixed when the high bit is set), exactly as chia's
        // `Coin::coin_id()` — not as a fixed 8-byte integer.
        let coin_id: [u8; 32] = {
            let amount_bytes = coin_value.to_be_bytes();
            let mut start = 0;
            while start < 7 && amount_bytes[start] == 0 && amount_bytes[start + 1] & 0x80 == 0 {
                start += 1;
            }
            let mut input = Vec::with_capacity(72);
            input.extend_from_slice(&parent);
            input.extend_from_slice(&from_ph);
            input.extend_from_slice(&amount_bytes[start..]);
            Sha256::digest(&input).into()
        };
        let mut conditions = Vec::with_capacity(3);
        if fee > 0 {
            conditions.push(SExp::list(vec![
                SExp::int(RESERVE_FEE as u64),
                SExp::int(fee),
            ]));
        }
        conditions.push(SExp::list(vec![
            SExp::int(CREATE_COIN as u64),
            SExp::atom(to_ph),
            SExp::int(amount),
        ]));
        if change > 0 {
            conditions.push(SExp::list(vec![
                SExp::int(CREATE_COIN as u64),
                SExp::atom(from_ph),
                SExp::int(change),
            ]));
        }
        Ok(Built {
            from_ph,
            parent,
            coin_value,
            conditions: SExp::list(conditions),
            coin_id,
            genesis,
        })
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native XCH transfers are enabled"));
                }
                if puzzle_hash_from_address(&self.chain_id, to)?
                    != puzzle_hash_from_address(&self.chain_id, &self.to)?
                {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.mojos {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Chia intent")),
        }
        self.build()?;
        Ok(())
    }

    /// The id of the coin this transfer spends (what indexers key the spend by).
    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(self.build()?.coin_id)
    }

    /// The exact `( delegated_puzzle_tree_hash || coin_id || genesis )` message
    /// the signature commits to (the pubkey is prepended by aug_scheme_mpl).
    pub fn signing_message(&self) -> Result<[u8; 96]> {
        let built = self.build()?;
        let delegated = SExp::pair(SExp::atom([1]), built.conditions.clone());
        let mut msg = [0u8; 96];
        msg[..32].copy_from_slice(&delegated.tree_hash());
        msg[32..64].copy_from_slice(&built.coin_id);
        msg[64..].copy_from_slice(&built.genesis);
        Ok(msg)
    }

    /// Signs and returns `(wire, name)`: the spend bundle JSON ready for
    /// `/push_tx` (as `{"spend_bundle": <wire>}`) and the bundle's name hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let built = self.build()?;
        let synth_pk = synthetic_public_key(secret)?;
        let puzzle = curry_standard(&synth_pk)?;
        if puzzle.tree_hash() != built.from_ph {
            return Err(invalid("sender differs from signing key"));
        }
        let msg = self.signing_message()?;
        let signature = aug_sign(&msg, secret)?;
        let delegated = SExp::pair(SExp::atom([1]), built.conditions.clone());
        let solution = SExp::list(vec![SExp::atom([]), delegated, SExp::atom([])]);
        let puzzle_hex = puzzle.serialize();
        let solution_hex = solution.serialize();
        let wire = serde_json::json!({
            "coin_spends": [{
                "coin": {
                    "parent_coin_info": format!("0x{}", hex::encode(built.parent)),
                    "puzzle_hash": format!("0x{}", hex::encode(built.from_ph)),
                    "amount": built.coin_value,
                },
                "puzzle_reveal": format!("0x{}", hex::encode(&puzzle_hex)),
                "solution": format!("0x{}", hex::encode(&solution_hex)),
            }],
            "aggregated_signature": format!("0x{}", hex::encode(signature)),
        });
        // The bundle name is sha256 of its streamable encoding: the spend count,
        // then each coin spend (coin, then the programs raw — SerializedProgram
        // is self-delimiting and streams without a length prefix), then the
        // signature. Pinned against a live testnet11 node's own computation.
        let mut stream = Vec::with_capacity(4 + 72 + puzzle_hex.len() + solution_hex.len() + 96);
        stream.extend_from_slice(&1u32.to_be_bytes());
        stream.extend_from_slice(&built.parent);
        stream.extend_from_slice(&built.from_ph);
        stream.extend_from_slice(&built.coin_value.to_be_bytes());
        stream.extend_from_slice(&puzzle_hex);
        stream.extend_from_slice(&solution_hex);
        stream.extend_from_slice(&signature);
        let name: [u8; 32] = Sha256::digest(&stream).into();
        Ok((wire.to_string(), hex::encode(name)))
    }
}

// ---------------------------------------------------------------------------
// Constants generated by .nur/chia-gen.mjs from RFC 9380 and the Chia sources.
// ---------------------------------------------------------------------------

const FP_MODULUS: [u64; 6] = [
    0xb9feffffffffaaab,
    0x1eabfffeb153ffff,
    0x6730d2a0f6b0f624,
    0x64774b84f38512bf,
    0x4b1ba7b6434bacd7,
    0x1a0111ea397fe69a,
];
const FP_INV: u64 = 0x89f3fffcfffcfffd;
const FP_R: [u64; 6] = [
    0x760900000002fffd,
    0xebf4000bc40c0002,
    0x5f48985753c758ba,
    0x77ce585370525745,
    0x5c071a97a256ec6d,
    0x15f65ec3fa80e493,
];
const FP_R2: [u64; 6] = [
    0xf4df1f341c341746,
    0xa76e6a609d104f1,
    0x8de5476c4c95b6d5,
    0x67eb88a9939d83c0,
    0x9a793e85b519952d,
    0x11988fe592cae3aa,
];
const FR_MODULUS: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];
const G1_GENERATOR_X: &str = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
const G1_GENERATOR_Y: &str = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const H_EFF: &str = "bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551";
const SQRT_C1: u32 = 3;
const SQRT_C2_HEX: &str = "5486f497186bf8e97a4f1d5445e4bd3c5b921ca1ce08d68cdcb3c92693d17a0a14c59fa2dbb94ddea62926612f1de023ad0c3390c30b8f6525d0b50e1234092cd7f23da7ce36e862c586706c42279faf9dad63aec705d564d54000038e31c7";
const SQRT_C3_HEX: &str = "2a437a4b8c35fc74bd278eaa22f25e9e2dc90e50e7046b466e59e49349e8bd050a62cfd16ddca6ef53149330978ef011d68619c86185c7b292e85a87091a04966bf91ed3e71b743162c338362113cfd7ced6b1d76382eab26aa00001c718e3";
const SQRT_C2P1H_HEX: &str = "2a437a4b8c35fc74bd278eaa22f25e9e2dc90e50e7046b466e59e49349e8bd050a62cfd16ddca6ef53149330978ef011d68619c86185c7b292e85a87091a04966bf91ed3e71b743162c338362113cfd7ced6b1d76382eab26aa00001c718e4";
const MOD_HEX: &str = "ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080";
#[cfg(test)]
const MOD_TREE_HASH: &str = "e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52";
const DEFAULT_HIDDEN_PUZZLE_HASH: &str =
    "711d6c4e32c92e53179b199484cf8c897542bc57f2b22582799f9d657eec4699";
const ISO_XNUM: [(&str, &str); 4] = [
    (
        "171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
        "08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a",
    ),
    (
        "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
        "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
    ),
];
const ISO_XDEN: [(&str, &str); 2] = [
    (
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63",
    ),
];
const ISO_YNUM: [(&str, &str); 4] = [
    (
        "124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
        "08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be",
    ),
    (
        "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
        "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
    ),
];
const ISO_YDEN: [(&str, &str); 3] = [
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99",
    ),
    (
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3",
    ),
    (
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    // All vectors are generated by .nur/chia-gen.mjs (@noble/curves oracle) and
    // pinned against: the ERC-2333 reference (master key), RFC 9380 Appendix J.10.1
    // (G2 hash vectors, reproduced by noble), on-chain testnet11/mainnet data
    // (puzzle MOD hex and tree hash), and a noble-verified example transfer.

    const SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    const MASTER_SK: &str = "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070";
    const SK0: &str = "34c88f28564e51bf16c91b8dac1e8f882e3f9c5ccc9c6212897da201f169de99";
    const SK1: &str = "4fb5cef79520a703815c664954119330ab5a33526149c166eb6db049f3c188d2";
    const PK0: &str = "b2fcc06b717db87fdb3db4c08e1af09b9dfbd03c26eadbc1f189c2cb0fc613e065b11345e4c8a3b42b1f648ec85e8485";
    const SYNTH_SK0: &str = "221ce259de3a497910eff95bf44cf29724a7b62ab10d1de6d7a82dfaaacf8455";
    const SYNTH_PK0: &str = "a190f944426d03ee611ce3051de3fc065c21ab14bedaa4dafef2a91906e8bdcf155a3986eeac6e46fbb4576652528450";
    const SYNTH_PK1: &str = "a8a69ea53ff234e9066ecc84e2a6f1024d5b397b146198a8ca7b3affad9caaa7c443794b1b40ef11fa083fde2370ea37";
    const PH0: &str = "64acb69e5b36b222912a945a87c51660d27b51f0e912ac8c4b0e1560b4e5a0a3";
    const PH1: &str = "c924f604d7ff8e651dd1720edd9f06723bb4435f8d1cd81f89d63571459dd381";
    const TXCH0: &str = "txch1vjktd8jmx6ez9yf2j3dg03gkvrf8k50sayf2erztpc2kpd895z3sgv6hx3";
    const TXCH1: &str = "txch1eyj0vpxhl78x28w3wg8dm8cxwgamgs6l35wds8uf6c6hz3va6wqslwp336";
    const XCH0: &str = "xch1vjktd8jmx6ez9yf2j3dg03gkvrf8k50sayf2erztpc2kpd895z3s9tap8z";
    const RFC_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

    fn sk(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }

    fn sample_tx() -> ChiaTx {
        ChiaTx {
            chain_id: TESTNET11.into(),
            from: TXCH0.into(),
            to: TXCH1.into(),
            mojos: "1500000".into(),
            fee: "100".into(),
            parent_coin_id: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                .into(),
            coin_mojos: "2000000".into(),
        }
    }

    fn intent(tx: &ChiaTx) -> TxIntent {
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
                amount: Amount(tx.mojos.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn eip2333_master_key_matches_erc_vector() {
        // ERC-2333 test case 0.
        let seed = hex::decode(SEED).unwrap();
        assert_eq!(hex::encode(master_sk_from_seed(&seed).unwrap()), MASTER_SK);
    }

    #[test]
    fn wallet_keys_match_oracle() {
        let master = sk(MASTER_SK);
        let sk0 = wallet_sk(&master, 0).unwrap();
        assert_eq!(hex::encode(sk0), SK0);
        assert_eq!(hex::encode(wallet_sk(&master, 1).unwrap()), SK1);
        assert_eq!(hex::encode(public_key(&sk0).unwrap()), PK0);
        assert_eq!(
            hex::encode(synthetic_secret(&sk0).unwrap().to_be_bytes()),
            SYNTH_SK0
        );
        assert_eq!(hex::encode(synthetic_public_key(&sk0).unwrap()), SYNTH_PK0);
        assert_eq!(
            hex::encode(synthetic_public_key(&sk(SK1)).unwrap()),
            SYNTH_PK1
        );
    }

    #[test]
    fn addresses_match_oracle() {
        let pk0 = hex::decode(PK0).unwrap();
        assert_eq!(address(&pk0).unwrap(), TXCH0);
        assert_eq!(address(&public_key(&sk(SK1)).unwrap()).unwrap(), TXCH1);
        let ph0 = hex_to_bytes32(PH0).unwrap();
        assert_eq!(puzzle_hash_from_address(TESTNET11, TXCH0).unwrap(), ph0);
        assert_eq!(
            puzzle_hash_from_address(TESTNET11, TXCH1).unwrap(),
            hex_to_bytes32(PH1).unwrap()
        );
        assert_eq!(address_from_puzzle_hash(MAINNET, &ph0).unwrap(), XCH0);
        // round-trip
        assert_eq!(address_from_puzzle_hash(TESTNET11, &ph0).unwrap(), TXCH0);
    }

    #[test]
    fn puzzle_mod_matches_deployed_program() {
        // Tree hash of the byte-for-byte MOD the network runs (extracted from
        // a real on-chain puzzle reveal).
        assert_eq!(
            hex::encode(standard_mod().unwrap().tree_hash()),
            MOD_TREE_HASH
        );
        // The sender's puzzle hashes to the address puzzle hash.
        let synth = hex::decode(SYNTH_PK0).unwrap().try_into().unwrap();
        let puzzle = curry_standard(&synth).unwrap();
        assert_eq!(hex::encode(puzzle.tree_hash()), PH0);
        // The puzzle reveal serializes to the oracle bytes.
        assert_eq!(
            hex::encode(puzzle.serialize()),
            "ff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b0a190f944426d03ee611ce3051de3fc065c21ab14bedaa4dafef2a91906e8bdcf155a3986eeac6e46fbb4576652528450ff018080"
        );
    }

    fn fp2_hex(f: &Fp2) -> (String, String) {
        (
            hex::encode(f.c0.to_be_bytes()),
            hex::encode(f.c1.to_be_bytes()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn check_rfc_vector(
        msg: &[u8],
        u0: (&str, &str),
        u1: (&str, &str),
        q0x: (&str, &str),
        q0y: (&str, &str),
        q1x: (&str, &str),
        q1y: (&str, &str),
        px: (&str, &str),
        py: (&str, &str),
    ) {
        let us = hash_to_field_fp2(msg, RFC_DST);
        assert_eq!(fp2_hex(&us[0]), (u0.0.to_string(), u0.1.to_string()));
        assert_eq!(fp2_hex(&us[1]), (u1.0.to_string(), u1.1.to_string()));
        let q0 = map_to_g2(&us[0]).unwrap().to_affine().unwrap();
        assert_eq!(fp2_hex(&q0.0), (q0x.0.to_string(), q0x.1.to_string()));
        assert_eq!(fp2_hex(&q0.1), (q0y.0.to_string(), q0y.1.to_string()));
        let q1 = map_to_g2(&us[1]).unwrap().to_affine().unwrap();
        assert_eq!(fp2_hex(&q1.0), (q1x.0.to_string(), q1x.1.to_string()));
        assert_eq!(fp2_hex(&q1.1), (q1y.0.to_string(), q1y.1.to_string()));
        let p = hash_to_g2(msg, RFC_DST).unwrap().to_affine().unwrap();
        assert_eq!(fp2_hex(&p.0), (px.0.to_string(), px.1.to_string()));
        assert_eq!(fp2_hex(&p.1), (py.0.to_string(), py.1.to_string()));
    }

    #[test]
    fn rfc9380_g2_empty_message_vector() {
        check_rfc_vector(
            b"",
            (
                "03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8",
                "05a2acec64114845711a54199ea339abd125ba38253b70a92c876df10598bd1986b739cad67961eb94f7076511b3b39a",
            ),
            (
                "02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846bc825de191b5b7641148c0dbc237726a334473eee94",
                "145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b2f6eb0c4b94c9115b436e6fa4607e95a98de30a435",
            ),
            (
                "019ad3fc9c72425a998d7ab1ea0e646a1f6093444fc6965f1cad5a3195a7b1e099c050d57f45e3fa191cc6d75ed7458c",
                "171c88b0b0efb5eb2b88913a9e74fe111a4f68867b59db252ce5868af4d1254bfab77ebde5d61cd1a86fb2fe4a5a1c1d",
            ),
            (
                "0ba10604e62bdd9eeeb4156652066167b72c8d743b050fb4c1016c31b505129374f76e03fa127d6a156213576910fef3",
                "0eb22c7a543d3d376e9716a49b72e79a89c9bfe9feee8533ed931cbb5373dde1fbcd7411d8052e02693654f71e15410a",
            ),
            (
                "113d2b9cd4bd98aee53470b27abc658d91b47a78a51584f3d4b950677cfb8a3e99c24222c406128c91296ef6b45608be",
                "13855912321c5cb793e9d1e88f6f8d342d49c0b0dbac613ee9e17e3c0b3c97dfbb5a49cc3fb45102fdbaf65e0efe2632",
            ),
            (
                "0fd3def0b7574a1d801be44fde617162aa2e89da47f464317d9bb5abc3a7071763ce74180883ad7ad9a723a9afafcdca",
                "056f617902b3c0d0f78a9a8cbda43a26b65f602f8786540b9469b060db7b38417915b413ca65f875c130bebfaa59790c",
            ),
            (
                "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
                "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
            ),
            (
                "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
                "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
            ),
        );
        // noble's compressed encoding of the same point.
        let p = hash_to_g2(b"", RFC_DST).unwrap();
        assert_eq!(
            hex::encode(g2_compress(&p)),
            "a5cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a"
        );
    }

    #[test]
    fn rfc9380_g2_abc_vector() {
        check_rfc_vector(
            b"abc",
            (
                "15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771",
                "01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670fd8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd",
            ),
            (
                "187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f8c372a693f60a033b461d81b025864a0ad051a06e4",
                "08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a051ea586f3538a6ebb1e80881a082fa2b24df9f566",
            ),
            (
                "12b2e525281b5f4d2276954e84ac4f42cf4e13b6ac4228624e17760faf94ce5706d53f0ca1952f1c5ef75239aeed55ad",
                "05d8a724db78e570e34100c0bc4a5fa84ad5839359b40398151f37cff5a51de945c563463c9efbdda569850ee5a53e77",
            ),
            (
                "02eacdc556d0bdb5d18d22f23dcb086dd106cad713777c7e6407943edbe0b3d1efe391eedf11e977fac55f9b94f2489c",
                "04bbe48bfd5814648d0b9e30f0717b34015d45a861425fabc1ee06fdfce36384ae2c808185e693ae97dcde118f34de41",
            ),
            (
                "19f18cc5ec0c2f055e47c802acc3b0e40c337256a208001dde14b25afced146f37ea3d3ce16834c78175b3ed61f3c537",
                "15b0dadc256a258b4c68ea43605dffa6d312eef215c19e6474b3e101d33b661dfee43b51abbf96fee68fc6043ac56a58",
            ),
            (
                "05e47c1781286e61c7ade887512bd9c2cb9f640d3be9cf87ea0bad24bd0ebfe946497b48a581ab6c7d4ca74b5147287f",
                "19f98db2f4a1fcdf56a9ced7b320ea9deecf57c8e59236b0dc21f6ee7229aa9705ce9ac7fe7a31c72edca0d92370c096",
            ),
            (
                "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
                "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
            ),
            (
                "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
                "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
            ),
        );
    }

    #[test]
    fn transfer_signs_to_oracle_vector() {
        let tx = sample_tx();
        // Coin id and the exact consensus message the signature commits to.
        // The coin id hashes the amount as a minimal CLVM integer; the message
        // semantics (tree hash || coin id || genesis, aug scheme) were verified
        // against real mainnet spends with an independent pairing library, and
        // this exact bundle was accepted past signature validation by a live
        // testnet11 node (it rejected only with UNKNOWN_UNSPENT, because the
        // example coin does not exist on-chain).
        assert_eq!(
            hex::encode(tx.txid().unwrap()),
            "a816778fb62b4c4628e85809dcabd8ce91160f986d6cf6db39c30c91f78d41db"
        );
        assert_eq!(
            hex::encode(tx.signing_message().unwrap()),
            "7dc53a420562c990921dd4eaf1d2134ee86c3cd0f37d1bdaa6170c66714d6d7ca816778fb62b4c4628e85809dcabd8ce91160f986d6cf6db39c30c91f78d41db37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
        );
        let (wire, name) = tx.sign(&sk(SK0)).unwrap();
        // A live testnet11 full node computed this same name for this exact bundle.
        assert_eq!(
            name,
            "12d2c57b75b1854472edd3c614e63ec215b89b1fb518f0ca5242c013d9151428"
        );
        let json: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(
            json["aggregated_signature"].as_str().unwrap(),
            "0x8aaec188399e9cafc3a38690b3b3188d2fb0e1542fca9effba4680c78d9b1b0afba9cbc9ccd74c06d433ca3ffb360ac516f8021eee45e4c4685069c76f89506c1addf02a71ebacc2730c07de8b951ca954f7bec1e6aea4fe034d73dc97a4bbd3"
        );
        let spend = &json["coin_spends"][0];
        assert_eq!(
            spend["puzzle_reveal"].as_str().unwrap(),
            "0xff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b0a190f944426d03ee611ce3051de3fc065c21ab14bedaa4dafef2a91906e8bdcf155a3986eeac6e46fbb4576652528450ff018080"
        );
        assert_eq!(
            spend["solution"].as_str().unwrap(),
            "0xff80ffff01ffff34ff6480ffff33ffa0c924f604d7ff8e651dd1720edd9f06723bb4435f8d1cd81f89d63571459dd381ff8316e36080ffff33ffa064acb69e5b36b222912a945a87c51660d27b51f0e912ac8c4b0e1560b4e5a0a3ff8307a0bc8080ff8080"
        );
        assert_eq!(
            spend["coin"]["parent_coin_info"].as_str().unwrap(),
            "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
        assert_eq!(spend["coin"]["amount"].as_u64().unwrap(), 2_000_000);
    }

    #[test]
    fn matches_intent() {
        let tx = sample_tx();
        tx.check_matches_intent(&intent(&tx)).unwrap();
    }

    #[test]
    fn rejects_intent_mismatches() {
        let tx = sample_tx();
        let mut wrong_amount = intent(&tx);
        wrong_amount.kind = TxIntentKind::Transfer {
            to: tx.to.clone(),
            asset: AssetRef(format!("{}:native", tx.chain_id)),
            amount: Amount("1500001".into()),
        };
        assert!(tx.check_matches_intent(&wrong_amount).is_err());
        let mut wrong_to = intent(&tx);
        wrong_to.kind = TxIntentKind::Transfer {
            to: TXCH0.into(),
            asset: AssetRef(format!("{}:native", tx.chain_id)),
            amount: Amount(tx.mojos.clone()),
        };
        assert!(tx.check_matches_intent(&wrong_to).is_err());
        let mut wrong_chain = intent(&tx);
        wrong_chain.chain_id = ChainId(MAINNET.into());
        assert!(tx.check_matches_intent(&wrong_chain).is_err());
        let mut wrong_asset = intent(&tx);
        wrong_asset.kind = TxIntentKind::Transfer {
            to: tx.to.clone(),
            asset: AssetRef("chia:testnet11:cat".into()),
            amount: Amount(tx.mojos.clone()),
        };
        assert!(tx.check_matches_intent(&wrong_asset).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let tx = sample_tx();
        // mainnet is disabled
        let mut t = tx.clone();
        t.chain_id = MAINNET.into();
        t.from = address_from_puzzle_hash(MAINNET, &hex_to_bytes32(PH0).unwrap()).unwrap();
        t.to = address_from_puzzle_hash(MAINNET, &hex_to_bytes32(PH1).unwrap()).unwrap();
        assert!(t.sign(&sk(SK0)).is_err());
        // wrong-prefix address on testnet
        let mut t = tx.clone();
        t.to = XCH0.into();
        assert!(t.sign(&sk(SK0)).is_err());
        // bech32 (not bech32m) payloads fail decoding
        let mut t = tx.clone();
        t.to = "txch1vjktd8jmx6ez9yf2j3dg03gkvrf8k50sayf2erztpc2kpd895z3slxq0u2".into();
        assert!(t.sign(&sk(SK0)).is_err());
        // garbage address
        let mut t = tx.clone();
        t.to = "not-an-address".into();
        assert!(t.sign(&sk(SK0)).is_err());
        // zero and non-canonical amounts
        let mut t = tx.clone();
        t.mojos = "0".into();
        assert!(t.sign(&sk(SK0)).is_err());
        let mut t = tx.clone();
        t.mojos = "01500000".into();
        assert!(t.sign(&sk(SK0)).is_err());
        let mut t = tx.clone();
        t.mojos = "1.5".into();
        assert!(t.sign(&sk(SK0)).is_err());
        // amounts above the CLVM signed-int cap
        let mut t = tx.clone();
        t.mojos = (i64::MAX as u64 + 1).to_string();
        t.coin_mojos = u64::MAX.to_string();
        assert!(t.sign(&sk(SK0)).is_err());
        // amount + fee exceeding the coin
        let mut t = tx.clone();
        t.coin_mojos = "1500099".into();
        assert!(t.sign(&sk(SK0)).is_err());
        // malformed parent coin id
        let mut t = tx.clone();
        t.parent_coin_id =
            "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899".into();
        assert!(t.sign(&sk(SK0)).is_err());
        let mut t = tx.clone();
        t.parent_coin_id = "abcd".into();
        assert!(t.sign(&sk(SK0)).is_err());
        // sender == recipient
        let mut t = tx.clone();
        t.to = t.from.clone();
        assert!(t.sign(&sk(SK0)).is_err());
        // a key that does not own the sender puzzle hash
        assert!(tx.sign(&sk(SK1)).is_err());
        // unknown JSON fields are refused
        let raw = r#"{"chainId":"chia:testnet11","from":"a","to":"b","mojos":"1","fee":"0","parentCoinId":"c","coinMojos":"2","memo":"x"}"#;
        assert!(serde_json::from_str::<ChiaTx>(raw).is_err());
        // zero secret key
        assert!(tx.sign(&[0u8; 32]).is_err());
    }
}
