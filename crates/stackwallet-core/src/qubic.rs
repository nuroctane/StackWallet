//! Qubic transfers. Qubic signs with SchnorrQ over the FourQ curve and hashes
//! with KangarooTwelve; neither is vendored, so this module carries a compact
//! hand-rolled implementation (the Chia module sets the same precedent for
//! BLS12-381). The arithmetic is plain double-and-add and schoolbook field
//! reduction: not constant-time, but it runs on local secrets for a local
//! signature, matching the Chia module's documented trade-off. Every byte is
//! pinned against the official `@qubic-lib/qubic-ts-library` wasm build of
//! Microsoft's FourQlib, run in `.nur/qubic-oracle`.
//!
//! Qubic has no public testnet (the network runs a single mainnet with weekly
//! epochs; probed 2026-10-17), so the mainnet id is the signing network.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2: Qubic mainnet (the only public network; there is no testnet).
pub const QUBIC_MAINNET: &str = "qubic:mainnet";

const IDENTITY_LEN: usize = 60;
const MAX_TICK: u32 = 4_000_000_000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Qubic transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // There is no public Qubic testnet to gate on; mainnet is the only
    // network, so it is the signing network.
    if chain != QUBIC_MAINNET {
        return Err(invalid("unknown Qubic chain"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KangarooTwelve over a hand-rolled Keccak-p[1600,12] (the vendored `sha3`
// crate exposes only the 24-round variants).
// ---------------------------------------------------------------------------

/// Round constants 12..24 of Keccak-f[1600]; Keccak-p[1600,12] runs the
/// last 12 rounds.
const RC: [u64; 12] = [
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets indexed by x + 5*y.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn keccak_p1600_12(state: &mut [u64; 25]) {
    for &rc in &RC {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        // rho + pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }
        // chi
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // iota
        state[0] ^= rc;
    }
}

const K12_RATE: usize = 168;
const K12_SINGLE_NODE_LIMIT: usize = 8192;

/// KangarooTwelve with an empty customization string. Panics at the Sakura
/// multi-node threshold; Qubic never hashes more than 144 bytes, and the
/// 64-byte profile stays within the 168-byte rate.
fn k12_xof(input: &[u8], out_len: usize) -> Vec<u8> {
    assert!(
        input.len() < K12_SINGLE_NODE_LIMIT && out_len <= K12_RATE,
        "K12 single-node profile"
    );
    let mut state = [0u64; 25];
    let mut block = [0u8; K12_RATE];
    let mut offset = 0usize;
    // Sakura single-node framing: absorb `input || 0x00` (right_encode of the
    // empty customization), then close with the 0x07 delimited suffix.
    for &b in input.iter().chain(&[0x00]) {
        block[offset] = b;
        offset += 1;
        if offset == K12_RATE {
            xor_block(&mut state, &block);
            keccak_p1600_12(&mut state);
            block = [0u8; K12_RATE];
            offset = 0;
        }
    }
    block[offset] ^= 0x07;
    block[K12_RATE - 1] ^= 0x80;
    xor_block(&mut state, &block);
    keccak_p1600_12(&mut state);
    (0..out_len)
        .map(|i| (state[i / 8] >> (8 * (i % 8))) as u8)
        .collect()
}

/// K12 with the 32-byte output Qubic uses for digests and checksums.
pub fn k12(input: &[u8]) -> [u8; 32] {
    k12_xof(input, 32).try_into().expect("32 bytes")
}

/// K12 with the 64-byte output Qubic's SchnorrQ fork uses as its
/// CryptoHashFunction (the wasm in `qubic-ts-library` is `libFourQ_K12`).
fn k12_64(parts: &[&[u8]]) -> [u8; 64] {
    let joined: Vec<u8> = parts.concat();
    k12_xof(&joined, 64).try_into().expect("64 bytes")
}

fn xor_block(state: &mut [u64; 25], block: &[u8; K12_RATE]) {
    for (i, limb) in state.iter_mut().take(K12_RATE / 8).enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&block[8 * i..8 * i + 8]);
        *limb ^= u64::from_le_bytes(bytes);
    }
}

// ---------------------------------------------------------------------------
// GF(p), p = 2^127 - 1, as two little-endian u64 limbs (values < 2^127).
// Not constant-time (see module docs).
// ---------------------------------------------------------------------------

/// value = self.0 + 2^64 * self.1, with self.1 < 2^63
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fp(u64, u64);

const P_HI: u64 = 0x7fff_ffff_ffff_ffff; // high limb of p = 2^127 - 1

impl Fp {
    const ZERO: Fp = Fp(0, 0);
    const ONE: Fp = Fp(1, 0);

    fn is_zero(&self) -> bool {
        self.0 == 0 && self.1 == 0
    }

    /// Reduce a value given as lo + 2^64*hi + 2^128*carry, with the sum below
    /// 2^129, to the canonical residue mod p.
    fn reduce(lo: u64, hi: u64, carry: u64) -> Fp {
        // fold bits >= 2^127: 2^127 == 1 (mod p)
        let over = u128::from(hi >> 63) + (u128::from(carry) << 1);
        let mut r = u128::from(lo) + (u128::from(hi & P_HI) << 64) + over; // < 2^127 + 4
        const P128: u128 = (1u128 << 127) - 1;
        while r >= P128 {
            r -= P128;
        }
        Fp(r as u64, (r >> 64) as u64)
    }

    fn add(self, rhs: Fp) -> Fp {
        let (lo, c1) = self.0.overflowing_add(rhs.0);
        let (hi, c2) = self.1.overflowing_add(rhs.1);
        let (hi, c3) = hi.overflowing_add(c1 as u64);
        Fp::reduce(lo, hi, u64::from(c2) + u64::from(c3))
    }

    fn sub(self, rhs: Fp) -> Fp {
        // self - rhs == self + (p - rhs) (mod p)
        let (nlo, b1) = u64::MAX.overflowing_sub(rhs.0);
        let (nhi, b2) = P_HI.overflowing_sub(rhs.1);
        let (nhi, b3) = nhi.overflowing_sub(b1 as u64);
        debug_assert!(!b2 && !b3);
        self.add(Fp(nlo, nhi))
    }

    fn neg(self) -> Fp {
        if self.is_zero() {
            self
        } else {
            Fp::ZERO.sub(self)
        }
    }

    fn mul(self, rhs: Fp) -> Fp {
        // 2x2 limb schoolbook; limbs .1 < 2^63, so each column of partial
        // products stays below 2^128 and fits a u128.
        let a = [self.0, self.1];
        let b = [rhs.0, rhs.1];
        let mut acc = [0u128; 3];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                acc[i + j] += u128::from(x) * u128::from(y);
            }
        }
        let mut limbs = [0u64; 4];
        let mut carry = 0u128;
        for (i, slot) in limbs.iter_mut().enumerate().take(3) {
            let v = acc[i] + carry;
            *slot = v as u64;
            carry = v >> 64;
        }
        limbs[3] = carry as u64;
        debug_assert!(carry >> 64 == 0);
        // v = L0 + L1 2^64 + L2 2^128 + L3 2^192
        //   == L0 + L1 2^64 + 2 L2 + 2 L3 2^64 (mod p)   [2^128 == 2, 2^192 == 2^65]
        let (lo, c1) = limbs[0].overflowing_add(limbs[2] << 1); // c1 lands at 2^64
        let (hi, c2) = limbs[1].overflowing_add(limbs[3] << 1);
        let (hi, c3) = hi.overflowing_add(limbs[2] >> 63);
        let (hi, c4) = hi.overflowing_add(c1 as u64);
        // each 2^128 carry folds to a factor of 2
        let extra = u64::from(c2) + u64::from(c3) + u64::from(c4) + (limbs[3] >> 63);
        let (lo, c5) = lo.overflowing_add(2 * extra);
        Fp::reduce(lo, hi, u64::from(c5))
    }

    fn sqr(self) -> Fp {
        self.mul(self)
    }

    fn inv(self) -> Fp {
        // a^(p-2), p - 2 = 2^127 - 3: binary 111...1101 (125 ones, then 01)
        debug_assert!(!self.is_zero());
        let mut result = Fp::ONE;
        for bit in (0..127).rev() {
            result = result.sqr();
            if bit != 1 {
                result = result.mul(self);
            }
        }
        result
    }

    /// Bit 126 of the canonical residue (the FourQ sign bit).
    fn sign_bit(&self) -> bool {
        (self.1 >> 62) & 1 == 1
    }

    fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.0.to_le_bytes());
        out[8..].copy_from_slice(&self.1.to_le_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// GF(p^2) = GF(p)[i] / (i^2 + 1); an element a + b*i is encoded as a || b.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fp2(Fp, Fp);

impl Fp2 {
    const ZERO: Fp2 = Fp2(Fp::ZERO, Fp::ZERO);
    const ONE: Fp2 = Fp2(Fp::ONE, Fp::ZERO);

    fn add(self, rhs: Fp2) -> Fp2 {
        Fp2(self.0.add(rhs.0), self.1.add(rhs.1))
    }
    fn sub(self, rhs: Fp2) -> Fp2 {
        Fp2(self.0.sub(rhs.0), self.1.sub(rhs.1))
    }
    fn neg(self) -> Fp2 {
        Fp2(self.0.neg(), self.1.neg())
    }
    fn mul(self, rhs: Fp2) -> Fp2 {
        let ac = self.0.mul(rhs.0);
        let bd = self.1.mul(rhs.1);
        let cross = self.0.add(self.1).mul(rhs.0.add(rhs.1)).sub(ac).sub(bd);
        Fp2(ac.sub(bd), cross)
    }
    fn sqr(self) -> Fp2 {
        let sum = self.0.add(self.1);
        let diff = self.0.sub(self.1);
        let two_ab = self.0.mul(self.1);
        Fp2(sum.mul(diff), two_ab.add(two_ab))
    }
    fn inv(self) -> Fp2 {
        let norm = self.0.sqr().add(self.1.sqr()).inv();
        Fp2(self.0.mul(norm), self.1.neg().mul(norm))
    }
}

/// FourQ curve constant d (FourQ_params.h, little-endian limbs).
const PARAMETER_D: Fp2 = Fp2(
    Fp(0x0000_0000_0000_0142, 0x0000_0000_0000_00e4),
    Fp(0xb382_1488_f1fc_0c8d, 0x5e47_2f84_6657_e0fc),
);
/// The prime-order generator (FourQ_params.h).
const GENERATOR_X: Fp2 = Fp2(
    Fp(0x2865_92ad_7b38_33aa, 0x1a34_7223_7c2f_b305),
    Fp(0x9686_9fb3_60ac_77f6, 0x1e1f_553f_2878_aa9c),
);
const GENERATOR_Y: Fp2 = Fp2(
    Fp(0xb924_a246_2bcb_b287, 0x0e3f_ee9b_a120_785a),
    Fp(0x49a7_c344_844c_8b5c, 0x6e1c_4af8_630e_0242),
);

/// Extended twisted Edwards point (X:Y:Z:T) on -x^2 + y^2 = 1 + d x^2 y^2.
#[derive(Clone, Copy)]
struct Point {
    x: Fp2,
    y: Fp2,
    z: Fp2,
    t: Fp2,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fp2::ZERO,
        y: Fp2::ONE,
        z: Fp2::ONE,
        t: Fp2::ZERO,
    };

    fn generator() -> Point {
        Point {
            x: GENERATOR_X,
            y: GENERATOR_Y,
            z: Fp2::ONE,
            t: GENERATOR_X.mul(GENERATOR_Y),
        }
    }

    /// dbl-2008-hwcd with a = -1.
    fn double(&self) -> Point {
        let a = self.x.sqr();
        let b = self.y.sqr();
        let c = self.z.sqr().add(self.z.sqr());
        let d = a.neg();
        let e = self.x.add(self.y).sqr().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// add-2008-hwcd-3 with a = -1; complete because d is a non-square.
    fn add(&self, rhs: &Point) -> Point {
        let a = self.x.mul(rhs.x);
        let b = self.y.mul(rhs.y);
        let c = PARAMETER_D.mul(self.t).mul(rhs.t);
        let d = self.z.mul(rhs.z);
        let e = self.x.add(self.y).mul(rhs.x.add(rhs.y)).sub(a).sub(b);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// scalar * point, plain MSB-first double-and-add.
    fn mul_scalar(&self, scalar: &[u8; 32]) -> Point {
        let mut acc = Point::IDENTITY;
        for bit in (0..256).rev() {
            acc = acc.double();
            if (scalar[bit / 8] >> (bit % 8)) & 1 == 1 {
                acc = acc.add(self);
            }
        }
        acc
    }

    /// FourQ encoding: y (a || b, 16 bytes each, little-endian) with the sign
    /// bit = bit 126 of x0 (of x1 when x0 is zero) in the top bit of byte 31.
    fn encode(&self) -> [u8; 32] {
        let zi = self.z.inv();
        let x = self.x.mul(zi);
        let y = self.y.mul(zi);
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&y.0.to_bytes());
        out[16..].copy_from_slice(&y.1.to_bytes());
        let sign = if x.0.is_zero() {
            x.1.sign_bit()
        } else {
            x.0.sign_bit()
        };
        if sign {
            out[31] |= 0x80;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Scalars mod the prime subgroup order q (246 bits), little-endian [u64; 4].
// Schoolbook with bitwise reduction; not constant-time (see module docs).
// ---------------------------------------------------------------------------

const ORDER: [u64; 4] = [
    0x2fb2_540e_c776_8ce7,
    0xdfbd_004d_fe0f_7999,
    0xf053_9782_9cbc_14e5,
    0x0029_cbc1_4e5e_0a72,
];

fn scalar_cmp(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    std::cmp::Ordering::Equal
}

/// a - b for a >= b.
fn scalar_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (r, b1) = a[i].overflowing_sub(b[i]);
        let (r, b2) = r.overflowing_sub(borrow as u64);
        out[i] = r;
        borrow = b1 || b2;
    }
    debug_assert!(!borrow);
    out
}

/// a + b mod q for a, b < q (the sum stays below 2^248, no 256-bit overflow).
fn scalar_add_mod(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = false;
    for i in 0..4 {
        let (r, c1) = a[i].overflowing_add(b[i]);
        let (r, c2) = r.overflowing_add(carry as u64);
        out[i] = r;
        carry = c1 || c2;
    }
    debug_assert!(!carry);
    if scalar_cmp(&out, &ORDER) != std::cmp::Ordering::Less {
        scalar_sub(out, ORDER)
    } else {
        out
    }
}

fn scalar_sub_mod(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    debug_assert!(scalar_cmp(&b, &ORDER) == std::cmp::Ordering::Less);
    if scalar_cmp(&a, &b) == std::cmp::Ordering::Less {
        scalar_add_mod(a, scalar_sub(ORDER, b))
    } else {
        scalar_sub(a, b)
    }
}

/// Reduce a little-endian byte string (up to 64 bytes) mod q, one bit at a
/// time. The accumulator stays below q < 2^246, so doubling never carries out
/// of bit 255 and one conditional subtraction per bit suffices.
fn scalar_reduce(bytes: &[u8]) -> [u64; 4] {
    let mut acc = [0u64; 4];
    for bit in (0..bytes.len() * 8).rev() {
        let mut top = false;
        for limb in acc.iter_mut() {
            let next = *limb >> 63 == 1;
            *limb = (*limb << 1) | u64::from(top);
            top = next;
        }
        debug_assert!(!top);
        if scalar_cmp(&acc, &ORDER) != std::cmp::Ordering::Less {
            acc = scalar_sub(acc, ORDER);
        }
        if (bytes[bit / 8] >> (bit % 8)) & 1 == 1 {
            acc = scalar_add_mod(acc, [1, 0, 0, 0]);
        }
    }
    acc
}

fn scalar_mul_mod(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    // 4x4 schoolbook into 8 limbs with per-row carry propagation, so the
    // u128 accumulator never holds more than one product plus a carry.
    let mut wide = [0u64; 8];
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &y) in b.iter().enumerate() {
            let cur = u128::from(x) * u128::from(y) + u128::from(wide[i + j]) + carry;
            wide[i + j] = cur as u64;
            carry = cur >> 64;
        }
        // propagate the leftover carry
        let mut k = i + 4;
        let mut c = carry as u64;
        while c != 0 {
            let (v, ov) = wide[k].overflowing_add(c);
            wide[k] = v;
            c = ov as u64;
            k += 1;
        }
    }
    let mut bytes = [0u8; 64];
    for (i, limb) in wide.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    scalar_reduce(&bytes)
}

fn scalar_to_le(s: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in s.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// SchnorrQ as Qubic runs it: FourQlib with KangarooTwelve (64-byte output)
// as CryptoHashFunction (the wasm in `qubic-ts-library` is `libFourQ_K12`).
// ---------------------------------------------------------------------------

/// The 32-byte FourQ public key for a 32-byte Qubic subseed (the value
/// `qubic-ts-library` calls the "private key", itself K12 of the 55-char seed;
/// any 32-byte secret works as a subseed).
pub fn public_key(subseed: &[u8; 32]) -> Result<[u8; 32]> {
    let k = k12_64(&[subseed]);
    let s: [u8; 32] = k[..32].try_into().expect("32 bytes");
    Ok(Point::generator().mul_scalar(&s).encode())
}

/// Signs a 32-byte message digest exactly like FourQlib's `SchnorrQ_Sign`
/// (with K12 as the hash): r_hash = K12(K12(sk)[32..] || m),
/// R = r_low256 * G, h = (K12(R || pk || m) low 256 bits) mod q,
/// S = (r_low256 - s*h) mod q. Deterministic; returns (encoded R, S LE).
fn schnorrq_sign(subseed: &[u8; 32], digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let public = public_key(subseed)?;
    let k = k12_64(&[subseed]);
    let s: [u8; 32] = k[..32].try_into().expect("32 bytes");
    let r512 = k12_64(&[&k[32..], digest]);
    let r_lo: [u8; 32] = r512[..32].try_into().expect("32 bytes");
    let encoded_r = Point::generator().mul_scalar(&r_lo).encode();
    let h512 = k12_64(&[&encoded_r, &public, digest]);
    let h = scalar_reduce(&h512[..32]);
    let s_h = scalar_mul_mod(scalar_reduce(&s), h);
    let big_s = scalar_sub_mod(scalar_reduce(&r_lo), s_h);
    Ok((encoded_r, scalar_to_le(big_s)))
}

/// Verifies encode(S*G + h*P) == R using the public key's point directly
/// (point decode is never needed: we only verify our own signatures in tests).
#[cfg(test)]
fn schnorrq_verify_with_point(
    public_point: &Point,
    public: &[u8; 32],
    digest: &[u8; 32],
    encoded_r: &[u8; 32],
    s_bytes: &[u8; 32],
) -> bool {
    let h512 = k12_64(&[encoded_r, public, digest]);
    let h = scalar_to_le(scalar_reduce(&h512[..32]));
    let r1 = Point::generator().mul_scalar(s_bytes);
    let r2 = public_point.mul_scalar(&h);
    r1.add(&r2).encode() == *encoded_r
}

// ---------------------------------------------------------------------------
// Identity codec: 4 little-endian u64 limbs, each as 14 base-26 uppercase
// letters (least significant digit first), then 4 checksum letters from the
// low 18 bits of K12(public key) read as a little-endian u24.
// ---------------------------------------------------------------------------

/// The 60-character uppercase identity for a 32-byte public key.
pub fn address(public: &[u8]) -> Result<String> {
    if public.len() != 32 {
        return Err(invalid("public key must be 32 bytes"));
    }
    let mut id = String::with_capacity(IDENTITY_LEN);
    for i in 0..4 {
        let limb = u64::from_le_bytes(public[8 * i..8 * i + 8].try_into().expect("8 bytes"));
        let mut n = limb;
        for _ in 0..14 {
            id.push((b'A' + (n % 26) as u8) as char);
            n /= 26;
        }
        // 26^14 > 2^64, so 14 digits always consume a u64 exactly.
    }
    let digest = k12(public);
    let mut checksum =
        (u32::from(digest[2]) << 16 | u32::from(digest[1]) << 8 | u32::from(digest[0])) & 0x3ffff;
    for _ in 0..4 {
        id.push((b'A' + (checksum % 26) as u8) as char);
        checksum /= 26;
    }
    Ok(id)
}

/// Validates an identity and returns its 32-byte public key. Non-canonical
/// base-26 limbs (value >= 2^64) are rejected so an identity has exactly one
/// spelling.
pub fn address_bytes(identity: &str) -> Result<[u8; 32]> {
    if identity.len() != IDENTITY_LEN || !identity.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(invalid("identity must be 60 uppercase letters"));
    }
    let bytes = identity.as_bytes();
    let mut public = [0u8; 32];
    for i in 0..4 {
        let mut n: u128 = 0;
        for j in (0..14).rev() {
            n = n * 26 + u128::from(bytes[i * 14 + j] - b'A');
        }
        if n > u128::from(u64::MAX) {
            return Err(invalid("identity is not canonical"));
        }
        public[8 * i..8 * i + 8].copy_from_slice(&(n as u64).to_le_bytes());
    }
    if address(&public)? != identity {
        return Err(invalid("identity checksum mismatch"));
    }
    Ok(public)
}

// ---------------------------------------------------------------------------
// The transfer. Wire layout (80 bytes + 64-byte signature):
//   source pubkey (32) || destination pubkey (32) || amount i64le ||
//   tick u32le || inputType u16le = 0 || inputSize u16le = 0
// The signature is SchnorrQ over K12 of the 80 bytes; the broadcast payload
// is base64 of the 144-byte package; the transaction id explorers show is the
// lowercase identity encoding of K12 of the full package.
// ---------------------------------------------------------------------------

const TX_LEN: usize = 80;
const PACKAGE_LEN: usize = 144;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QubicTx {
    pub chain_id: String,
    /// Sender identity (60 uppercase letters).
    pub from: String,
    /// Destination identity (60 uppercase letters).
    pub to: String,
    /// Decimal qubic (the chain's base unit; amounts are whole, no decimals).
    pub qu: String,
    /// The tick the transaction is scheduled for; the network ignores it
    /// once that tick passes, so it acts as the expiry.
    pub tick: u32,
}

impl QubicTx {
    fn amount(&self) -> Result<u64> {
        let amount = self
            .qu
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds u64 qu"))?;
        if amount == 0 || amount > i64::MAX as u64 || amount.to_string() != self.qu {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        Ok(amount)
    }

    /// The 80 bytes that get hashed and signed.
    pub fn raw_bytes(&self) -> Result<[u8; TX_LEN]> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = self.amount()?;
        if self.tick == 0 || self.tick > MAX_TICK {
            return Err(invalid("tick out of range"));
        }
        let mut out = [0u8; TX_LEN];
        out[..32].copy_from_slice(&from);
        out[32..64].copy_from_slice(&to);
        out[64..72].copy_from_slice(&amount.to_le_bytes());
        out[72..76].copy_from_slice(&self.tick.to_le_bytes());
        // inputType = 0, inputSize = 0 for a plain QU transfer
        Ok(out)
    }

    /// K12 of the raw bytes; this is what SchnorrQ signs.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(k12(&self.raw_bytes()?))
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native QU transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.qu {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Qubic intent")),
        }
        self.raw_bytes()?;
        Ok(())
    }

    /// Returns the base64 broadcast payload for `/v1/broadcast-transaction`
    /// and the lowercase identity-style transaction id explorers show.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let public = public_key(secret)?;
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let digest = self.digest()?;
        let (encoded_r, s) = schnorrq_sign(secret, &digest)?;
        let mut package = [0u8; PACKAGE_LEN];
        package[..TX_LEN].copy_from_slice(&self.raw_bytes()?);
        package[TX_LEN..TX_LEN + 32].copy_from_slice(&encoded_r);
        package[TX_LEN + 32..].copy_from_slice(&s);
        let txid = address(&k12(&package))?.to_lowercase();
        Ok((
            base64::engine::general_purpose::STANDARD.encode(package),
            txid,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors from `@qubic-lib/qubic-ts-library` (the wasm build of
    // Microsoft's FourQlib), generated by `.nur/qubic-oracle/vectors.cjs`.

    // seed "a"*55 -> subseed 4453512f..; the library's "private key" is the
    // subseed itself, so our 32-byte wallet secret plays the subseed role.
    const SECRET_A: &str = "4453512f1ef597b365cc384f0a2b10ceb5c94f516b911acc8e8bc1b55e646c74";
    const PUB_A: &str = "1f590d03e613bdded38b4c0820ac44615f91af12435980b3ede3c08c315a2544";
    const ID_A: &str = "BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK";
    const ID_Z: &str = "ZSDAHLHNHVWTEDYXRTTDWNKGRVPAFQKNTOUXPOXSCDGOPTMUJFWPVATFXHPG";

    fn secret() -> [u8; 32] {
        hex::decode(SECRET_A).unwrap().try_into().unwrap()
    }

    #[test]
    fn k12_matches_oracle() {
        assert_eq!(
            hex::encode(k12(b"")),
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"
        );
        assert_eq!(
            hex::encode(k12(b"abc")),
            "ab174f328c55a5510b0b209791bf8b60e801a7cfc2aa42042dcb8f547fbe3a7d"
        );
        assert_eq!(
            hex::encode(k12(&[0u8; 32])),
            "235c3c067d94fb13b1dbd3ec5ab5c4587078c4f1442580b3f3a47687cb778089"
        );
        let seq80: Vec<u8> = (0..80u8).collect();
        assert_eq!(
            hex::encode(k12(&seq80)),
            "3eb01170a5c1172bf1a0f26fe38a3bf71283b0c8603f9b266a4e021d9b440ad0"
        );
        let seq1000: Vec<u8> = (0..1000u16).map(|i| (i & 0xff) as u8).collect();
        assert_eq!(
            hex::encode(k12(&seq1000)),
            "15e060a21b8e8cf10aa1867d52b1af8d32f8ea6f9d763c7d9cc6ddb5d62a5602"
        );
    }

    #[test]
    fn keys_and_identities_match_oracle() {
        let pub_a = public_key(&secret()).unwrap();
        assert_eq!(hex::encode(pub_a), PUB_A);
        assert_eq!(address(&pub_a).unwrap(), ID_A);
        let subseed_z: [u8; 32] =
            hex::decode("7746c6b3d57f02d4fb562d2ae62ce275a87918fbe31d302af76cfbcd45734f07")
                .unwrap()
                .try_into()
                .unwrap();
        let pub_z = public_key(&subseed_z).unwrap();
        assert_eq!(
            hex::encode(pub_z),
            "69e68dc170cd9b6dda32b69490f5f71405c5c8d67012e96a86d3ff98ef915ec5"
        );
        assert_eq!(address(&pub_z).unwrap(), ID_Z);
        let pub_c: [u8; 32] =
            hex::decode("ed11ca0ed8fa3fc75dc1052c38074b5933a3413f92e3fc677e151d19cfbb46f0")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            address(&pub_c).unwrap(),
            "HBBBQGBNZMTLUFBGCPAFMDBYALPCXUTBYYZTMTNNADYZXMKJEGDCFLZGQFVL"
        );
    }

    #[test]
    fn identity_codec_round_trips_and_rejects() {
        let pub_a: [u8; 32] = hex::decode(PUB_A).unwrap().try_into().unwrap();
        assert_eq!(address_bytes(ID_A).unwrap(), pub_a);
        assert!(address_bytes(&ID_A.to_lowercase()).is_err());
        assert!(address_bytes(&ID_A[..59]).is_err());
        let mut bad = ID_A.to_string();
        bad.replace_range(10..11, "B");
        assert!(address_bytes(&bad).is_err()); // checksum mismatch
                                               // non-canonical limb: 14 x 'Z' decodes above u64::MAX
        let over = format!("{}{}", "Z".repeat(14), "A".repeat(46));
        assert!(address_bytes(&over).is_err());
    }

    fn tx1() -> QubicTx {
        QubicTx {
            chain_id: QUBIC_MAINNET.into(),
            from: ID_A.into(),
            to: ID_Z.into(),
            qu: "987654321".into(),
            tick: 100_000_007,
        }
    }

    #[test]
    fn raw_bytes_and_digest_match_oracle() {
        let tx = tx1();
        let raw = hex::encode(tx.raw_bytes().unwrap());
        let expected = [
            "1f590d03e613bdded38b4c0820ac44615f91af12435980b3ede3c08c315a2544",
            "69e68dc170cd9b6dda32b69490f5f71405c5c8d67012e96a86d3ff98ef915ec5",
            "b168de3a00000000",
            "07e1f505",
            "00000000", // inputType = 0, inputSize = 0
        ]
        .concat();
        assert_eq!(raw, expected);
        assert_eq!(
            hex::encode(tx.digest().unwrap()),
            "b32648335de8e060e5bbef0dafe538dbfe7097749625fbab957dbe99b1b4ec43"
        );
    }

    #[test]
    fn signed_package_matches_oracle_byte_for_byte() {
        let tx = tx1();
        let (wire, txid) = tx.sign(&secret()).unwrap();
        assert_eq!(
            txid,
            "tkvndhloeqpfteojfmhrdhukpsqafymsbguvphnjsfpmugukpjmesmqcxuua"
        );
        let package = base64::engine::general_purpose::STANDARD
            .decode(wire)
            .unwrap();
        assert_eq!(package.len(), 144);
        let sig = [
            "5160ae04baf136fe783aa79fe0a470473f1e0e4101f6a4cd33b5fdc13ced2746",
            "3b5b5db585b75037017bcad8e17fc7918d253cada969919466fb529740562000",
        ]
        .concat();
        assert_eq!(hex::encode(&package[80..]), sig);

        let tx2 = QubicTx {
            qu: "1".into(),
            tick: 85_214_250,
            ..tx1()
        };
        let (wire2, txid2) = tx2.sign(&secret()).unwrap();
        assert_eq!(
            txid2,
            "ejmcmukpztedihcarlrnzfnbfghewbvhopgvczbvdenydorohrfuxqebvqkd"
        );
        let package2 = base64::engine::general_purpose::STANDARD
            .decode(wire2)
            .unwrap();
        let sig2 = [
            "50b717525fbb4995995aedc6d2892e0a9e99e8da105199a8a68885ffd4bce23d",
            "9cf053b76c5dba919be4ea4b95c30437e32dc066c269794ff9ce71d676071700",
        ]
        .concat();
        assert_eq!(hex::encode(&package2[80..]), sig2);
    }

    #[test]
    fn signature_verifies_against_own_point() {
        let tx = tx1();
        let public = public_key(&secret()).unwrap();
        let k = k12_64(&[&secret()]);
        let s: [u8; 32] = k[..32].try_into().unwrap();
        let point = Point::generator().mul_scalar(&s);
        assert_eq!(point.encode(), public);
        let digest = tx.digest().unwrap();
        let (r, s_sig) = schnorrq_sign(&secret(), &digest).unwrap();
        assert!(schnorrq_verify_with_point(
            &point, &public, &digest, &r, &s_sig
        ));
        let other = k12(b"different message");
        assert!(!schnorrq_verify_with_point(
            &point, &public, &other, &r, &s_sig
        ));
    }

    #[test]
    fn hostile_inputs_are_refused() {
        tx1().raw_bytes().unwrap(); // the fixture itself is valid
        let cases: Vec<QubicTx> = vec![
            QubicTx {
                chain_id: "qubic:testnet".into(),
                ..tx1()
            },
            QubicTx {
                qu: "0".into(),
                ..tx1()
            },
            QubicTx {
                qu: "01".into(),
                ..tx1()
            },
            QubicTx {
                qu: "18446744073709551615".into(),
                ..tx1()
            }, // u64 max > i64 max
            QubicTx {
                to: ID_A.into(),
                ..tx1()
            }, // self-transfer
            QubicTx { tick: 0, ..tx1() },
            QubicTx {
                tick: 4_000_000_001,
                ..tx1()
            }, // beyond MAX_TICK
        ];
        for tx in &cases {
            assert!(tx.raw_bytes().is_err(), "{tx:?} must be refused");
        }
        // wrong key refuses
        assert!(tx1().sign(&[0x11; 32]).is_err());
        // a corrupt destination identity refuses
        let mut bad = tx1();
        bad.to = format!("{}B", &ID_Z[..59]);
        assert!(bad.raw_bytes().is_err());
    }

    #[test]
    fn generator_is_on_curve() {
        let g = Point::generator();
        let zi = g.z.inv();
        let x = g.x.mul(zi);
        let y = g.y.mul(zi);
        let x2 = x.sqr();
        let lhs = y.sqr().sub(x2);
        let rhs = Fp2::ONE.add(PARAMETER_D.mul(x2).mul(y.sqr()));
        assert_eq!(lhs, rhs);
    }
}
