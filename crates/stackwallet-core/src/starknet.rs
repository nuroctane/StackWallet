//! STRK transfers from an OpenZeppelin account on Starknet Sepolia.
//!
//! The Stark key is ground (EIP-2645 `grindKey`) from the secp256k1 secret
//! the core holds at `m/44'/9004'/0'/0/{i}`, the same derivation Braavos uses
//! for a BIP-39 phrase. The account is OpenZeppelin's upgradeable account
//! class, deployed counterfactually: the first send carries a DEPLOY_ACCOUNT
//! v3 built here from the key, followed by an INVOKE v3 that calls the STRK
//! token's `transfer`. Every felt that gets hashed and signed is derived here
//! from checked fields; the Stark curve, Pedersen and Poseidon are implemented
//! below because no available crate covers them.

use std::cmp::Ordering;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

pub const SEPOLIA: &str = "starknet:SN_SEPOLIA";
pub const MAINNET: &str = "starknet:SN_MAIN";
/// OpenZeppelin AccountUpgradeable (SRC-6, constructor `public_key`), declared on mainnet and Sepolia.
pub const ACCOUNT_CLASS_HASH: &str =
    "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
/// The STRK ERC-20; the same address on mainnet and Sepolia.
pub const STRK_TOKEN: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

const SN_SEPOLIA_FELT: U256 = h("534e5f5345504f4c4941");
const CLASS_HASH: U256 = h("05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564");
const STRK: U256 = h("04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");
/// `sn_keccak("transfer")`.
const TRANSFER_SELECTOR: U256 =
    h("0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e");
const INVOKE_PREFIX: U256 = h("696e766f6b65");
const DEPLOY_ACCOUNT_PREFIX: U256 = h("6465706c6f795f6163636f756e74");
const CONTRACT_ADDRESS_PREFIX: U256 = h("535441524b4e45545f434f4e54524143545f41444452455353");
const L1_GAS: u64 = 0x4c315f474153;
const L2_GAS: u64 = 0x4c325f474153;
const L1_DATA: u64 = 0x4c315f44415441;
/// 2^251 - 256: contract addresses are reduced below this.
const ADDR_BOUND: U256 = h("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00");
/// 2^251: Stark ECDSA message hashes and `r` / `s^-1` must stay below it.
const MAX_VALUE: U256 = h("0800000000000000000000000000000000000000000000000000000000000000");
const P: U256 = h("0800000000000011000000000000000000000000000000000000000000000001");
const N: U256 = h("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f");
const CURVE_B: U256 = h("06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89");
const GX: U256 = h("01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca");
const GY: U256 = h("005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f");
/// Shift point and the four generators of StarkWare's Pedersen hash.
const PEDERSEN_POINTS: [(U256, U256); 5] = [
    (
        h("049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804"),
        h("03ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a"),
    ),
    (
        h("0234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b"),
        h("03b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615"),
    ),
    (
        h("04fa56f376c83db33f9dab2656558f3399099ec1de5e3018b7a6932dba8aa378"),
        h("03fa0984c931c9e38113e0c0e47e4401562761f92a7a23b45168f4e80ff5b54d"),
    ),
    (
        h("04ba4cc166be8dec764910f75b45f74b40c690c74709e90f3aa372f0bd2d6997"),
        h("0040301cf5c1751f4b971e46c4ede85fcac5c59a5ce5ae7c48151f27b24b219c"),
    ),
    (
        h("054302dcb0e6cc1c6e44cca8f61a63bb2ca65048d53fb325d36ff12c49a58202"),
        h("01b77b3e37d13504b348046268d8ae25ce98ad783c25561a879dcc77e99c2426"),
    ),
];

const MAX_L1_GAS: u64 = 1_000_000;
const MAX_L2_GAS: u64 = 1_000_000_000;
const MAX_L1_DATA_GAS: u64 = 1_000_000;
/// Per resource unit; current Sepolia prices sit around 3e13 (L1) and 1e10 (L2) fri.
const MAX_PRICE: u128 = 1_000_000_000_000_000;
/// Worst-case fee of one transaction: 20 STRK.
const MAX_FEE_FRI: u128 = 20_000_000_000_000_000_000;
const MAX_NONCE: u64 = 1 << 53;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Starknet transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != SEPOLIA {
        return Err(invalid("only Starknet Sepolia transfers are enabled"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 256-bit integers and Montgomery arithmetic modulo the Stark prime and order.

/// Little-endian 64-bit limbs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct U256([u64; 4]);

const fn h(s: &str) -> U256 {
    let b = s.as_bytes();
    let mut limbs = [0u64; 4];
    let mut i = 0;
    while i < b.len() {
        let c = b[b.len() - 1 - i];
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("constant is not lowercase hex"),
        } as u64;
        limbs[i / 16] |= v << ((i % 16) * 4);
        i += 1;
    }
    U256(limbs)
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}
impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl U256 {
    const ZERO: Self = Self([0; 4]);
    const ONE: Self = Self([1, 0, 0, 0]);

    fn from_u128(v: u128) -> Self {
        Self([v as u64, (v >> 64) as u64, 0, 0])
    }

    fn from_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            limbs[3 - i] = u64::from_be_bytes(*chunk);
        }
        Self(limbs)
    }

    fn to_be(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    fn overflowing_add(&self, o: &Self) -> (Self, bool) {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (a, c1) = self.0[i].overflowing_add(o.0[i]);
            let (b, c2) = a.overflowing_add(carry as u64);
            *limb = b;
            carry = c1 || c2;
        }
        (Self(out), carry)
    }

    fn overflowing_sub(&self, o: &Self) -> (Self, bool) {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for (i, limb) in out.iter_mut().enumerate() {
            let (a, b1) = self.0[i].overflowing_sub(o.0[i]);
            let (b, b2) = a.overflowing_sub(borrow as u64);
            *limb = b;
            borrow = b1 || b2;
        }
        (Self(out), borrow)
    }

    fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    fn shr(&self, n: u32) -> Self {
        if n == 0 {
            return *self;
        }
        let mut out = [0u64; 4];
        for (i, limb) in out.iter_mut().enumerate() {
            let hi = if i < 3 { self.0[i + 1] << (64 - n) } else { 0 };
            *limb = (self.0[i] >> n) | hi;
        }
        Self(out)
    }

    /// `0x` plus the minimal lowercase hex digits, the JSON-RPC FELT form.
    fn hex_min(&self) -> String {
        let full = hex::encode(self.to_be());
        let trimmed = full.trim_start_matches('0');
        format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
    }

    fn hex_padded(&self) -> String {
        format!("0x{}", hex::encode(self.to_be()))
    }
}

struct Field {
    m: U256,
    /// `-m^-1 mod 2^64`.
    inv: u64,
    /// `2^512 mod m`.
    r2: U256,
}

impl Field {
    fn new(m: U256) -> Self {
        let mut x: u64 = 1;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m.0[0].wrapping_mul(x)));
        }
        let mut f = Field {
            m,
            inv: x.wrapping_neg(),
            r2: U256::ONE,
        };
        let mut r = U256::ONE;
        for _ in 0..512 {
            r = f.add(&r, &r);
        }
        f.r2 = r;
        f
    }

    fn add(&self, a: &U256, b: &U256) -> U256 {
        let (s, carry) = a.overflowing_add(b);
        if carry || s >= self.m {
            s.overflowing_sub(&self.m).0
        } else {
            s
        }
    }

    fn sub(&self, a: &U256, b: &U256) -> U256 {
        let (d, borrow) = a.overflowing_sub(b);
        if borrow {
            d.overflowing_add(&self.m).0
        } else {
            d
        }
    }

    /// Montgomery product `a * b / 2^256 mod m` (CIOS).
    fn mul(&self, a: &U256, b: &U256) -> U256 {
        let mut t = [0u64; 6];
        for i in 0..4 {
            let mut c: u128 = 0;
            for (j, limb) in t.iter_mut().enumerate().take(4) {
                let s = *limb as u128 + (a.0[j] as u128) * (b.0[i] as u128) + c;
                *limb = s as u64;
                c = s >> 64;
            }
            let s = t[4] as u128 + c;
            t[4] = s as u64;
            t[5] = (s >> 64) as u64;
            let mf = t[0].wrapping_mul(self.inv);
            let s = t[0] as u128 + (mf as u128) * (self.m.0[0] as u128);
            let mut c = s >> 64;
            for j in 1..4 {
                let s = t[j] as u128 + (mf as u128) * (self.m.0[j] as u128) + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = t[4] as u128 + c;
            t[3] = s as u64;
            t[4] = t[5] + (s >> 64) as u64;
            t[5] = 0;
        }
        let r = U256([t[0], t[1], t[2], t[3]]);
        if t[4] != 0 || r >= self.m {
            r.overflowing_sub(&self.m).0
        } else {
            r
        }
    }

    /// Canonical residue of any 256-bit value; both moduli exceed 2^251, so at most 32 steps.
    fn reduce(&self, mut a: U256) -> U256 {
        while a >= self.m {
            a = a.overflowing_sub(&self.m).0;
        }
        a
    }

    fn to_mont(&self, a: &U256) -> U256 {
        self.mul(&self.reduce(*a), &self.r2)
    }

    fn out_of_mont(&self, a: &U256) -> U256 {
        self.mul(a, &U256::ONE)
    }

    fn one(&self) -> U256 {
        self.to_mont(&U256::ONE)
    }

    fn pow(&self, base: &U256, e: &U256) -> U256 {
        let mut r = self.one();
        for i in (0..256).rev() {
            r = self.mul(&r, &r);
            if e.bit(i) {
                r = self.mul(&r, base);
            }
        }
        r
    }

    fn inv(&self, a: &U256) -> U256 {
        let e = self.m.overflowing_sub(&U256::from_u128(2)).0;
        self.pow(a, &e)
    }
}

fn fp() -> &'static Field {
    static F: OnceLock<Field> = OnceLock::new();
    F.get_or_init(|| Field::new(P))
}

fn fn_() -> &'static Field {
    static F: OnceLock<Field> = OnceLock::new();
    F.get_or_init(|| Field::new(N))
}

// ---------------------------------------------------------------------------
// The Stark curve y^2 = x^3 + x + b, affine points in Montgomery form.

type Point = Option<(U256, U256)>;

fn mont_point(p: &(U256, U256)) -> (U256, U256) {
    (fp().to_mont(&p.0), fp().to_mont(&p.1))
}

fn generator() -> (U256, U256) {
    static G: OnceLock<(U256, U256)> = OnceLock::new();
    *G.get_or_init(|| mont_point(&(GX, GY)))
}

fn point_double(p: Point) -> Point {
    let f = fp();
    let (x, y) = p?;
    if y.is_zero() {
        return None;
    }
    let xx = f.mul(&x, &x);
    let num = f.add(&f.add(&f.add(&xx, &xx), &xx), &f.one());
    let l = f.mul(&num, &f.inv(&f.add(&y, &y)));
    let x3 = f.sub(&f.sub(&f.mul(&l, &l), &x), &x);
    let y3 = f.sub(&f.mul(&l, &f.sub(&x, &x3)), &y);
    Some((x3, y3))
}

fn point_add(p: Point, q: Point) -> Point {
    let f = fp();
    let (Some((x1, y1)), Some((x2, y2))) = (p, q) else {
        return p.or(q);
    };
    if x1 == x2 {
        return if y1 == y2 { point_double(p) } else { None };
    }
    let l = f.mul(&f.sub(&y2, &y1), &f.inv(&f.sub(&x2, &x1)));
    let x3 = f.sub(&f.sub(&f.mul(&l, &l), &x1), &x2);
    let y3 = f.sub(&f.mul(&l, &f.sub(&x1, &x3)), &y1);
    Some((x3, y3))
}

fn point_mul(p: Point, k: &U256) -> Point {
    let mut acc: Point = None;
    for i in (0..256).rev() {
        acc = point_double(acc);
        if k.bit(i) {
            acc = point_add(acc, p);
        }
    }
    acc
}

fn on_curve_x(x: &U256) -> bool {
    // Euler's criterion: x^3 + x + b must be a square for a point with this x to exist.
    let f = fp();
    let xm = f.to_mont(x);
    let rhs = f.add(
        &f.add(&f.mul(&f.mul(&xm, &xm), &xm), &xm),
        &f.to_mont(&CURVE_B),
    );
    let e = P.overflowing_sub(&U256::ONE).0.shr(1);
    let legendre = f.pow(&rhs, &e);
    legendre == f.one() || rhs.is_zero()
}

// ---------------------------------------------------------------------------
// Hashes.

fn pedersen_tables() -> &'static [Vec<(U256, U256)>; 2] {
    static T: OnceLock<[Vec<(U256, U256)>; 2]> = OnceLock::new();
    T.get_or_init(|| {
        let table = |low: &(U256, U256), high: &(U256, U256)| {
            let mut out = Vec::with_capacity(252);
            let mut p = Some(mont_point(low));
            for _ in 0..248 {
                out.push(p.expect("generator multiple"));
                p = point_double(p);
            }
            let mut p = Some(mont_point(high));
            for _ in 0..4 {
                out.push(p.expect("generator multiple"));
                p = point_double(p);
            }
            out
        };
        [
            table(&PEDERSEN_POINTS[1], &PEDERSEN_POINTS[2]),
            table(&PEDERSEN_POINTS[3], &PEDERSEN_POINTS[4]),
        ]
    })
}

fn pedersen(a: &U256, b: &U256) -> Result<U256> {
    if *a >= P || *b >= P {
        return Err(invalid("Pedersen input outside the field"));
    }
    let tables = pedersen_tables();
    let mut acc = Some(mont_point(&PEDERSEN_POINTS[0]));
    for (value, table) in [(a, &tables[0]), (b, &tables[1])] {
        for (j, pt) in table.iter().enumerate() {
            if acc == Some(*pt) {
                return Err(invalid("Pedersen hit a table point"));
            }
            if value.bit(j) {
                acc = point_add(acc, Some(*pt));
            }
        }
    }
    let (x, _) = acc.ok_or_else(|| invalid("Pedersen reached infinity"))?;
    Ok(fp().out_of_mont(&x))
}

/// `pedersen(...pedersen(pedersen(0, d0), d1)..., len)`.
fn hash_on_elements(data: &[U256]) -> Result<U256> {
    let mut acc = U256::ZERO;
    for d in data {
        acc = pedersen(&acc, d)?;
    }
    pedersen(&acc, &U256::from_u128(data.len() as u128))
}

fn poseidon_constants() -> &'static Vec<[U256; 3]> {
    static C: OnceLock<Vec<[U256; 3]>> = OnceLock::new();
    C.get_or_init(|| {
        (0..91)
            .map(|round| {
                let c = |j: usize| {
                    let digest: [u8; 32] =
                        Sha256::digest(format!("Hades{}", 3 * round + j).as_bytes()).into();
                    fp().to_mont(&U256::from_be(&digest))
                };
                [c(0), c(1), c(2)]
            })
            .collect()
    })
}

/// Hades permutation, width 3: 4 full rounds, 83 partial (S-box on the last lane), 4 full.
fn poseidon_permute(s: &mut [U256; 3]) {
    let f = fp();
    let cube = |x: &U256| f.mul(&f.mul(x, x), x);
    for (round, rc) in poseidon_constants().iter().enumerate() {
        for (lane, c) in s.iter_mut().zip(rc) {
            *lane = f.add(lane, c);
        }
        if !(4..87).contains(&round) {
            for lane in s.iter_mut() {
                *lane = cube(lane);
            }
        } else {
            s[2] = cube(&s[2]);
        }
        // MDS [[3,1,1],[1,-1,1],[1,1,-2]].
        let t = f.add(&f.add(&s[0], &s[1]), &s[2]);
        let a2 = f.add(&s[0], &s[0]);
        let b2 = f.add(&s[1], &s[1]);
        let c3 = f.add(&f.add(&s[2], &s[2]), &s[2]);
        *s = [f.add(&t, &a2), f.sub(&t, &b2), f.sub(&t, &c3)];
    }
}

fn poseidon_many(values: &[U256]) -> Result<U256> {
    let f = fp();
    if values.iter().any(|v| *v >= P) {
        return Err(invalid("Poseidon input outside the field"));
    }
    let mut padded: Vec<U256> = values.iter().map(|v| f.to_mont(v)).collect();
    padded.push(f.one());
    if padded.len() % 2 == 1 {
        padded.push(U256::ZERO);
    }
    let mut state = [U256::ZERO; 3];
    for pair in padded.as_chunks::<2>().0 {
        state[0] = f.add(&state[0], &pair[0]);
        state[1] = f.add(&state[1], &pair[1]);
        poseidon_permute(&mut state);
    }
    Ok(f.out_of_mont(&state[0]))
}

// ---------------------------------------------------------------------------
// Keys and Stark ECDSA.

/// EIP-2645 key grinding: the first `sha256(seed || i)` below the largest multiple of n, mod n.
fn grind_key(seed: &[u8; 32]) -> Result<U256> {
    let n = fn_();
    // 2^256 mod n is the Montgomery form of one.
    let limit = U256::ZERO.overflowing_sub(&n.one()).0;
    for i in 0u32..=100_000 {
        let be = i.to_be_bytes();
        let skip = be.iter().take(3).take_while(|b| **b == 0).count();
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&be[skip..]);
        let key = U256::from_be(&hasher.finalize().into());
        if key < limit {
            let k = n.reduce(key);
            if k.is_zero() {
                break;
            }
            return Ok(k);
        }
    }
    Err(invalid("key grinding failed"))
}

struct StarkKey {
    secret: U256,
    public: U256,
}

impl StarkKey {
    fn from_core_secret(secret: &[u8; 32]) -> Result<Self> {
        let d = grind_key(secret)?;
        let (x, _) = point_mul(Some(generator()), &d).ok_or_else(|| invalid("invalid key"))?;
        Ok(Self {
            secret: d,
            public: fp().out_of_mont(&x),
        })
    }
}

impl Drop for StarkKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret.0);
    }
}

fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// The RFC 6979 candidate as @scure/starknet reads it: leading zero bytes are
/// dropped before truncating to the 252-bit order, so a digest that starts
/// with 0x00 is not shifted.
fn bits2int(bytes: &[u8; 32]) -> U256 {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let delta = ((32 - zeros) * 8).saturating_sub(252);
    U256::from_be(bytes).shr(delta as u32)
}

/// Deterministic Stark ECDSA, byte-for-byte what starknet.js produces.
fn ecdsa_sign(msg: &U256, d: &U256) -> Result<(U256, U256)> {
    if *msg >= MAX_VALUE {
        return Err(invalid("message hash out of range"));
    }
    let n = fn_();
    let seed = [d.to_be(), msg.to_be()].concat();
    let mut v = [1u8; 32];
    let mut k = [0u8; 32];
    k = hmac_sha256(&k, &[&v, &[0], &seed]);
    v = hmac_sha256(&k, &[&v]);
    k = hmac_sha256(&k, &[&v, &[1], &seed]);
    v = hmac_sha256(&k, &[&v]);
    for _ in 0..1000 {
        v = hmac_sha256(&k, &[&v]);
        let nonce = bits2int(&v);
        if !nonce.is_zero() && nonce < N {
            if let Some((x, _)) = point_mul(Some(generator()), &nonce) {
                let r = n.reduce(fp().out_of_mont(&x));
                if !r.is_zero() {
                    let km = n.to_mont(&nonce);
                    let sum = n.add(&n.to_mont(msg), &n.mul(&n.to_mont(&r), &n.to_mont(d)));
                    let s = n.out_of_mont(&n.mul(&n.inv(&km), &sum));
                    if !s.is_zero() {
                        let w = n.out_of_mont(&n.inv(&n.to_mont(&s)));
                        if r >= MAX_VALUE || w >= MAX_VALUE {
                            return Err(invalid("signature out of the Stark range"));
                        }
                        return Ok((r, s));
                    }
                }
            }
        }
        k = hmac_sha256(&k, &[&v, &[0]]);
        v = hmac_sha256(&k, &[&v]);
    }
    Err(invalid("nonce generation failed"))
}

// ---------------------------------------------------------------------------
// Addresses.

fn account_address(public: &U256) -> Result<U256> {
    let calldata_hash = hash_on_elements(&[*public])?;
    let raw = hash_on_elements(&[
        CONTRACT_ADDRESS_PREFIX,
        U256::ZERO,
        *public,
        CLASS_HASH,
        calldata_hash,
    ])?;
    Ok(if raw >= ADDR_BOUND {
        raw.overflowing_sub(&ADDR_BOUND).0
    } else {
        raw
    })
}

/// Account address for a 32-byte big-endian Stark public key (the x coordinate).
pub fn address(public: &[u8]) -> Result<String> {
    let bytes: &[u8; 32] = public
        .try_into()
        .map_err(|_| invalid("a Stark public key is 32 bytes"))?;
    let x = U256::from_be(bytes);
    if x.is_zero() || x >= P || !on_curve_x(&x) {
        return Err(invalid("not a Stark public key"));
    }
    Ok(account_address(&x)?.hex_padded())
}

/// The Stark public key (x coordinate) ground from the core's `m/44'/9004'/0'/0/{i}` secret.
pub fn stark_public_key(secret: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(StarkKey::from_core_secret(secret)?.public.to_be())
}

pub fn address_from_secret(secret: &[u8; 32]) -> Result<String> {
    address(&stark_public_key(secret)?)
}

/// Canonical form: `0x` and 64 lowercase hex digits, inside the contract address range.
fn parse_address(value: &str) -> Result<U256> {
    let digits = value
        .strip_prefix("0x")
        .filter(|d| {
            d.len() == 64
                && d.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| invalid("address must be 0x and 64 lowercase hex digits"))?;
    let bytes: [u8; 32] = hex::decode(digits)
        .map_err(|_| invalid("address is not hex"))?
        .try_into()
        .expect("32 bytes");
    check_address_range(U256::from_be(&bytes))
}

/// Intent destinations may be unpadded or mixed case, as wallets display them.
fn parse_address_loose(value: &str) -> Result<U256> {
    let digits = value
        .strip_prefix("0x")
        .filter(|d| !d.is_empty() && d.len() <= 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("address must be 0x-prefixed hex"))?;
    let padded = format!("{:0>64}", digits.to_ascii_lowercase());
    let bytes: [u8; 32] = hex::decode(padded)
        .map_err(|_| invalid("address is not hex"))?
        .try_into()
        .expect("32 bytes");
    check_address_range(U256::from_be(&bytes))
}

fn check_address_range(a: U256) -> Result<U256> {
    // 0x0..0xff holds system contracts and aliases; nothing a user sends to.
    if a < U256::from_u128(0x100) || a >= ADDR_BOUND {
        return Err(invalid("address outside the contract address range"));
    }
    Ok(a)
}

fn parse_decimal(value: &str, what: &str) -> Result<u128> {
    let n = value
        .parse::<u128>()
        .map_err(|_| invalid(format!("{what} must be a decimal integer")))?;
    if n.to_string() != value {
        return Err(invalid(format!("{what} must be canonical decimal")));
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// The transfer.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StarknetTx {
    pub chain_id: String,
    /// The sender's OpenZeppelin account, `0x` + 64 lowercase hex.
    pub from: String,
    pub to: String,
    /// Decimal fri (1 STRK = 10^18 fri); never a JSON floating-point number.
    pub fri: String,
    /// The INVOKE nonce. With `deploy` it must be 1: the DEPLOY_ACCOUNT takes nonce 0.
    pub nonce: u64,
    /// Prepend a DEPLOY_ACCOUNT v3 for the sender's account (first send only).
    pub deploy: bool,
    /// Decimal fri per L2 gas unit, at most `l2GasMaxPrice`.
    pub tip: String,
    pub l1_gas_max_amount: u64,
    /// Decimal fri per unit.
    pub l1_gas_max_price: String,
    pub l2_gas_max_amount: u64,
    pub l2_gas_max_price: String,
    pub l1_data_gas_max_amount: u64,
    pub l1_data_gas_max_price: String,
}

struct Checked {
    from: U256,
    to: U256,
    amount: u128,
    nonce: u64,
    tip: u128,
    /// (amount, price) for L1 gas, L2 gas, L1 data gas.
    bounds: [(u64, u128); 3],
}

impl StarknetTx {
    fn checked(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = parse_address(&self.from)?;
        let to = parse_address(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        if to == STRK {
            return Err(invalid("refusing to send STRK to the token contract"));
        }
        let amount = parse_decimal(&self.fri, "amount")?;
        if amount == 0 {
            return Err(invalid("amount must be positive"));
        }
        if self.deploy && self.nonce != 1 {
            return Err(invalid("a deploying send uses invoke nonce 1"));
        }
        if self.nonce == 0 || self.nonce > MAX_NONCE {
            return Err(invalid("nonce out of range"));
        }
        let bounds = [
            (
                self.l1_gas_max_amount,
                parse_decimal(&self.l1_gas_max_price, "L1 gas price")?,
                MAX_L1_GAS,
            ),
            (
                self.l2_gas_max_amount,
                parse_decimal(&self.l2_gas_max_price, "L2 gas price")?,
                MAX_L2_GAS,
            ),
            (
                self.l1_data_gas_max_amount,
                parse_decimal(&self.l1_data_gas_max_price, "L1 data gas price")?,
                MAX_L1_DATA_GAS,
            ),
        ];
        let mut fee: u128 = 0;
        for (amount, price, cap) in bounds {
            if amount > cap || price > MAX_PRICE {
                return Err(invalid("resource bound out of range"));
            }
            fee += amount as u128 * price;
        }
        if bounds[1].0 == 0 || bounds[1].1 == 0 {
            return Err(invalid("L2 gas bound must be positive"));
        }
        let tip = parse_decimal(&self.tip, "tip")?;
        if tip > bounds[1].1 {
            return Err(invalid("tip exceeds the L2 gas price bound"));
        }
        if fee > MAX_FEE_FRI {
            return Err(invalid("maximum fee exceeds 20 STRK"));
        }
        Ok(Checked {
            from,
            to,
            amount,
            nonce: self.nonce,
            tip,
            bounds: bounds.map(|(a, p, _)| (a, p)),
        })
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        let c = self.checked()?;
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native STRK transfers are enabled"));
                }
                if parse_address_loose(to)? != c.to {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.fri {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Starknet intent")),
        }
        Ok(())
    }

    /// Worst-case fee in fri across both transactions when deploying.
    pub fn max_fee(&self) -> Result<u128> {
        let c = self.checked()?;
        let one: u128 = c.bounds.iter().map(|(a, p)| *a as u128 * p).sum();
        Ok(if self.deploy { one * 2 } else { one })
    }

    /// `account.__execute__` calldata for one `transfer(recipient, u256)` call.
    fn calldata(c: &Checked) -> Vec<U256> {
        vec![
            U256::ONE,
            STRK,
            TRANSFER_SELECTOR,
            U256::from_u128(3),
            c.to,
            U256::from_u128(c.amount),
            U256::ZERO,
        ]
    }

    fn fee_hash(c: &Checked) -> Result<U256> {
        let bound = |name: u64, (amount, price): (u64, u128)| {
            U256([price as u64, (price >> 64) as u64, amount, name])
        };
        poseidon_many(&[
            U256::from_u128(c.tip),
            bound(L1_GAS, c.bounds[0]),
            bound(L2_GAS, c.bounds[1]),
            bound(L1_DATA, c.bounds[2]),
        ])
    }

    fn invoke_hash(c: &Checked) -> Result<U256> {
        poseidon_many(&[
            INVOKE_PREFIX,
            U256::from_u128(3),
            c.from,
            Self::fee_hash(c)?,
            poseidon_many(&[])?,
            SN_SEPOLIA_FELT,
            U256::from_u128(c.nonce as u128),
            U256::ZERO,
            poseidon_many(&[])?,
            poseidon_many(&Self::calldata(c))?,
        ])
    }

    fn deploy_hash(c: &Checked, public: &U256) -> Result<U256> {
        poseidon_many(&[
            DEPLOY_ACCOUNT_PREFIX,
            U256::from_u128(3),
            c.from,
            Self::fee_hash(c)?,
            poseidon_many(&[])?,
            SN_SEPOLIA_FELT,
            U256::ZERO,
            U256::ZERO,
            poseidon_many(&[*public])?,
            CLASS_HASH,
            *public,
        ])
    }

    /// The INVOKE v3 hash: what is signed and what explorers show.
    pub fn tx_hash(&self) -> Result<String> {
        Ok(Self::invoke_hash(&self.checked()?)?.hex_padded())
    }

    fn rpc_common(c: &Checked, signature: (U256, U256), nonce: u64) -> Value {
        let bound = |(amount, price): (u64, u128)| {
            json!({
                "max_amount": U256::from_u128(amount as u128).hex_min(),
                "max_price_per_unit": U256::from_u128(price).hex_min(),
            })
        };
        json!({
            "version": "0x3",
            "signature": [signature.0.hex_min(), signature.1.hex_min()],
            "nonce": U256::from_u128(nonce as u128).hex_min(),
            "resource_bounds": {
                "l1_gas": bound(c.bounds[0]),
                "l2_gas": bound(c.bounds[1]),
                "l1_data_gas": bound(c.bounds[2]),
            },
            "tip": U256::from_u128(c.tip).hex_min(),
            "paymaster_data": [],
            "nonce_data_availability_mode": "L1",
            "fee_data_availability_mode": "L1",
        })
    }

    /// Returns the JSON-RPC parameters to broadcast (`deploy_account_transaction`
    /// when deploying, then `invoke_transaction`) and the invoke hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = StarkKey::from_core_secret(secret)?;
        if account_address(&key.public)?.hex_padded() != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let c = self.checked()?;
        let invoke_hash = Self::invoke_hash(&c)?;
        let mut invoke = Self::rpc_common(&c, ecdsa_sign(&invoke_hash, &key.secret)?, c.nonce);
        let obj = invoke.as_object_mut().expect("object");
        obj.insert("type".into(), json!("INVOKE"));
        obj.insert("sender_address".into(), json!(c.from.hex_min()));
        obj.insert(
            "calldata".into(),
            json!(Self::calldata(&c)
                .iter()
                .map(U256::hex_min)
                .collect::<Vec<_>>()),
        );
        obj.insert("account_deployment_data".into(), json!([]));
        let mut wire = json!({ "invoke_transaction": invoke });
        if self.deploy {
            let deploy_hash = Self::deploy_hash(&c, &key.public)?;
            let mut deploy = Self::rpc_common(&c, ecdsa_sign(&deploy_hash, &key.secret)?, 0);
            let obj = deploy.as_object_mut().expect("object");
            obj.insert("type".into(), json!("DEPLOY_ACCOUNT"));
            obj.insert("contract_address_salt".into(), json!(key.public.hex_min()));
            obj.insert("constructor_calldata".into(), json!([key.public.hex_min()]));
            obj.insert("class_hash".into(), json!(CLASS_HASH.hex_min()));
            wire["deploy_account_transaction"] = deploy;
        }
        Ok((wire.to_string(), invoke_hash.hex_padded()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// starknet.js 10.8 / @scure/starknet 2.4 for `grindKey(07 * 32)`.
    const STARK_PRIVATE: &str = "056324adc0a9d518ce5a8e2ac1f6a433a88de5c673e1dc0cf2264a86f839ddef";
    const STARK_PUBLIC: &str = "0689f60839e8d2780333345a68dbc81424b38a8b866598f0c872c09af9c10e7b";
    /// `hash.calculateContractAddressFromHash(pub, ACCOUNT_CLASS_HASH, [pub], 0)`.
    const ADDRESS: &str = "0x060827ce138bbccc66ce987d602f8413eabe379a860e89f1f4192a5e936da657";
    const RECIPIENT: &str = "0x00123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
    /// starknet.js `calculateInvokeTransactionHash` / `calculateDeployAccountTransactionHash`
    /// and `ec.starkCurve.sign` for `tx()`; the adapter tests pin the same values.
    const INVOKE_HASH: &str = "0x0228bdeec54524f74407845cef655f3582d51ccb273bf2d234994e9d87e04817";
    const INVOKE_SIG: [&str; 2] = [
        "0x46e85009472358b0b54f09427b1004eeca918eea3305e5e8f126fdef31fd67",
        "0x15b67b030195236956e1f689094745b2714e2fc24fb4bbe2d49879ade4b1d68",
    ];
    const DEPLOY_HASH: &str = "0x4d57fa49ca4b96a0b0b56ab1267524ed7277d46997d37a57a665489eda97dec";
    const DEPLOY_SIG: [&str; 2] = [
        "0x5932f7bef4099ae9421b4f36a1ab2c09bc6a8224e64df27f8e2d2349303fd28",
        "0x74202fc97806cb0a6689f80865acadf86e2bb7964bf216a62b07337fd52b603",
    ];

    fn hx(s: &str) -> U256 {
        let d = s.trim_start_matches("0x");
        let bytes: [u8; 32] = hex::decode(format!("{d:0>64}"))
            .unwrap()
            .try_into()
            .unwrap();
        U256::from_be(&bytes)
    }

    fn tx() -> StarknetTx {
        StarknetTx {
            chain_id: SEPOLIA.into(),
            from: ADDRESS.into(),
            to: RECIPIENT.into(),
            fri: "1500000000000000000".into(),
            nonce: 1,
            deploy: true,
            tip: "0".into(),
            l1_gas_max_amount: 0,
            l1_gas_max_price: "50000000000000".into(),
            l2_gas_max_amount: 2_000_000,
            l2_gas_max_price: "12000000000".into(),
            l1_data_gas_max_amount: 256,
            l1_data_gas_max_price: "1000000000".into(),
        }
    }

    fn intent(tx: &StarknetTx) -> TxIntent {
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
                amount: Amount(tx.fri.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    fn verify(msg: &U256, (r, s): (U256, U256), public: Point) -> bool {
        let n = fn_();
        let w = n.inv(&n.to_mont(&s));
        let u1 = n.out_of_mont(&n.mul(&n.to_mont(msg), &w));
        let u2 = n.out_of_mont(&n.mul(&n.to_mont(&r), &w));
        let p = point_add(point_mul(Some(generator()), &u1), point_mul(public, &u2));
        p.is_some_and(|(x, _)| n.reduce(fp().out_of_mont(&x)) == r)
    }

    #[test]
    fn hashes_match_starknet_js() {
        let pedersen12 = pedersen(&U256::ONE, &U256::from_u128(2)).unwrap();
        assert_eq!(
            pedersen12.hex_min(),
            "0x5bb9440e27889a364bcb678b1f679ecd1347acdedcbf36e83494f857cc58026"
        );
        let big = pedersen(
            &hx("0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb"),
            &hx("0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a"),
        )
        .unwrap();
        assert_eq!(
            big.hex_min(),
            "0x30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662"
        );
        assert_eq!(
            poseidon_many(&[]).unwrap().hex_min(),
            "0x2272be0f580fd156823304800919530eaa97430e972d7213ee13f4fbf7a5dbc"
        );
        assert_eq!(
            poseidon_many(&[U256::ONE, U256::from_u128(2), U256::from_u128(3)])
                .unwrap()
                .hex_min(),
            "0x2f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad082"
        );
        let mut state =
            [U256::ONE, U256::from_u128(2), U256::from_u128(2)].map(|v| fp().to_mont(&v));
        poseidon_permute(&mut state);
        assert_eq!(
            fp().out_of_mont(&state[0]).hex_min(),
            "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a"
        );
        let digest = <sha3::Keccak256 as sha3::Digest>::digest(b"transfer");
        let mut sel = U256::from_be(&digest.into());
        sel.0[3] &= (1 << 58) - 1;
        assert_eq!(sel, TRANSFER_SELECTOR);
        assert!(pedersen(&P, &U256::ONE).is_err());
    }

    #[test]
    fn key_grinding_and_address_match_starknet_js() {
        let key = StarkKey::from_core_secret(&SECRET).unwrap();
        assert_eq!(hex::encode(key.secret.to_be()), STARK_PRIVATE);
        assert_eq!(hex::encode(key.public.to_be()), STARK_PUBLIC);
        assert_eq!(
            hex::encode(grind_key(&[1u8; 32]).unwrap().to_be()),
            "045939f5f81789134639d211a06cc86b395977ea4840718127417e8fd57990c6"
        );
        assert_eq!(address_from_secret(&SECRET).unwrap(), ADDRESS);
        assert_eq!(
            address(&hex::decode(STARK_PUBLIC).unwrap()).unwrap(),
            ADDRESS
        );
        // getStarkKey(1) is the generator's x.
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(address(&GX.to_be()).unwrap().len(), 66);
        assert!(address(&[0u8; 32]).is_err());
        assert!(address(&[0u8; 33]).is_err());
        assert!(address(&P.to_be()).is_err());
        assert_eq!(U256::from_be(&one), U256::ONE);
    }

    /// BIP-39 "abandon x11 about", m/44'/9004'/0'/0/0, then grindKey, as Braavos derives it.
    #[test]
    fn bip39_derivation_matches_braavos_style_grinding() {
        let seed = crate::hd::derive(
            crate::hd::Mnemonic::parse(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            )
            .unwrap()
            .to_seed("")
            .as_ref(),
            crate::model::Curve::Secp256k1,
            "m/44'/9004'/0'/0/0",
        )
        .unwrap();
        let key = StarkKey::from_core_secret(seed.secret()).unwrap();
        assert_eq!(
            key.secret.hex_min(),
            "0x1b8e16cdf31892c56c0370f0e4ca0da096ef4e0c81007b3ba10b11452f8971"
        );
        assert_eq!(
            key.public.hex_min(),
            "0x5d97a4a9174d9158c3886717a70112c5e60b17318a1d3ae17f563f1cf8292f4"
        );
        assert_eq!(
            address_from_secret(seed.secret()).unwrap(),
            "0x0125ed61bca4741c31b567501fdf0527ffbfc7965b7271a8be78a9ad0042d6df"
        );
    }

    #[test]
    fn signatures_match_starknet_js() {
        let key = StarkKey::from_core_secret(&SECRET).unwrap();
        let public = point_mul(Some(generator()), &key.secret);
        let cases = [
            (
                "0x1",
                "0x5e52d5004ad00c9a425dd5809f9740ce14b799651157ead3453761807608f66",
                "0x5309a9bf57049d4a86242c7648201ea9edce230685b42c6b73b8b912567aef2",
            ),
            (
                "0x1234",
                "0x25f615d485d2369c8ea8858968c4cec54271e3a00002f9f9b8184eb46e05b4f",
                "0x2e744843ed46f92741b757483ddff6850368f02ed2442818822e4d73b1a36a3",
            ),
            (
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "0x362aaa9443b227117f573c3261fad587904e9913bf34f90d68f30aa74198c67",
                "0x6f0e608cadbbfceaeb09a44c2852733861956603239949b10af50700f9d7af0",
            ),
            (
                "0x7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0x1f8aabff3d1807b19095f241727f9710df685c7c5893a244197018d3dbb02e5",
                "0x2745b69c327f14bdf37498772051d180a7047157cafd854d417200e66c45340",
            ),
        ];
        for (msg, r, s) in cases {
            let sig = ecdsa_sign(&hx(msg), &key.secret).unwrap();
            assert_eq!(
                (sig.0.hex_min(), sig.1.hex_min()),
                (r.to_string(), s.to_string()),
                "{msg}"
            );
            assert!(verify(&hx(msg), sig, public));
            assert!(!verify(&hx("0x1235"), sig, public));
        }
        assert!(ecdsa_sign(&MAX_VALUE, &key.secret).is_err());
    }

    #[test]
    fn transaction_hashes_and_wire_match_starknet_js() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        assert_eq!(t.tx_hash().unwrap(), INVOKE_HASH);
        let c = t.checked().unwrap();
        let key = StarkKey::from_core_secret(&SECRET).unwrap();
        assert_eq!(
            StarknetTx::deploy_hash(&c, &key.public).unwrap().hex_min(),
            DEPLOY_HASH
        );
        assert_eq!(
            t.max_fee().unwrap(),
            2 * (2_000_000 * 12_000_000_000u128 + 256_000_000_000)
        );
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(hash, INVOKE_HASH);
        let v: Value = serde_json::from_str(&wire).unwrap();
        let invoke = &v["invoke_transaction"];
        assert_eq!(invoke["signature"], json!(INVOKE_SIG));
        assert_eq!(invoke["type"], "INVOKE");
        assert_eq!(invoke["nonce"], "0x1");
        assert_eq!(
            invoke["sender_address"],
            "0x60827ce138bbccc66ce987d602f8413eabe379a860e89f1f4192a5e936da657"
        );
        assert_eq!(
            invoke["calldata"],
            json!([
                "0x1",
                "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                "0x3",
                "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
                "0x14d1120d7b160000",
                "0x0"
            ])
        );
        assert_eq!(
            invoke["resource_bounds"]["l2_gas"],
            json!({"max_amount": "0x1e8480", "max_price_per_unit": "0x2cb417800"})
        );
        let deploy = &v["deploy_account_transaction"];
        assert_eq!(deploy["signature"], json!(DEPLOY_SIG));
        assert_eq!(deploy["nonce"], "0x0");
        assert_eq!(
            deploy["class_hash"],
            "0x5b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564"
        );
        assert_eq!(
            deploy["constructor_calldata"],
            json!([key.public.hex_min()])
        );
        assert_eq!(deploy["contract_address_salt"], key.public.hex_min());

        let later = StarknetTx {
            nonce: 7,
            deploy: false,
            tip: "1000".into(),
            ..tx()
        };
        let (wire, hash) = later.sign(&SECRET).unwrap();
        assert_eq!(
            hash,
            "0x00a3d1c20800355f2bfc063dd7104b2911e681231b31b983ee08a4c1ca603a97"
        );
        let v: Value = serde_json::from_str(&wire).unwrap();
        assert!(v.get("deploy_account_transaction").is_none());
        assert_eq!(v["invoke_transaction"]["tip"], "0x3e8");
        assert_eq!(
            v["invoke_transaction"]["signature"],
            json!([
                "0x5fbb21ec7d2648e62633e731203988bfa6842e532380ba8adc04d8a36aeb443",
                "0x53abb3f8db0f8c2d792b79fb72924ad5a356e250bd2683ca100c5fe4c0ec23b"
            ])
        );
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let refuse = |t: StarknetTx| assert!(t.checked().is_err() || t.sign(&SECRET).is_err());
        refuse(StarknetTx {
            chain_id: MAINNET.into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            chain_id: "eip155:1".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            fri: "0".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            fri: "01".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            fri: "1.5".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            fri: "340282366920938463463374607431768211456".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            to: base.from.clone(),
            ..base.clone()
        });
        refuse(StarknetTx {
            to: STRK_TOKEN.into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            to: RECIPIENT.to_uppercase().replace("0X", "0x"),
            ..base.clone()
        });
        refuse(StarknetTx {
            to: "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            to: format!("0x{}", "0".repeat(62) + "01"),
            ..base.clone()
        });
        refuse(StarknetTx {
            to: format!("0x08{}", "0".repeat(62)),
            ..base.clone()
        });
        refuse(StarknetTx {
            nonce: 2,
            ..base.clone()
        });
        refuse(StarknetTx {
            nonce: 0,
            deploy: false,
            ..base.clone()
        });
        refuse(StarknetTx {
            l2_gas_max_amount: 0,
            ..base.clone()
        });
        refuse(StarknetTx {
            l2_gas_max_amount: MAX_L2_GAS + 1,
            ..base.clone()
        });
        refuse(StarknetTx {
            l1_gas_max_price: (MAX_PRICE + 1).to_string(),
            ..base.clone()
        });
        refuse(StarknetTx {
            l2_gas_max_amount: 100_000_000,
            l2_gas_max_price: "1000000000000".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            tip: "12000000001".into(),
            ..base.clone()
        });
        refuse(StarknetTx {
            tip: "-1".into(),
            ..base.clone()
        });

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000000000000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "0x123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdf".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        // The same destination as a wallet displays it, unpadded and mixed case, matches.
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "0x123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcde".into();
        }
        base.check_matches_intent(&i).unwrap();
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{SEPOLIA}:erc20:{STRK_TOKEN}");
        }
        assert!(base.check_matches_intent(&i).is_err());

        let other = StarknetTx {
            from: RECIPIENT.into(),
            to: ADDRESS.into(),
            ..base.clone()
        };
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": SEPOLIA, "from": base.from, "to": base.to, "fri": "1", "nonce": 1,
            "deploy": false, "tip": "0", "l1GasMaxAmount": 0, "l1GasMaxPrice": "1",
            "l2GasMaxAmount": 1, "l2GasMaxPrice": "1", "l1DataGasMaxAmount": 0,
            "l1DataGasMaxPrice": "1", "calldata": []
        });
        assert!(serde_json::from_value::<StarknetTx>(extra).is_err());
    }

    /// Prints a signed pair for a live `starknet_simulateTransactions` probe:
    /// `STARKNET_PROBE='{...StarknetTx json...}' cargo test ... -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn print_live_probe_payload() {
        let fields = std::env::var("STARKNET_PROBE").expect("STARKNET_PROBE");
        let t: StarknetTx = serde_json::from_str(&fields).unwrap();
        let (wire, hash) = t.sign(&SECRET).unwrap();
        println!("PROBE_HASH={hash}");
        println!("PROBE_WIRE={wire}");
    }
}
