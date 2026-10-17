//! Hierarchical deterministic keys for `single` wallets: BIP39 mnemonics,
//! BIP32 for secp256k1 and SLIP-10 for Ed25519. Standard derivation is a
//! deliberate choice: a phrase exported from StackWallet must restore the same
//! accounts in any other wallet, otherwise "export" would be a trap.
//!
//! Everything here stays inside the core. Callers get public keys; private
//! material leaves only through `provenance::reveal`, which marks the wallet
//! exposed first.

use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use sha2::{Digest, Sha256};
use sha2_v011::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::model::Curve;
use crate::{CoreError, Result};

const WORDLIST_TEXT: &str = include_str!("english.txt");
const PBKDF2_ROUNDS: u32 = 2048;
const HARDENED: u32 = 0x8000_0000;
/// Deep enough for every standard scheme (BIP44/49/84/86 use five levels).
pub const MAX_PATH_DEPTH: usize = 10;

fn invalid(what: &'static str, reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what,
        reason: reason.into(),
    }
}

fn wordlist() -> Vec<&'static str> {
    WORDLIST_TEXT.lines().collect()
}

/// A validated BIP39 mnemonic. Display and Debug never print the words.
pub struct Mnemonic {
    phrase: Zeroizing<String>,
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mnemonic(<{} words>)", self.word_count())
    }
}

impl Mnemonic {
    /// A fresh 24-word phrase from 256 bits of OS entropy.
    pub fn generate() -> Result<Self> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| CoreError::Crypto("entropy"))?;
        Self::from_entropy(entropy.as_ref())
    }

    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(invalid("mnemonic", "entropy must be 128-256 bits"));
        }
        let words = wordlist();
        let checksum_bits = entropy.len() * 8 / 32;
        let hash = Sha256::digest(entropy);
        let mut bits = Zeroizing::new(Vec::with_capacity(entropy.len() * 8 + checksum_bits));
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        for i in 0..checksum_bits {
            bits.push((hash[i / 8] >> (7 - (i % 8))) & 1);
        }
        let mut out = Vec::with_capacity(bits.len() / 11);
        for chunk in bits.chunks(11) {
            let idx = chunk.iter().fold(0usize, |acc, b| (acc << 1) | *b as usize);
            out.push(words[idx]);
        }
        Ok(Self {
            phrase: Zeroizing::new(out.join(" ")),
        })
    }

    /// Parse and checksum-verify a phrase typed or pasted by the user.
    pub fn parse(input: &str) -> Result<Self> {
        let words = wordlist();
        let given: Vec<String> = input.split_whitespace().map(|w| w.to_lowercase()).collect();
        if !matches!(given.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(invalid("mnemonic", "expected 12, 15, 18, 21 or 24 words"));
        }
        let mut bits = Zeroizing::new(Vec::with_capacity(given.len() * 11));
        for (n, w) in given.iter().enumerate() {
            let idx = words
                .binary_search(&w.as_str())
                .map_err(|_| invalid("mnemonic", format!("word {} is not in the list", n + 1)))?;
            for i in (0..11).rev() {
                bits.push(((idx >> i) & 1) as u8);
            }
        }
        let checksum_bits = bits.len() / 33;
        let entropy_bits = bits.len() - checksum_bits;
        let mut entropy = Zeroizing::new(vec![0u8; entropy_bits / 8]);
        for (i, bit) in bits[..entropy_bits].iter().enumerate() {
            entropy[i / 8] |= bit << (7 - (i % 8));
        }
        let hash = Sha256::digest(entropy.as_slice());
        for i in 0..checksum_bits {
            if bits[entropy_bits + i] != (hash[i / 8] >> (7 - (i % 8))) & 1 {
                return Err(invalid("mnemonic", "checksum does not match"));
            }
        }
        Ok(Self {
            phrase: Zeroizing::new(given.join(" ")),
        })
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    pub fn word_count(&self) -> usize {
        self.phrase.split(' ').count()
    }

    /// BIP39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt `"mnemonic" + passphrase`.
    pub fn to_seed(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        let salt = format!("mnemonic{passphrase}");
        pbkdf2_sha512(self.phrase.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS)
    }
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("hmac takes any key");
    for p in parts {
        mac.update(p);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn pbkdf2_sha512(password: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 64]> {
    // One 64-byte block is exactly the seed length, so block index is always 1.
    let mut u = hmac_sha512(password, &[salt, &1u32.to_be_bytes()]);
    let mut out = Zeroizing::new(*u);
    for _ in 1..rounds {
        u = hmac_sha512(password, &[u.as_ref()]);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// Parse `m/44'/60'/0'/0/0` (or `h` for hardened) into child indices.
pub fn parse_path(path: &str) -> Result<Vec<u32>> {
    let mut parts = path.trim().split('/');
    if parts.next() != Some("m") {
        return Err(invalid("derivation path", "must start with m"));
    }
    let mut out = Vec::new();
    for p in parts {
        let (num, hardened) = match p.strip_suffix('\'').or_else(|| p.strip_suffix('h')) {
            Some(n) => (n, true),
            None => (p, false),
        };
        if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) || num.len() > 10 {
            return Err(invalid("derivation path", format!("bad segment {p:?}")));
        }
        let n: u32 = num
            .parse()
            .map_err(|_| invalid("derivation path", format!("bad segment {p:?}")))?;
        if n >= HARDENED {
            return Err(invalid("derivation path", "index out of range"));
        }
        out.push(if hardened { n | HARDENED } else { n });
    }
    if out.len() > MAX_PATH_DEPTH {
        return Err(invalid("derivation path", "too deep"));
    }
    Ok(out)
}

/// A derived private key with its public counterpart. The secret is wiped on drop.
pub struct DerivedKey {
    pub curve: Curve,
    secret: Zeroizing<[u8; 32]>,
    /// Compressed SEC1 for secp256k1, raw 32 bytes for Ed25519.
    pub public: Vec<u8>,
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DerivedKey({:?}, pub {})",
            self.curve,
            hex::encode(&self.public)
        )
    }
}

impl DerivedKey {
    /// A key produced outside the HD routes (Chia's EIP-2333 scalar).
    pub(crate) fn from_parts(curve: Curve, secret: [u8; 32], public: Vec<u8>) -> Self {
        Self {
            curve,
            secret: Zeroizing::new(secret),
            public,
        }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
    pub fn public_hex(&self) -> String {
        hex::encode(&self.public)
    }
}

fn secp_public(secret: &[u8; 32]) -> Result<Vec<u8>> {
    let sk = k256::SecretKey::from_slice(secret).map_err(|_| CoreError::Crypto("secp256k1 key"))?;
    Ok(sk.public_key().to_encoded_point(true).as_bytes().to_vec())
}

/// BIP32 for secp256k1.
pub fn derive_secp256k1(seed: &[u8], path: &[u32]) -> Result<DerivedKey> {
    let master = hmac_sha512(b"Bitcoin seed", &[seed]);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&master[..32]);
    chain.copy_from_slice(&master[32..]);
    if k256::SecretKey::from_slice(key.as_ref()).is_err() {
        return Err(CoreError::Crypto("bip32 master key"));
    }
    for &index in path {
        let i = if index & HARDENED != 0 {
            hmac_sha512(
                chain.as_ref(),
                &[&[0u8], key.as_ref(), &index.to_be_bytes()],
            )
        } else {
            let public = secp_public(&key)?;
            hmac_sha512(chain.as_ref(), &[&public, &index.to_be_bytes()])
        };
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let tweak = Option::<k256::Scalar>::from(k256::Scalar::from_repr(il.into()))
            .ok_or(CoreError::Crypto("bip32 child out of range"))?;
        il.zeroize();
        let parent = Option::<k256::Scalar>::from(k256::Scalar::from_repr((*key).into()))
            .ok_or(CoreError::Crypto("bip32 parent"))?;
        let child = tweak + parent;
        if bool::from(child.is_zero()) {
            return Err(CoreError::Crypto("bip32 child is zero"));
        }
        key.copy_from_slice(&child.to_repr());
        chain.copy_from_slice(&i[32..]);
    }
    let public = secp_public(&key)?;
    Ok(DerivedKey {
        curve: Curve::Secp256k1,
        secret: key,
        public,
    })
}

/// SLIP-10 for Ed25519; every level is hardened by definition.
pub fn derive_ed25519(seed: &[u8], path: &[u32]) -> Result<DerivedKey> {
    let master = hmac_sha512(b"ed25519 seed", &[seed]);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&master[..32]);
    chain.copy_from_slice(&master[32..]);
    for &index in path {
        if index & HARDENED == 0 {
            return Err(invalid(
                "derivation path",
                "ed25519 supports hardened levels only",
            ));
        }
        let i = hmac_sha512(
            chain.as_ref(),
            &[&[0u8], key.as_ref(), &index.to_be_bytes()],
        );
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
    }
    let public = ed25519_dalek::SigningKey::from_bytes(&key)
        .verifying_key()
        .to_bytes()
        .to_vec();
    Ok(DerivedKey {
        curve: Curve::Ed25519,
        secret: key,
        public,
    })
}

pub fn derive(seed: &[u8], curve: Curve, path: &str) -> Result<DerivedKey> {
    let indices = parse_path(path)?;
    match curve {
        Curve::Secp256k1 => derive_secp256k1(seed, &indices),
        Curve::Ed25519 => derive_ed25519(seed, &indices),
        Curve::Secp256k1Tr => Err(invalid(
            "curve",
            "taproot single-key accounts are not offered yet",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_bip39_english() {
        let w = wordlist();
        assert_eq!(w.len(), 2048);
        assert_eq!(w[0], "abandon");
        assert_eq!(w[2047], "zoo");
        assert!(
            w.windows(2).all(|p| p[0] < p[1]),
            "binary search needs sorted words"
        );
    }

    // Trezor reference vectors (passphrase "TREZOR").
    #[test]
    fn bip39_vectors() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            m.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(
            hex::encode(&m.to_seed("TREZOR")[..]),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        let m = Mnemonic::from_entropy(&[0xffu8; 32]).unwrap();
        assert_eq!(
            m.phrase(),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        );
        assert_eq!(
            hex::encode(&m.to_seed("TREZOR")[..]),
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"
        );
    }

    #[test]
    fn parse_checks_words_and_checksum() {
        assert!(Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_ok());
        assert!(Mnemonic::parse("  Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ABOUT ").is_ok());
        assert!(Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());
        assert!(Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzz").is_err());
        assert!(Mnemonic::parse("abandon about").is_err());
        let fresh = Mnemonic::generate().unwrap();
        assert_eq!(fresh.word_count(), 24);
        assert!(Mnemonic::parse(fresh.phrase()).is_ok());
        assert!(!format!("{fresh:?}").contains(fresh.phrase()));
    }

    #[test]
    fn paths() {
        assert_eq!(
            parse_path("m/44'/60'/0'/0/7").unwrap(),
            vec![44 | HARDENED, 60 | HARDENED, HARDENED, 0, 7]
        );
        assert_eq!(parse_path("m/0h").unwrap(), vec![HARDENED]);
        assert_eq!(parse_path("m").unwrap(), Vec::<u32>::new());
        for bad in [
            "44'/0",
            "m/x",
            "m/-1",
            "m//1",
            "m/2147483648",
            "m/1/2/3/4/5/6/7/8/9/10/11",
        ] {
            assert!(parse_path(bad).is_err(), "{bad}");
        }
    }

    // BIP32 test vector 1.
    #[test]
    fn bip32_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let k = derive(&seed, Curve::Secp256k1, "m").unwrap();
        assert_eq!(
            hex::encode(k.secret()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        let k = derive(&seed, Curve::Secp256k1, "m/0'/1/2'/2/1000000000").unwrap();
        assert_eq!(
            hex::encode(k.secret()),
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        );
        assert_eq!(
            k.public_hex(),
            "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
        );
    }

    // SLIP-10 ed25519 test vector 1.
    #[test]
    fn slip10_ed25519_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let k = derive(&seed, Curve::Ed25519, "m/0'/1'/2'/2'/1000000000'").unwrap();
        assert_eq!(
            hex::encode(k.secret()),
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
        );
        assert_eq!(
            k.public_hex(),
            "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"
        );
        assert!(derive(&seed, Curve::Ed25519, "m/0").is_err());
    }

    #[test]
    fn well_known_ethereum_account() {
        // The "test test ... junk" development mnemonic and its first Ethereum account key.
        let m =
            Mnemonic::parse("test test test test test test test test test test test junk").unwrap();
        let k = derive(m.to_seed("").as_ref(), Curve::Secp256k1, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(
            hex::encode(k.secret()),
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        );
    }
}
