//! Native ADA transfers on Cardano preprod, plus CIP-1852 (Icarus,
//! BIP32-Ed25519) key derivation. The core CBOR-encodes the whole Conway-era
//! transaction from checked fields: sorted key-address inputs, one payment
//! output, an optional change output back to the sender, an explicit fee and a
//! TTL. No metadata, certificates, withdrawals, native assets or scripts.
//!
//! The ledger rule `inputs = outputs + fee` makes the explicit fee the only
//! value the transaction can spend beyond the outputs: wrong input amounts from
//! the adapter make the transaction invalid, never more expensive.

use bech32::{primitives::decode::CheckedHrpstring, Bech32, Hrp};
use blake2::digest::consts::{U28, U32};
use blake2::{Blake2b, Digest};
use frost_ed25519::{Ciphersuite, Ed25519Group, Ed25519ScalarField, Ed25519Sha512, Field, Group};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2_v011::Sha512;
use zeroize::Zeroizing;

use crate::hd::Mnemonic;
use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 (CIP-34) id of preprod, the only network transfers are signed for.
pub const PREPROD: &str = "cip34:0-1";
/// Preview testnet; catalogued read-only.
pub const PREVIEW: &str = "cip34:0-2";
pub const MAINNET: &str = "cip34:1-764824073";

const HARDENED: u32 = 0x8000_0000;
const PURPOSE: u32 = 1852 | HARDENED;
const COIN_TYPE: u32 = 1815 | HARDENED;
const ICARUS_ROUNDS: u32 = 4096;
const HRP_TESTNET: &str = "addr_test";
const HRP_MAINNET: &str = "addr";
const TESTNET_ID: u8 = 0;
const MAINNET_ID: u8 = 1;
/// CIP-19 header types: key payment with key stake, key payment with script
/// stake, and enterprise (no stake part).
const BASE_KEY_KEY: u8 = 0;
const BASE_KEY_SCRIPT: u8 = 2;
const ENTERPRISE_KEY: u8 = 6;

/// Total ADA supply in lovelace; nothing larger can exist in one output.
pub const MAX_LOVELACE: u64 = 45_000_000_000_000_000;
/// 1 ADA. Typical transfers pay about 0.17 ADA.
pub const MAX_FEE: u64 = 1_000_000;
pub const MAX_INPUTS: usize = 40;
pub const MAX_TTL_SLOTS: u64 = 86_400;
/// Fixed extra bytes of the signed transaction around the body: the 4-array
/// header, the witness set with one vkey witness, `true` and `null`.
const ENVELOPE_OVERHEAD: usize = 1 + WITNESS_SET_LEN + 2;
const WITNESS_SET_LEN: usize = 1 + 1 + 3 + 1 + 1 + 2 + 32 + 2 + 64;
/// The ledger adds this many bytes to an output's size for the min-UTxO rule.
const UTXO_ENTRY_OVERHEAD: u64 = 160;

type Scalar = <Ed25519ScalarField as Field>::Scalar;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Cardano transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != PREPROD {
        return Err(invalid("only Cardano preprod transfers are enabled"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Keys: CIP-3 Icarus master key and BIP32-Ed25519 (V2) child derivation.

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("hmac takes any key");
    for p in parts {
        mac.update(p);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// PBKDF2-HMAC-SHA512 with a 96-byte output (two blocks).
fn pbkdf2_96(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 96]> {
    let mut out = Zeroizing::new([0u8; 96]);
    for (block, chunk) in out.chunks_mut(64).enumerate() {
        let index = (block as u32 + 1).to_be_bytes();
        let mut u = hmac_sha512(password, &[salt, &index]);
        let mut acc = Zeroizing::new(*u);
        for _ in 1..ICARUS_ROUNDS {
            u = hmac_sha512(password, &[u.as_ref()]);
            for (a, x) in acc.iter_mut().zip(u.iter()) {
                *a ^= x;
            }
        }
        chunk.copy_from_slice(&acc[..chunk.len()]);
    }
    out
}

/// A little-endian 256-bit integer reduced mod l. BIP32-Ed25519 scalars are
/// not clamped after derivation, so they must not go through RFC 8032 clamping.
fn scalar_le(bytes: &[u8; 32]) -> Scalar {
    let mut lo = Zeroizing::new([0u8; 32]);
    let mut hi = Zeroizing::new([0u8; 32]);
    lo[..16].copy_from_slice(&bytes[..16]);
    hi[..16].copy_from_slice(&bytes[16..]);
    let mut shift = [0u8; 32];
    shift[16] = 1;
    // Each limb is below 2^129 < l, so it is a canonical encoding.
    let canonical = |b: &[u8; 32]| Ed25519ScalarField::deserialize(b).expect("below l");
    canonical(&hi) * canonical(&shift) + canonical(&lo)
}

fn point_bytes(scalar: Scalar) -> Result<[u8; 32]> {
    Ed25519Group::serialize(&(Ed25519Group::generator() * scalar))
        .map_err(|_| CoreError::Crypto("cardano key is the identity"))
}

fn public_of(xsk: &[u8; 64]) -> Result<[u8; 32]> {
    let kl: &[u8; 32] = xsk[..32].try_into().expect("32 bytes");
    point_bytes(scalar_le(kl))
}

/// Ed25519 over an extended key `kL || kR`: `kL` is the scalar, `kR` the nonce
/// prefix, exactly as RFC 8032 uses the two halves of SHA-512(seed).
pub fn sign_extended(xsk: &[u8; 64], message: &[u8]) -> Result<[u8; 64]> {
    let kl: &[u8; 32] = xsk[..32].try_into().expect("32 bytes");
    let public = point_bytes(scalar_le(kl))?;
    let mut nonce_input = Zeroizing::new(Vec::with_capacity(32 + message.len()));
    nonce_input.extend_from_slice(&xsk[32..]);
    nonce_input.extend_from_slice(message);
    let r = Ed25519Sha512::H2(&nonce_input);
    let big_r = point_bytes(r)?;
    let mut challenge = Vec::with_capacity(64 + message.len());
    challenge.extend_from_slice(&big_r);
    challenge.extend_from_slice(&public);
    challenge.extend_from_slice(message);
    let k = Ed25519Sha512::H2(&challenge);
    let s = r + k * scalar_le(kl);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&Ed25519ScalarField::serialize(&s));
    Ok(sig)
}

/// A BIP32-Ed25519 extended private key. Debug never prints the secret.
pub struct ExtendedKey {
    xsk: Zeroizing<[u8; 64]>,
    chain_code: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl std::fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExtendedKey(pub {})", hex::encode(self.public))
    }
}

impl ExtendedKey {
    /// CIP-3 Icarus master key: PBKDF2(passphrase, entropy, 4096) then clamped.
    pub fn from_entropy(entropy: &[u8], passphrase: &str) -> Result<Self> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(invalid("entropy must be 128-256 bits"));
        }
        let raw = pbkdf2_96(passphrase.as_bytes(), entropy);
        let mut xsk = Zeroizing::new([0u8; 64]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        xsk.copy_from_slice(&raw[..64]);
        chain_code.copy_from_slice(&raw[64..]);
        xsk[0] &= 0b1111_1000;
        xsk[31] &= 0b0001_1111;
        xsk[31] |= 0b0100_0000;
        let public = public_of(&xsk)?;
        Ok(Self {
            xsk,
            chain_code,
            public,
        })
    }

    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> Result<Self> {
        Self::from_entropy(&mnemonic_entropy(mnemonic)?, passphrase)
    }

    /// V2 child derivation (Khovratovich and Law, as implemented by Icarus wallets).
    pub fn child(&self, index: u32) -> Result<Self> {
        let hardened = index & HARDENED != 0;
        let mut data = Zeroizing::new(Vec::with_capacity(69));
        if hardened {
            data.push(0);
            data.extend_from_slice(self.xsk.as_ref());
        } else {
            data.push(2);
            data.extend_from_slice(&self.public);
        }
        data.extend_from_slice(&index.to_le_bytes());
        let z = hmac_sha512(self.chain_code.as_ref(), &[&data]);
        data[0] = if hardened { 1 } else { 3 };
        let i = hmac_sha512(self.chain_code.as_ref(), &[&data]);

        let mut xsk = Zeroizing::new([0u8; 64]);
        // kL' = kL + 8 * zL[..28], kR' = kR + zR (mod 2^256), both little-endian.
        let mut carry = 0u32;
        for n in 0..32 {
            let add = if n < 28 { (z[n] as u32) << 3 } else { 0 };
            let sum = self.xsk[n] as u32 + add + carry;
            xsk[n] = sum as u8;
            carry = sum >> 8;
        }
        if carry != 0 {
            return Err(CoreError::Crypto("bip32-ed25519 child overflow"));
        }
        let mut carry = 0u16;
        for n in 0..32 {
            let sum = self.xsk[32 + n] as u16 + z[32 + n] as u16 + carry;
            xsk[32 + n] = sum as u8;
            carry = sum >> 8;
        }
        let mut chain_code = Zeroizing::new([0u8; 32]);
        chain_code.copy_from_slice(&i[32..]);
        let public = public_of(&xsk)?;
        Ok(Self {
            xsk,
            chain_code,
            public,
        })
    }

    pub fn derive_path(&self, path: &[u32]) -> Result<Self> {
        let mut key = self.child(*path.first().ok_or_else(|| invalid("empty path"))?)?;
        for &index in &path[1..] {
            key = key.child(index)?;
        }
        Ok(key)
    }

    /// `kL || kR`, the 64-byte signing secret.
    pub fn secret(&self) -> &[u8; 64] {
        &self.xsk
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

/// The payment (`m/1852'/1815'/i'/0/0`) and stake (`m/1852'/1815'/i'/2/0`) keys of account i.
#[derive(Debug)]
pub struct AccountKeys {
    pub payment: ExtendedKey,
    pub stake: ExtendedKey,
}

impl AccountKeys {
    /// Payment public key followed by stake public key; `address` turns it into a base address.
    pub fn public(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.payment.public);
        out[32..].copy_from_slice(&self.stake.public);
        out
    }
}

pub fn account_keys(mnemonic: &Mnemonic, passphrase: &str, account: u32) -> Result<AccountKeys> {
    if account >= HARDENED {
        return Err(invalid("account index out of range"));
    }
    let root = ExtendedKey::from_mnemonic(mnemonic, passphrase)?;
    let acct = root.derive_path(&[PURPOSE, COIN_TYPE, account | HARDENED])?;
    Ok(AccountKeys {
        payment: acct.derive_path(&[0, 0])?,
        stake: acct.derive_path(&[2, 0])?,
    })
}

/// BIP39 entropy behind an already validated phrase (Icarus derives from
/// entropy, not from the BIP39 seed).
fn mnemonic_entropy(mnemonic: &Mnemonic) -> Result<Zeroizing<Vec<u8>>> {
    let words: Vec<&str> = include_str!("hd/english.txt").lines().collect();
    let mut bits = Zeroizing::new(Vec::with_capacity(24 * 11));
    for w in mnemonic.phrase().split(' ') {
        let idx = words
            .binary_search(&w)
            .map_err(|_| invalid("mnemonic word not in the list"))?;
        for i in (0..11).rev() {
            bits.push(((idx >> i) & 1) as u8);
        }
    }
    let entropy_bits = bits.len() - bits.len() / 33;
    let mut entropy = Zeroizing::new(vec![0u8; entropy_bits / 8]);
    for (i, bit) in bits[..entropy_bits].iter().enumerate() {
        entropy[i / 8] |= bit << (7 - (i % 8));
    }
    Ok(entropy)
}

// ---------------------------------------------------------------------------
// Addresses (CIP-19).

fn key_hash(public: &[u8; 32]) -> [u8; 28] {
    Blake2b::<U28>::digest(public).into()
}

fn encode_raw(network: u8, raw: &[u8]) -> String {
    let hrp = if network == MAINNET_ID {
        HRP_MAINNET
    } else {
        HRP_TESTNET
    };
    bech32::encode::<Bech32>(Hrp::parse(hrp).expect("static hrp"), raw).expect("short address")
}

/// A base address for `payment || stake` (64 bytes) or an enterprise address
/// for a lone payment key (32 bytes, e.g. a threshold group key).
pub fn address_on(network: u8, public: &[u8]) -> Result<String> {
    if network != TESTNET_ID && network != MAINNET_ID {
        return Err(invalid("unknown network id"));
    }
    let mut raw = Vec::with_capacity(57);
    match public.len() {
        32 => {
            raw.push(ENTERPRISE_KEY << 4 | network);
            raw.extend_from_slice(&key_hash(public.try_into().expect("32")));
        }
        64 => {
            raw.push(BASE_KEY_KEY << 4 | network);
            raw.extend_from_slice(&key_hash(public[..32].try_into().expect("32")));
            raw.extend_from_slice(&key_hash(public[32..].try_into().expect("32")));
        }
        _ => {
            return Err(invalid(
                "public key must be 32 (payment) or 64 (payment || stake) bytes",
            ))
        }
    }
    Ok(encode_raw(network, &raw))
}

/// The preprod/preview (`addr_test1â€¦`) address for a public key.
pub fn address(public: &[u8]) -> Result<String> {
    address_on(TESTNET_ID, public)
}

/// A decoded testnet Shelley address whose payment part is a key hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAddress {
    pub raw: Vec<u8>,
    pub kind: u8,
    pub payment: [u8; 28],
}

/// Decode a canonical lowercase `addr_test1â€¦` address with a key payment
/// credential. Script, pointer, Byron and mainnet addresses are refused.
pub fn decode_address(address: &str) -> Result<KeyAddress> {
    if address.len() > 120 {
        return Err(invalid("address too long"));
    }
    let checked =
        CheckedHrpstring::new::<Bech32>(address).map_err(|_| invalid("invalid bech32 address"))?;
    if checked.hrp().as_str() != HRP_TESTNET {
        return Err(invalid("expected an addr_test address"));
    }
    let raw: Vec<u8> = checked.byte_iter().collect();
    let header = *raw.first().ok_or_else(|| invalid("empty address"))?;
    let (kind, network) = (header >> 4, header & 0x0f);
    if network != TESTNET_ID {
        return Err(invalid("address is not for a test network"));
    }
    let len = match kind {
        BASE_KEY_KEY | BASE_KEY_SCRIPT => 57,
        ENTERPRISE_KEY => 29,
        _ => {
            return Err(invalid(
                "only key-payment base and enterprise addresses are accepted",
            ))
        }
    };
    if raw.len() != len || encode_raw(network, &raw) != address {
        return Err(invalid("non-canonical address"));
    }
    let payment = raw[1..29].try_into().expect("28 bytes");
    Ok(KeyAddress { raw, kind, payment })
}

// ---------------------------------------------------------------------------
// Minimal deterministic CBOR (RFC 8949 preferred serialization).

fn cbor_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}
fn cbor_uint(out: &mut Vec<u8>, n: u64) {
    cbor_head(out, 0, n);
}
fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}
fn cbor_array(out: &mut Vec<u8>, len: usize) {
    cbor_head(out, 4, len as u64);
}
fn cbor_map(out: &mut Vec<u8>, len: usize) {
    cbor_head(out, 5, len as u64);
}
/// Conway's tag 258 marks a CBOR array as a set.
fn cbor_set(out: &mut Vec<u8>, len: usize) {
    cbor_head(out, 6, 258);
    cbor_array(out, len);
}

fn output_bytes(address: &[u8], lovelace: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(70);
    cbor_array(&mut out, 2);
    cbor_bytes(&mut out, address);
    cbor_uint(&mut out, lovelace);
    out
}

// ---------------------------------------------------------------------------
// Transfers.

fn canonical_lovelace(value: &str, what: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} is not a decimal integer")))?;
    if n == 0 || n > MAX_LOVELACE || n.to_string() != value {
        return Err(invalid(format!(
            "{what} must be a positive canonical lovelace amount"
        )));
    }
    Ok(n)
}

/// One UTxO the transfer spends, as the adapter read it from the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardanoInput {
    /// 64 lowercase hex characters.
    pub tx_hash: String,
    pub index: u32,
    /// The UTxO's ADA value; it must hold no native assets.
    pub lovelace: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardanoTx {
    pub chain_id: String,
    /// Sender address (base or enterprise); change goes back here.
    pub from: String,
    pub to: String,
    /// Decimal lovelace sent to `to` (1 ADA = 1,000,000 lovelace).
    pub lovelace: String,
    /// Strictly ascending by (txHash, index).
    pub inputs: Vec<CardanoInput>,
    /// Explicit fee in lovelace; at least `minFeeA * size + minFeeB` of the signed bytes.
    pub fee: u64,
    /// Absolute slot after which the transaction is invalid.
    pub ttl: u64,
    /// The chain tip slot when the transaction was built; bounds `ttl`, not encoded.
    pub built_slot: u64,
    pub min_fee_a: u64,
    pub min_fee_b: u64,
    pub coins_per_utxo_byte: u64,
}

impl CardanoTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native ADA transfers are enabled"));
                }
                if decode_address(to)?.raw != decode_address(&self.to)?.raw {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.lovelace {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Cardano intent")),
        }
        self.body()?;
        Ok(())
    }

    /// Lovelace returned to `from`; zero means no change output.
    pub fn change(&self) -> Result<u64> {
        let amount = canonical_lovelace(&self.lovelace, "amount")?;
        let mut total: u128 = 0;
        for input in &self.inputs {
            total += canonical_lovelace(&input.lovelace, "input amount")? as u128;
        }
        total
            .checked_sub(amount as u128 + self.fee as u128)
            .map(|c| c as u64)
            .ok_or_else(|| invalid("inputs do not cover amount plus fee"))
    }

    /// CBOR of the transaction body; its blake2b-256 is the tx id.
    pub fn body(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = decode_address(&self.from)?;
        if from.kind == BASE_KEY_SCRIPT {
            return Err(invalid("sender must be a key base or enterprise address"));
        }
        let to = decode_address(&self.to)?;
        if from.raw == to.raw {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_lovelace(&self.lovelace, "amount")?;
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(invalid(format!("between 1 and {MAX_INPUTS} inputs")));
        }
        let mut refs: Vec<([u8; 32], u32)> = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let h = &input.tx_hash;
            if h.len() != 64 || !h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(invalid("input txHash must be 64 lowercase hex characters"));
            }
            let hash: [u8; 32] = hex::decode(h)
                .expect("checked hex")
                .try_into()
                .expect("32 bytes");
            if refs.last().is_some_and(|last| *last >= (hash, input.index)) {
                return Err(invalid("inputs must be unique and sorted"));
            }
            refs.push((hash, input.index));
        }
        if !(1..=1_000).contains(&self.min_fee_a)
            || !(1..=1_000_000).contains(&self.min_fee_b)
            || !(1..=100_000).contains(&self.coins_per_utxo_byte)
        {
            return Err(invalid(
                "protocol parameters are outside the accepted range",
            ));
        }
        if self.fee == 0 || self.fee > MAX_FEE {
            return Err(invalid("fee is outside the accepted range"));
        }
        if self.built_slot == 0
            || self.ttl <= self.built_slot
            || self.ttl - self.built_slot > MAX_TTL_SLOTS
        {
            return Err(invalid("ttl must fall within a day of the build slot"));
        }
        let change = self.change()?;
        let min_utxo = |o: &[u8]| (UTXO_ENTRY_OVERHEAD + o.len() as u64) * self.coins_per_utxo_byte;
        let payment = output_bytes(&to.raw, amount);
        if amount < min_utxo(&payment) {
            return Err(invalid("amount is below the minimum UTxO value"));
        }
        let mut outputs = vec![payment];
        if change > 0 {
            let back = output_bytes(&from.raw, change);
            if change < min_utxo(&back) {
                return Err(invalid("change is below the minimum UTxO value"));
            }
            outputs.push(back);
        }

        let mut body = Vec::with_capacity(128 + 40 * refs.len());
        cbor_map(&mut body, 4);
        cbor_uint(&mut body, 0);
        cbor_set(&mut body, refs.len());
        for (hash, index) in &refs {
            cbor_array(&mut body, 2);
            cbor_bytes(&mut body, hash);
            cbor_uint(&mut body, *index as u64);
        }
        cbor_uint(&mut body, 1);
        cbor_array(&mut body, outputs.len());
        for o in &outputs {
            body.extend_from_slice(o);
        }
        cbor_uint(&mut body, 2);
        cbor_uint(&mut body, self.fee);
        cbor_uint(&mut body, 3);
        cbor_uint(&mut body, self.ttl);

        let size = (body.len() + ENVELOPE_OVERHEAD) as u64;
        if self.fee < self.min_fee_a * size + self.min_fee_b {
            return Err(invalid("fee is below the protocol minimum"));
        }
        Ok(body)
    }

    /// blake2b-256 of the body: the signed message and the explorer hash.
    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(Blake2b::<U32>::digest(self.body()?).into())
    }

    /// Signs with the payment key's extended secret `kL || kR` and returns the
    /// signed transaction as `0x` CBOR hex plus the tx id.
    pub fn sign(&self, xsk: &[u8; 64]) -> Result<(String, String)> {
        let public = public_of(xsk)?;
        if key_hash(&public) != decode_address(&self.from)?.payment {
            return Err(invalid("sender differs from signing key"));
        }
        let signature = sign_extended(xsk, &self.txid()?)?;
        self.assemble(&public, &signature)
    }

    /// The signed transaction for a signature made elsewhere (a threshold
    /// ceremony), accepted only if `public` is the sender's payment key and the
    /// signature verifies over the tx id.
    pub fn assemble(&self, public: &[u8; 32], signature: &[u8; 64]) -> Result<(String, String)> {
        if key_hash(public) != decode_address(&self.from)?.payment {
            return Err(invalid("public key is not the sender's payment key"));
        }
        let body = self.body()?;
        let id: [u8; 32] = Blake2b::<U32>::digest(&body).into();
        let key = ed25519_dalek::VerifyingKey::from_bytes(public)
            .map_err(|_| invalid("payment key is not an Ed25519 point"))?;
        key.verify_strict(&id, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the payment key"))?;
        let mut wire = Vec::with_capacity(body.len() + ENVELOPE_OVERHEAD);
        cbor_array(&mut wire, 4);
        wire.extend_from_slice(&body);
        cbor_map(&mut wire, 1);
        cbor_uint(&mut wire, 0);
        cbor_set(&mut wire, 1);
        cbor_array(&mut wire, 2);
        cbor_bytes(&mut wire, public);
        cbor_bytes(&mut wire, signature);
        wire.push(0xf5);
        wire.push(0xf6);
        debug_assert_eq!(wire.len(), body.len() + ENVELOPE_OVERHEAD);
        Ok((format!("0x{}", hex::encode(wire)), hex::encode(id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    // Vectors below come from @emurgo/cardano-serialization-lib-nodejs 17
    // (`.nur/cardano-scratch/vectors.mjs`).
    const ROOT: &str = "60ce7dbec3616e9fc17e0c32578b3f380337b1b61a1f3cb9651aee30670e6f53970419a23a2e4e4082d12bf78faa8645dfc882cee2ae7179e2b07fe88098abb2072310084784c7308182dbbdb1449b2706586f1ff5cbf13d15e9b6e78c15f067";
    const ACCOUNT: &str = "c026fb6c43215bf0b2e2132ad4852d6e2b47bb09eae796ea9571f9e06f0e6f53817147a33facaf204927be405e3dbcd2e31abe734b354d5e1bc7317d3ada5b68b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16";
    const ACCOUNT_PUB: &str = "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0";
    const PAYMENT_XPRV: &str = "105d2ef2192150655a926bca9cccf5e2f6e496efa9580508192e1f4a790e6f53de06529129511d1cacb0664bcf04853fdc0055a47cc6d2c6d20512702076065288848e8af62a27a57e982215741c9eac17e6e45cbfd6ea65a0e0dcc03bb777b2";
    const PAYMENT_PUB: &str = "7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a";
    const STAKE_PUB: &str = "012f5dc3115b8a07981e6e50f5a671e2c6fbb26c3ffde1cd1dcaf40a7fe8f160";
    const BASE_TESTNET: &str = "addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn";
    const BASE_MAINNET: &str = "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv";
    const BASE_ACCOUNT1: &str = "addr_test1qpkjqjg3yfql7uspafzanp0xq4fvuqzgyewhqhcqnk94w4gk9jlajcx98yc9g8rxgw0zrdsprlkkjl4l2s9ls6hvxlsq3n089y";
    const ENTERPRISE_TESTNET: &str =
        "addr_test1vq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7ss9hjl0y";
    const SIG_ABC: &str = "e92e8980aa313dbda6a193c96e99f81b6ae5693353787be2aa1f06be9620a2db3edbbbc7bf3820f6225f4e71b3c9b2847ce93b1693b7e00891ab7d12ab908f07";
    /// CIP-19 test vectors (base address type 0 from its payment and stake keys).
    const CIP19_BASE: &str = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae";
    const CIP19_ENTERPRISE: &str =
        "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz";
    const CIP19_PAYMENT_VK: &str =
        "addr_vk1w0l2sr2zgfm26ztc6nl9xy8ghsk5sh6ldwemlpmp9xylzy4dtf7st80zhd";
    const CIP19_STAKE_VK: &str =
        "stake_vk1px4j0r2fk7ux5p23shz8f3y5y2qam7s954rgf3lg5merqcj6aetsft99wu";

    fn keys() -> AccountKeys {
        account_keys(&Mnemonic::parse(ABANDON).unwrap(), "", 0).unwrap()
    }

    fn xprv96(k: &ExtendedKey) -> String {
        format!("{}{}", hex::encode(k.secret()), hex::encode(k.chain_code()))
    }

    fn bech_bytes(s: &str) -> Vec<u8> {
        CheckedHrpstring::new::<Bech32>(s)
            .unwrap()
            .byte_iter()
            .collect()
    }

    #[test]
    fn icarus_keys_match_the_sdk() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let root = ExtendedKey::from_mnemonic(&m, "").unwrap();
        assert_eq!(xprv96(&root), ROOT);
        let acct = root.derive_path(&[PURPOSE, COIN_TYPE, HARDENED]).unwrap();
        assert_eq!(xprv96(&acct), ACCOUNT);
        assert_eq!(hex::encode(acct.public()), ACCOUNT_PUB);
        let k = keys();
        assert_eq!(xprv96(&k.payment), PAYMENT_XPRV);
        assert_eq!(hex::encode(k.payment.public()), PAYMENT_PUB);
        assert_eq!(hex::encode(k.stake.public()), STAKE_PUB);
        assert_eq!(address(&k.public()).unwrap(), BASE_TESTNET);
        assert_eq!(address_on(MAINNET_ID, &k.public()).unwrap(), BASE_MAINNET);
        assert_eq!(address(k.payment.public()).unwrap(), ENTERPRISE_TESTNET);
        let k1 = account_keys(&m, "", 1).unwrap();
        assert_eq!(address(&k1.public()).unwrap(), BASE_ACCOUNT1);
        assert!(account_keys(&m, "", HARDENED).is_err());
        assert!(address(&[0u8; 33]).is_err());
        assert!(address_on(2, &k.public()).is_err());
    }

    #[test]
    fn cip19_address_vectors() {
        let pay = bech_bytes(CIP19_PAYMENT_VK);
        let stake = bech_bytes(CIP19_STAKE_VK);
        assert_eq!(address(&pay).unwrap(), CIP19_ENTERPRISE);
        assert_eq!(address(&[pay, stake].concat()).unwrap(), CIP19_BASE);
        let d = decode_address(CIP19_BASE).unwrap();
        assert_eq!(d.kind, BASE_KEY_KEY);
        assert_eq!(d.payment, decode_address(CIP19_ENTERPRISE).unwrap().payment);
    }

    #[test]
    fn extended_signature_matches_the_sdk() {
        let k = keys();
        let sig = sign_extended(k.payment.secret(), b"abc").unwrap();
        assert_eq!(hex::encode(sig), SIG_ABC);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(k.payment.public()).unwrap();
        vk.verify_strict(b"abc", &ed25519_dalek::Signature::from_bytes(&sig))
            .unwrap();
    }

    #[test]
    fn bad_addresses_are_refused() {
        assert!(decode_address(BASE_MAINNET).is_err());
        assert!(decode_address(&BASE_TESTNET.to_uppercase()).is_err());
        let mut flipped = BASE_TESTNET.to_string();
        flipped.pop();
        flipped.push('q');
        assert!(decode_address(&flipped).is_err());
        // Script payment (type 7) and Byron-era addresses.
        let script = encode_raw(0, &[[0x70].as_slice(), &[1u8; 28]].concat());
        assert!(decode_address(&script).is_err());
        assert!(
            decode_address("Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi").is_err()
        );
        // Mainnet network nibble under the testnet prefix.
        let wrong_net = encode_raw(0, &[[0x61].as_slice(), &[1u8; 28]].concat());
        assert!(decode_address(&wrong_net).is_err());
        assert!(
            decode_address("stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn")
                .is_err()
        );
    }

    fn tx(lovelace: &str, fee: u64) -> CardanoTx {
        CardanoTx {
            chain_id: PREPROD.into(),
            from: BASE_TESTNET.into(),
            to: CIP19_BASE.into(),
            lovelace: lovelace.into(),
            inputs: vec![
                CardanoInput {
                    tx_hash: "11".repeat(32),
                    index: 0,
                    lovelace: "4000000".into(),
                },
                CardanoInput {
                    tx_hash: "22".repeat(32),
                    index: 3,
                    lovelace: "6000000".into(),
                },
            ],
            fee,
            ttl: 90_000_000,
            built_slot: 89_992_800,
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4310,
        }
    }

    fn intent(tx: &CardanoTx) -> TxIntent {
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
                amount: Amount(tx.lovelace.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    const CHANGE_BODY: &str = "a400d90102828258201111111111111111111111111111111111111111111111111111111111111111008258202222222222222222222222222222222222222222222222222222222222222222030182825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c472511a0016e360825839000fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a007f1b1b021a00029805031a055d4a80";
    const CHANGE_TXID: &str = "c4a617268d07fefc80257fb80fd66987415de9c0564934371131f1a2c2c6f5f2";
    const CHANGE_TX: &str = "84a400d90102828258201111111111111111111111111111111111111111111111111111111111111111008258202222222222222222222222222222222222222222222222222222222222222222030182825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c472511a0016e360825839000fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a007f1b1b021a00029805031a055d4a80a100d90102818258207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a5840b2ab840c40143a9463fd7544d804a3d8599cd3dca5a9f2aa3284e5c7d434bd86eb308d2967b24d712e875044831c69382b6b6b278d4a7a14929421faa0d62808f5f6";
    const MAX_BODY: &str = "a400d90102828258201111111111111111111111111111111111111111111111111111111111111111008258202222222222222222222222222222222222222222222222222222222222222222030181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c472511a009609a7021a00028cd9031a055d4a80";
    const MAX_TXID: &str = "4e7df7d6232382556e7f086ed43f7723ce56a3cabca81d30241f8342f8e1fa29";
    const MAX_TX: &str = "84a400d90102828258201111111111111111111111111111111111111111111111111111111111111111008258202222222222222222222222222222222222222222222222222222222222222222030181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c472511a009609a7021a00028cd9031a055d4a80a100d90102818258207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a5840bb8b09a23a33b6430993cef0f04bd8f12fc555b0fb788901274c547454f1e5a3da27c6d49b98c71671f884d17cf7f7c31ea0c4724e22d3eb22d86131ba722004f5f6";

    #[test]
    fn transactions_match_the_sdk_vectors() {
        let k = keys();
        let t = tx("1500000", 169_989);
        t.check_matches_intent(&intent(&t)).unwrap();
        assert_eq!(t.change().unwrap(), 8_330_011);
        assert_eq!(hex::encode(t.body().unwrap()), CHANGE_BODY);
        assert_eq!(hex::encode(t.txid().unwrap()), CHANGE_TXID);
        let (wire, id) = t.sign(k.payment.secret()).unwrap();
        assert_eq!(wire, format!("0x{CHANGE_TX}"));
        assert_eq!(id, CHANGE_TXID);
        assert_eq!(CHANGE_TX.len() / 2, 332);

        // Send-max: no change output.
        let t = tx("9832871", 167_129);
        assert_eq!(t.change().unwrap(), 0);
        assert_eq!(hex::encode(t.body().unwrap()), MAX_BODY);
        assert_eq!(hex::encode(t.txid().unwrap()), MAX_TXID);
        let (wire, _) = t.sign(k.payment.secret()).unwrap();
        assert_eq!(wire, format!("0x{MAX_TX}"));
    }

    /// Accepted by the preprod ledger in block 5298845.
    #[test]
    fn reproduces_a_confirmed_preprod_transfer() {
        let k = account_keys(&Mnemonic::parse(ABANDON).unwrap(), "", 2).unwrap();
        let from = address(&k.public()).unwrap();
        assert_eq!(from, "addr_test1qzr0r2u6j5m8zjxa33gfxum2x26vzt6qqgrmcdjl4xvzw9768t369lant874tr0ftdx5jtrynfgehxlwepc6zgcml8vs4faw9w");
        let t = CardanoTx {
            chain_id: PREPROD.into(),
            from,
            to: "addr_test1qpxry7y64zl76gemdcpmkgccqqw55nk8c530crcr05rhp47trx7cdnm23ydjnm7sqf9kl08rqurc8x3na5h32ageccxq6kcpw6".into(),
            lovelace: "1200000".into(),
            inputs: vec![CardanoInput {
                tx_hash: "4d7acd627bf97a684edfcd290a015c695cb80139b9e24c22c26c18669e7d4382".into(),
                index: 0,
                lovelace: "67000000".into(),
            }],
            fee: 168_405,
            ttl: 136_475_065,
            built_slot: 136_467_865,
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4310,
        };
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(k.payment.secret()).unwrap();
        assert_eq!(
            id,
            "fb996b5627a9ce0a68b9c6785ec191d06d12372e5f42b69a843a006070248095"
        );
        assert_eq!(wire.len(), 2 + 2 * 296);
    }

    #[test]
    fn assemble_checks_key_and_signature() {
        let k = keys();
        let t = tx("1500000", 169_989);
        let sig = sign_extended(k.payment.secret(), &t.txid().unwrap()).unwrap();
        let (wire, _) = t.assemble(k.payment.public(), &sig).unwrap();
        assert_eq!(wire, format!("0x{CHANGE_TX}"));
        assert!(t.assemble(k.payment.public(), &[0u8; 64]).is_err());
        assert!(t.assemble(k.stake.public(), &sig).is_err());
        assert!(t.sign(k.stake.secret()).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx("1500000", 169_989);
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.body().is_err());
        assert!(check_chain(MAINNET).is_err());
        assert!(check_chain(PREVIEW).is_err());
        for bad in ["01500000", "0", "45000000000000001", "1.5", "-1", ""] {
            let mut t = base.clone();
            t.lovelace = bad.into();
            assert!(t.body().is_err(), "{bad}");
        }
        // Fee below the protocol minimum, above the cap, or unaffordable.
        assert!(tx("1500000", 169_988).body().is_err());
        assert!(tx("1500000", MAX_FEE + 1).body().is_err());
        assert!(tx("9832872", 167_129).body().is_err());
        // Payment output below min-UTxO (969,750 at 4310/byte).
        assert!(tx("969749", 169_989).body().is_err());
        assert!(tx("969750", 169_989).body().is_ok());
        // Change below min-UTxO.
        assert!(tx("9000000", 169_989).body().is_err());
        let mut t = base.clone();
        t.inputs.reverse();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.inputs[1] = t.inputs[0].clone();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.inputs[0].tx_hash = "AA".repeat(32);
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.inputs.clear();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.ttl = t.built_slot;
        assert!(t.body().is_err());
        t.ttl = t.built_slot + MAX_TTL_SLOTS + 1;
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.min_fee_a = 0;
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.coins_per_utxo_byte = 100_001;
        assert!(t.body().is_err());

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = CIP19_ENTERPRISE.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{PREPROD}:token");
        }
        assert!(base.check_matches_intent(&i).is_err());

        let extra = serde_json::json!({
            "chainId": PREPROD, "from": base.from, "to": base.to, "lovelace": "1500000",
            "inputs": [{"txHash": "11".repeat(32), "index": 0, "lovelace": "4000000"}],
            "fee": 169989, "ttl": 90000000, "builtSlot": 89992800, "minFeeA": 44,
            "minFeeB": 155381, "coinsPerUtxoByte": 4310, "metadata": "hi"
        });
        assert!(serde_json::from_value::<CardanoTx>(extra).is_err());
        let round = serde_json::to_value(&base).unwrap();
        assert_eq!(serde_json::from_value::<CardanoTx>(round).unwrap(), base);
    }
}
