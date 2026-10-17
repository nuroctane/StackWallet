//! Radix family: native XRD transfers as Babylon `NotarizedTransactionV1`s.
//!
//! The core encodes the whole intent (header, a fixed withdraw / take /
//! try_deposit_or_abort instruction list, empty blobs, no message) in manifest
//! SBOR from checked fields, so an adapter cannot add instructions, blobs,
//! a tip or a second signer. Hashes follow the node: every hash is
//! blake2b-256 over `b'T'` + discriminator + the concatenated sub-hashes,
//! and the explorer-facing transaction id is the intent hash as bech32m
//! `txid_…`. The intent signature signs the intent hash; the notary
//! signature signs the signed-intent hash.

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 uses the network's logical name; the gateway reports it in every response.
pub const STOKENET: &str = "radix:stokenet";
pub const MAINNET: &str = "radix:mainnet";

const STOKENET_ID: u8 = 2;
const ACCOUNT_HRP: &str = "account_tdx_2_";
const TXID_HRP: &str = "txid_tdx_2_";
/// XRD resource node id on Stokenet (the bech32m is `resource_tdx_2_1tkn…tfd2jc`).
const XRD_NODE_ID: [u8; 30] = [
    0x5d, 0xa6, 0x63, 0x18, 0xc6, 0x31, 0x8c, 0x61, 0xf5, 0xa6, 0x1b, 0x4c, 0x63, 0x18, 0xc6, 0x31,
    0x8c, 0xf7, 0x94, 0xaa, 0x8d, 0x29, 0x5f, 0x14, 0xe6, 0x31, 0x8c, 0x63, 0x18, 0xc6,
];
/// Entity type bytes that a `account_…` address may carry.
const ENTITY_VIRTUAL_ED25519_ACCOUNT: u8 = 0x51;
const ENTITY_VIRTUAL_SECP256K1_ACCOUNT: u8 = 0xd1;
const ENTITY_ACCOUNT_COMPONENT: u8 = 0xc1;
/// Largest epoch range a user transaction may span (protocol bound is 100).
const MAX_EPOCH_RANGE: u64 = 100;
/// Fee locked by the first manifest instruction, in attos (5 XRD). The ledger
/// refunds everything the execution does not burn, so a fixed generous lock is
/// the same fee model the official wallet uses.
const LOCK_FEE_ATTOS: u128 = 5_000_000_000_000_000_000;
/// Radix never issues more than 24bn XRD; attos (10^-18) must stay below this.
const MAX_ATTOS: u128 = 30_000_000_000_000_000_000_000_000_000; // 30bn XRD
const TIP_MAX: u16 = 100;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Radix transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != STOKENET {
        return Err(invalid("only Radix Stokenet transfers are enabled"));
    }
    Ok(())
}

fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(bytes).into()
}

/// The 30-byte node id behind an `account_tdx_2_…` bech32m address.
pub fn address_bytes(address: &str) -> Result<[u8; 30]> {
    if address.len() > 90 {
        return Err(invalid("address too long"));
    }
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|_| invalid("invalid bech32m address"))?;
    if checked.hrp().as_str() != ACCOUNT_HRP {
        return Err(invalid("not a Stokenet account address"));
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    if bytes.len() != 30 {
        return Err(invalid("account address must be 30 bytes"));
    }
    let out: [u8; 30] = bytes.try_into().expect("30 bytes");
    if ![
        ENTITY_VIRTUAL_ED25519_ACCOUNT,
        ENTITY_VIRTUAL_SECP256K1_ACCOUNT,
        ENTITY_ACCOUNT_COMPONENT,
    ]
    .contains(&out[0])
    {
        return Err(invalid("not an account entity"));
    }
    if bech32::encode::<Bech32m>(checked.hrp(), &out).map_err(|_| invalid("invalid address"))?
        != address
    {
        return Err(invalid("address is not canonical"));
    }
    Ok(out)
}

/// The Stokenet `account_tdx_2_…` address of a 32-byte Ed25519 public key:
/// entity byte 0x51 followed by bytes 3..32 of its blake2b-256.
pub fn address(public: &[u8]) -> Result<String> {
    if public.len() != 32 {
        return Err(invalid("Ed25519 public key must be 32 bytes"));
    }
    let hash = blake2b256(public);
    let mut node = [0u8; 30];
    node[0] = ENTITY_VIRTUAL_ED25519_ACCOUNT;
    node[1..].copy_from_slice(&hash[3..]);
    let hrp = Hrp::parse(ACCOUNT_HRP).map_err(|_| invalid("bad hrp"))?;
    bech32::encode::<Bech32m>(hrp, &node).map_err(|_| invalid("address encoding failed"))
}

/// The bech32m transaction id (`txid_tdx_2_…`) of a 32-byte intent hash.
pub fn txid_string(intent_hash: &[u8; 32]) -> Result<String> {
    let hrp = Hrp::parse(TXID_HRP).map_err(|_| invalid("bad hrp"))?;
    bech32::encode::<Bech32m>(hrp, intent_hash).map_err(|_| invalid("txid encoding failed"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RadixTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal attos (1 XRD = 10^18 attos); never a JSON floating-point number.
    pub attos: String,
    pub start_epoch_inclusive: u64,
    pub end_epoch_exclusive: u64,
    pub nonce: u32,
    /// u16 percentage; the wallet never sets one.
    pub tip_percentage: u16,
}

// --- manifest SBOR fragments -------------------------------------------------

const KIND_U8: u8 = 0x07;
const KIND_U16: u8 = 0x08;
const KIND_U32: u8 = 0x09;
const KIND_U64: u8 = 0x0a;
const KIND_STRING: u8 = 0x0c;
const KIND_ARRAY: u8 = 0x20;
const KIND_TUPLE: u8 = 0x21;
const KIND_ENUM: u8 = 0x22;
const KIND_ADDRESS: u8 = 0x80;
const KIND_BUCKET: u8 = 0x81;
const KIND_DECIMAL: u8 = 0x85;

fn push_size(out: &mut Vec<u8>, mut size: usize) {
    loop {
        let seven = (size & 0x7f) as u8;
        size >>= 7;
        if size == 0 {
            out.push(seven);
            return;
        }
        out.push(seven | 0x80);
    }
}

fn sbor_u8(out: &mut Vec<u8>, v: u8) {
    out.extend_from_slice(&[KIND_U8, v]);
}
fn sbor_u16(out: &mut Vec<u8>, v: u16) {
    out.push(KIND_U16);
    out.extend_from_slice(&v.to_le_bytes());
}
fn sbor_u32(out: &mut Vec<u8>, v: u32) {
    out.push(KIND_U32);
    out.extend_from_slice(&v.to_le_bytes());
}
fn sbor_u64(out: &mut Vec<u8>, v: u64) {
    out.push(KIND_U64);
    out.extend_from_slice(&v.to_le_bytes());
}
fn sbor_bool(out: &mut Vec<u8>, v: bool) {
    out.extend_from_slice(&[0x01, v as u8]);
}
fn sbor_string(out: &mut Vec<u8>, s: &str) {
    out.push(KIND_STRING);
    push_size(out, s.len());
    out.extend_from_slice(s.as_bytes());
}
fn sbor_tuple(out: &mut Vec<u8>, fields: &[&[u8]]) {
    out.push(KIND_TUPLE);
    push_size(out, fields.len());
    for f in fields {
        out.extend_from_slice(f);
    }
}
fn sbor_enum(out: &mut Vec<u8>, disc: u8, fields: &[&[u8]]) {
    out.push(KIND_ENUM);
    sbor_enum_body(out, disc, fields);
}
/// The body of an enum value; array elements omit the value-kind byte.
fn sbor_enum_body(out: &mut Vec<u8>, disc: u8, fields: &[&[u8]]) {
    out.push(disc);
    push_size(out, fields.len());
    for f in fields {
        out.extend_from_slice(f);
    }
}
/// `PublicKey::Ed25519`: enum 1 with the 32-byte key as a `u8` array.
fn sbor_ed25519_public_key(public: &[u8; 32]) -> Vec<u8> {
    let mut key = vec![KIND_ARRAY, KIND_U8];
    push_size(&mut key, 32);
    key.extend_from_slice(public);
    let mut out = Vec::new();
    sbor_enum(&mut out, 1, &[&key]);
    out
}
/// `Ed25519Signature`: a single-field tuple wrapping the 64-byte `u8` array.
fn sbor_ed25519_signature(signature: &[u8; 64]) -> Vec<u8> {
    let mut array = vec![KIND_ARRAY, KIND_U8];
    push_size(&mut array, 64);
    array.extend_from_slice(signature);
    let mut out = Vec::new();
    sbor_tuple(&mut out, &[&array]);
    out
}
/// `ManifestAddress::Static`: kind 0x80, discriminator 0, then the 30-byte node id.
fn sbor_static_address(node: &[u8; 30]) -> Vec<u8> {
    let mut out = vec![KIND_ADDRESS, 0x00];
    out.extend_from_slice(node);
    out
}
/// `ManifestDecimal`: kind 0x85, then the 24-byte little-endian scaled integer.
fn sbor_decimal(attos: u128) -> Vec<u8> {
    let mut out = vec![KIND_DECIMAL];
    out.extend_from_slice(&attos.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]);
    out
}

impl RadixTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native XRD transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.attos {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Radix intent")),
        }
        self.checked_fields()?;
        Ok(())
    }

    /// Checked fields shared by every encoding step; nothing is signed unvalidated.
    fn checked_fields(&self) -> Result<([u8; 30], [u8; 30], u128)> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        if from[0] != ENTITY_VIRTUAL_ED25519_ACCOUNT {
            return Err(invalid("sender must be a virtual Ed25519 account"));
        }
        let amount = self
            .attos
            .parse::<u128>()
            .map_err(|_| invalid("amount is not an integer"))?;
        if amount == 0 || amount > MAX_ATTOS || amount.to_string() != self.attos {
            return Err(invalid(
                "amount must be a positive canonical integer in range",
            ));
        }
        if self.start_epoch_inclusive == 0
            || self.end_epoch_exclusive <= self.start_epoch_inclusive
            || self.end_epoch_exclusive - self.start_epoch_inclusive > MAX_EPOCH_RANGE
        {
            return Err(invalid("invalid epoch range"));
        }
        if self.tip_percentage > TIP_MAX {
            return Err(invalid("tip above 100 percent"));
        }
        Ok((from, to, amount))
    }

    fn header(&self, public: &[u8; 32]) -> Result<Vec<u8>> {
        self.checked_fields()?;
        let mut out = Vec::new();
        let mut network = Vec::new();
        sbor_u8(&mut network, STOKENET_ID);
        let mut start = Vec::new();
        sbor_u64(&mut start, self.start_epoch_inclusive);
        let mut end = Vec::new();
        sbor_u64(&mut end, self.end_epoch_exclusive);
        let mut nonce = Vec::new();
        sbor_u32(&mut nonce, self.nonce);
        let notary = sbor_ed25519_public_key(public);
        let mut signatory = Vec::new();
        sbor_bool(&mut signatory, true);
        let mut tip = Vec::new();
        sbor_u16(&mut tip, self.tip_percentage);
        sbor_tuple(
            &mut out,
            &[&network, &start, &end, &nonce, &notary, &signatory, &tip],
        );
        Ok(out)
    }

    fn instructions(&self) -> Result<Vec<u8>> {
        let (from, to, amount) = self.checked_fields()?;
        let xrd = sbor_static_address(&XRD_NODE_ID);
        let decimal = sbor_decimal(amount);
        // CALL_METHOD <from> "lock_fee" (Decimal(5)): the network refunds the
        // unspent remainder; without this instruction the transfer cannot pay
        // its fee and is rejected.
        let mut lock_fee_args = Vec::new();
        sbor_tuple(&mut lock_fee_args, &[&sbor_decimal(LOCK_FEE_ATTOS)]);
        let mut lock_fee_name = Vec::new();
        sbor_string(&mut lock_fee_name, "lock_fee");
        let mut lock_fee = Vec::new();
        sbor_enum_body(
            &mut lock_fee,
            0x41,
            &[&sbor_static_address(&from), &lock_fee_name, &lock_fee_args],
        );
        // CALL_METHOD <from> "withdraw" (Address(XRD), Decimal(amount))
        let mut withdraw_args = Vec::new();
        sbor_tuple(&mut withdraw_args, &[&xrd, &decimal]);
        let mut withdraw = Vec::new();
        sbor_string(&mut withdraw, "withdraw");
        let mut call_withdraw = Vec::new();
        sbor_enum_body(
            &mut call_withdraw,
            0x41,
            &[&sbor_static_address(&from), &withdraw, &withdraw_args],
        );
        // TAKE_FROM_WORKTOP Address(XRD) Decimal(amount)
        let mut take = Vec::new();
        sbor_enum_body(&mut take, 0x00, &[&xrd, &decimal]);
        // CALL_METHOD <to> "try_deposit_or_abort" (Bucket(0), None)
        let mut bucket = vec![KIND_BUCKET];
        bucket.extend_from_slice(&0u32.to_le_bytes());
        let mut none = Vec::new();
        sbor_enum(&mut none, 0, &[]);
        let mut deposit_args = Vec::new();
        sbor_tuple(&mut deposit_args, &[&bucket, &none]);
        let mut deposit = Vec::new();
        sbor_string(&mut deposit, "try_deposit_or_abort");
        let mut call_deposit = Vec::new();
        sbor_enum_body(
            &mut call_deposit,
            0x41,
            &[&sbor_static_address(&to), &deposit, &deposit_args],
        );
        let mut out = vec![KIND_ARRAY, KIND_ENUM];
        push_size(&mut out, 4);
        out.extend_from_slice(&lock_fee);
        out.extend_from_slice(&call_withdraw);
        out.extend_from_slice(&take);
        out.extend_from_slice(&call_deposit);
        Ok(out)
    }

    /// blake2b-256 of `b'T'` + 0x01 + the four field hashes; what the intent
    /// signature signs and what explorers show as the transaction id.
    pub fn intent_hash(&self, public: &[u8; 32]) -> Result<[u8; 32]> {
        let header = self.header(public)?;
        let instructions = self.instructions()?;
        let blobs_hash = blake2b256(&[]);
        let message_hash = blake2b256(&[KIND_ENUM, 0x00, 0x00]);
        let mut preimage = vec![b'T', 0x01];
        preimage.extend_from_slice(&blake2b256(&header));
        preimage.extend_from_slice(&blake2b256(&instructions));
        preimage.extend_from_slice(&blobs_hash);
        preimage.extend_from_slice(&message_hash);
        Ok(blake2b256(&preimage))
    }

    /// The `20 22 01 …` intent-signatures array holding one Ed25519 signature.
    fn intent_signatures(public: &[u8; 32], signature: &[u8; 64]) -> Vec<u8> {
        let mut key = vec![KIND_ARRAY, KIND_U8];
        push_size(&mut key, 32);
        key.extend_from_slice(public);
        let sig = sbor_ed25519_signature(signature);
        let mut element = Vec::new();
        // SignatureWithPublicKeyV1::Ed25519 { public_key, signature }
        sbor_enum_body(&mut element, 1, &[&key, &sig]);
        let mut out = vec![KIND_ARRAY, KIND_ENUM];
        push_size(&mut out, 1);
        out.extend_from_slice(&element);
        out
    }

    /// Returns the compiled `NotarizedTransactionV1` hex (for `/transaction/submit`)
    /// and the bech32m `txid_tdx_2_…` transaction id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let intent_hash = self.intent_hash(&public)?;
        let intent_sig: [u8; 64] = key.sign(&intent_hash).to_bytes();
        let sigs = Self::intent_signatures(&public, &intent_sig);
        let mut preimage = vec![b'T', 0x02];
        preimage.extend_from_slice(&intent_hash);
        preimage.extend_from_slice(&blake2b256(&sigs));
        let signed_hash = blake2b256(&preimage);
        let notary_sig: [u8; 64] = key.sign(&signed_hash).to_bytes();
        // Versioned notarized payload: enum 3 with the signed-intent tuple and
        // the notary signature enum.
        let mut intent = Vec::new();
        sbor_tuple(
            &mut intent,
            &[
                &self.header(&public)?,
                &self.instructions()?,
                &[KIND_ARRAY, KIND_ARRAY, 0x00],
                &[KIND_ENUM, 0x00, 0x00],
            ],
        );
        let mut signed_intent = Vec::new();
        sbor_tuple(&mut signed_intent, &[&intent, &sigs]);
        let mut notary = Vec::new();
        let sig = sbor_ed25519_signature(&notary_sig);
        sbor_enum(&mut notary, 1, &[&sig]);
        let mut wire = vec![0x4d, KIND_ENUM, 0x03];
        push_size(&mut wire, 2);
        wire.extend_from_slice(&signed_intent);
        wire.extend_from_slice(&notary);
        Ok((hex::encode(wire), txid_string(&intent_hash)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// Radix Engine Toolkit 1.0.6 `deriveVirtualAccountAddressFromPublicKey`.
    const FROM: &str = "account_tdx_2_12ynqzf78g3mtyufkch3ccqpmv6ugnawgqqe0hq0tc06y73dr0sf2qk";
    /// RET: virtual account of the secp256k1 key [8;32].
    const TO: &str = "account_tdx_2_169qlmuyvq8vcfdtlgmjllvy4ehs2tky7y8ckkmkhpq776j8vec5c2a";

    fn tx() -> RadixTx {
        RadixTx {
            chain_id: STOKENET.into(),
            from: FROM.into(),
            to: TO.into(),
            attos: "1500000000000000000".into(),
            start_epoch_inclusive: 100,
            end_epoch_exclusive: 110,
            nonce: 123456789,
            tip_percentage: 0,
        }
    }

    fn intent(tx: &RadixTx) -> TxIntent {
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
                amount: Amount(tx.attos.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_the_ret_vector() {
        let key = SigningKey::from_bytes(&SECRET);
        let addr = address(&key.verifying_key().to_bytes()).unwrap();
        assert_eq!(addr, FROM);
        assert_eq!(
            bech32::encode::<Bech32m>(
                Hrp::parse(ACCOUNT_HRP).unwrap(),
                &address_bytes(&addr).unwrap()
            )
            .unwrap(),
            addr
        );
    }

    #[test]
    fn sign_matches_the_ret_compiled_transaction() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, COMPILED);
        assert_eq!(
            id,
            "txid_tdx_2_15atq5dgdw6f8g9r23p6pm59kfsmzqu6tq5g23jnjyyqwvgegnglq3380l4"
        );
        assert_eq!(
            hex::encode(
                t.intent_hash(&SigningKey::from_bytes(&SECRET).verifying_key().to_bytes())
                    .unwrap()
            ),
            "a7560a350d769274146a88741dd0b64c3620734b0510a8ca722100e623289a3e"
        );
    }

    /// Byte-for-byte the transaction RET 1.0.6 compiles for these fields
    /// (`.nur/radix-sdk/oracle-vector2.txt`).
    const COMPILED: &str = "4d22030221022104210707020a64000000000000000a6e000000000000000915cd5b07220101200720ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c01010800002022044103800051260127c74476b27136c5e38c003b66b889f5c80032fb81ebc3f44f45a30c086c6f636b5f6665652101850000f44482916345000000000000000000000000000000004103800051260127c74476b27136c5e38c003b66b889f5c80032fb81ebc3f44f45a30c087769746864726177210280005da66318c6318c61f5a61b4c6318c6318cf794aa8d295f14e6318c6318c6850000167b0d12d11400000000000000000000000000000000000280005da66318c6318c61f5a61b4c6318c6318cf794aa8d295f14e6318c6318c6850000167b0d12d1140000000000000000000000000000000041038000d141fdf08c01d984b57f46e5ffb095cde0a5d89e21f16b6ed7083ded48ec0c147472795f6465706f7369745f6f725f61626f7274210281000000002200002020002200002022010102200720ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c2101200740422cd583dd91743c1ba895f35c6d7760e76658ddaabc1d881bd26180d9c481f5dfa376a6f4f9b5291db847ce50a89157196fd59ec636b7e1986677626a68ac082201012101200740d592ac09da6e63bcf203d7c77b22f1eb875cfecdcf84ad4732ae4f121899397012b513eb5a8a8c87df8578136a51a2f29da45e4d66cfc5edceb4180225a9e703";

    #[test]
    fn signatures_verify_against_intent_and_signed_intent_hashes() {
        let t = tx();
        let key = SigningKey::from_bytes(&SECRET);
        let public = key.verifying_key();
        let intent_hash = t.intent_hash(&public.to_bytes()).unwrap();
        let sigs =
            RadixTx::intent_signatures(&public.to_bytes(), &key.sign(&intent_hash).to_bytes());
        let mut preimage = vec![b'T', 0x02];
        preimage.extend_from_slice(&intent_hash);
        preimage.extend_from_slice(&blake2b256(&sigs));
        let signed_hash = blake2b256(&preimage);
        let (wire, _) = t.sign(&SECRET).unwrap();
        let bytes = hex::decode(&wire).unwrap();
        let intent_sig = ed25519_dalek::Signature::from_slice(&sigs[sigs.len() - 64..]).unwrap();
        public.verify_strict(&intent_hash, &intent_sig).unwrap();
        let notary_sig = ed25519_dalek::Signature::from_slice(&bytes[bytes.len() - 64..]).unwrap();
        public.verify_strict(&signed_hash, &notary_sig).unwrap();
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.attos = "0".into();
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.attos = "015".into();
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.attos = format!("{}", MAX_ATTOS + 1);
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.end_epoch_exclusive = t.start_epoch_inclusive + MAX_EPOCH_RANGE + 1;
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.start_epoch_inclusive = 0;
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.tip_percentage = 101;
        assert!(t.sign(&SECRET).is_err());
        // The sender must be the virtual Ed25519 account of the signing key.
        let mut t = base.clone();
        t.from = TO.into();
        t.to = FROM.into();
        assert!(t.sign(&SECRET).is_err());
        assert!(address_bytes(
            "account_rdx12ynqzf78g3mtyufkch3ccqpmv6ugnawgqqe0hq0tc06y73drulycnv"
        )
        .is_err());
        assert!(address_bytes(&FROM[..FROM.len() - 1].replace('k', "l")).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000000000000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let extra = serde_json::json!({
            "chainId": STOKENET, "from": FROM, "to": TO, "attos": "1",
            "startEpochInclusive": 100, "endEpochExclusive": 110, "nonce": 1,
            "tipPercentage": 0, "blobs": ["00"]
        });
        assert!(serde_json::from_value::<RadixTx>(extra).is_err());
    }
}
