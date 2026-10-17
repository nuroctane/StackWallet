//! Native KTA transfers on Keeta. The core encodes the whole v1 block as
//! ASN.1 DER from checked fields: one SEND operation of the network base
//! token, signed as plain secp256k1 ECDSA (low-s, r||s) over
//! sha3-256(sha3-256(unsigned block)).
//!
//! Pinned against `@keetanetwork/keetanet-client` 0.18.8 (pure-TS oracle;
//! see `.nur/wiring/keeta.md` for the probe evidence).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// Keeta has no registered CAIP-2 namespace; `keeta:<alias>` uses the SDK
/// network alias. Only the test network is enabled for signing.
pub const KEETA_TEST: &str = "keeta:test";
const NETWORK_TEST: u64 = 0x5445_5354; // "TEST"

/// The test network's base token (KTA), derived from the network id by the
/// SDK's `Account.generateBaseAddresses` and confirmed live. publicKeyAndType
/// is `0x03 || 32-byte identifier` and the address is its base32 form.
pub const TEST_BASE_TOKEN: &str =
    "keeta_anyiff4v34alvumupagmdyosydeq24lc4def5mrpmmyhx3j6vj2uucckeqn52";

const MAX_TIMESTAMP: u64 = 0xFFFF_FFFF; // GeneralizedTime stays 4-digit years

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Keeta transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != KEETA_TEST {
        return Err(invalid("only Keeta test-network transfers are enabled"));
    }
    Ok(())
}

fn sha3(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

fn base32_lower(data: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(data).to_lowercase()
}

fn base32_decode(text: &str) -> Result<Vec<u8>> {
    data_encoding::BASE32_NOPAD
        .decode(text.to_uppercase().as_bytes())
        .map_err(|_| invalid("address is not canonical base32"))
}

/// Decoded `keeta_` account address: `0x00 || compressed SEC1 (33) || checksum(5)`.
pub fn address_bytes(address: &str) -> Result<[u8; 34]> {
    let body = address
        .strip_prefix("keeta_")
        .ok_or_else(|| invalid("address must start with keeta_"))?;
    if body.len() != 63 || body.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(
            "account address must be 63 lowercase base32 characters",
        ));
    }
    let decoded = base32_decode(body)?;
    if decoded.len() != 39 || decoded[0] != 0x00 {
        return Err(invalid("not a Keeta secp256k1 account address"));
    }
    let (payload, check) = decoded.split_at(34);
    if sha3(payload)[..5] != *check {
        return Err(invalid("address checksum mismatch"));
    }
    let key = &payload[1..];
    if k256::ecdsa::VerifyingKey::from_sec1_bytes(key).is_err() {
        return Err(invalid("address carries an invalid secp256k1 public key"));
    }
    Ok(payload.try_into().expect("34 bytes"))
}

/// Decoded `keeta_` identifier (token) address: `type || 32-byte id || checksum(5)`.
fn identifier_bytes(address: &str) -> Result<[u8; 33]> {
    let body = address
        .strip_prefix("keeta_")
        .ok_or_else(|| invalid("token must start with keeta_"))?;
    if body.len() != 61 || body.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(
            "token address must be 61 lowercase base32 characters",
        ));
    }
    let decoded = base32_decode(body)?;
    if decoded.len() != 38 || decoded[0] != 0x03 {
        return Err(invalid("not a Keeta token identifier address"));
    }
    let (payload, check) = decoded.split_at(33);
    if sha3(payload)[..5] != *check {
        return Err(invalid("token checksum mismatch"));
    }
    Ok(payload.try_into().expect("33 bytes"))
}

fn encode_address(payload: &[u8]) -> String {
    let mut full = payload.to_vec();
    full.extend_from_slice(&sha3(payload)[..5]);
    format!("keeta_{}", base32_lower(&full))
}

/// The account address of a 33-byte compressed secp256k1 public key.
pub fn address(public: &[u8]) -> Result<String> {
    if public.len() != 33 || k256::ecdsa::VerifyingKey::from_sec1_bytes(public).is_err() {
        return Err(invalid("public key must be 33-byte compressed SEC1"));
    }
    let mut payload = Vec::with_capacity(34);
    payload.push(0x00);
    payload.extend_from_slice(public);
    Ok(encode_address(&payload))
}

fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be {N} lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

// --- Minimal DER writer for the v1 block subset ---------------------------

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Positive INTEGER from big-endian magnitude bytes, minimally encoded.
fn der_int(magnitude: &[u8]) -> Vec<u8> {
    let mut m: &[u8] = magnitude;
    while m.len() > 1 && m[0] == 0 {
        m = &m[1..];
    }
    if m[0] & 0x80 != 0 {
        let mut padded = vec![0u8];
        padded.extend_from_slice(m);
        der_tlv(0x02, &padded)
    } else {
        der_tlv(0x02, m)
    }
}

fn der_octet(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// UTC GeneralizedTime `YYYYMMDDhhmmssZ` from unix seconds (civil_from_days).
fn der_gentime(secs: u64) -> Vec<u8> {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let text = format!(
        "{year:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    );
    der_tlv(0x18, text.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeetaTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal 10^-18 KTA base units; never a JSON floating-point number.
    pub atto_kta: String,
    /// Head block hash of the sender account, lowercase hex.
    pub previous: String,
    /// Unix seconds; the network records this as the block date.
    pub timestamp: u64,
}

impl KeetaTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native KTA transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.atto_kta {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Keeta intent")),
        }
        self.unsigned_block()?;
        Ok(())
    }

    fn network(&self) -> Result<u64> {
        check_chain(&self.chain_id)?;
        Ok(NETWORK_TEST)
    }

    fn amount(&self) -> Result<u128> {
        let amount = self
            .atto_kta
            .parse::<u128>()
            .map_err(|_| invalid("amount exceeds u128 base units"))?;
        if amount == 0 || amount.to_string() != self.atto_kta {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        Ok(amount)
    }

    /// The DER-encoded unsigned v1 block; its sha3-256 is the block hash.
    pub fn unsigned_block(&self) -> Result<Vec<u8>> {
        let network = self.network()?;
        let amount = self.amount()?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let token = identifier_bytes(TEST_BASE_TOKEN)?;
        if self.previous == "0".repeat(64) {
            return Err(invalid("zero previous block hash"));
        }
        let previous = fixed_hex::<32>(&self.previous, "previous block hash")?;
        if previous == [0; 32] {
            return Err(invalid("zero previous block hash"));
        }
        if self.timestamp == 0 || self.timestamp > MAX_TIMESTAMP {
            return Err(invalid("timestamp out of range"));
        }
        let send = der_tlv(
            0xa0,
            &der_tlv(
                0x30,
                &[
                    der_octet(&to),
                    der_int(&amount.to_be_bytes()),
                    der_octet(&token),
                ]
                .concat(),
            ),
        );
        let operations = der_tlv(0x30, &send);
        let block = [
            der_int(&[0]),
            der_int(&network.to_be_bytes()),
            der_null(),
            der_gentime(self.timestamp),
            der_octet(&from),
            der_null(),
            der_octet(&previous),
            operations,
        ]
        .concat();
        Ok(der_tlv(0x30, &block))
    }

    pub fn block_hash(&self) -> Result<[u8; 32]> {
        Ok(sha3(&self.unsigned_block()?))
    }

    /// Returns the signed block as base64 (for the publish-aid endpoint) and
    /// the block hash in the uppercase hex form the explorer shows.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let unsigned = self.unsigned_block()?;
        let hash = sha3(&unsigned);
        // Accounts sign sha3-256(blockHash); the signature is canonical r||s.
        let sighash = sha3(&hash);
        let (_parity, r, s) = evm::sign_digest(secret, &sighash)?;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        let signed = append_signature(&unsigned, &signature)?;
        Ok((
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signed),
            hex::encode(hash).to_uppercase(),
        ))
    }
}

/// Re-encode the unsigned block with the signature field appended inside the
/// outer SEQUENCE, instead of trusting string surgery on the DER.
fn append_signature(unsigned: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>> {
    let (content, _len) = read_tlv(unsigned, 0x30)?;
    let mut body = content.to_vec();
    body.extend_from_slice(&der_octet(signature));
    Ok(der_tlv(0x30, &body))
}

/// Reads one TLV, returning the content slice and total TLV length.
fn read_tlv(bytes: &[u8], tag: u8) -> Result<(&[u8], usize)> {
    if bytes.len() < 2 || bytes[0] != tag {
        return Err(invalid("block encoding is malformed"));
    }
    let (len, header) = match bytes[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81 => {
            if bytes.len() < 3 {
                return Err(invalid("block encoding is malformed"));
            }
            (bytes[2] as usize, 3)
        }
        0x82 => {
            if bytes.len() < 4 {
                return Err(invalid("block encoding is malformed"));
            }
            ((((bytes[2] as usize) << 8) | bytes[3] as usize), 4)
        }
        _ => return Err(invalid("block encoding is malformed")),
    };
    if bytes.len() < header + len {
        return Err(invalid("block encoding is malformed"));
    }
    Ok((&bytes[header..header + len], header + len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];
    const SENDER: &str = "keeta_aabjrhalo3fvmolr7xe354y6ybwdkyhtesow52pf3a6foysvs3qf6326j34n5yq";
    const RECIPIENT: &str = "keeta_aabhtptgp345zo5mkwqgffooq4fqoau37tns3tri3fm7fak3c34bpgftsw4yiua";

    fn tx() -> KeetaTx {
        KeetaTx {
            chain_id: KEETA_TEST.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            atto_kta: "1500000000".into(),
            previous: "11".repeat(32),
            timestamp: 1_760_000_000,
        }
    }

    fn intent(tx: &KeetaTx) -> TxIntent {
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
                amount: Amount(tx.atto_kta.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_sdk_vectors() {
        // Private key 7 and private key 1, derived by keetanet-client 0.18.8.
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        let addr = address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(addr, SENDER);
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = k256::ecdsa::SigningKey::from_bytes((&one).into()).unwrap();
        let addr = address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(addr, RECIPIENT);
        // Address round-trips and the payload is 0x00 || compressed SEC1.
        let payload = address_bytes(&addr).unwrap();
        assert_eq!(payload[0], 0x00);
        assert_eq!(
            &payload[1..],
            key.verifying_key().to_encoded_point(true).as_bytes()
        );
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes(
            "keeta_aabjrhalo3fvmolr7xe354y6ybwdkyhtesow52pf3a6foysvs3qf6326j34n5yx"
        )
        .is_err());
        assert!(address_bytes(&SENDER.to_uppercase()).is_err());
        assert!(address_bytes("TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC").is_err());
        // The base token is an identifier, not an account.
        assert!(address_bytes(TEST_BASE_TOKEN).is_err());
        assert!(identifier_bytes(SENDER).is_err());
        assert_eq!(identifier_bytes(TEST_BASE_TOKEN).unwrap()[0], 0x03);
    }

    #[test]
    fn unsigned_block_matches_the_sdk_vector() {
        // Byte-exact against keetanet-client Block.Builder output.
        assert_eq!(hex::encode(tx().unsigned_block().unwrap()), UNSIGNED_VECTOR);
        assert_eq!(
            hex::encode(tx().block_hash().unwrap()).to_uppercase(),
            "871150734C5D92FE65756B5B5EE9DD1E84A63DA2467D53D479C31243C6397A4E"
        );
    }
    const UNSIGNED_VECTOR: &str = "3081b70201000204544553540500180f32303235313030393038353332305a04220002989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f0500042011111111111111111111111111111111111111111111111111111111111111113051a04f304d0422000279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798020459682f0004210370829795df00bad194780cc1e1d2c0c90d7162e0c85eb22f63307bed3eaa754a";

    #[test]
    fn signature_verifies_against_the_double_sha3_digest() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(
            hash,
            "871150734C5D92FE65756B5B5EE9DD1E84A63DA2467D53D479C31243C6397A4E"
        );
        use base64::Engine;
        let signed = base64::engine::general_purpose::STANDARD
            .decode(wire)
            .unwrap();
        // Signed block is the unsigned block with one 64-byte signature appended
        // (the outer SEQUENCE length grows; the content prefix is identical).
        let unsigned = t.unsigned_block().unwrap();
        assert_eq!(&signed[3..unsigned.len()], &unsigned[3..]);
        assert_eq!(signed.len() - unsigned.len(), 2 + 64);
        let sig_start = signed.len() - 64;
        assert_eq!(signed[sig_start - 2], 0x04);
        assert_eq!(signed[sig_start - 1], 0x40);
        let sighash = sha3(&t.block_hash().unwrap());
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        key.verifying_key()
            .verify_prehash(
                &sighash,
                &Signature::from_slice(&signed[sig_start..]).unwrap(),
            )
            .unwrap();
        let _ = VerifyingKey::from_sec1_bytes(&address_bytes(&t.from).unwrap()[1..]).unwrap();
    }

    #[test]
    fn der_helpers_cover_length_edges() {
        assert_eq!(der_gentime(1_760_000_000), b"\x18\x0f20251009085320Z");
        assert_eq!(der_int(&[0]), b"\x02\x01\x00");
        assert_eq!(der_int(&[0x80]), b"\x02\x02\x00\x80");
        assert_eq!(der_int(&[0, 1]), b"\x02\x01\x01");
        assert_eq!(der_len(0x7f), vec![0x7f]);
        assert_eq!(der_len(0x80), vec![0x81, 0x80]);
        assert_eq!(der_len(0x100), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "keeta:main".into();
        assert!(t.unsigned_block().is_err());
        let mut t = base.clone();
        t.atto_kta = "01500000000".into();
        assert!(t.unsigned_block().is_err());
        let mut t = base.clone();
        t.atto_kta = "0".into();
        assert!(t.unsigned_block().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.unsigned_block().is_err());
        let mut t = base.clone();
        t.previous = "aa".repeat(32).to_uppercase();
        assert!(t.unsigned_block().is_err());
        let mut t = base.clone();
        t.previous = "00".repeat(32);
        assert!(t.unsigned_block().is_err());
        let mut t = base.clone();
        t.timestamp = 0;
        assert!(t.unsigned_block().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": KEETA_TEST, "from": SENDER, "to": RECIPIENT, "attoKta": "1",
            "previous": "1111111111111111111111111111111111111111111111111111111111111111",
            "timestamp": 1, "idempotent": "00"
        });
        assert!(serde_json::from_value::<KeetaTx>(extra).is_err());
    }
}
