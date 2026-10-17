//! Native AE transfers. The core RLP-encodes the whole SpendTx from checked
//! fields (empty payload, fee and nonce bounded), so an adapter cannot add
//! contract calls or calldata. Encoding follows the official aepp-sdk:
//! aeser RLP (Ethereum RLP), `tx_`/`th_` checksum strings, and ed25519 over
//! `network_id || blake2b256(unsigned RLP)`.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 references are the node's `network_id` (`ae_mainnet` / `ae_uat`).
pub const TESTNET: &str = "aet:ae_uat";
const NETWORK_ID: &str = "ae_uat";
const SPEND_TX_TAG: u8 = 12;
const SIGNED_TX_TAG: u8 = 11;
const TX_VERSION: u8 = 1;
const ID_TAG_ACCOUNT: u8 = 1;
/// Total supply is ~5.4e26 aettos; leave headroom but bound the encoder.
const MAX_AETTOS: u128 = 1_000_000_000_000_000_000_000_000_000_000; // 1e30
/// Between an implausible fee and one whole AE.
const MIN_FEE: u128 = 1_000_000_000_000; // 1e12
const MAX_FEE: u128 = 1_000_000_000_000_000_000; // 1e18
const MAX_TTL: u64 = u32::MAX as u64;
const MAX_NONCE: u64 = u32::MAX as u64;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Aeternity transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Aeternity testnet transfers are enabled"));
    }
    Ok(())
}

fn blake2b256(data: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(data).into()
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(Sha256::digest(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The 32-byte ed25519 public key behind an `ak_` base58check address.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    let encoded = address
        .strip_prefix("ak_")
        .ok_or_else(|| invalid("address must carry the ak_ prefix"))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if bytes.len() != 36 {
        return Err(invalid("address must be 32 bytes plus a checksum"));
    }
    let (payload, check) = bytes.split_at(32);
    if checksum(payload) != check {
        return Err(invalid("address checksum mismatch"));
    }
    let out: [u8; 32] = payload.try_into().expect("32 bytes");
    if out == [0; 32] {
        return Err(invalid("zero address"));
    }
    if encode_address(&out) != address {
        return Err(invalid("non-canonical address"));
    }
    Ok(out)
}

pub fn encode_address(public: &[u8; 32]) -> String {
    let mut full = public.to_vec();
    full.extend_from_slice(&checksum(public));
    format!("ak_{}", bs58::encode(full).into_string())
}

pub fn address(public: &[u8]) -> Result<String> {
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Aeternity public keys are 32 bytes"))?;
    Ok(encode_address(&public))
}

/// `tx_` strings are base64check of the RLP record.
fn encode_tx(rlp: &[u8]) -> String {
    use base64::Engine as _;
    let mut full = rlp.to_vec();
    full.extend_from_slice(&checksum(rlp));
    format!(
        "tx_{}",
        base64::engine::general_purpose::STANDARD.encode(full)
    )
}

/// `th_` transaction hashes are base58check of blake2b256(signed RLP).
fn encode_hash(signed_rlp: &[u8]) -> String {
    let digest = blake2b256(signed_rlp);
    let mut full = digest.to_vec();
    full.extend_from_slice(&checksum(&digest));
    format!("th_{}", bs58::encode(full).into_string())
}

// --- aeser RLP (Ethereum RLP; integers are minimal big-endian, zero is empty) ---

fn rlp_header(offset: u8, len: usize) -> Vec<u8> {
    if len <= 55 {
        vec![offset + len as u8]
    } else {
        let len_bytes = (len as u64).to_be_bytes();
        let start = len_bytes.iter().position(|b| *b != 0).expect("len > 55");
        let mut out = vec![offset + 55 + (len_bytes.len() - start) as u8];
        out.extend_from_slice(&len_bytes[start..]);
        out
    }
}

fn rlp_item(payload: &[u8]) -> Vec<u8> {
    if payload.len() == 1 && payload[0] < 0x80 {
        return payload.to_vec();
    }
    let mut out = rlp_header(0x80, payload.len());
    out.extend_from_slice(payload);
    out
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = rlp_header(0xc0, payload.len());
    out.extend_from_slice(&payload);
    out
}

fn rlp_int(value: u128) -> Vec<u8> {
    // aeser_rlp encodes a zero integer as one 0x00 byte, not the empty string.
    if value == 0 {
        return vec![0];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).expect("nonzero");
    rlp_item(&bytes[start..])
}

/// An `id` is the one-byte id tag followed by the 32-byte hash, one RLP string.
fn rlp_id(public: &[u8; 32]) -> Vec<u8> {
    let mut id = vec![ID_TAG_ACCOUNT];
    id.extend_from_slice(public);
    rlp_item(&id)
}

fn canonical_u128(value: &str, what: &str) -> Result<u128> {
    let parsed = value
        .parse::<u128>()
        .map_err(|_| invalid(format!("{what} must be a decimal integer")))?;
    if parsed.to_string() != value {
        return Err(invalid(format!("{what} must be canonical")));
    }
    Ok(parsed)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AeternityTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal aettos (1 AE = 10^18 aettos); never a JSON floating-point number.
    pub aettos: String,
    /// Decimal aettos; at least the protocol minimum for an empty-payload spend.
    pub fee: String,
    /// Key block height after which the network drops the transaction; 0 never expires.
    pub ttl: u64,
    /// The sender's next account nonce.
    pub nonce: u64,
}

impl AeternityTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native AE transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.aettos {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Aeternity intent")),
        }
        self.unsigned_rlp()?;
        Ok(())
    }

    /// The unsigned SpendTx RLP; the adapter pins these exact bytes.
    pub fn unsigned_rlp(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u128(&self.aettos, "amount")?;
        if amount == 0 || amount > MAX_AETTOS {
            return Err(invalid("amount is outside the aettos bounds"));
        }
        let fee = canonical_u128(&self.fee, "fee")?;
        if !(MIN_FEE..=MAX_FEE).contains(&fee) {
            return Err(invalid("fee is outside the aettos bounds"));
        }
        if self.ttl > MAX_TTL {
            return Err(invalid("ttl is implausibly far ahead"));
        }
        if self.nonce == 0 || self.nonce > MAX_NONCE {
            return Err(invalid("invalid nonce"));
        }
        // Payload stays empty: no calldata, no memo, nothing opaque to sign.
        Ok(rlp_list(&[
            rlp_int(SPEND_TX_TAG as u128),
            rlp_int(TX_VERSION as u128),
            rlp_id(&from),
            rlp_id(&to),
            rlp_int(amount),
            rlp_int(fee),
            rlp_int(self.ttl as u128),
            rlp_int(self.nonce as u128),
            rlp_item(&[]),
        ]))
    }

    /// The unsigned transaction as the node's `tx_` string.
    pub fn unsigned_tx(&self) -> Result<String> {
        Ok(encode_tx(&self.unsigned_rlp()?))
    }

    /// What the ed25519 key signs: `network_id || blake2b256(unsigned RLP)`.
    pub fn sighash(&self) -> Result<Vec<u8>> {
        let unsigned = self.unsigned_rlp()?;
        let mut buffer = NETWORK_ID.as_bytes().to_vec();
        buffer.extend_from_slice(&blake2b256(&unsigned));
        Ok(buffer)
    }

    fn signed_wire(&self, signature: &[u8; 64]) -> Result<(String, String)> {
        let unsigned = self.unsigned_rlp()?;
        let signed = rlp_list(&[
            rlp_int(SIGNED_TX_TAG as u128),
            rlp_int(TX_VERSION as u128),
            rlp_list(&[rlp_item(signature)]),
            rlp_item(&unsigned),
        ]);
        Ok((encode_tx(&signed), encode_hash(&signed)))
    }

    /// Returns the signed `tx_` string (POST body for `/v3/transactions`) and its `th_` hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if address(&key.verifying_key().to_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        self.signed_wire(&key.sign(&self.sighash()?).to_bytes())
    }

    /// The wire transaction for a signature made elsewhere (a threshold
    /// ceremony), accepted only if it verifies against the sender.
    pub fn assemble(&self, signature: &[u8; 64]) -> Result<(String, String)> {
        let sighash = self.sighash()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&address_bytes(&self.from)?)
            .map_err(|_| invalid("sender is not an Ed25519 point"))?;
        key.verify_strict(&sighash, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        self.signed_wire(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// Vectors produced by @aeternity/aepp-sdk 15.0.1 (AccountMemory + buildTx).
    const SENDER: &str = "ak_2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK";
    const RECIPIENT: &str = "ak_4yo5ZzPDUKCsoucyTX2GfktgoyjxM9cjFUWqkiQsUJrWLdLS7";

    fn tx() -> AeternityTx {
        AeternityTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            aettos: "123456789012345678".into(),
            fee: "20000000000000".into(),
            ttl: 12345,
            nonce: 42,
        }
    }

    fn intent(tx: &AeternityTx) -> TxIntent {
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
                amount: Amount(tx.aettos.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_the_sdk_vector() {
        let derived = address(&SigningKey::from_bytes(&SECRET).verifying_key().to_bytes()).unwrap();
        assert_eq!(derived, SENDER);
        assert_eq!(encode_address(&address_bytes(SENDER).unwrap()), SENDER);
        assert_eq!(encode_address(&[9u8; 32]), RECIPIENT);
    }

    #[test]
    fn unsigned_rlp_matches_the_sdk_vector() {
        let t = tx();
        assert_eq!(hex::encode(t.unsigned_rlp().unwrap()), UNSIGNED_RLP_HEX);
        assert_eq!(t.unsigned_tx().unwrap(), UNSIGNED_TX);
        assert_eq!(hex::encode(t.sighash().unwrap()), SIGHASH_HEX);
    }
    const UNSIGNED_RLP_HEX: &str =
        "f85b0c01a101ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca10109090909090909090909090909090909090909090909090909090909090909098801b69b4ba630f34e8612309ce540008230392a80";
    const UNSIGNED_TX: &str =
        "tx_+FsMAaEB6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iyhAQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJiAG2m0umMPNOhhIwnOVAAIIwOSqAy8BfRA==";
    const SIGHASH_HEX: &str =
        "61655f7561747656f261cb0755469bae1d31646afced7e80eb228dca3c05c306c4f158a21fac";

    #[test]
    fn signed_tx_matches_the_sdk_vector() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, SIGNED_TX);
        assert_eq!(hash, "th_KFzgyySVPVKzB6bk5redoSMLhDNmDyhEZyi2zHnzSVPcKGsxf");
        // A ceremony signature for the same sighash assembles to the same wire bytes.
        let sig = SigningKey::from_bytes(&SECRET).sign(&t.sighash().unwrap());
        assert_eq!(t.assemble(&sig.to_bytes()).unwrap().0, wire);
    }
    const SIGNED_TX: &str =
        "tx_+KULAfhCuEA1SmSAelItWslxxrdAjm3YUesQzOrfdXhyCFaQYDn49S+WmAOUi/cZt8lAZwB02trpaO+B+5MS+v2AokE2IlECuF34WwwBoQHqSmxj4pxSCr71UHsTLsX5lUd2rr6+e5JCHuppFEbSLKEBCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQmIAbabS6Yw806GEjCc5UAAgjA5KoApenxY";

    #[test]
    fn zero_ttl_and_minimal_amount_match_the_sdk_vector() {
        let t = AeternityTx {
            aettos: "1".into(),
            ttl: 0,
            nonce: 1,
            ..tx()
        };
        assert_eq!(
            hex::encode(t.unsigned_rlp().unwrap()),
            "f8510c01a101ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca1010909090909090909090909090909090909090909090909090909090909090909018612309ce54000000180"
        );
        let (_, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(
            hash,
            "th_2ut6FUeaJwrVYtPNb8aVYZ1dgQZu2dkUS1gTcyf7p5QzZVRkfV"
        );
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "aet:ae_mainnet".into();
        assert!(t.unsigned_rlp().is_err());
        let mut t = base.clone();
        t.aettos = "0123".into();
        assert!(t.unsigned_rlp().is_err());
        let mut t = base.clone();
        t.aettos = "0".into();
        assert!(t.unsigned_rlp().is_err());
        let mut t = base.clone();
        t.fee = "1".into();
        assert!(t.unsigned_rlp().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.unsigned_rlp().is_err());
        let mut t = base.clone();
        t.nonce = 0;
        assert!(t.unsigned_rlp().is_err());
        assert!(address_bytes("ak_2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvL").is_err());
        assert!(address_bytes(SENDER.replace("ak_", "ct_").as_str()).is_err());
        assert!(address_bytes(&encode_address(&[0u8; 32])).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "123456789012345679".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "aettos": "1",
            "fee": "20000000000000", "ttl": 0, "nonce": 1, "payload": "ba_AAAA"
        });
        assert!(serde_json::from_value::<AeternityTx>(extra).is_err());
    }

    /// Live-proof helper: prints the signed testnet spend when the lead probe
    /// passes the next nonce and ttl through the environment.
    #[test]
    fn live_vector_from_env() {
        let (Ok(nonce), Ok(ttl)) = (std::env::var("AE_NONCE"), std::env::var("AE_TTL")) else {
            return;
        };
        let t = AeternityTx {
            aettos: std::env::var("AE_AETTOS").unwrap_or_else(|_| "1000000000000000".into()),
            nonce: nonce.parse().unwrap(),
            ttl: ttl.parse().unwrap(),
            ..tx()
        };
        let (wire, hash) = t.sign(&SECRET).unwrap();
        eprintln!("AE_WIRE={wire}\nAE_HASH={hash}");
    }
}
