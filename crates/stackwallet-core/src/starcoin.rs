//! Native STC transfers on Starcoin. The core encodes the whole BCS
//! `RawUserTransaction` (a fixed `0x1::TransferScripts::peer_to_peer_with_metadata_v2`
//! call on `0x1::STC::STC` with empty metadata) from checked fields, so an
//! adapter cannot swap the payload, token or gas coin.
//!
//! Encoding was pinned byte-for-byte against `@starcoin/starcoin` 2.3.7:
//! - signed message: sha3-256("STARCOIN::RawUserTransaction") || bcs(raw), signed directly
//! - raw id:  sha3-256 of the signed message above
//! - txid:    sha3-256( sha3-256("STARCOIN::SignedUserTransaction") || bcs(signed) )
//! - address: last 16 bytes of sha3-256(ed25519_pubkey || 0x00), as `0x` + 32 hex

use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 for the Barnard testnet (Starcoin chain id 251).
pub const BARNARD: &str = "starcoin:251";
const BARNARD_ID: u8 = 251;
const CORE_ADDRESS: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const GAS_TOKEN_CODE: &str = "0x1::STC::STC";
const MAX_GAS_AMOUNT: u64 = 50_000_000;
const MAX_GAS_UNIT_PRICE: u64 = 1_000_000;
/// 2100-01-01T00:00:00Z; expirations beyond this are nonsense for a transfer.
const MAX_EXPIRATION_SECS: u64 = 4_102_444_800;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Starcoin transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != BARNARD {
        return Err(invalid("only Starcoin Barnard transfers are enabled"));
    }
    Ok(())
}

/// A canonical Starcoin address is `0x` plus 16 lowercase-hex bytes.
pub fn address_bytes(address: &str) -> Result<[u8; 16]> {
    if address.len() != 34 || !address.starts_with("0x") {
        return Err(invalid("address must be 0x plus 16 hex bytes"));
    }
    if address[2..].bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid("address must be lowercase hex"));
    }
    let bytes = hex::decode(&address[2..]).map_err(|_| invalid("address is not hex"))?;
    let out: [u8; 16] = bytes.try_into().expect("length checked");
    if out.iter().all(|b| *b == 0) {
        return Err(invalid("zero address"));
    }
    Ok(out)
}

/// Last 16 bytes of sha3-256(pubkey || 0x00): the single-key auth-key tail.
pub fn address(public: &[u8]) -> Result<String> {
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    let mut preimage = Vec::with_capacity(33);
    preimage.extend_from_slice(&public);
    preimage.push(0x00);
    let auth_key = Sha3_256::digest(&preimage);
    Ok(format!("0x{}", hex::encode(&auth_key[16..])))
}

fn prefix_hash(name: &str) -> [u8; 32] {
    Sha3_256::digest(format!("STARCOIN::{name}").as_bytes()).into()
}

fn uleb128_len(out: &mut Vec<u8>, len: usize) {
    let mut v = len as u64;
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    uleb128_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    push_bytes(out, s.as_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StarcoinTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal nanoSTC (1 STC = 1,000,000,000 nano); never a JSON floating-point number.
    pub nano: String,
    pub sequence_number: u64,
    pub max_gas_amount: u64,
    pub gas_unit_price: u64,
    /// Unix seconds; the network drops the transaction after this.
    pub expiration_timestamp_secs: u64,
}

impl StarcoinTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native STC transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.nano {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Starcoin intent")),
        }
        self.raw_bytes()?;
        Ok(())
    }

    fn fields(&self) -> Result<([u8; 16], [u8; 16], u128)> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = self
            .nano
            .parse::<u128>()
            .map_err(|_| invalid("amount exceeds u128 nano"))?;
        if amount == 0 || amount.to_string() != self.nano {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        if self.sequence_number > i64::MAX as u64 {
            return Err(invalid("sequence number exceeds i64"));
        }
        if self.max_gas_amount == 0 || self.max_gas_amount > MAX_GAS_AMOUNT {
            return Err(invalid("max gas amount out of range"));
        }
        if self.gas_unit_price == 0 || self.gas_unit_price > MAX_GAS_UNIT_PRICE {
            return Err(invalid("gas unit price out of range"));
        }
        if self.expiration_timestamp_secs == 0
            || self.expiration_timestamp_secs > MAX_EXPIRATION_SECS
        {
            return Err(invalid("expiration out of range"));
        }
        Ok((from, to, amount))
    }

    /// The BCS `RawUserTransaction`; its prefixed sha3-256 is the sighash.
    pub fn raw_bytes(&self) -> Result<Vec<u8>> {
        let (from, to, amount) = self.fields()?;
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(&from);
        out.extend_from_slice(&self.sequence_number.to_le_bytes());
        // TransactionPayload::ScriptFunction (variant 2); BCS variants are uleb128
        out.push(2);
        out.extend_from_slice(&CORE_ADDRESS);
        push_str(&mut out, "TransferScripts");
        push_str(&mut out, "peer_to_peer_with_metadata_v2");
        // type args: one Struct tag 0x1::STC::STC
        uleb128_len(&mut out, 1);
        out.push(7); // TypeTag::Struct
        out.extend_from_slice(&CORE_ADDRESS);
        push_str(&mut out, "STC");
        push_str(&mut out, "STC");
        uleb128_len(&mut out, 0); // no nested type params
                                  // args: payee address, u128 amount, empty metadata
        uleb128_len(&mut out, 3);
        push_bytes(&mut out, &to);
        push_bytes(&mut out, &amount.to_le_bytes());
        push_bytes(&mut out, &[]);
        out.extend_from_slice(&self.max_gas_amount.to_le_bytes());
        out.extend_from_slice(&self.gas_unit_price.to_le_bytes());
        push_str(&mut out, GAS_TOKEN_CODE);
        out.extend_from_slice(&self.expiration_timestamp_secs.to_le_bytes());
        out.push(BARNARD_ID);
        Ok(out)
    }

    /// The message ed25519 signs: the "STARCOIN::RawUserTransaction" prefix
    /// hash followed by the BCS bytes (Starcoin signs this message directly,
    /// without a second pre-hash).
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let mut msg = prefix_hash("RawUserTransaction").to_vec();
        msg.extend_from_slice(&self.raw_bytes()?);
        Ok(msg)
    }

    /// sha3-256 of the signing message: the raw transaction's crypto id.
    pub fn raw_id(&self) -> Result<[u8; 32]> {
        Ok(Sha3_256::digest(self.signing_message()?).into())
    }

    fn assemble_wire(&self, public: &[u8; 32], signature: &[u8; 64]) -> Result<(Vec<u8>, String)> {
        let mut wire = self.raw_bytes()?;
        // TransactionAuthenticator::Ed25519 (variant 0)
        wire.push(0);
        push_bytes(&mut wire, public);
        push_bytes(&mut wire, signature);
        let mut hasher = Sha3_256::new();
        hasher.update(prefix_hash("SignedUserTransaction"));
        hasher.update(&wire);
        let txid: [u8; 32] = hasher.finalize().into();
        Ok((wire, format!("0x{}", hex::encode(txid))))
    }

    /// Returns the signed BCS hex (for `txpool.submit_hex_transaction`) and the tx hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let message = self.signing_message()?;
        self.assemble(&key.sign(&message).to_bytes(), &public)
    }

    /// The wire transaction for a signature made elsewhere (a threshold
    /// ceremony), accepted only if `public` derives `from` (the address
    /// commits to the auth key, so the key itself must be presented) and the
    /// signature verifies over `signing_hash()`.
    pub fn assemble(&self, signature: &[u8; 64], public: &[u8; 32]) -> Result<(String, String)> {
        if address(public)? != self.from {
            return Err(invalid("public key does not derive the sender address"));
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(public)
            .map_err(|_| invalid("sender key is not an Ed25519 point"))?;
        key.verify_strict(
            &self.signing_message()?,
            &ed25519_dalek::Signature::from_bytes(signature),
        )
        .map_err(|_| invalid("signature does not verify against the sender"))?;
        let (wire, txid) = self.assemble_wire(public, signature)?;
        Ok((format!("0x{}", hex::encode(wire)), txid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// Vectors produced by `@starcoin/starcoin` 2.3.7 for the secret above.
    const PUBLIC: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const SENDER: &str = "0xe61b780ad0935f3363bc7fce64edbdad";
    const RECIPIENT: &str = "0xd8f5a2f3b1c4e5a69788776655443322";
    const RAW_BCS: &str = "e61b780ad0935f3363bc7fce64edbdad290000000000000002000000000000000000000000000000010f5472616e73666572536372697074731d706565725f746f5f706565725f776974685f6d657461646174615f76320107000000000000000000000000000000010353544303535443000310d8f5a2f3b1c4e5a697887766554433221015cd5b0700000000000000000000000000809698000000000001000000000000000d3078313a3a5354433a3a53544380e14e6800000000fb";
    const SIGNING_HASH: &str = "028c49948238b53c1fe4c2c4acb871f48b17b6e9fe1aa9d85c71c044af8aba3f";
    const SIGNED_HEX: &str = "e61b780ad0935f3363bc7fce64edbdad290000000000000002000000000000000000000000000000010f5472616e73666572536372697074731d706565725f746f5f706565725f776974685f6d657461646174615f76320107000000000000000000000000000000010353544303535443000310d8f5a2f3b1c4e5a697887766554433221015cd5b0700000000000000000000000000809698000000000001000000000000000d3078313a3a5354433a3a53544380e14e6800000000fb0020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c402313b4bb295d7ef908f38e9e24dfa5cc695f66e65025c4a7d1dc8728c4ccba6ad411bade3850e263afa6b936ff925d40cf46e22c349b9469f31d4f0582471708";
    const TX_HASH: &str = "0xb14893aea75d9bea680fc5742b6a0659c7973f414c69d1711c77af20180f1bf4";

    fn tx() -> StarcoinTx {
        StarcoinTx {
            chain_id: BARNARD.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            nano: "123456789".into(),
            sequence_number: 41,
            max_gas_amount: 10_000_000,
            gas_unit_price: 1,
            expiration_timestamp_secs: 1_750_000_000,
        }
    }

    fn intent(tx: &StarcoinTx) -> TxIntent {
        TxIntent {
            id: "tx".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(BARNARD.into()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{BARNARD}:native")),
                amount: Amount(tx.nano.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_the_sdk_vector() {
        let public = hex::decode(PUBLIC).unwrap();
        assert_eq!(address(&public).unwrap(), SENDER);
        let key = SigningKey::from_bytes(&SECRET);
        assert_eq!(hex::encode(key.verifying_key().to_bytes()), PUBLIC);
        assert_eq!(address(&key.verifying_key().to_bytes()).unwrap(), SENDER);
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes("0xE61B780AD0935F3363BC7FCE64EDBDAD").is_err());
        assert!(address_bytes("e61b780ad0935f3363bc7fce64edbdad").is_err());
        assert!(address_bytes("0x1").is_err());
        assert!(address_bytes("0x00000000000000000000000000000000").is_err());
        assert!(address_bytes("0xe61b780ad0935f3363bc7fce64edbda").is_err());
        assert!(address_bytes("0xe61b780ad0935f3363bc7fce64edbdad00").is_err());
    }

    #[test]
    fn raw_bytes_match_the_sdk_vector() {
        assert_eq!(hex::encode(tx().raw_bytes().unwrap()), RAW_BCS);
        assert_eq!(hex::encode(tx().raw_id().unwrap()), SIGNING_HASH);
        assert_eq!(
            hex::encode(prefix_hash("RawUserTransaction")),
            "f7abb31497be2d952de2e1c64e2ce3edae7c4d9f5a522386a38af0c76457301e"
        );
    }

    #[test]
    fn signature_matches_the_sdk_and_verifies() {
        let (wire, txid) = tx().sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{SIGNED_HEX}"));
        assert_eq!(txid, TX_HASH);
        let key = SigningKey::from_bytes(&SECRET).verifying_key();
        let digest = tx().signing_message().unwrap();
        let bytes = hex::decode(SIGNED_HEX).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&bytes[bytes.len() - 64..]).unwrap();
        key.verify_strict(&digest, &signature).unwrap();
        assert!(tx().sign(&[6; 32]).is_err());
        let public: [u8; 32] = hex::decode(PUBLIC).unwrap().try_into().unwrap();
        let sig_bytes = signature.to_bytes();
        let (wire2, txid2) = tx().assemble(&sig_bytes, &public).unwrap();
        assert_eq!((wire2, txid2), (format!("0x{SIGNED_HEX}"), TX_HASH.into()));
        let mut wrong = sig_bytes;
        wrong[10] ^= 1;
        assert!(tx().assemble(&wrong, &public).is_err());
        assert!(tx().assemble(&sig_bytes, &[9; 32]).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let original = tx();
        original.check_matches_intent(&intent(&original)).unwrap();
        let mut bad = original.clone();
        bad.to = "0x00000000000000000000000000000001".into();
        assert!(bad.check_matches_intent(&intent(&original)).is_err());
        let mut bad = original.clone();
        bad.nano = "123456790".into();
        assert!(bad.check_matches_intent(&intent(&original)).is_err());
        let mut bad = original.clone();
        bad.chain_id = "starcoin:1".into();
        assert!(bad.check_matches_intent(&intent(&bad)).is_err());
        assert!(bad.raw_bytes().is_err());
        for amount in [
            "0",
            "01",
            "-1",
            "123456789 ",
            "340282366920938463463374607431768211456",
        ] {
            let mut bad = original.clone();
            bad.nano = amount.into();
            assert!(bad.raw_bytes().is_err(), "{amount}");
        }
        let mut bad = original.clone();
        bad.max_gas_amount = 0;
        assert!(bad.raw_bytes().is_err());
        let mut bad = original.clone();
        bad.gas_unit_price = 0;
        assert!(bad.raw_bytes().is_err());
        let mut bad = original.clone();
        bad.expiration_timestamp_secs = 0;
        assert!(bad.raw_bytes().is_err());
        let mut bad = original.clone();
        bad.expiration_timestamp_secs = MAX_EXPIRATION_SECS + 1;
        assert!(bad.raw_bytes().is_err());
        let mut bad = original.clone();
        bad.to = bad.from.clone();
        assert!(bad.raw_bytes().is_err());
        let mut hostile = serde_json::to_value(original).unwrap();
        hostile["payload"] = serde_json::json!("0xdeadbeef");
        assert!(serde_json::from_value::<StarcoinTx>(hostile).is_err());
    }
}
