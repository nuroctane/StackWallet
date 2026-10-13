//! Native SOL transfers with a single fee payer. The core constructs the entire
//! message from checked fields, so an adapter cannot add instructions or signers.

use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

pub const DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageVersion {
    #[default]
    #[serde(rename = "legacy")]
    Legacy,
    #[serde(rename = "v0")]
    V0,
}

impl MessageVersion {
    fn is_legacy(&self) -> bool {
        *self == Self::Legacy
    }
}

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Solana transfer",
        reason: reason.into(),
    }
}

pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    if address.len() > 44 {
        return Err(invalid("address is too long"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("address must be 32 bytes"))?;
    if bs58::encode(bytes).into_string() != address {
        return Err(invalid("non-canonical address"));
    }
    Ok(bytes)
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != DEVNET {
        return Err(invalid("only Solana Devnet transfers are enabled"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SolanaTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal lamports; never a JSON floating-point number.
    pub lamports: String,
    pub recent_blockhash: String,
    pub last_valid_block_height: u64,
    #[serde(default, skip_serializing_if = "MessageVersion::is_legacy")]
    pub message_version: MessageVersion,
}

impl SolanaTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native SOL transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.lamports {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Solana intent")),
        }
        self.message()?;
        Ok(())
    }

    pub fn message(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        let blockhash = address_bytes(&self.recent_blockhash)?;
        if from == to || from == [0; 32] || to == [0; 32] {
            return Err(invalid(
                "sender, recipient and System Program must be distinct",
            ));
        }
        if blockhash == [0; 32] {
            return Err(invalid("zero blockhash"));
        }
        let amount = self
            .lamports
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds u64 lamports"))?;
        if amount == 0 || amount.to_string() != self.lamports {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        if self.last_valid_block_height == 0 || self.last_valid_block_height > 9_007_199_254_740_991
        {
            return Err(invalid("invalid last valid block height"));
        }
        let mut message = vec![1, 0, 1, 3];
        message.extend_from_slice(&from);
        message.extend_from_slice(&to);
        message.extend_from_slice(&[0; 32]);
        message.extend_from_slice(&blockhash);
        // One System Program Transfer: program index 2, writable sender and recipient.
        message.extend_from_slice(&[1, 2, 2, 0, 1, 12]);
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&amount.to_le_bytes());
        if self.message_version == MessageVersion::V0 {
            message.insert(0, 0x80);
            // All checked accounts stay inline; lookup-table state cannot change destinations.
            message.push(0);
        }
        Ok(message)
    }

    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if key.verifying_key().to_bytes() != address_bytes(&self.from)? {
            return Err(invalid("fee payer differs from signing key"));
        }
        let message = self.message()?;
        let signature = key.sign(&message).to_bytes();
        let mut wire = vec![1];
        wire.extend_from_slice(&signature);
        wire.extend_from_slice(&message);
        Ok((
            format!("0x{}", hex::encode(wire)),
            bs58::encode(signature).into_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    fn tx() -> SolanaTx {
        SolanaTx {
            chain_id: DEVNET.into(),
            from: bs58::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())
                .into_string(),
            to: bs58::encode([8; 32]).into_string(),
            lamports: "1000".into(),
            recent_blockhash: bs58::encode([9; 32]).into_string(),
            last_valid_block_height: 100,
            message_version: MessageVersion::Legacy,
        }
    }
    fn intent(tx: &SolanaTx) -> TxIntent {
        TxIntent {
            id: "tx".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(DEVNET.into()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{DEVNET}:native")),
                amount: Amount(tx.lamports.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }
    #[test]
    fn wire_signature_verifies_over_exact_message() {
        let tx = tx();
        let (wire, hash) = tx.sign(&[7; 32]).unwrap();
        let bytes = hex::decode(wire.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(bytes.len(), 215);
        assert_eq!(bytes[0], 1);
        assert_eq!(bs58::decode(hash).into_vec().unwrap(), bytes[1..65]);
        let signature = ed25519_dalek::Signature::from_slice(&bytes[1..65]).unwrap();
        SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .verify_strict(&bytes[65..], &signature)
            .unwrap();
        assert_eq!(&bytes[65..], tx.message().unwrap());
        assert!(tx.sign(&[6; 32]).is_err());
    }
    #[test]
    fn hostile_payloads_are_refused() {
        let original = tx();
        let intent = intent(&original);
        original.check_matches_intent(&intent).unwrap();
        let mut bad = original.clone();
        bad.to = bs58::encode([10; 32]).into_string();
        assert!(bad.check_matches_intent(&intent).is_err());
        let mut bad = original.clone();
        bad.lamports = "1001".into();
        assert!(bad.check_matches_intent(&intent).is_err());
        let mut bad = original.clone();
        bad.chain_id = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        assert!(bad.message().is_err());
        for amount in ["0", "01", "-1", "18446744073709551616"] {
            let mut bad = original.clone();
            bad.lamports = amount.into();
            assert!(bad.message().is_err());
        }
        let mut bad = original.clone();
        bad.to = original.from.clone();
        assert!(bad.message().is_err());
        let mut bad = original.clone();
        bad.recent_blockhash = "11111111111111111111111111111111".into();
        assert!(bad.message().is_err());
        let mut json = serde_json::to_value(original).unwrap();
        json["instructions"] = serde_json::json!(["extra"]);
        assert!(serde_json::from_value::<SolanaTx>(json).is_err());
    }

    #[test]
    fn versioned_message_is_signed_and_old_records_stay_legacy() {
        let legacy = tx();
        let saved = serde_json::to_value(&legacy).unwrap();
        assert!(saved.get("messageVersion").is_none());
        assert_eq!(
            serde_json::from_value::<SolanaTx>(saved.clone()).unwrap(),
            legacy
        );
        let mut versioned = legacy.clone();
        versioned.message_version = MessageVersion::V0;
        versioned.check_matches_intent(&intent(&legacy)).unwrap();
        let message = versioned.message().unwrap();
        assert_eq!(message[0], 0x80);
        assert_eq!(&message[1..151], legacy.message().unwrap());
        assert_eq!(message[151], 0);
        let (wire, _) = versioned.sign(&[7; 32]).unwrap();
        let bytes = hex::decode(wire.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(bytes.len(), 217);
        let signature = ed25519_dalek::Signature::from_slice(&bytes[1..65]).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        key.verify_strict(&message, &signature).unwrap();
        assert!(key
            .verify_strict(&legacy.message().unwrap(), &signature)
            .is_err());
        let mut hostile = saved;
        hostile["messageVersion"] = serde_json::json!("v1");
        assert!(serde_json::from_value::<SolanaTx>(hostile).is_err());
        let mut hostile = serde_json::to_value(versioned).unwrap();
        hostile["addressTableLookups"] = serde_json::json!(["untrusted"]);
        assert!(serde_json::from_value::<SolanaTx>(hostile).is_err());
    }
}
