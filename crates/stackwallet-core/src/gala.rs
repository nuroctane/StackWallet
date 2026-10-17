//! GALA transfers on GalaChain (Hyperledger Fabric, REST gateway).
//!
//! GalaChain authenticates end users by secp256k1 recovery over
//! `keccak256(canonical_json(dto))` where the canonical JSON is the DTO with
//! recursively sorted keys, no whitespace, and `signature`/`multisig`/`trace`
//! removed. The signature is `r || s || v` hex with `v` a single byte 27/28
//! (verified byte-exact against `@gala-chain/api` 3.3.0 and live against both
//! gateways, which recovered the intended signer from a probe signature).
//! The core builds the canonical payload itself from checked fields, so an
//! adapter cannot sneak in `dtoOperation`, a different token, or a multisig.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// Testnet gateway (gateway-testnet.galachain.com) answered the signing probe
/// identically to mainnet, so signing stays testnet-gated like other families.
pub const TESTNET: &str = "gala:testnet";
pub const MAINNET: &str = "gala:mainnet";
/// GALA has 8 decimals (FetchTokenClasses on mainnet: `"decimals":8`).
pub const DECIMALS: u32 = 8;
const MAX_UNIQUE_KEY_LEN: usize = 128;
/// `dtoExpiresAt` is unix ms; bound it to a sane window (2020..2100).
const MIN_EXPIRES_MS: u64 = 1_577_836_800_000;
const MAX_EXPIRES_MS: u64 = 4_102_444_800_000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Gala transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    if chain != TESTNET {
        return Err(invalid("only GalaChain testnet transfers are enabled"));
    }
    Ok(())
}

/// EIP-55 checksum of a 20-byte address (GalaChain user refs keep the case,
/// without the `0x` prefix).
fn checksumed(bytes: &[u8; 20]) -> String {
    evm::checksum_address(bytes)[2..].to_string()
}

/// `eth|<EIP-55 address>` from a 33-byte compressed secp256k1 public key.
pub fn address(public: &[u8]) -> Result<String> {
    Ok(format!(
        "eth|{}",
        checksumed(&evm::address_from_public(public)?)
    ))
}

/// Parses an `eth|`-user ref, enforcing the EIP-55 checksum the chaincode
/// requires, and returns the raw 20 bytes.
pub fn address_bytes(user_ref: &str) -> Result<[u8; 20]> {
    let hexpart = user_ref
        .strip_prefix("eth|")
        .ok_or_else(|| invalid("user ref must start with eth|"))?;
    if hexpart.len() != 40 || hexpart.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return Err(invalid("user ref must be eth| plus 40 hex characters"));
    }
    let raw: [u8; 20] = hex::decode(hexpart)
        .map_err(|_| invalid("user ref is not hex"))?
        .try_into()
        .expect("40 hex chars");
    if raw.iter().all(|b| *b == 0) {
        return Err(invalid("zero address"));
    }
    if checksumed(&raw) != hexpart {
        return Err(invalid("user ref address checksum mismatch"));
    }
    Ok(raw)
}

fn check_unique_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > MAX_UNIQUE_KEY_LEN
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid(
            "unique key must be 1..=128 characters of [A-Za-z0-9_-]",
        ));
    }
    Ok(())
}

/// Decimal GALA string from base units (1 GALA = 10^8 gunits), fixed notation
/// with no trailing zeros, exactly how the SDK's BigNumber serializes.
fn quantity_from_gunits(gunits: u64) -> String {
    let whole = gunits / 100_000_000;
    let frac = gunits % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_str = format!("{frac:08}");
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{whole}.{frac_str}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GalaTx {
    pub chain_id: String,
    /// Sender user ref `eth|<EIP-55>`; must be the signing key's address.
    pub from: String,
    /// Recipient user ref `eth|<EIP-55>`.
    pub to: String,
    /// Decimal gunits (1 GALA = 100,000,000 gunits); never a JSON float.
    pub gunits: String,
    /// Replay-protection key; the chaincode rejects a repeated one.
    pub unique_key: String,
    /// Unix ms after which the chaincode refuses the DTO.
    pub dto_expires_at: u64,
}

impl GalaTx {
    fn checked_fields(&self) -> Result<(u64, [u8; 20], [u8; 20])> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = self
            .gunits
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds u64 gunits"))?;
        if amount == 0 || amount.to_string() != self.gunits {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        check_unique_key(&self.unique_key)?;
        if !(MIN_EXPIRES_MS..=MAX_EXPIRES_MS).contains(&self.dto_expires_at) {
            return Err(invalid("dto expiry must be a unix ms timestamp"));
        }
        Ok((amount, from, to))
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native GALA transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.gunits {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Gala intent")),
        }
        self.payload()?;
        Ok(())
    }

    /// The exact string the chaincode hashes: recursively sorted JSON of the
    /// DTO minus `signature`, no whitespace. Token instance is pinned to the
    /// GALA unit class (`GALA/Unit/none/none/0`), so only GALA can move.
    pub fn payload(&self) -> Result<String> {
        let (amount, _, _) = self.checked_fields()?;
        let quantity = quantity_from_gunits(amount);
        // Addresses and the unique key are charset-restricted above, so plain
        // JSON string interpolation cannot inject or break sorting.
        Ok(format!(
            "{{\"dtoExpiresAt\":{},\"from\":\"{}\",\"quantity\":\"{}\",\"to\":\"{}\",\
             \"tokenInstance\":{{\"additionalKey\":\"none\",\"category\":\"Unit\",\
             \"collection\":\"GALA\",\"instance\":\"0\",\"type\":\"none\"}},\
             \"uniqueKey\":\"{}\"}}",
            self.dto_expires_at, self.from, quantity, self.to, self.unique_key
        ))
    }

    /// keccak256 of the payload: what the signature authorizes.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(Keccak256::digest(self.payload()?.as_bytes()).into())
    }

    /// Local pre-broadcast id (the gateway assigns the real transaction id in
    /// its synchronous response): keccak256 of the payload.
    pub fn local_id(&self) -> Result<String> {
        Ok(format!("0x{}", hex::encode(self.digest()?)))
    }

    /// Returns the POST body for `/api/asset/token-contract/TransferToken`
    /// (the DTO plus the `signature` field) and the local id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let (amount, _, _) = self.checked_fields()?;
        let digest = self.digest()?;
        let (parity, r, s) = evm::sign_digest(secret, &digest)?;
        let signature = format!("{}{}{:02x}", hex::encode(r), hex::encode(s), parity + 27);
        let wire = format!(
            "{{\"dtoExpiresAt\":{},\"from\":\"{}\",\"quantity\":\"{}\",\"signature\":\"{}\",\
             \"to\":\"{}\",\"tokenInstance\":{{\"additionalKey\":\"none\",\"category\":\"Unit\",\
             \"collection\":\"GALA\",\"instance\":\"0\",\"type\":\"none\"}},\
             \"uniqueKey\":\"{}\"}}",
            self.dto_expires_at,
            self.from,
            quantity_from_gunits(amount),
            signature,
            self.to,
            self.unique_key
        );
        Ok((wire, self.local_id()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];
    /// Verified live: both gateways recovered this address from a signature
    /// made with key 0x07*32 over the payload below.
    const SENDER: &str = "eth|4a62316623ad457F02cDC5D997deD67a383EC569";
    const RECIPIENT: &str = "eth|8ba1f109551bD432803012645Ac136ddd64DBA72";

    fn sender() -> String {
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn tx() -> GalaTx {
        GalaTx {
            chain_id: TESTNET.into(),
            from: sender(),
            to: RECIPIENT.into(),
            gunits: "100000000".into(),
            unique_key: "stackwallet-probe-1792206705582".into(),
            dto_expires_at: 1_792_207_005_582,
        }
    }

    fn intent(tx: &GalaTx) -> TxIntent {
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
                amount: Amount(tx.gunits.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_the_live_recovered_signer() {
        assert_eq!(sender(), SENDER);
        assert_eq!(address_bytes(SENDER).unwrap().len(), 20);
        assert!(address_bytes(&SENDER.to_lowercase()).is_err());
        assert!(address_bytes("0x4a62316623ad457F02cDC5D997deD67a383EC569").is_err());
        assert!(address_bytes("client|4a62316623ad457F02cDC5D997deD67a383EC569").is_err());
    }

    /// The deterministic serializer itself, pinned against `@gala-chain/api`'s
    /// spec vector: {"c":8,"b":[{"z":6,"y":5,"x":4},7],"a":3} hashes to this.
    #[test]
    fn sorted_json_keccak_matches_sdk_vector() {
        let payload = r#"{"a":3,"b":[{"x":4,"y":5,"z":6},7],"c":8}"#;
        let digest = Keccak256::digest(payload.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "79dd0efca18dd25aecc5aa5b5c6e89c1ea0ba96a04280cb7cb9a617e771d702b"
        );
    }

    #[test]
    fn payload_and_signature_match_the_live_gateway_proof() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        // Exactly the payload the mainnet/testnet gateways accepted (they
        // recovered `from` from it and failed only on the 1 GALA fee).
        assert_eq!(
            t.payload().unwrap(),
            "{\"dtoExpiresAt\":1792207005582,\"from\":\"eth|4a62316623ad457F02cDC5D997deD67a383EC569\",\
             \"quantity\":\"1\",\"to\":\"eth|8ba1f109551bD432803012645Ac136ddd64DBA72\",\
             \"tokenInstance\":{\"additionalKey\":\"none\",\"category\":\"Unit\",\"collection\":\"GALA\",\
             \"instance\":\"0\",\"type\":\"none\"},\"uniqueKey\":\"stackwallet-probe-1792206705582\"}"
                .replace(' ', "")
        );
        let (wire, id) = t.sign(&SECRET).unwrap();
        assert_eq!(id, format!("0x{}", hex::encode(t.digest().unwrap())));
        // The signature the gateway recovered to `from`.
        let expected_sig = "e91952ed063994efd30aa1e2dc7ed4bd05f9692e6becb908b9b11ed5b6b06d79396b6df82a72d3c064f06d7458a458bf29e4fc0dd787a28b01dbd6c937fe8c151c";
        assert!(wire.contains(&format!("\"signature\":\"{expected_sig}\"")));
        // Independent recovery check.
        let sig = hex::decode(expected_sig).unwrap();
        let recovered = VerifyingKey::recover_from_prehash(
            &t.digest().unwrap(),
            &Signature::from_slice(&sig[..64]).unwrap(),
            RecoveryId::from_byte(sig[64] - 27).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
    }

    #[test]
    fn quantity_formats_like_the_sdk_big_number() {
        assert_eq!(quantity_from_gunits(100_000_000), "1");
        assert_eq!(quantity_from_gunits(1), "0.00000001");
        assert_eq!(quantity_from_gunits(150_000_000), "1.5");
        assert_eq!(quantity_from_gunits(110_000_000), "1.1");
        assert_eq!(
            quantity_from_gunits(123_456_789_012_345_678),
            "1234567890.12345678"
        );
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.payload().is_err());
        let mut t = base.clone();
        t.gunits = "0".into();
        assert!(t.payload().is_err());
        let mut t = base.clone();
        t.gunits = "0100000000".into();
        assert!(t.payload().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.payload().is_err());
        let mut t = base.clone();
        t.unique_key = "bad key{\"inject\":1}".into();
        assert!(t.payload().is_err());
        let mut t = base.clone();
        t.dto_expires_at = u64::MAX;
        assert!(t.payload().is_err());
        let mut t = base.clone();
        t.from = SENDER.to_lowercase();
        assert!(t.payload().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "100000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": SENDER, "to": RECIPIENT, "gunits": "1",
            "uniqueKey": "k", "dtoExpiresAt": 1_792_207_005_582_u64, "dtoOperation": "evil"
        });
        assert!(serde_json::from_value::<GalaTx>(extra).is_err());
    }
}
