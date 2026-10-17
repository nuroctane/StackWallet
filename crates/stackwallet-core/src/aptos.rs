//! Native APT transfers. The core BCS-encodes the whole `RawTransaction` from
//! checked fields as one `0x1::aptos_account::transfer` entry function call, so
//! an adapter cannot add scripts, type arguments or other modules.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 references are the ledger's `chain_id` (mainnet 1, testnet 2).
pub const TESTNET: &str = "aptos:2";
const TESTNET_CHAIN_ID: u8 = 2;
/// The single-signer Ed25519 authentication scheme byte appended before hashing.
const ED25519_SCHEME: u8 = 0;
const ENTRY_FUNCTION_PAYLOAD: u8 = 2;
const ED25519_AUTHENTICATOR: u8 = 0;
const USER_TRANSACTION: u8 = 0;
const MAX_GAS_AMOUNT: u64 = 20_000;
const MAX_GAS_UNIT_PRICE: u64 = 10_000;
/// One APT; a transfer never needs more than a small fraction of this.
const MAX_FEE_OCTAS: u64 = 100_000_000;
const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
/// Year 2100; anything later is a unit mistake (ms or µs instead of seconds).
const MAX_EXPIRATION_SECS: u64 = 4_102_444_800;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Aptos transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Aptos testnet transfers are enabled"));
    }
    Ok(())
}

/// The 32-byte account address behind the AIP-40 long form `0x` + 64 lowercase hex.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    let digits = address
        .strip_prefix("0x")
        .ok_or_else(|| invalid("address must start with 0x"))?;
    if digits.len() != 64 || digits.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid("address must be 0x and 64 lowercase hex digits"));
    }
    let bytes = hex::decode(digits).map_err(|_| invalid("address is not hex"))?;
    let out: [u8; 32] = bytes.try_into().expect("length checked");
    // 0x0..0xf are reserved framework accounts, never a user's wallet.
    if out[..31].iter().all(|b| *b == 0) && out[31] < 0x10 {
        return Err(invalid("reserved framework address"));
    }
    Ok(out)
}

pub fn encode_address(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// `sha3-256(pubkey || 0x00)`: the address of a fresh single-key Ed25519
/// account. Rotated accounts keep their original address and are not supported.
pub fn address(public: &[u8]) -> Result<String> {
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    let mut hasher = Sha3_256::new();
    hasher.update(public);
    hasher.update([ED25519_SCHEME]);
    Ok(encode_address(&hasher.finalize().into()))
}

fn uleb128(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn bcs_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    uleb128(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn domain(tag: &str) -> [u8; 32] {
    Sha3_256::digest(tag.as_bytes()).into()
}

fn amount(value: &str, what: &str) -> Result<u64> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} must be a u64 decimal")))?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(invalid(format!(
            "{what} must be a positive canonical integer"
        )));
    }
    Ok(parsed)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AptosTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal octas (1 APT = 100,000,000 octas); never a JSON floating-point number.
    pub octas: String,
    /// The sender's next account sequence number, decimal. It makes the transaction single-use.
    pub sequence_number: String,
    /// Gas units the sender allows; the fee charged is at most this times the unit price.
    pub max_gas_amount: u64,
    /// Octas per gas unit.
    pub gas_unit_price: u64,
    /// Unix seconds; validators drop the transaction once block time passes this.
    pub expiration_timestamp_secs: u64,
}

impl AptosTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native APT transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.octas {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Aptos intent")),
        }
        let lifetime_ms =
            i128::from(self.expiration_timestamp_secs) * 1000 - i128::from(intent.created_at_ms);
        if lifetime_ms <= 0 || lifetime_ms > i128::from(MAX_LIFETIME_MS) {
            return Err(invalid("expiration must fall within a day of the intent"));
        }
        self.raw_transaction()?;
        Ok(())
    }

    /// BCS of `RawTransaction`; the signer signs its domain-separated form.
    pub fn raw_transaction(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let octas = amount(&self.octas, "amount")?;
        let sequence = match self.sequence_number.as_str() {
            "0" => 0,
            other => amount(other, "sequence number")?,
        };
        if self.max_gas_amount == 0 || self.max_gas_amount > MAX_GAS_AMOUNT {
            return Err(invalid(format!(
                "max gas amount must be between 1 and {MAX_GAS_AMOUNT}"
            )));
        }
        if self.gas_unit_price == 0 || self.gas_unit_price > MAX_GAS_UNIT_PRICE {
            return Err(invalid(format!(
                "gas unit price must be between 1 and {MAX_GAS_UNIT_PRICE}"
            )));
        }
        if self.max_gas_amount * self.gas_unit_price > MAX_FEE_OCTAS {
            return Err(invalid("maximum fee exceeds one APT"));
        }
        if self.expiration_timestamp_secs == 0
            || self.expiration_timestamp_secs > MAX_EXPIRATION_SECS
        {
            return Err(invalid("expiration must be unix seconds"));
        }
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(&from);
        out.extend_from_slice(&sequence.to_le_bytes());
        out.push(ENTRY_FUNCTION_PAYLOAD);
        let mut framework = [0u8; 32];
        framework[31] = 1;
        out.extend_from_slice(&framework);
        bcs_bytes(&mut out, b"aptos_account");
        bcs_bytes(&mut out, b"transfer");
        uleb128(&mut out, 0);
        uleb128(&mut out, 2);
        bcs_bytes(&mut out, &to);
        bcs_bytes(&mut out, &octas.to_le_bytes());
        out.extend_from_slice(&self.max_gas_amount.to_le_bytes());
        out.extend_from_slice(&self.gas_unit_price.to_le_bytes());
        out.extend_from_slice(&self.expiration_timestamp_secs.to_le_bytes());
        out.push(TESTNET_CHAIN_ID);
        Ok(out)
    }

    /// `sha3-256("APTOS::RawTransaction") || bcs(raw)`; Ed25519 signs these bytes directly.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let raw = self.raw_transaction()?;
        let mut message = domain("APTOS::RawTransaction").to_vec();
        message.extend_from_slice(&raw);
        Ok(message)
    }

    /// Wraps an Ed25519 signature over `signing_message` into the BCS `SignedTransaction`
    /// for `POST /transactions` and returns it with the hash explorers show.
    pub fn signed(&self, public: &[u8; 32], signature: &[u8; 64]) -> Result<(String, String)> {
        if address(public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let message = self.signing_message()?;
        VerifyingKey::from_bytes(public)
            .map_err(|_| invalid("public key is not an Ed25519 point"))?
            .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        let mut wire = self.raw_transaction()?;
        wire.push(ED25519_AUTHENTICATOR);
        bcs_bytes(&mut wire, public);
        bcs_bytes(&mut wire, signature);
        let mut hasher = Sha3_256::new();
        hasher.update(domain("APTOS::Transaction"));
        hasher.update([USER_TRANSACTION]);
        hasher.update(&wire);
        let hash: [u8; 32] = hasher.finalize().into();
        Ok((
            format!("0x{}", hex::encode(wire)),
            format!("0x{}", hex::encode(hash)),
        ))
    }

    /// `secret` is the 32-byte Ed25519 seed of the account at `m/44'/637'/0'/0'/i'`.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let signature = key.sign(&self.signing_message()?).to_bytes();
        self.signed(&public, &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::{derive_ed25519, parse_path, Mnemonic};
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    const SENDER: &str = "0xcc405722b15c00a19d37e51d9a756de1e61b780ad0935f3363bc7fce64edbdad";
    const RECIPIENT: &str = "0x978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa";

    fn tx() -> AptosTx {
        AptosTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            octas: "150000000".into(),
            sequence_number: "7".into(),
            max_gas_amount: 2000,
            gas_unit_price: 100,
            expiration_timestamp_secs: 1_760_000_600,
        }
    }

    fn intent(tx: &AptosTx) -> TxIntent {
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
                amount: Amount(tx.octas.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 1_760_000_000_000,
        }
    }

    #[test]
    fn address_matches_published_sdk_vector() {
        // @aptos-labs/ts-sdk unit-test Ed25519 key 0xc5338cd2…efa5.
        let public =
            hex::decode("de19e5d1880cac87d57484ce9ed2e84cf0f9599f12e7cc3a52e4e7657a763f2c")
                .unwrap();
        assert_eq!(address(&public).unwrap(), RECIPIENT);
        let seven = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        assert_eq!(address(&seven).unwrap(), SENDER);
        // ts-sdk `Account.fromDerivationPath` at m/44'/637'/0'/0'/0' for the
        // "abandon … about" mnemonic: the seed the core's SLIP-10 derivation must produce.
        let seed = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
        .to_seed("");
        let petra = derive_ed25519(&*seed, &parse_path("m/44'/637'/0'/0'/0'").unwrap()).unwrap();
        assert_eq!(
            hex::encode(petra.secret()),
            "cc92c0eaf80206d817f150e21917f797e49cf644a33ac514de3c316baa2f1bf5"
        );
        assert_eq!(
            hex::encode(&petra.public),
            "a686f0309ab80312979606cfccc10ea2740147ae6888351488d11c46f08fbf60"
        );
        assert_eq!(
            address(&petra.public).unwrap(),
            "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf"
        );
        assert!(address(&public[..31]).is_err());
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes(&RECIPIENT.to_uppercase().replacen("0X", "0x", 1)).is_err());
        assert!(address_bytes(&RECIPIENT[2..]).is_err());
        assert!(address_bytes("0x1").is_err());
        assert!(address_bytes(&format!("0x{}", "0".repeat(64))).is_err());
        assert!(address_bytes(&format!("0x{}1", "0".repeat(63))).is_err());
        assert!(address_bytes(&format!("0x{}", "g".repeat(64))).is_err());
        assert_eq!(encode_address(&address_bytes(SENDER).unwrap()), SENDER);
    }

    /// Bytes and hash produced by `@aptos-labs/ts-sdk` 7.5.0 for these fields; Ed25519 is
    /// deterministic, so the signed bytes match exactly. The TypeScript adapter pins RAW_VECTOR too.
    #[test]
    fn encoding_matches_the_official_sdk() {
        let t = tx();
        assert_eq!(hex::encode(t.raw_transaction().unwrap()), RAW_VECTOR);
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{SIGNED_VECTOR}"));
        assert_eq!(hash, HASH_VECTOR);
    }
    const RAW_VECTOR: &str = "cc405722b15c00a19d37e51d9a756de1e61b780ad0935f3363bc7fce64edbdad07000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa0880d1f00800000000d0070000000000006400000000000000587ae7680000000002";
    const SIGNED_VECTOR: &str = "cc405722b15c00a19d37e51d9a756de1e61b780ad0935f3363bc7fce64edbdad07000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa0880d1f00800000000d0070000000000006400000000000000587ae76800000000020020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c40d470aff68b8e1aa3d7210140520d9ab949df0d310c5a5e14f8865cc39bb7ed742ad0be147e2c1f9aadacf4efa0c0ccccbbed6e20ecc8a000ed28546177e39500";
    const HASH_VECTOR: &str = "0xdb94298325234b017360f255cc13ebab45dba88a371c5e401df7d640c29952c9";

    #[test]
    fn signature_verifies_over_the_signing_message() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, _) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let raw = t.raw_transaction().unwrap();
        assert_eq!(&wire[..raw.len()], raw.as_slice());
        let auth = &wire[raw.len()..];
        assert_eq!(auth.len(), 1 + 1 + 32 + 1 + 64);
        assert_eq!(&auth[..2], &[ED25519_AUTHENTICATOR, 32]);
        assert_eq!(auth[34], 64);
        let public = VerifyingKey::from_bytes(auth[2..34].try_into().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&auth[35..]).unwrap();
        public
            .verify_strict(&t.signing_message().unwrap(), &signature)
            .unwrap();
        assert_eq!(address(&public.to_bytes()).unwrap(), t.from);
        let mut forged = signature.to_bytes();
        forged[0] ^= 1;
        assert!(t.signed(&public.to_bytes(), &forged).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let refused = |f: &dyn Fn(&mut AptosTx)| {
            let mut t = base.clone();
            f(&mut t);
            t.raw_transaction().is_err()
        };
        assert!(refused(&|t| t.chain_id = "aptos:1".into()));
        assert!(refused(&|t| t.chain_id = "aptos:126".into()));
        assert!(refused(&|t| t.octas = "0".into()));
        assert!(refused(&|t| t.octas = "0150000000".into()));
        assert!(refused(&|t| t.octas = "18446744073709551616".into()));
        assert!(refused(&|t| t.octas = "1.5".into()));
        assert!(refused(&|t| t.sequence_number = "07".into()));
        assert!(refused(&|t| t.sequence_number = "-1".into()));
        assert!(refused(&|t| t.to = t.from.clone()));
        assert!(refused(&|t| t.to = "0x1".into()));
        assert!(refused(&|t| t.max_gas_amount = 0));
        assert!(refused(&|t| t.max_gas_amount = MAX_GAS_AMOUNT + 1));
        assert!(refused(&|t| t.gas_unit_price = 0));
        assert!(refused(&|t| {
            t.max_gas_amount = MAX_GAS_AMOUNT;
            t.gas_unit_price = MAX_GAS_UNIT_PRICE;
        }));
        assert!(refused(&|t| t.expiration_timestamp_secs = 1_760_000_600_000));
        let mut zero_seq = base.clone();
        zero_seq.sequence_number = "0".into();
        assert!(zero_seq.raw_transaction().is_ok());

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "150000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = SENDER.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{TESTNET}:fa:0xa");
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.created_at_ms = 1_760_000_600_000;
        assert!(base.check_matches_intent(&i).is_err());
        i.created_at_ms = 1_760_000_600_000 - MAX_LIFETIME_MS as i64 - 1;
        assert!(base.check_matches_intent(&i).is_err());

        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "octas": "1",
            "sequenceNumber": "0", "maxGasAmount": 10, "gasUnitPrice": 100,
            "expirationTimestampSecs": 1_760_000_600u64, "payload": "00"
        });
        assert!(serde_json::from_value::<AptosTx>(extra).is_err());
    }
}
