//! Native ICX transfers (ICON / SODAX goloop). The core builds the canonical
//! `icx_sendTransaction` hash-key string from checked fields, signs its
//! sha3-256 digest (ICON uses SHA3-256, not keccak), and emits the JSON-RPC
//! params object, so an adapter cannot inject data, contracts or a call type.
//!
//! Serialization and signature byte-format are pinned against icon-sdk-js
//! 1.5.3 output (see .nur/icon-probe*.mjs) and the signature was verified
//! live: a mainnet node accepts it and rejects a bit-flipped one with
//! E2005 "Failed to verify transaction".

use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// CAIP-2 references are the network id (nid) in decimal: mainnet 0x1, Lisbon 0x2.
pub const LISBON: &str = "icon:2";
pub const MAINNET: &str = "icon:1";

const MIN_STEP_LIMIT: u64 = 100_000;
const MAX_STEP_LIMIT: u64 = 25_000_000;
/// Total supply is under a billion ICX; 1 ICX = 10^18 loop.
const MAX_LOOP: u128 = 1_000_000_000_000_000_000_000_000_000;
/// The node rejects stale or future timestamps; keep the built time close.
const MAX_TIMESTAMP_SKEW_MS: u64 = 60 * 60 * 1000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "ICON transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != LISBON {
        return Err(invalid("only ICON Lisbon transfers are enabled"));
    }
    Ok(())
}

fn nid(chain: &str) -> Result<u64> {
    match chain {
        MAINNET => Ok(1),
        LISBON => Ok(2),
        _ => Err(invalid("unknown ICON network")),
    }
}

/// The 20 bytes behind an `hx` address: sha3-256(pubkey)[12..].
pub fn address_bytes(address: &str) -> Result<[u8; 20]> {
    let hex_part = address
        .strip_prefix("hx")
        .ok_or_else(|| invalid("address must start with hx"))?;
    if hex_part.len() != 40
        || !hex_part.bytes().all(|b| b.is_ascii_hexdigit())
        || hex_part.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(invalid("address must be hx plus 40 lowercase hex chars"));
    }
    let bytes = hex::decode(hex_part).map_err(|_| invalid("address is not hex"))?;
    let out: [u8; 20] = bytes.try_into().expect("40 hex chars");
    if out.iter().all(|b| *b == 0) {
        return Err(invalid("zero address"));
    }
    Ok(out)
}

pub fn encode_address(bytes: &[u8; 20]) -> String {
    format!("hx{}", hex::encode(bytes))
}

pub fn address(public: &[u8]) -> Result<String> {
    let key = k256::PublicKey::from_sec1_bytes(public).map_err(|_| invalid("bad public key"))?;
    let point = key.to_encoded_point(false);
    let digest = Sha3_256::digest(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    Ok(encode_address(&out))
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | '.' | '{' | '}' | '[' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IconTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal loop (1 ICX = 10^18 loop); never a JSON floating-point number.
    #[serde(rename = "loop")]
    pub r#loop: String,
    /// Transaction nonce; 1 by convention on ICON.
    pub nonce: u64,
    /// Step budget; a plain transfer costs exactly 100,000 step.
    pub step_limit: u64,
    /// Microseconds since the Unix epoch.
    pub timestamp: u64,
    /// Unix ms when the adapter built the transaction.
    pub built_at_ms: u64,
}

struct Checked {
    nid: u64,
    value: u128,
}

impl IconTx {
    fn checked_fields(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let value = self
            .r#loop
            .parse::<u128>()
            .map_err(|_| invalid("amount is not a loop integer"))?;
        if value == 0 || value > MAX_LOOP || value.to_string() != self.r#loop {
            return Err(invalid("amount must be a positive canonical loop integer"));
        }
        if self.nonce == 0 || self.nonce > 1_000_000 {
            return Err(invalid("nonce out of range"));
        }
        if !(MIN_STEP_LIMIT..=MAX_STEP_LIMIT).contains(&self.step_limit) {
            return Err(invalid("step limit out of range"));
        }
        if self.timestamp == 0 || self.built_at_ms == 0 {
            return Err(invalid("missing timestamp"));
        }
        let ts_ms = self.timestamp / 1_000;
        if ts_ms.abs_diff(self.built_at_ms) > MAX_TIMESTAMP_SKEW_MS {
            return Err(invalid(
                "timestamp must be within an hour of the build time",
            ));
        }
        Ok(Checked {
            nid: nid(&self.chain_id)?,
            value,
        })
    }

    /// The fields exactly as the JSON-RPC params object and the hash key carry them.
    fn fields(&self) -> Result<[(&'static str, String); 8]> {
        let c = self.checked_fields()?;
        Ok([
            ("from", self.from.clone()),
            ("nid", format!("0x{:x}", c.nid)),
            ("nonce", format!("0x{:x}", self.nonce)),
            ("stepLimit", format!("0x{:x}", self.step_limit)),
            ("timestamp", format!("0x{:x}", self.timestamp)),
            ("to", self.to.clone()),
            ("value", format!("0x{:x}", c.value)),
            ("version", "0x3".into()),
        ])
    }

    /// `icx_sendTransaction` + sorted `key.escaped(value)` pairs, per icon-sdk-js.
    fn hash_key(&self, signature: Option<&str>) -> Result<String> {
        let mut pairs: Vec<(String, String)> = self
            .fields()?
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        if let Some(sig) = signature {
            pairs.push(("signature".into(), sig.into()));
        }
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let mut key = String::from("icx_sendTransaction");
        for (k, v) in pairs {
            key.push('.');
            key.push_str(&k);
            key.push('.');
            key.push_str(&escape(&v));
        }
        Ok(key)
    }

    /// sha3-256 of the unsigned hash key; this is what gets signed.
    pub fn sighash(&self) -> Result<[u8; 32]> {
        Ok(Sha3_256::digest(self.hash_key(None)?.as_bytes()).into())
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native ICX transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.r#loop {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported ICON intent")),
        }
        self.checked_fields()?;
        Ok(())
    }

    /// The transaction hash as the tracker shows it: 0x + sha3-256 of the signed hash key.
    pub fn txid(&self, signature: &str) -> Result<String> {
        let digest = Sha3_256::digest(self.hash_key(Some(signature))?.as_bytes());
        Ok(format!("0x{}", hex::encode(digest)))
    }

    /// Returns the `icx_sendTransaction` params JSON (ready to broadcast) and the tx hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let sighash = self.sighash()?;
        let (parity, r, s) = evm::sign_digest(secret, &sighash)?;
        // ICON carries a bare 0/1 recovery id, not Ethereum's 27/28.
        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [r.as_slice(), s.as_slice(), &[parity]].concat(),
        );
        let hash = self.txid(&signature)?;
        let mut params = serde_json::Map::new();
        for (k, v) in self.fields()? {
            params.insert(k.into(), serde_json::Value::String(v));
        }
        params.insert("signature".into(), serde_json::Value::String(signature));
        let wire = serde_json::to_string(&serde_json::Value::Object(params))
            .map_err(|_| invalid("params serialization failed"))?;
        Ok((wire, hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];
    /// icon-sdk-js 1.5.3: IconWallet.loadPrivateKey("07"*32).getAddress().
    const SENDER: &str = "hxcd5cd849ef6f20d6d22e4c0b3b3702b7c2667457";
    const RECIPIENT: &str = "hx9d8a8376e7db9f00478feb9a46f44f0d051aab57";

    fn tx() -> IconTx {
        IconTx {
            chain_id: LISBON.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            r#loop: "250000000000000000".into(),
            nonce: 1,
            step_limit: 100_000,
            timestamp: 1_760_000_000_000_000,
            built_at_ms: 1_760_000_000_000,
        }
    }

    fn intent(tx: &IconTx) -> TxIntent {
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
                amount: Amount(tx.r#loop.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_the_sdk_vector() {
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        let addr = address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(addr, SENDER);
        assert_eq!(encode_address(&address_bytes(&addr).unwrap()), addr);
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes("hxCD5CD849EF6F20D6D22E4C0B3B3702B7C2667457").is_err());
        assert!(address_bytes("cxcd5cd849ef6f20d6d22e4c0b3b3702b7c2667457").is_err());
        assert!(address_bytes("hxcd5cd849ef6f20d6d22e4c0b3b3702b7c266745").is_err());
        assert!(address_bytes("0xcd5cd849ef6f20d6d22e4c0b3b3702b7c2667457").is_err());
        assert!(address_bytes("hx0000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn hash_key_and_signature_match_the_sdk_vector() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        assert_eq!(t.hash_key(None).unwrap(), HASH_KEY);
        assert_eq!(hex::encode(t.sighash().unwrap()), SIGHASH);
        let (wire, hash) = t.sign(&SECRET).unwrap();
        // RFC6979 + low-S must reproduce icon-sdk-js byte for byte.
        let params: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(params["signature"], SIGNATURE);
        assert_eq!(params["nid"], "0x2");
        assert_eq!(params["version"], "0x3");
        assert_eq!(params["value"], "0x3782dace9d90000");
        assert_eq!(hash, TX_HASH);
        let sig = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            params["signature"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(sig.len(), 65);
        let recovered = VerifyingKey::recover_from_prehash(
            &t.sighash().unwrap(),
            &Signature::from_slice(&sig[..64]).unwrap(),
            RecoveryId::from_byte(sig[64]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
    }

    const HASH_KEY: &str = "icx_sendTransaction.from.hxcd5cd849ef6f20d6d22e4c0b3b3702b7c2667457.nid.0x2.nonce.0x1.stepLimit.0x186a0.timestamp.0x640b5eece0000.to.hx9d8a8376e7db9f00478feb9a46f44f0d051aab57.value.0x3782dace9d90000.version.0x3";
    const SIGHASH: &str = "19d06d298eefcc44a155c831f3e97c7a1bd6df68565e9d9902936879d9a1ecda";
    const SIGNATURE: &str =
        "TVo+ig+MFFtwoXjDdRBbcrogjZaKEvdxzF9iB3Ea4etZPAnFRpgSPYeA+os3TNT4Ol1TBxOGz5Z+fhEpSZ8kjwA=";
    const TX_HASH: &str = "0x12db38e5ebe22e8338cc80bf2b634465746cf0a594687688050b8605e7f25e95";

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.chain_id = "icon:7".into();
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.r#loop = "0250000000000000000".into();
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.r#loop = "0".into();
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.r#loop = "2000000000000000000000000000".into();
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.step_limit = 99_999;
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.step_limit = 25_000_001;
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.nonce = 0;
        assert!(t.checked_fields().is_err());
        let mut t = base.clone();
        t.timestamp += (MAX_TIMESTAMP_SKEW_MS + 1) * 1_000;
        assert!(t.checked_fields().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "250000000000000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": LISBON, "from": SENDER, "to": RECIPIENT, "loop": "1",
            "nonce": 1, "stepLimit": 100000, "timestamp": 1, "builtAtMs": 1,
            "data": "00"
        });
        assert!(serde_json::from_value::<IconTx>(extra).is_err());
    }
}
