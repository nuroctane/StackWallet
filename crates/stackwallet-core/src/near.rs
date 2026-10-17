//! Native NEAR transfers. The core Borsh-encodes the whole `Transaction` from
//! checked fields: an implicit-account signer, one `Transfer` action, a
//! bounded deposit. The recent block hash bounds the lifetime on chain.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

pub const TESTNET: &str = "near:testnet";
pub const MAINNET: &str = "near:mainnet";
const KEY_TYPE_ED25519: u8 = 0;
const ACTION_TRANSFER: u8 = 3;
/// Ten billion NEAR, several times the total supply.
pub const MAX_YOCTO: u128 = 10_000_000_000 * 10u128.pow(24);
/// Blocks after the referenced block during which the network accepts the transaction.
pub const VALIDITY_PERIOD_BLOCKS: u64 = 86_400;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "NEAR transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only NEAR testnet transfers are enabled"));
    }
    Ok(())
}

/// The implicit account id of an Ed25519 key: its 64 lowercase hex characters.
pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    Ok(hex::encode(key))
}

/// The key behind an implicit account id; named and ETH-implicit ids are refused.
pub fn implicit_key(account: &str) -> Result<[u8; 32]> {
    if account.len() != 64
        || !account
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            "sender must be a 64-character lowercase hex implicit account",
        ));
    }
    let raw = hex::decode(account).map_err(|_| invalid("invalid implicit account"))?;
    Ok(raw.try_into().expect("32 bytes"))
}

/// NEAR account id rules: 2..=64 bytes, dot-separated parts of `[a-z0-9]`
/// runs joined by single `-` or `_`.
pub fn is_valid_account_id(account: &str) -> bool {
    if !(2..=64).contains(&account.len()) {
        return false;
    }
    account.split('.').all(|part| {
        let bytes = part.as_bytes();
        !bytes.is_empty()
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_')
            && !matches!(bytes[0], b'-' | b'_')
            && !matches!(bytes[bytes.len() - 1], b'-' | b'_')
            && !bytes
                .windows(2)
                .any(|w| matches!(w[0], b'-' | b'_') && matches!(w[1], b'-' | b'_'))
    })
}

fn canonical_decimal(value: &str, what: &str) -> Result<u128> {
    let n = value
        .parse::<u128>()
        .map_err(|_| invalid(format!("{what} is not a decimal integer")))?;
    if n == 0 || n.to_string() != value {
        return Err(invalid(format!(
            "{what} must be a positive canonical integer"
        )));
    }
    Ok(n)
}

fn block_hash_bytes(value: &str) -> Result<[u8; 32]> {
    let raw = bs58::decode(value)
        .into_vec()
        .map_err(|_| invalid("block hash is not base58"))?;
    let hash: [u8; 32] = raw
        .try_into()
        .map_err(|_| invalid("block hash must be 32 bytes"))?;
    if bs58::encode(hash).into_string() != value {
        return Err(invalid("non-canonical block hash"));
    }
    Ok(hash)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NearTx {
    pub chain_id: String,
    /// Implicit account of the signing key (64 lowercase hex characters).
    pub from: String,
    /// Implicit or named account id.
    pub to: String,
    /// Decimal yoctoNEAR (1 NEAR = 10^24); never a JSON floating-point number.
    pub yocto: String,
    /// Decimal u64: the access key's current nonce plus one.
    pub nonce: String,
    /// Base58 hash of a recent final block; the network refuses the
    /// transaction once that block is `VALIDITY_PERIOD_BLOCKS` old.
    pub block_hash: String,
    /// Height of `block_hash`, for expiry reporting; not encoded.
    pub block_height: u64,
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

impl NearTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native NEAR transfers are enabled"));
                }
                if *to != self.to {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.yocto {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported NEAR intent")),
        }
        self.borsh()?;
        Ok(())
    }

    /// Borsh of the v0 `Transaction`.
    pub fn borsh(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let key = implicit_key(&self.from)?;
        if !is_valid_account_id(&self.to) {
            return Err(invalid("recipient is not a valid NEAR account id"));
        }
        if self.to == self.from {
            return Err(invalid("sender and recipient must differ"));
        }
        let deposit = canonical_decimal(&self.yocto, "amount")?;
        if deposit > MAX_YOCTO {
            return Err(invalid("amount exceeds the accepted maximum"));
        }
        let nonce = canonical_decimal(&self.nonce, "nonce")?;
        let nonce = u64::try_from(nonce).map_err(|_| invalid("nonce exceeds u64"))?;
        let block_hash = block_hash_bytes(&self.block_hash)?;
        if self.block_height == 0 || self.block_height > MAX_SAFE_INTEGER {
            return Err(invalid("block height is out of range"));
        }

        let mut out = Vec::with_capacity(200);
        put_str(&mut out, &self.from);
        out.push(KEY_TYPE_ED25519);
        out.extend_from_slice(&key);
        out.extend_from_slice(&nonce.to_le_bytes());
        put_str(&mut out, &self.to);
        out.extend_from_slice(&block_hash);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.push(ACTION_TRANSFER);
        out.extend_from_slice(&deposit.to_le_bytes());
        Ok(out)
    }

    /// sha256 of the Borsh transaction: the signed message and, in base58, the explorer hash.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.borsh()?).into())
    }

    pub fn txid(&self) -> Result<String> {
        Ok(bs58::encode(self.hash()?).into_string())
    }

    /// Returns the Borsh `SignedTransaction` as `0x` hex and the base58 transaction hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if hex::encode(key.verifying_key().to_bytes()) != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let hash = self.hash()?;
        self.assemble(&key.sign(&hash).to_bytes())
    }

    /// The signed transaction for a signature made elsewhere (a threshold
    /// ceremony), accepted only if it verifies against the sender's key.
    pub fn assemble(&self, signature: &[u8; 64]) -> Result<(String, String)> {
        let hash = self.hash()?;
        let key = VerifyingKey::from_bytes(&implicit_key(&self.from)?)
            .map_err(|_| invalid("sender is not an Ed25519 point"))?;
        key.verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        let mut wire = self.borsh()?;
        wire.push(KEY_TYPE_ED25519);
        wire.extend_from_slice(signature);
        Ok((
            format!("0x{}", hex::encode(wire)),
            bs58::encode(hash).into_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// Implicit account of seed `[7; 32]`, from `@near-js/crypto` KeyPair.
    const SENDER: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    /// RFC 8032 test 1 seed and its implicit account (`@near-js/crypto`).
    const RFC_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC_ACCOUNT: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// Bytes 1..=32.
    const BLOCK_HASH: &str = "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw";

    fn tx() -> NearTx {
        NearTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: "receiver.testnet".into(),
            yocto: "1500000000000000000000000".into(),
            nonce: "123456789012345".into(),
            block_hash: BLOCK_HASH.into(),
            block_height: 273_319_917,
        }
    }

    fn intent(tx: &NearTx) -> TxIntent {
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
                amount: Amount(tx.yocto.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn implicit_accounts_match_the_sdk() {
        let key = SigningKey::from_bytes(&SECRET);
        assert_eq!(address(&key.verifying_key().to_bytes()).unwrap(), SENDER);
        let rfc: [u8; 32] = hex::decode(RFC_SEED).unwrap().try_into().unwrap();
        let key = SigningKey::from_bytes(&rfc);
        assert_eq!(
            address(&key.verifying_key().to_bytes()).unwrap(),
            RFC_ACCOUNT
        );
        assert_eq!(hex::encode(implicit_key(RFC_ACCOUNT).unwrap()), RFC_ACCOUNT);
        assert!(address(&[0u8; 33]).is_err());
        assert!(implicit_key(&RFC_ACCOUNT.to_uppercase()).is_err());
        assert!(implicit_key("alice.testnet").is_err());
        assert!(implicit_key(&RFC_ACCOUNT[..62]).is_err());
    }

    #[test]
    fn account_id_rules() {
        for ok in [
            "ab",
            "alice.testnet",
            "a-b_c.near",
            "app.alice.testnet",
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            RFC_ACCOUNT,
            &"a".repeat(64),
        ] {
            assert!(is_valid_account_id(ok), "{ok}");
        }
        for bad in [
            "a",
            "",
            &"a".repeat(65),
            "Alice.testnet",
            "alice..testnet",
            ".alice",
            "alice.",
            "-alice",
            "alice-",
            "al--ice",
            "al-_ice",
            "alice@testnet",
            "alice testnet",
            "alice.testnet_",
        ] {
            assert!(!is_valid_account_id(bad), "{bad}");
        }
    }

    /// Checked against `@near-js/transactions` 2.5 (createTransaction,
    /// encodeTransaction, SignedTransaction.encode); the TypeScript adapter
    /// pins the same bytes.
    #[test]
    fn transaction_matches_the_sdk_vectors() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        assert_eq!(hex::encode(t.borsh().unwrap()), TX_VECTOR);
        assert_eq!(t.txid().unwrap(), HASH_VECTOR);
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{SIGNED_VECTOR}"));
        assert_eq!(hash, HASH_VECTOR);
    }
    const TX_VECTOR: &str = "400000006561346136633633653239633532306162656635353037623133326563356639393534373736616562656265376239323432316565613639313434366432326300ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c79df0d86487000001000000072656365697665722e746573746e65740102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200100000003000080716433b629a33d010000000000";
    const HASH_VECTOR: &str = "7Cxca3BzhUVDPn3Mh6Y266hGuHmHoUkkEfF5TGe8HQtv";
    const SIGNED_VECTOR: &str = "400000006561346136633633653239633532306162656635353037623133326563356639393534373736616562656265376239323432316565613639313434366432326300ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c79df0d86487000001000000072656365697665722e746573746e65740102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200100000003000080716433b629a33d010000000000001bfe0065918525840da2baf3a9be68d89b55ec2936a4df2aa83e8173b692fecf409820d8ed0303ff16fc40fd6d65b8ee3beee0bcbcac98af5d6de00d1bc14407";

    #[test]
    fn signature_verifies_over_the_hash() {
        let t = NearTx {
            to: RFC_ACCOUNT.into(),
            ..tx()
        };
        let (wire, id) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let body = t.borsh().unwrap();
        assert_eq!(wire.len(), body.len() + 65);
        assert_eq!(wire[..body.len()], body[..]);
        assert_eq!(wire[body.len()], KEY_TYPE_ED25519);
        let sig = ed25519_dalek::Signature::from_slice(&wire[body.len() + 1..]).unwrap();
        let public = SigningKey::from_bytes(&SECRET).verifying_key();
        public.verify_strict(&t.hash().unwrap(), &sig).unwrap();
        assert_eq!(id, bs58::encode(Sha256::digest(&body)).into_string());
        assert!(t.assemble(&[0u8; 64]).is_err());
        assert!(t.assemble(&sig.to_bytes()).is_ok());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.borsh().is_err());
        assert!(check_chain(MAINNET).is_err());
        assert!(check_chain("near:betanet").is_err());
        for bad in ["0", "01", "1.5", "-1", "", "1e24"] {
            let mut t = base.clone();
            t.yocto = bad.into();
            assert!(t.borsh().is_err(), "{bad}");
        }
        let mut t = base.clone();
        t.yocto = (MAX_YOCTO + 1).to_string();
        assert!(t.borsh().is_err());
        t.yocto = MAX_YOCTO.to_string();
        assert!(t.borsh().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.borsh().is_err());
        let mut t = base.clone();
        t.to = "Bad..id".into();
        assert!(t.borsh().is_err());
        let mut t = base.clone();
        t.from = "alice.testnet".into();
        assert!(t.borsh().is_err());
        let mut t = base.clone();
        t.nonce = "0".into();
        assert!(t.borsh().is_err());
        t.nonce = "18446744073709551616".into();
        assert!(t.borsh().is_err());
        let mut t = base.clone();
        t.block_hash = "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vig".into();
        assert!(t.borsh().is_err());
        t.block_hash = "0wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw".into();
        assert!(t.borsh().is_err());
        t.block_hash = format!("1{BLOCK_HASH}");
        assert!(t.borsh().is_err());
        let mut t = base.clone();
        t.block_height = 0;
        assert!(t.borsh().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000000000000000000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "other.testnet".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = "near:testnet:nep141:usdc.testnet".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RFC_ACCOUNT.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "yocto": "1",
            "nonce": "2", "blockHash": BLOCK_HASH, "blockHeight": 1, "memo": "hi"
        });
        assert!(serde_json::from_value::<NearTx>(extra).is_err());
    }
}
