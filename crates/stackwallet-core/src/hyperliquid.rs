//! HyperCore USDC transfers (`usdSend`). The core builds the EIP-712
//! `HyperliquidTransaction:UsdSend` digest and the `/exchange` request body
//! from checked fields, so an adapter cannot sign any other action type.

use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

pub const TESTNET: &str = "hype:testnet";
/// `signatureChainId` only selects the EIP-712 domain the wallet signs under;
/// `hyperliquidChain` is what separates mainnet from testnet. The SDKs use 0x66eee.
pub const SIGNATURE_CHAIN_ID: u64 = 0x66eee;
const HYPERLIQUID_CHAIN: &str = "Testnet";
/// 1e9 USDC, far above any real balance and well inside u64 and 2^53.
pub const MAX_USD_MICRO: u64 = 1_000_000_000_000_000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// 2023-01-01; HyperCore did not exist before, so an older nonce is a bug.
const MIN_TIME_MS: u64 = 1_672_531_200_000;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const USD_SEND_TYPE: &str = "HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)";

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Hyperliquid transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Hyperliquid testnet transfers are enabled"));
    }
    Ok(())
}

/// The canonical spelling is lowercase `0x` hex: `destination` is signed as an
/// EIP-712 `string`, so its exact characters are part of the digest.
pub fn address_bytes(address: &str) -> Result<[u8; 20]> {
    let body = address
        .strip_prefix("0x")
        .filter(|b| {
            b.len() == 40
                && b.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .ok_or_else(|| invalid("address must be 0x and 40 lowercase hex characters"))?;
    let bytes: [u8; 20] = hex::decode(body)
        .map_err(|_| invalid("address is not hex"))?
        .try_into()
        .expect("length checked");
    if bytes == [0; 20] {
        return Err(invalid("zero address"));
    }
    Ok(bytes)
}

pub fn address(public: &[u8]) -> Result<String> {
    Ok(format!(
        "0x{}",
        hex::encode(evm::address_from_public(public)?)
    ))
}

/// Micro-USDC as the shortest decimal string: `1000000` is `"1"`, `1500000` is `"1.5"`.
pub fn amount_string(micro: u64) -> String {
    let whole = micro / 1_000_000;
    let frac = micro % 1_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let digits = format!("{frac:06}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

fn word(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

fn domain_separator() -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend(evm::keccak256(DOMAIN_TYPE.as_bytes()));
    buf.extend(evm::keccak256(b"HyperliquidSignTransaction"));
    buf.extend(evm::keccak256(b"1"));
    buf.extend(word(SIGNATURE_CHAIN_ID));
    buf.extend([0u8; 32]);
    evm::keccak256(&buf)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HyperliquidTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal micro-USDC (1 USDC = 1,000,000) taken from the sender's perp account.
    pub hl_usd_micro: String,
    /// Unix ms; signed as `time` and sent as the action nonce.
    pub time: u64,
    /// Unix ms the adapter prepared the transfer.
    pub built_at_ms: u64,
}

impl HyperliquidTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only perp USDC transfers are enabled"));
                }
                if evm::parse_address(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.hl_usd_micro {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Hyperliquid intent")),
        }
        self.digest()?;
        Ok(())
    }

    fn micro(&self) -> Result<u64> {
        let micro = self
            .hl_usd_micro
            .parse::<u64>()
            .map_err(|_| invalid("amount must be a decimal integer"))?;
        if micro == 0 || micro > MAX_USD_MICRO || micro.to_string() != self.hl_usd_micro {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        Ok(micro)
    }

    /// Every field the action carries, after all checks: (destination, amount string).
    fn checked(&self) -> Result<(String, String)> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let micro = self.micro()?;
        if self.time < MIN_TIME_MS
            || self.time > MAX_SAFE_INTEGER
            || self.built_at_ms < MIN_TIME_MS
            || self.built_at_ms > MAX_SAFE_INTEGER
            || self.time.abs_diff(self.built_at_ms) > DAY_MS
        {
            return Err(invalid("time must fall within a day of the build time"));
        }
        Ok((self.to.clone(), amount_string(micro)))
    }

    /// The EIP-712 struct hash of the `UsdSend` message.
    pub fn struct_hash(&self) -> Result<[u8; 32]> {
        let (destination, amount) = self.checked()?;
        let mut buf = Vec::with_capacity(5 * 32);
        buf.extend(evm::keccak256(USD_SEND_TYPE.as_bytes()));
        buf.extend(evm::keccak256(HYPERLIQUID_CHAIN.as_bytes()));
        buf.extend(evm::keccak256(destination.as_bytes()));
        buf.extend(evm::keccak256(amount.as_bytes()));
        buf.extend(word(self.time));
        Ok(evm::keccak256(&buf))
    }

    /// `keccak256(0x1901 || domainSeparator || structHash)`: the signed digest.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut buf = vec![0x19, 0x01];
        buf.extend(domain_separator());
        buf.extend(self.struct_hash()?);
        Ok(evm::keccak256(&buf))
    }

    /// The API returns no transaction hash and the L1 hash embeds the block
    /// position, so the ledger tracks `keccak256(digest)` and the adapter
    /// resolves the explorer hash from the sender's history.
    pub fn local_id(&self) -> Result<String> {
        Ok(format!(
            "0x{}",
            hex::encode(evm::keccak256(&self.digest()?))
        ))
    }

    /// The `action` object exactly as signed.
    pub fn action_json(&self) -> Result<String> {
        let (destination, amount) = self.checked()?;
        Ok(format!(
            r#"{{"type":"usdSend","signatureChainId":"0x{SIGNATURE_CHAIN_ID:x}","hyperliquidChain":"{HYPERLIQUID_CHAIN}","destination":"{destination}","amount":"{amount}","time":{}}}"#,
            self.time
        ))
    }

    /// The `/exchange` request body for a signature with y parity 0 or 1.
    pub fn assemble(&self, parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Result<String> {
        if parity > 1 {
            return Err(invalid("y parity must be 0 or 1"));
        }
        Ok(format!(
            r#"{{"action":{},"nonce":{},"signature":{{"r":"0x{}","s":"0x{}","v":{}}}}}"#,
            self.action_json()?,
            self.time,
            hex::encode(r),
            hex::encode(s),
            27 + parity
        ))
    }

    /// Returns the `/exchange` JSON body and the local transfer id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let (parity, r, s) = evm::sign_digest(secret, &self.digest()?)?;
        Ok((self.assemble(parity, &r, &s)?, self.local_id()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    /// The key `hyperliquid-python-sdk` uses in `tests/signing_test.py`.
    const SDK_SECRET: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x01, 0x23,
    ];
    const SECRET: [u8; 32] = [7u8; 32];
    const RECIPIENT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

    fn sender(secret: &[u8; 32]) -> String {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into()).unwrap();
        address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn tx() -> HyperliquidTx {
        HyperliquidTx {
            chain_id: TESTNET.into(),
            from: sender(&SECRET),
            to: RECIPIENT.into(),
            hl_usd_micro: "1500000".into(),
            time: 1_760_000_000_000,
            built_at_ms: 1_760_000_000_000,
        }
    }

    fn intent(tx: &HyperliquidTx) -> TxIntent {
        TxIntent {
            id: "tx".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(tx.chain_id.clone()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: "0x5E9EE1089755C3435139848e47e6635505D5a13A".into(),
                asset: AssetRef(format!("{}:native", tx.chain_id)),
                amount: Amount(tx.hl_usd_micro.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_published_vector() {
        // Private key 1 is 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf on Ethereum.
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(sender(&one), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        assert_eq!(
            sender(&SECRET),
            "0x4a62316623ad457f02cdc5d997ded67a383ec569"
        );
    }

    #[test]
    fn amounts_render_like_the_sdk() {
        assert_eq!(amount_string(1_000_000), "1");
        assert_eq!(amount_string(1_500_000), "1.5");
        assert_eq!(amount_string(1), "0.000001");
        assert_eq!(amount_string(10_010_000), "10.01");
        assert_eq!(amount_string(MAX_USD_MICRO), "1000000000");
    }

    /// `test_sign_usd_transfer_action` in hyperliquid-python-sdk: same key,
    /// message and expected (r, s, v); RFC 6979 makes the signature deterministic.
    #[test]
    fn signature_matches_the_python_sdk_vector() {
        let t = HyperliquidTx {
            chain_id: TESTNET.into(),
            from: sender(&SDK_SECRET),
            to: RECIPIENT.into(),
            hl_usd_micro: "1000000".into(),
            time: 1_687_816_341_423,
            built_at_ms: 1_687_816_341_423,
        };
        assert_eq!(hex::encode(domain_separator()), DOMAIN_VECTOR);
        assert_eq!(hex::encode(t.digest().unwrap()), SDK_DIGEST);
        let (wire, id) = t.sign(&SDK_SECRET).unwrap();
        assert!(wire.ends_with(
            r#""signature":{"r":"0x637b37dd731507cdd24f46532ca8ba6eec616952c56218baeff04144e4a77073","s":"0x11a6a24900e6e314136d2592e2f8d502cd89b7c15b198e1bee043c9589f9fad7","v":27}}"#
        ));
        assert_eq!(id, t.local_id().unwrap());
    }
    const DOMAIN_VECTOR: &str = "feb1393ca4412a4ca577bd51d04f0a77033514c602f4d0a11490fb95f7428df6";
    const SDK_DIGEST: &str = "cacf7585cc49ca60c6c5fb3001e226c0ca03c46252c893eea574c78907b7cebe";

    /// The TypeScript adapter builds the same body and digest and asserts these exact values.
    #[test]
    fn wire_matches_the_adapter_vector() {
        let t = tx();
        assert_eq!(hex::encode(t.digest().unwrap()), DIGEST_VECTOR);
        assert_eq!(t.local_id().unwrap(), LOCAL_ID_VECTOR);
        let (wire, _) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, WIRE_VECTOR);
        let parsed: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed["nonce"], parsed["action"]["time"]);
    }
    const DIGEST_VECTOR: &str = "0ebbb76c717b9789670bdd716db9325f366a3180e42899cf0f6a35d2c2bbd822";
    const LOCAL_ID_VECTOR: &str =
        "0xc9070af983a3b8cb20601f8f36307232b8f3b9da029b938cdd8fb8d1c86b8248";
    const WIRE_VECTOR: &str = r#"{"action":{"type":"usdSend","signatureChainId":"0x66eee","hyperliquidChain":"Testnet","destination":"0x5e9ee1089755c3435139848e47e6635505d5a13a","amount":"1.5","time":1760000000000},"nonce":1760000000000,"signature":{"r":"0x51356fc44db0039e410f9907cf2e2526c70394c4814b3b8a34d488483dade90c","s":"0x3dcc4cc273b54e3781fb1ca9d0e239808966d097d888b23e31966c38cb0dc416","v":28}}"#;

    #[test]
    fn signature_recovers_to_the_sender_over_the_digest() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, _) = t.sign(&SECRET).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&wire).unwrap();
        let sig = &parsed["signature"];
        let r = hex::decode(sig["r"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let s = hex::decode(sig["s"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let v = sig["v"].as_u64().unwrap() as u8;
        let recovered = VerifyingKey::recover_from_prehash(
            &t.digest().unwrap(),
            &Signature::from_slice(&[r, s].concat()).unwrap(),
            RecoveryId::from_byte(v - 27).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "hype:mainnet".into();
        assert!(t.digest().is_err());
        let mut t = base.clone();
        t.hl_usd_micro = "01500000".into();
        assert!(t.digest().is_err());
        for bad in ["0", "-1", "1.5", "1000000000000001", "18446744073709551616"] {
            let mut t = base.clone();
            t.hl_usd_micro = bad.into();
            assert!(t.digest().is_err(), "{bad}");
        }
        let mut t = base.clone();
        t.hl_usd_micro = MAX_USD_MICRO.to_string();
        assert!(t.digest().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.digest().is_err());
        for bad in [
            "0x5E9EE1089755C3435139848e47e6635505D5a13A",
            "5e9ee1089755c3435139848e47e6635505d5a13a",
            "0x5e9ee1089755c3435139848e47e6635505d5a1",
            "0x0000000000000000000000000000000000000000",
            "0x5e9ee1089755c3435139848e47e6635505d5a13a\"",
        ] {
            let mut t = base.clone();
            t.to = bad.into();
            assert!(t.digest().is_err(), "{bad}");
        }
        let mut t = base.clone();
        t.time = t.built_at_ms + DAY_MS + 1;
        assert!(t.digest().is_err());
        let mut t = base.clone();
        t.time = t.built_at_ms - DAY_MS - 1;
        assert!(t.digest().is_err());
        let mut t = base.clone();
        t.time = MIN_TIME_MS - 1;
        t.built_at_ms = MIN_TIME_MS - 1;
        assert!(t.digest().is_err());
        let mut t = base.clone();
        t.time = MAX_SAFE_INTEGER + 1;
        t.built_at_ms = MAX_SAFE_INTEGER;
        assert!(t.digest().is_err());
        assert!(base.assemble(2, &[1; 32], &[1; 32]).is_err());

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{TESTNET}:spot:150");
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId("hype:mainnet".into());
        assert!(base.check_matches_intent(&i).is_err());

        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = sender(&SECRET);
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "hlUsdMicro": "1",
            "time": base.time, "builtAtMs": base.built_at_ms, "vaultAddress": RECIPIENT
        });
        assert!(serde_json::from_value::<HyperliquidTx>(extra).is_err());
    }
}
