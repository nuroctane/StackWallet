//! Native SUI transfers. The core BCS-encodes the whole `TransactionData::V1`
//! from checked fields: one programmable transaction that splits the amount
//! off the gas coin and transfers it, the sender paying gas from a bounded set
//! of its own coin objects, and no expiration.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

pub const TESTNET: &str = "sui:testnet";
pub const MAINNET: &str = "sui:mainnet";
pub const DEVNET: &str = "sui:devnet";

/// Signature scheme flag for Ed25519, both in the address preimage and the serialized signature.
const ED25519_FLAG: u8 = 0x00;
/// Intent scope TransactionData, version V0, app id Sui.
const TX_INTENT: [u8; 3] = [0, 0, 0];
const MAX_GAS_COINS: usize = 16;
/// The protocol refuses a gas price below the reference price or above this.
pub const MAX_GAS_PRICE: u64 = 100_000;
/// 1 SUI; a budget beyond this is refused rather than silently paid.
pub const MAX_GAS_BUDGET: u64 = 1_000_000_000;
/// The cheapest transaction charges at least 1000 computation units.
const MIN_GAS_UNITS: u64 = 1_000;
/// Versions travel as JSON numbers; keep them exactly representable in TypeScript.
const MAX_VERSION: u64 = (1 << 53) - 1;
/// Length of a serialized Ed25519 signature: flag, signature, public key.
pub const SIGNATURE_LEN: usize = 1 + 64 + 32;

type Blake2b256 = Blake2b<U32>;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Sui transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Sui testnet transfers are enabled"));
    }
    Ok(())
}

/// The 32 bytes behind `0x` + 64 hex digits. Short (`0x2`) forms are refused so
/// an address has one spelling.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    let digits = address
        .strip_prefix("0x")
        .filter(|d| d.len() == 64)
        .ok_or_else(|| invalid("address must be 0x followed by 64 hex digits"))?;
    let raw = hex::decode(digits).map_err(|_| invalid("address is not hex"))?;
    Ok(raw.try_into().expect("32 bytes"))
}

fn canonical_address(address: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = address_bytes(address)?;
    if encode_address(&bytes) != address {
        return Err(invalid(format!("{what} must be lowercase hex")));
    }
    Ok(bytes)
}

pub fn encode_address(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// blake2b-256(flag || public key) for an Ed25519 key.
pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    let mut h = Blake2b256::new();
    h.update([ED25519_FLAG]);
    h.update(key);
    Ok(encode_address(&h.finalize().into()))
}

fn canonical_u64(value: &str, what: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} is not a decimal integer")))?;
    if n == 0 || n.to_string() != value {
        return Err(invalid(format!("{what} must be a positive canonical u64")));
    }
    Ok(n)
}

/// A coin object the sender owns, at the version and digest the adapter read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuiObjectRef {
    pub object_id: String,
    pub version: u64,
    /// Base58 of the 32-byte object digest.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuiTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal MIST (1 SUI = 1,000,000,000 MIST); never a JSON floating-point number.
    pub mist: String,
    /// Coin objects that pay gas; they are merged into the gas coin the amount is split from.
    pub gas_payment: Vec<SuiObjectRef>,
    /// MIST per computation unit; at least the epoch's reference gas price.
    pub gas_price: u64,
    /// The most MIST the transaction may charge for gas.
    pub gas_budget: u64,
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn object_digest(digest: &str) -> Result<[u8; 32]> {
    let raw = bs58::decode(digest)
        .into_vec()
        .map_err(|_| invalid("object digest is not base58"))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| invalid("object digest must be 32 bytes"))?;
    if bs58::encode(bytes).into_string() != digest {
        return Err(invalid("non-canonical object digest"));
    }
    Ok(bytes)
}

fn blake2b256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

impl SuiTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native SUI transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.mist {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Sui intent")),
        }
        self.tx_bcs()?;
        Ok(())
    }

    /// BCS of `TransactionData::V1`.
    pub fn tx_bcs(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = canonical_address(&self.from, "sender")?;
        let to = canonical_address(&self.to, "recipient")?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u64(&self.mist, "amount")?;
        if self.gas_price == 0 || self.gas_price > MAX_GAS_PRICE {
            return Err(invalid("gas price is outside the accepted range"));
        }
        if self.gas_budget < self.gas_price * MIN_GAS_UNITS || self.gas_budget > MAX_GAS_BUDGET {
            return Err(invalid("gas budget is outside the accepted range"));
        }
        if self.gas_payment.is_empty() || self.gas_payment.len() > MAX_GAS_COINS {
            return Err(invalid("gas payment must name 1 to 16 coin objects"));
        }
        let mut coins = Vec::with_capacity(self.gas_payment.len());
        for coin in &self.gas_payment {
            let id = canonical_address(&coin.object_id, "gas object id")?;
            if coins.iter().any(|(seen, _, _)| *seen == id) {
                return Err(invalid("gas payment repeats a coin object"));
            }
            if coin.version == 0 || coin.version > MAX_VERSION {
                return Err(invalid("gas object version is out of range"));
            }
            coins.push((id, coin.version, object_digest(&coin.digest)?));
        }

        let mut out = Vec::with_capacity(200 + 72 * coins.len());
        // TransactionData::V1, TransactionKind::ProgrammableTransaction
        out.extend_from_slice(&[0, 0]);
        // inputs: Pure(u64 amount), Pure(address recipient)
        out.push(2);
        out.extend_from_slice(&[0, 8]);
        put_u64(&mut out, amount);
        out.extend_from_slice(&[0, 32]);
        out.extend_from_slice(&to);
        // commands: SplitCoins(GasCoin, [Input(0)]), TransferObjects([Result(0)], Input(1))
        out.push(2);
        out.extend_from_slice(&[2, 0, 1, 1, 0, 0]);
        out.extend_from_slice(&[1, 1, 2, 0, 0, 1, 1, 0]);
        out.extend_from_slice(&from);
        // GasData { payment, owner = sender, price, budget }
        out.push(coins.len() as u8);
        for (id, version, digest) in &coins {
            out.extend_from_slice(id);
            put_u64(&mut out, *version);
            out.push(32);
            out.extend_from_slice(digest);
        }
        out.extend_from_slice(&from);
        put_u64(&mut out, self.gas_price);
        put_u64(&mut out, self.gas_budget);
        // TransactionExpiration::None
        out.push(0);
        Ok(out)
    }

    /// blake2b-256(intent || bcs): the message the Ed25519 key signs.
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        Ok(blake2b256(&[&TX_INTENT, &self.tx_bcs()?]))
    }

    /// base58(blake2b-256("TransactionData::" || bcs)): the digest explorers show.
    pub fn digest(&self) -> Result<String> {
        let hash = blake2b256(&[b"TransactionData::", &self.tx_bcs()?]);
        Ok(bs58::encode(hash).into_string())
    }

    /// Returns `0x` hex of the transaction bytes followed by the 97-byte serialized
    /// signature, and the transaction digest.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if address(&key.verifying_key().to_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let digest = self.signing_digest()?;
        self.assemble(
            &key.sign(&digest).to_bytes(),
            &key.verifying_key().to_bytes(),
        )
    }

    /// The wire for a signature made elsewhere (a threshold ceremony), accepted
    /// only if the key derives the sender address and the signature verifies.
    pub fn assemble(&self, signature: &[u8; 64], public: &[u8; 32]) -> Result<(String, String)> {
        if address(public)? != self.from {
            return Err(invalid("public key does not derive the sender address"));
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(public)
            .map_err(|_| invalid("sender key is not an Ed25519 point"))?;
        key.verify_strict(
            &self.signing_digest()?,
            &ed25519_dalek::Signature::from_bytes(signature),
        )
        .map_err(|_| invalid("signature does not verify against the sender"))?;
        let mut wire = self.tx_bcs()?;
        wire.push(ED25519_FLAG);
        wire.extend_from_slice(signature);
        wire.extend_from_slice(public);
        Ok((format!("0x{}", hex::encode(wire)), self.digest()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::{derive_ed25519, parse_path, Mnemonic};
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use base64::Engine as _;

    const SECRET: [u8; 32] = [7u8; 32];
    /// `Ed25519Keypair.fromSecretKey(new Uint8Array(32).fill(7))` in `@mysten/sui` 1.45.2.
    const SENDER: &str = "0xa0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233da";
    /// The Sui SDK's keypair test mnemonic, path m/44'/784'/0'/0'/0'.
    const MNEMONIC: &str = "film crazy soon outside stand loop subway crumble thrive popular green nuclear struggle pistol arm wife phrase warfare march wheat nephew ask sunny firm";
    const RECIPIENT: &str = "0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133";

    fn coin(byte: u8, version: u64, digest: u8) -> SuiObjectRef {
        SuiObjectRef {
            object_id: format!("0x{}", hex::encode([byte; 32])),
            version,
            digest: bs58::encode([digest; 32]).into_string(),
        }
    }

    fn tx() -> SuiTx {
        SuiTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            mist: "1500000".into(),
            gas_payment: vec![coin(0x11, 42, 0x22)],
            gas_price: 1000,
            gas_budget: 5_000_000,
        }
    }

    fn intent(tx: &SuiTx) -> TxIntent {
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
                amount: Amount(tx.mist.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn addresses_match_the_sdk() {
        let public = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        assert_eq!(address(&public).unwrap(), SENDER);
        let seed = Mnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let k0 = derive_ed25519(&*seed, &parse_path("m/44'/784'/0'/0'/0'").unwrap()).unwrap();
        assert_eq!(address(&k0.public).unwrap(), RECIPIENT);
        let k1 = derive_ed25519(&*seed, &parse_path("m/44'/784'/0'/0'/1'").unwrap()).unwrap();
        assert_eq!(
            address(&k1.public).unwrap(),
            "0xe46a2af9d3ed2062b4b5e6b47b07a4a404d922fef0d29e3f51c0d7f43e088601"
        );
        assert!(address(&[0u8; 33]).is_err());
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes("0x2").is_err());
        assert!(address_bytes(&RECIPIENT[2..]).is_err());
        assert!(address_bytes(&format!("{RECIPIENT}00")).is_err());
        assert!(address_bytes(&RECIPIENT.replace('a', "g")).is_err());
        // Uppercase is the same account for intent comparison but not a canonical tx field.
        let upper = format!("0x{}", RECIPIENT[2..].to_uppercase());
        assert_eq!(
            address_bytes(&upper).unwrap(),
            address_bytes(RECIPIENT).unwrap()
        );
        let mut t = tx();
        t.to = upper.clone();
        assert!(t.tx_bcs().is_err());
        let mut i = intent(&tx());
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = upper;
        }
        tx().check_matches_intent(&i).unwrap();
    }

    /// `Transaction` built and signed by `@mysten/sui` 1.45.2 for the same fields
    /// (`.nur/sui-sdk/vector.mjs`); the TypeScript adapter asserts the same bytes.
    #[test]
    fn transaction_matches_the_sdk_vectors() {
        let one = tx();
        assert_eq!(hex::encode(one.tx_bcs().unwrap()), BCS_ONE);
        assert_eq!(one.digest().unwrap(), DIGEST_ONE);
        let (wire, digest) = one.sign(&SECRET).unwrap();
        assert_eq!(digest, DIGEST_ONE);
        let wire = hex::decode(wire.strip_prefix("0x").unwrap()).unwrap();
        let (body, sig) = wire.split_at(wire.len() - SIGNATURE_LEN);
        assert_eq!(hex::encode(body), BCS_ONE);
        let b64 = base64::engine::general_purpose::STANDARD;
        assert_eq!(b64.encode(sig), SIGNATURE_ONE);

        let two = SuiTx {
            gas_payment: vec![coin(0x11, 42, 0x22), coin(0x33, 7, 0x44)],
            ..tx()
        };
        assert_eq!(hex::encode(two.tx_bcs().unwrap()), BCS_TWO);
        assert_eq!(two.digest().unwrap(), DIGEST_TWO);
        let (wire, _) = two.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(
            b64.encode(&wire[wire.len() - SIGNATURE_LEN..]),
            SIGNATURE_TWO
        );
    }
    const BCS_ONE: &str = "000002000860e31600000000000020a2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133020200010100000101020000010100a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233da0111111111111111111111111111111111111111111111111111111111111111112a00000000000000202222222222222222222222222222222222222222222222222222222222222222a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233dae803000000000000404b4c000000000000";
    const DIGEST_ONE: &str = "8LcP7xBrPoZQeKavX1L3aDsku2U7q7PyPcKge8YXNp31";
    const SIGNATURE_ONE: &str = "ALXGu6o7C+a0kizXho4bCriBBUHK4LqbJCs5JdcSsE5InySileG1HOe3QhhAPVwfIbDfVWx/gGeXXpfDaevz9ATqSmxj4pxSCr71UHsTLsX5lUd2rr6+e5JCHuppFEbSLA==";
    const BCS_TWO: &str = "000002000860e31600000000000020a2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133020200010100000101020000010100a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233da0211111111111111111111111111111111111111111111111111111111111111112a0000000000000020222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330700000000000000204444444444444444444444444444444444444444444444444444444444444444a0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233dae803000000000000404b4c000000000000";
    const DIGEST_TWO: &str = "EXLf3pP1MZM5m6RJxYfPghiS6CiuiCaEZ5Z2QQosiJrn";
    const SIGNATURE_TWO: &str = "AE0FYwXasKaaHXK8XpMspOVbg6uPtdMwJH5Dm43JJ8xiN64dYtBGvelRWcJmZWcOP8VIdd+GjOV421wO4Z25mgzqSmxj4pxSCr71UHsTLsX5lUd2rr6+e5JCHuppFEbSLA==";

    #[test]
    fn signature_verifies_over_the_intent_digest() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, _) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.strip_prefix("0x").unwrap()).unwrap();
        let sig = &wire[wire.len() - SIGNATURE_LEN..];
        assert_eq!(sig[0], ED25519_FLAG);
        let public = SigningKey::from_bytes(&SECRET).verifying_key();
        assert_eq!(sig[65..], public.to_bytes());
        let s = ed25519_dalek::Signature::from_slice(&sig[1..65]).unwrap();
        public
            .verify_strict(&t.signing_digest().unwrap(), &s)
            .unwrap();
        assert!(t.assemble(&[0u8; 64], &public.to_bytes()).is_err());
        let other = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(t.assemble(&s.to_bytes(), &other).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.tx_bcs().is_err());
        assert!(check_chain(MAINNET).is_err());
        assert!(check_chain(DEVNET).is_err());
        assert!(check_chain("iota:testnet").is_err());
        for bad in ["0", "01500000", "-1", "1.5", "18446744073709551616", ""] {
            let mut t = base.clone();
            t.mist = bad.into();
            assert!(t.tx_bcs().is_err(), "{bad}");
        }
        let mut t = base.clone();
        t.mist = u64::MAX.to_string();
        assert!(t.tx_bcs().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.tx_bcs().is_err());
        let mut t = base.clone();
        t.gas_price = 0;
        assert!(t.tx_bcs().is_err());
        t.gas_price = MAX_GAS_PRICE + 1;
        assert!(t.tx_bcs().is_err());
        let mut t = base.clone();
        t.gas_budget = MAX_GAS_BUDGET + 1;
        assert!(t.tx_bcs().is_err());
        t.gas_budget = t.gas_price * MIN_GAS_UNITS - 1;
        assert!(t.tx_bcs().is_err());
        let mut t = base.clone();
        t.gas_payment.clear();
        assert!(t.tx_bcs().is_err());
        t.gas_payment = (0..17).map(|i| coin(i, 1, 1)).collect();
        assert!(t.tx_bcs().is_err());
        t.gas_payment.truncate(16);
        assert!(t.tx_bcs().is_ok());
        let mut t = base.clone();
        t.gas_payment.push(coin(0x11, 43, 0x23));
        assert!(t.tx_bcs().is_err());
        let mut t = base.clone();
        t.gas_payment[0].version = 0;
        assert!(t.tx_bcs().is_err());
        t.gas_payment[0].version = MAX_VERSION + 1;
        assert!(t.tx_bcs().is_err());
        let mut t = base.clone();
        t.gas_payment[0].digest = bs58::encode([1u8; 31]).into_string();
        assert!(t.tx_bcs().is_err());
        t.gas_payment[0].digest = "0OIl".into();
        assert!(t.tx_bcs().is_err());
        let mut t = base.clone();
        t.gas_payment[0].object_id = "0x11".into();
        assert!(t.tx_bcs().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = SENDER.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = "sui:testnet:coin:0x2::sui::SUI".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "mist": "1",
            "gasPayment": [{"objectId": base.gas_payment[0].object_id, "version": 1, "digest": base.gas_payment[0].digest}],
            "gasPrice": 1000, "gasBudget": 5000000, "sponsor": base.from
        });
        assert!(serde_json::from_value::<SuiTx>(extra).is_err());
        let extra_coin = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "mist": "1",
            "gasPayment": [{"objectId": base.gas_payment[0].object_id, "version": 1, "digest": base.gas_payment[0].digest, "owner": base.from}],
            "gasPrice": 1000, "gasBudget": 5000000
        });
        assert!(serde_json::from_value::<SuiTx>(extra_coin).is_err());
    }
}
