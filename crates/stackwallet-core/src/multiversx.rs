//! Native EGLD transfers. The core writes the canonical JSON the protocol
//! signs and the protobuf whose blake2b-256 is the transaction hash from
//! checked fields, so an adapter cannot add data, guardians or relayers.

use bech32::{primitives::decode::CheckedHrpstring, Bech32, Hrp};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 references are the protocol `chainID` (devnet "D", mainnet "1").
pub const DEVNET: &str = "mvx:D";
const DEVNET_CHAIN_ID: &str = "D";
const HRP: &str = "erd";
const VERSION: u32 = 2;
/// `erd_min_gas_limit`: a move-balance transfer without data costs exactly this.
pub const MIN_GAS_LIMIT: u64 = 50_000;
/// Gas above the move-balance cost is only charged at 1%, but there is no
/// reason for a plain transfer to carry much of it.
pub const MAX_GAS_LIMIT: u64 = 1_000_000;
/// `erd_min_gas_price` on devnet and mainnet.
pub const MIN_GAS_PRICE: u64 = 1_000_000_000;
pub const MAX_GAS_PRICE: u64 = 100 * MIN_GAS_PRICE;
/// The capped EGLD supply (31,415,926 EGLD); no balance can exceed it.
pub const MAX_ATTOEGLD: u128 = 31_415_926 * 1_000_000_000_000_000_000;
/// The signed JSON carries the nonce as a number; keep it exact in JavaScript.
const MAX_NONCE: u64 = (1 << 53) - 1;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "MultiversX transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != DEVNET {
        return Err(invalid("only MultiversX Devnet transfers are enabled"));
    }
    Ok(())
}

/// The 32-byte account behind a canonical lowercase `erd1…` bech32 address.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    if address.len() != 62 {
        return Err(invalid("address must be 62 characters"));
    }
    let checked =
        CheckedHrpstring::new::<Bech32>(address).map_err(|_| invalid("invalid bech32 address"))?;
    if checked.hrp().as_str() != HRP {
        return Err(invalid("not an erd1 address"));
    }
    let bytes: [u8; 32] = checked
        .byte_iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| invalid("address must be 32 bytes"))?;
    if bytes == [0; 32] {
        return Err(invalid("zero address"));
    }
    if encode_address(&bytes) != address {
        return Err(invalid("non-canonical address"));
    }
    Ok(bytes)
}

pub fn encode_address(bytes: &[u8; 32]) -> String {
    bech32::encode::<Bech32>(Hrp::parse(HRP).expect("static hrp"), bytes).expect("short address")
}

/// The account of a 32-byte Ed25519 public key.
pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key).map_err(|_| invalid("not an Ed25519 point"))?;
    Ok(encode_address(&key))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MultiversxTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal atto-EGLD (1 EGLD = 10^18); never a JSON floating-point number.
    pub attoegld: String,
    /// The sender account's next nonce.
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
}

struct Checked {
    from: [u8; 32],
    to: [u8; 32],
    value: u128,
}

impl MultiversxTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native EGLD transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.attoegld {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported MultiversX intent")),
        }
        self.check()?;
        Ok(())
    }

    fn check(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let value = self
            .attoegld
            .parse::<u128>()
            .map_err(|_| invalid("amount is not a decimal integer"))?;
        if value == 0 || value > MAX_ATTOEGLD || value.to_string() != self.attoegld {
            return Err(invalid(
                "amount must be a positive canonical integer within the EGLD supply",
            ));
        }
        if self.nonce > MAX_NONCE {
            return Err(invalid("nonce is out of range"));
        }
        if !(MIN_GAS_LIMIT..=MAX_GAS_LIMIT).contains(&self.gas_limit) {
            return Err(invalid("gas limit is out of range for a plain transfer"));
        }
        if !(MIN_GAS_PRICE..=MAX_GAS_PRICE).contains(&self.gas_price) {
            return Err(invalid("gas price is out of range"));
        }
        Ok(Checked { from, to, value })
    }

    /// The exact JSON the protocol verifies the sender's signature over: no
    /// data, usernames, options, guardian or relayer.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.check()?;
        Ok(self.json(None).into_bytes())
    }

    fn json(&self, signature: Option<&[u8; 64]>) -> String {
        let signature = signature
            .map(|s| format!(",\"signature\":\"{}\"", hex::encode(s)))
            .unwrap_or_default();
        format!(
            "{{\"nonce\":{},\"value\":\"{}\",\"receiver\":\"{}\",\"sender\":\"{}\",\"gasPrice\":{},\"gasLimit\":{},\"chainID\":\"{}\",\"version\":{}{}}}",
            self.nonce,
            self.attoegld,
            self.to,
            self.from,
            self.gas_price,
            self.gas_limit,
            DEVNET_CHAIN_ID,
            VERSION,
            signature,
        )
    }

    /// mx-chain-go's protobuf `Transaction`; its blake2b-256 is the hash.
    pub fn proto(&self, signature: &[u8; 64]) -> Result<Vec<u8>> {
        let checked = self.check()?;
        // The node's big-int encoding: a 0x00 sign byte, then the minimal big-endian magnitude.
        let magnitude = checked.value.to_be_bytes();
        let start = magnitude.iter().position(|b| *b != 0).expect("positive");
        let mut value = vec![0];
        value.extend_from_slice(&magnitude[start..]);
        Ok(ProtoTx {
            nonce: self.nonce,
            value,
            rcv_addr: checked.to.to_vec(),
            snd_addr: checked.from.to_vec(),
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            chain_id: DEVNET_CHAIN_ID.as_bytes().to_vec(),
            version: VERSION,
            signature: signature.to_vec(),
        }
        .encode_to_vec())
    }

    pub fn hash(&self, signature: &[u8; 64]) -> Result<[u8; 32]> {
        Ok(Blake2b::<U32>::digest(self.proto(signature)?).into())
    }

    /// Returns the signed transaction JSON (for `POST /transactions`) and its hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if encode_address(&key.verifying_key().to_bytes()) != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let message = self.signing_bytes()?;
        self.assemble(&key.sign(&message).to_bytes())
    }

    /// The wire transaction for a signature made elsewhere (a threshold
    /// ceremony), accepted only if it verifies against the sender.
    pub fn assemble(&self, signature: &[u8; 64]) -> Result<(String, String)> {
        let message = self.signing_bytes()?;
        let key = VerifyingKey::from_bytes(&address_bytes(&self.from)?)
            .map_err(|_| invalid("sender is not an Ed25519 point"))?;
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        Ok((
            self.json(Some(signature)),
            hex::encode(self.hash(signature)?),
        ))
    }
}

#[derive(Clone, PartialEq, Message)]
struct ProtoTx {
    #[prost(uint64, tag = "1")]
    nonce: u64,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    rcv_addr: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    snd_addr: Vec<u8>,
    #[prost(uint64, tag = "7")]
    gas_price: u64,
    #[prost(uint64, tag = "8")]
    gas_limit: u64,
    #[prost(bytes = "vec", tag = "10")]
    chain_id: Vec<u8>,
    #[prost(uint32, tag = "11")]
    version: u32,
    #[prost(bytes = "vec", tag = "12")]
    signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::{derive_ed25519, parse_path, Mnemonic};
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7; 32];
    /// Ed25519 seed `[7; 32]` and `[8; 32]`, per `@multiversx/sdk-core` 16.0.0.
    const SENDER: &str = "erd1af9xcclzn3fq40h42pa3xtk9lx25wa4wh6l8hyjzrm4xj9zx6gkq38dn52";
    const RECIPIENT: &str = "erd1zwv0vtrdrfzhc5d6df9470da9a5le2fjzcscmjye0eqkh5taj09qjg4tnr";
    /// The MultiversX docs' "alice" test wallet.
    const ALICE_WORDS: &str = "moral volcano peasant pass circle pen over picture flat shop clap goat never lyrics gather prepare woman film husband gravity behind test tiger improve";

    /// sdk-core 16.0.0 `computeBytesForSigning`, signature, `ProtoSerializer` and
    /// `computeTransactionHash` for these fields; the adapter pins the same values.
    const SIGNING_VECTOR: &str = r#"{"nonce":42,"value":"1500000000000000000","receiver":"erd1zwv0vtrdrfzhc5d6df9470da9a5le2fjzcscmjye0eqkh5taj09qjg4tnr","sender":"erd1af9xcclzn3fq40h42pa3xtk9lx25wa4wh6l8hyjzrm4xj9zx6gkq38dn52","gasPrice":1000000000,"gasLimit":50000,"chainID":"D","version":2}"#;
    const SIGNATURE_VECTOR: &str = "7d2c795035e59013e1d7aa043a19565537c87cbe9cfff4b9220d29ab1364b43ed6329c8df70d01b44b6a03b2e2782476699f0d55ffc5758ef8a489ce84095c08";
    const PROTO_VECTOR: &str = "082a12090014d1120d7b1600001a201398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca2a20ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c388094ebdc0340d08603520144580262407d2c795035e59013e1d7aa043a19565537c87cbe9cfff4b9220d29ab1364b43ed6329c8df70d01b44b6a03b2e2782476699f0d55ffc5758ef8a489ce84095c08";
    const HASH_VECTOR: &str = "c59864fb0b542181600d1974dbe74f183e64838adbbf5e66cb4c233c805bb416";
    /// Nonce 0, value 1: the devnet gateway's `/transaction/simulate` reported this hash.
    const NONCE_ZERO_HASH: &str =
        "af045283bc1da1b9cc97be16a7fbbefb8b42098d2f46600218f0563cbf227902";

    fn tx() -> MultiversxTx {
        MultiversxTx {
            chain_id: DEVNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            attoegld: "1500000000000000000".into(),
            nonce: 42,
            gas_price: 1_000_000_000,
            gas_limit: 50_000,
        }
    }

    fn intent(tx: &MultiversxTx) -> TxIntent {
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
                amount: Amount(tx.attoegld.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn addresses_match_the_sdk_and_published_wallets() {
        let public = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        assert_eq!(address(&public).unwrap(), SENDER);
        assert_eq!(encode_address(&address_bytes(SENDER).unwrap()), SENDER);
        let seed = Mnemonic::parse(ALICE_WORDS).unwrap().to_seed("");
        let alice = derive_ed25519(&*seed, &parse_path("m/44'/508'/0'/0'/0'").unwrap()).unwrap();
        assert_eq!(
            hex::encode(alice.secret()),
            "413f42575f7f26fad3317a778771212fdb80245850981e48b58a4f25e344e8f9"
        );
        assert_eq!(
            address(&alice.public).unwrap(),
            "erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th"
        );
        let second = derive_ed25519(&*seed, &parse_path("m/44'/508'/0'/0'/1'").unwrap()).unwrap();
        assert_eq!(
            address(&second.public).unwrap(),
            "erd1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruqzu66jx"
        );
        assert!(address(&public[..31]).is_err());
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes(&SENDER.to_uppercase()).is_err());
        assert!(address_bytes(&format!("{}3", &SENDER[..61])).is_err());
        assert!(address_bytes(&encode_address(&[0; 32])).is_err());
        let other_hrp = bech32::encode::<Bech32>(Hrp::parse("xrd").unwrap(), &[5; 32]).unwrap();
        assert!(address_bytes(&other_hrp).is_err());
        let m = bech32::encode::<bech32::Bech32m>(Hrp::parse(HRP).unwrap(), &[5; 32]).unwrap();
        assert!(address_bytes(&m).is_err());
        let short = bech32::encode::<Bech32>(Hrp::parse(HRP).unwrap(), &[5; 31]).unwrap();
        assert!(address_bytes(&short).is_err());
    }

    #[test]
    fn encoding_matches_the_sdk_vectors() {
        let t = tx();
        assert_eq!(
            String::from_utf8(t.signing_bytes().unwrap()).unwrap(),
            SIGNING_VECTOR
        );
        let (wire, hash) = t.sign(&SECRET).unwrap();
        let signature: [u8; 64] = hex::decode(SIGNATURE_VECTOR).unwrap().try_into().unwrap();
        assert_eq!(hex::encode(t.proto(&signature).unwrap()), PROTO_VECTOR);
        assert_eq!(hash, HASH_VECTOR);
        let parsed: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed["signature"], SIGNATURE_VECTOR);
        assert_eq!(parsed["value"], "1500000000000000000");
        assert_eq!(parsed.as_object().unwrap().len(), 9);

        let zero = MultiversxTx {
            nonce: 0,
            attoegld: "1".into(),
            ..tx()
        };
        let (_, hash) = zero.sign(&SECRET).unwrap();
        assert_eq!(hash, NONCE_ZERO_HASH);
    }

    #[test]
    fn signature_verifies_over_the_signing_json() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, _) = t.sign(&SECRET).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&wire).unwrap();
        let sig: [u8; 64] = hex::decode(parsed["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        SigningKey::from_bytes(&SECRET)
            .verifying_key()
            .verify_strict(
                &t.signing_bytes().unwrap(),
                &ed25519_dalek::Signature::from_bytes(&sig),
            )
            .unwrap();
        assert_eq!(t.assemble(&sig).unwrap(), t.sign(&SECRET).unwrap());
        let mut forged = sig;
        forged[0] ^= 1;
        assert!(t.assemble(&forged).is_err());
        assert!(t.sign(&[8; 32]).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let refused = |f: &dyn Fn(&mut MultiversxTx)| {
            let mut t = base.clone();
            f(&mut t);
            assert!(t.signing_bytes().is_err(), "{t:?}");
        };
        refused(&|t| t.chain_id = "mvx:1".into());
        refused(&|t| t.chain_id = "mvx:T".into());
        refused(&|t| t.attoegld = "0".into());
        refused(&|t| t.attoegld = "01500000000000000000".into());
        refused(&|t| t.attoegld = "+1".into());
        refused(&|t| t.attoegld = "1.5".into());
        refused(&|t| t.attoegld = (MAX_ATTOEGLD + 1).to_string());
        refused(&|t| t.to = t.from.clone());
        refused(&|t| t.to = "erd1invalid".into());
        refused(&|t| t.gas_limit = MIN_GAS_LIMIT - 1);
        refused(&|t| t.gas_limit = MAX_GAS_LIMIT + 1);
        refused(&|t| t.gas_price = MIN_GAS_PRICE - 1);
        refused(&|t| t.gas_price = MAX_GAS_PRICE + 1);
        refused(&|t| t.nonce = 1 << 53);
        let mut max = base.clone();
        max.attoegld = MAX_ATTOEGLD.to_string();
        assert!(max.signing_bytes().is_ok());

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000000000000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = SENDER.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{DEVNET}:esdt:USDC-c76f1f");
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId("mvx:1".into());
        assert!(base.check_matches_intent(&i).is_err());

        let extra = serde_json::json!({
            "chainId": DEVNET, "from": SENDER, "to": RECIPIENT, "attoegld": "1",
            "nonce": 0, "gasPrice": 1_000_000_000u64, "gasLimit": 50_000, "data": "aGk="
        });
        assert!(serde_json::from_value::<MultiversxTx>(extra).is_err());
        let ok = serde_json::json!({
            "chainId": DEVNET, "from": SENDER, "to": RECIPIENT, "attoegld": "1",
            "nonce": 0, "gasPrice": 1_000_000_000u64, "gasLimit": 50_000
        });
        assert!(serde_json::from_value::<MultiversxTx>(ok).is_ok());
    }
}
