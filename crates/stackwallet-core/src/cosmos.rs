//! Bounded native bank sends. Rust constructs the protobuf sign document from
//! intent-bound fields rather than trusting an adapter's arbitrary message bytes.
use crate::{
    evm,
    intent::{TxIntent, TxIntentKind},
    CoreError, Result,
};
use bech32::{primitives::decode::CheckedHrpstring, Bech32, Hrp};
use prost::Message;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TESTNET: &str = "cosmos:osmo-test-5";
fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Cosmos transfer",
        reason: reason.into(),
    }
}
pub fn check_chain(chain: &str) -> Result<()> {
    if chain != TESTNET {
        return Err(invalid("only Osmosis Testnet native transfers are enabled"));
    }
    Ok(())
}
fn number(value: &str, positive: bool) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid("integer exceeds u64"))?;
    if n.to_string() != value || (positive && n == 0) {
        return Err(invalid("non-canonical or zero integer"));
    }
    Ok(n)
}
fn address_bytes(address: &str) -> Result<Vec<u8>> {
    hrp_bytes(address, "osmo")
}
fn hrp_bytes(address: &str, hrp: &str) -> Result<Vec<u8>> {
    if address.len() > 90 {
        return Err(invalid("address too long"));
    }
    let checked =
        CheckedHrpstring::new::<Bech32>(address).map_err(|_| invalid("invalid bech32 address"))?;
    let bytes: Vec<_> = checked.byte_iter().collect();
    if checked.hrp().as_str() != hrp
        || ![20, 32].contains(&bytes.len())
        || bytes.iter().all(|b| *b == 0)
        || bech32::encode::<Bech32>(checked.hrp(), &bytes)
            .map_err(|_| invalid("invalid address"))?
            != address
    {
        return Err(invalid(format!("expected a canonical {hrp} address")));
    }
    Ok(bytes)
}
pub fn address(public: &[u8]) -> Result<String> {
    let key =
        k256::PublicKey::from_sec1_bytes(public).map_err(|_| invalid("invalid public key"))?;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let hash = Ripemd160::digest(Sha256::digest(key.to_encoded_point(true).as_bytes()));
    bech32::encode::<Bech32>(Hrp::parse("osmo").unwrap(), &hash)
        .map_err(|_| invalid("invalid address"))
}

/// The one message a transaction carries. Staking messages name a validator
/// operator (`osmovaloper…`) in `to`; a reward claim moves no `amount` ("0").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CosmosMsg {
    #[default]
    Send,
    Delegate,
    Undelegate,
    WithdrawRewards,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CosmosTx {
    #[serde(default, skip_serializing_if = "is_send")]
    pub msg: CosmosMsg,
    pub chain_id: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub public_key_hex: String,
    pub account_number: String,
    pub sequence: String,
    pub gas_limit: u64,
    pub fee_amount: String,
    pub timeout_height: u64,
}
fn is_send(m: &CosmosMsg) -> bool {
    *m == CosmosMsg::Send
}

impl CosmosTx {
    pub fn validate(&self) -> Result<()> {
        check_chain(&self.chain_id)?;
        address_bytes(&self.from)?;
        match self.msg {
            CosmosMsg::Send => {
                address_bytes(&self.to)?;
            }
            _ => {
                hrp_bytes(&self.to, "osmovaloper")?;
            }
        }
        if self.from == self.to {
            return Err(invalid("sender and recipient must differ"));
        }
        if self.msg == CosmosMsg::WithdrawRewards {
            if self.amount != "0" {
                return Err(invalid("a reward claim carries no amount"));
            }
        } else {
            number(&self.amount, true)?;
        }
        number(&self.account_number, false)?;
        number(&self.sequence, false)?;
        let fee = number(&self.fee_amount, true)?;
        if fee > 1_000_000
            || self.gas_limit == 0
            || self.gas_limit > 1_000_000
            || self.timeout_height == 0
            || self.timeout_height > 9_007_199_254_740_991
        {
            return Err(invalid("fee, gas or timeout out of bounds"));
        }
        let public =
            hex::decode(&self.public_key_hex).map_err(|_| invalid("invalid public key hex"))?;
        if public.len() != 33
            || hex::encode(&public) != self.public_key_hex
            || address(&public)? != self.from
        {
            return Err(invalid("public key differs from sender"));
        }
        Ok(())
    }
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        self.validate()?;
        if intent.chain_id.0 != self.chain_id {
            return Err(invalid("chain differs from intent"));
        }
        let native = format!("{TESTNET}:native");
        match (&intent.kind, self.msg) {
            (TxIntentKind::Transfer { to, asset, amount }, CosmosMsg::Send)
            | (
                TxIntentKind::Stake {
                    validator: to,
                    asset,
                    amount,
                },
                CosmosMsg::Delegate,
            )
            | (
                TxIntentKind::Unstake {
                    validator: to,
                    asset,
                    amount,
                },
                CosmosMsg::Undelegate,
            ) if *to == self.to && amount.0 == self.amount && asset.0 == native => Ok(()),
            (TxIntentKind::Claim { validator: Some(v) }, CosmosMsg::WithdrawRewards)
                if *v == self.to =>
            {
                Ok(())
            }
            _ => Err(invalid(
                "message, destination, amount or asset differs from the intent",
            )),
        }
    }
    pub fn body_auth(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        self.validate()?;
        let coin = |amount: &str| Coin {
            denom: "uosmo".into(),
            amount: amount.into(),
        };
        let stake = || Stake {
            delegator_address: self.from.clone(),
            validator_address: self.to.clone(),
            amount: Some(coin(&self.amount)),
        };
        let message = match self.msg {
            CosmosMsg::Send => Any {
                type_url: "/cosmos.bank.v1beta1.MsgSend".into(),
                value: BankSend {
                    from_address: self.from.clone(),
                    to_address: self.to.clone(),
                    amount: vec![coin(&self.amount)],
                }
                .encode_to_vec(),
            },
            CosmosMsg::Delegate => Any {
                type_url: "/cosmos.staking.v1beta1.MsgDelegate".into(),
                value: stake().encode_to_vec(),
            },
            CosmosMsg::Undelegate => Any {
                type_url: "/cosmos.staking.v1beta1.MsgUndelegate".into(),
                value: stake().encode_to_vec(),
            },
            CosmosMsg::WithdrawRewards => Any {
                type_url: "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward".into(),
                value: WithdrawReward {
                    delegator_address: self.from.clone(),
                    validator_address: self.to.clone(),
                }
                .encode_to_vec(),
            },
        };
        let body = Body {
            messages: vec![message],
            timeout_height: self.timeout_height,
        };
        let auth = Auth {
            signer_infos: vec![SignerInfo {
                public_key: Some(Any {
                    type_url: "/cosmos.crypto.secp256k1.PubKey".into(),
                    value: PublicKey {
                        key: hex::decode(&self.public_key_hex).unwrap(),
                    }
                    .encode_to_vec(),
                }),
                mode_info: Some(ModeInfo {
                    single: Some(Single { mode: 1 }),
                }),
                sequence: number(&self.sequence, false)?,
            }],
            fee: Some(Fee {
                amount: vec![coin(&self.fee_amount)],
                gas_limit: self.gas_limit,
            }),
        };
        Ok((body.encode_to_vec(), auth.encode_to_vec()))
    }
    pub fn sign_doc(&self) -> Result<Vec<u8>> {
        let (body_bytes, auth_info_bytes) = self.body_auth()?;
        Ok(SignDoc {
            body_bytes,
            auth_info_bytes,
            chain_id: "osmo-test-5".into(),
            account_number: number(&self.account_number, false)?,
        }
        .encode_to_vec())
    }
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        if hex::encode(key.verifying_key().to_encoded_point(true).as_bytes()) != self.public_key_hex
        {
            return Err(invalid("signing key differs from public key"));
        }
        let digest: [u8; 32] = Sha256::digest(self.sign_doc()?).into();
        let (_, r, s) = evm::sign_digest(secret, &digest)?;
        let (body_bytes, auth_info_bytes) = self.body_auth()?;
        let raw = Raw {
            body_bytes,
            auth_info_bytes,
            signatures: vec![[r.as_slice(), s.as_slice()].concat()],
        }
        .encode_to_vec();
        Ok((
            format!("0x{}", hex::encode(&raw)),
            hex::encode_upper(Sha256::digest(&raw)),
        ))
    }
}

#[derive(Clone, PartialEq, Message)]
struct Coin {
    #[prost(string, tag = "1")]
    denom: String,
    #[prost(string, tag = "2")]
    amount: String,
}
#[derive(Clone, PartialEq, Message)]
struct Any {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct BankSend {
    #[prost(string, tag = "1")]
    from_address: String,
    #[prost(string, tag = "2")]
    to_address: String,
    #[prost(message, repeated, tag = "3")]
    amount: Vec<Coin>,
}
#[derive(Clone, PartialEq, Message)]
struct Stake {
    #[prost(string, tag = "1")]
    delegator_address: String,
    #[prost(string, tag = "2")]
    validator_address: String,
    #[prost(message, optional, tag = "3")]
    amount: Option<Coin>,
}
#[derive(Clone, PartialEq, Message)]
struct WithdrawReward {
    #[prost(string, tag = "1")]
    delegator_address: String,
    #[prost(string, tag = "2")]
    validator_address: String,
}
#[derive(Clone, PartialEq, Message)]
struct Body {
    #[prost(message, repeated, tag = "1")]
    messages: Vec<Any>,
    #[prost(uint64, tag = "3")]
    timeout_height: u64,
}
#[derive(Clone, PartialEq, Message)]
struct PublicKey {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct Single {
    #[prost(int32, tag = "1")]
    mode: i32,
}
#[derive(Clone, PartialEq, Message)]
struct ModeInfo {
    #[prost(message, optional, tag = "1")]
    single: Option<Single>,
}
#[derive(Clone, PartialEq, Message)]
struct SignerInfo {
    #[prost(message, optional, tag = "1")]
    public_key: Option<Any>,
    #[prost(message, optional, tag = "2")]
    mode_info: Option<ModeInfo>,
    #[prost(uint64, tag = "3")]
    sequence: u64,
}
#[derive(Clone, PartialEq, Message)]
struct Fee {
    #[prost(message, repeated, tag = "1")]
    amount: Vec<Coin>,
    #[prost(uint64, tag = "2")]
    gas_limit: u64,
}
#[derive(Clone, PartialEq, Message)]
struct Auth {
    #[prost(message, repeated, tag = "1")]
    signer_infos: Vec<SignerInfo>,
    #[prost(message, optional, tag = "2")]
    fee: Option<Fee>,
}
#[derive(Clone, PartialEq, Message)]
struct SignDoc {
    #[prost(bytes = "vec", tag = "1")]
    body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    auth_info_bytes: Vec<u8>,
    #[prost(string, tag = "3")]
    chain_id: String,
    #[prost(uint64, tag = "4")]
    account_number: u64,
}
#[derive(Clone, PartialEq, Message)]
struct Raw {
    #[prost(bytes = "vec", tag = "1")]
    body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    auth_info_bytes: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    signatures: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tx() -> CosmosTx {
        let key = k256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let public = key.verifying_key().to_encoded_point(true);
        CosmosTx {
            msg: CosmosMsg::Send,
            chain_id: TESTNET.into(),
            from: address(public.as_bytes()).unwrap(),
            to: address(
                k256::ecdsa::SigningKey::from_bytes((&[8; 32]).into())
                    .unwrap()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes(),
            )
            .unwrap(),
            amount: "1000".into(),
            public_key_hex: hex::encode(public),
            account_number: "42".into(),
            sequence: "0".into(),
            gas_limit: 100000,
            fee_amount: "2500".into(),
            timeout_height: 123,
        }
    }
    #[test]
    fn signature_binds_chain_fee_timeout_and_bank_message() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let tx = tx();
        let (hex, hash) = tx.sign(&[7; 32]).unwrap();
        let bytes = hex::decode(hex.trim_start_matches("0x")).unwrap();
        assert_eq!(hash, hex::encode_upper(Sha256::digest(&bytes)));
        let raw = Raw::decode(bytes.as_slice()).unwrap();
        let sig = k256::ecdsa::Signature::from_slice(&raw.signatures[0]).unwrap();
        assert!(sig.normalize_s().is_none());
        let key =
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&hex::decode(&tx.public_key_hex).unwrap())
                .unwrap();
        key.verify_prehash(&Sha256::digest(tx.sign_doc().unwrap()), &sig)
            .unwrap();
        let mut changed = tx.clone();
        changed.fee_amount = "2501".into();
        assert!(key
            .verify_prehash(&Sha256::digest(changed.sign_doc().unwrap()), &sig)
            .is_err());
        assert!(tx.sign(&[8; 32]).is_err());
    }
    #[test]
    fn rejects_hidden_messages_and_unsafe_fields() {
        let original = tx();
        for value in ["0", "01", "18446744073709551616"] {
            let mut bad = original.clone();
            bad.amount = value.into();
            assert!(bad.validate().is_err());
        }
        let mut bad = original.clone();
        bad.chain_id = "cosmos:osmosis-1".into();
        assert!(bad.validate().is_err());
        let mut bad = original.clone();
        bad.to = bad.from.clone();
        assert!(bad.validate().is_err());
        let mut bad = original.clone();
        bad.fee_amount = "1000001".into();
        assert!(bad.validate().is_err());
        let mut json = serde_json::to_value(original).unwrap();
        json["memo"] = serde_json::json!("extra");
        assert!(serde_json::from_value::<CosmosTx>(json).is_err());
    }
    #[test]
    fn staking_messages_name_a_validator_and_match_the_intent() {
        use crate::intent::{Amount, Proposer, TxIntent};
        use crate::model::{AssetRef, ChainId};
        let base = tx();
        let operator =
            bech32::encode::<Bech32>(Hrp::parse("osmovaloper").unwrap(), &[9u8; 20]).unwrap();
        let delegate = CosmosTx {
            msg: CosmosMsg::Delegate,
            to: operator.clone(),
            ..base.clone()
        };
        delegate.validate().unwrap();
        // A delegation to an account address, or a send to an operator, is refused.
        assert!(CosmosTx {
            to: base.to.clone(),
            ..delegate.clone()
        }
        .validate()
        .is_err());
        assert!(CosmosTx {
            msg: CosmosMsg::Send,
            ..delegate.clone()
        }
        .validate()
        .is_err());
        let claim = CosmosTx {
            msg: CosmosMsg::WithdrawRewards,
            amount: "0".into(),
            ..delegate.clone()
        };
        claim.validate().unwrap();
        assert!(CosmosTx {
            amount: "5".into(),
            ..claim.clone()
        }
        .validate()
        .is_err());

        let intent = |kind| TxIntent {
            id: "t".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(TESTNET.into()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind,
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        };
        let asset = AssetRef(format!("{TESTNET}:native"));
        let stake = intent(TxIntentKind::Stake {
            validator: operator.clone(),
            asset: asset.clone(),
            amount: Amount("1000".into()),
        });
        delegate.check_matches_intent(&stake).unwrap();
        // The same fields as an undelegation do not satisfy a stake intent.
        assert!(CosmosTx {
            msg: CosmosMsg::Undelegate,
            ..delegate.clone()
        }
        .check_matches_intent(&stake)
        .is_err());
        claim
            .check_matches_intent(&intent(TxIntentKind::Claim {
                validator: Some(operator),
            }))
            .unwrap();
        assert!(claim
            .check_matches_intent(&intent(TxIntentKind::Claim { validator: None }))
            .is_err());
        let (body, _) = delegate.body_auth().unwrap();
        let decoded = Body::decode(body.as_slice()).unwrap();
        assert_eq!(
            decoded.messages[0].type_url,
            "/cosmos.staking.v1beta1.MsgDelegate"
        );
        // A plain send keeps its exact serialized form.
        let json = serde_json::to_value(&base).unwrap();
        assert!(json.get("msg").is_none());
    }
}
