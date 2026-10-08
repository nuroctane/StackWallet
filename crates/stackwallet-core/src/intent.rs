//! What the user or agent wants to do (`TxIntent`) and what the core must sign
//! (`SignRequest`). Adapters turn an intent into an unsigned transaction and
//! derive one or more sign requests from it; the core only ever sees the latter.

use serde::{Deserialize, Serialize};

use crate::model::{AssetRef, ChainId, Curve};

/// Base-unit amount as a decimal string. Chains exceed u128, so no native integer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Amount(pub String);

impl Amount {
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.bytes().all(|b| b.is_ascii_digit())
    }
}

/// Who created the intent. Approvers see this; policy may key on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Proposer {
    Human {
        device_id: String,
    },
    Agent {
        session_id: String,
        grant_id: String,
        rationale: String,
    },
    Automation {
        automation_id: String,
        run_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TxIntentKind {
    Transfer {
        to: String,
        asset: AssetRef,
        amount: Amount,
    },
    ContractCall {
        to: String,
        data_hex: String,
        value: Amount,
    },
    Swap {
        sell: AssetRef,
        sell_amount: Amount,
        buy: AssetRef,
        min_buy_amount: Amount,
        max_slippage_bps: u32,
        aggregator: String,
    },
    Stake {
        validator: String,
        asset: AssetRef,
        amount: Amount,
    },
    Unstake {
        validator: String,
        asset: AssetRef,
        amount: Amount,
    },
    Claim {
        validator: Option<String>,
    },
    IbcTransfer {
        to: String,
        asset: AssetRef,
        amount: Amount,
        channel: String,
        dest_chain: ChainId,
    },
    Psbt {
        psbt_base64: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxIntent {
    pub id: String,
    pub wallet_id: String,
    pub account_id: String,
    pub chain_id: ChainId,
    pub proposer: Proposer,
    #[serde(flatten)]
    pub kind: TxIntentKind,
    /// Approximate USD value in micro-dollars, supplied by the market package and
    /// re-checked by policy against its own price snapshot.
    pub usd_micros: Option<u64>,
    /// Destinations that came from untrusted content (model output, memos, token
    /// metadata) rather than the user's own input or allowlists.
    #[serde(default)]
    pub untrusted_destinations: Vec<String>,
    pub created_at_ms: i64,
}

impl TxIntent {
    /// Every address this intent sends value to, for allow/deny evaluation.
    pub fn destinations(&self) -> Vec<&str> {
        match &self.kind {
            TxIntentKind::Transfer { to, .. }
            | TxIntentKind::ContractCall { to, .. }
            | TxIntentKind::IbcTransfer { to, .. } => vec![to.as_str()],
            TxIntentKind::Stake { validator, .. } | TxIntentKind::Unstake { validator, .. } => {
                vec![validator.as_str()]
            }
            TxIntentKind::Claim { validator } => validator.iter().map(String::as_str).collect(),
            TxIntentKind::Swap { .. } | TxIntentKind::Psbt { .. } => vec![],
        }
    }

    pub fn assets(&self) -> Vec<&AssetRef> {
        match &self.kind {
            TxIntentKind::Transfer { asset, .. }
            | TxIntentKind::Stake { asset, .. }
            | TxIntentKind::Unstake { asset, .. }
            | TxIntentKind::IbcTransfer { asset, .. } => vec![asset],
            TxIntentKind::Swap { sell, buy, .. } => vec![sell, buy],
            TxIntentKind::ContractCall { .. }
            | TxIntentKind::Claim { .. }
            | TxIntentKind::Psbt { .. } => {
                vec![]
            }
        }
    }
}

/// A single payload the core must sign. Bitcoin produces one per input; the
/// other families produce exactly one per transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pub id: String,
    pub tx_id: String,
    pub key_group_id: String,
    pub curve: Curve,
    /// 32-byte digest, hex. Ceremony messages are bound to this value.
    pub payload_hash_hex: String,
    /// Full serialized unsigned payload so the core can recompute the digest
    /// instead of trusting the adapter.
    pub payload_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub sign_request_id: String,
    pub curve: Curve,
    pub signature_hex: String,
    /// ECDSA recovery id for EVM; absent for other curves.
    pub recovery_id: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ChainId;

    #[test]
    fn intent_round_trips_through_json() {
        let intent = TxIntent {
            id: "tx1".into(),
            wallet_id: "w1".into(),
            account_id: "a1".into(),
            chain_id: ChainId("eip155:1".into()),
            proposer: Proposer::Agent {
                session_id: "s".into(),
                grant_id: "g".into(),
                rationale: "rebalance".into(),
            },
            kind: TxIntentKind::Transfer {
                to: "0xabc".into(),
                asset: AssetRef("eip155:1:native".into()),
                amount: Amount("1000".into()),
            },
            usd_micros: Some(2_000_000),
            untrusted_destinations: vec![],
            created_at_ms: 0,
        };
        let json = serde_json::to_string(&intent).unwrap();
        assert!(json.contains("\"kind\":\"transfer\""));
        let back: TxIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, intent);
        assert_eq!(back.destinations(), vec!["0xabc"]);
    }

    #[test]
    fn amount_validation() {
        assert!(Amount("0".into()).is_valid());
        assert!(!Amount("1.5".into()).is_valid());
        assert!(!Amount("".into()).is_valid());
    }
}
