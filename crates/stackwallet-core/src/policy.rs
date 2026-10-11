//! Deterministic policy evaluation.
//!
//! Every rule is evaluated independently and an intent must pass all of them.
//! That single choice gives the composition semantics the spec asks for without
//! a merge step: allowlists intersect, denylists union, caps take the minimum,
//! approver requirements union, and the result cannot depend on rule order.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::model::{AssetRef, ChainId, KeyGroup};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Window {
    Tx,
    #[serde(rename = "1h")]
    H1,
    #[serde(rename = "24h")]
    H24,
    #[serde(rename = "7d")]
    D7,
    #[serde(rename = "30d")]
    D30,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "rule",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Rule {
    SpendCap {
        window: Window,
        usd_micros: u64,
    },
    DestinationAllow {
        addresses: Vec<String>,
    },
    DestinationDeny {
        addresses: Vec<String>,
    },
    ChainAllow {
        chain_ids: Vec<ChainId>,
    },
    AssetAllow {
        assets: Vec<AssetRef>,
    },
    MaxSlippageBps {
        bps: u32,
    },
    RequireSimulationPass,
    RequireApprovers {
        device_ids: Vec<String>,
        at_least: u8,
    },
    Cooldown {
        seconds: u64,
    },
    MaxPendingProposals {
        count: u32,
    },
    /// Untrusted destinations (see `TxIntent::untrusted_destinations`) are refused
    /// unless they are also on an allowlist.
    RefuseUntrustedDestinations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Enforce,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub mode: PolicyMode,
    pub rules: Vec<Rule>,
}

/// Facts the engine needs beyond the intent itself. Assembled by the store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyContext {
    pub now_ms: i64,
    /// USD already spent **or reserved** (Awaiting / Signing) per window, excluding this intent.
    #[serde(default)]
    pub spent_usd_micros: BTreeMap<Window, u64>,
    #[serde(default)]
    pub pending_proposals: u32,
    pub last_tx_at_ms: Option<i64>,
    /// `None` means no simulation was run.
    pub simulation_ok: Option<bool>,
    /// The signing group, so D6 can be re-checked at evaluation time.
    pub key_group: Option<KeyGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproverRequirement {
    pub device_ids: Vec<String>,
    pub at_least: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "decision",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Decision {
    Allow {
        required_approvers: Vec<ApproverRequirement>,
        /// Reasons that audit-mode policies would have denied on.
        audit_notes: Vec<String>,
    },
    Deny {
        reasons: Vec<String>,
        audit_notes: Vec<String>,
    },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

fn contains_addr(list: &[String], addr: &str, chain: &str) -> bool {
    // Only EVM hex addresses are case-insensitive. Base58 keys encode case as data.
    list.iter().any(|x| {
        if chain.starts_with("eip155:") {
            x.trim().eq_ignore_ascii_case(addr.trim())
        } else {
            x.trim() == addr.trim()
        }
    })
}

fn check_rule(rule: &Rule, intent: &TxIntent, ctx: &PolicyContext) -> Result<(), String> {
    match rule {
        Rule::SpendCap { window, usd_micros } => {
            let this = intent.usd_micros.ok_or_else(|| {
                format!("spend cap {window:?} requires a USD valuation and none was available")
            })?;
            let already = if *window == Window::Tx {
                0
            } else {
                ctx.spent_usd_micros.get(window).copied().unwrap_or(0)
            };
            let total = already.saturating_add(this);
            if total > *usd_micros {
                return Err(format!(
                    "spend cap {window:?}: {total} micro-USD would exceed {usd_micros}"
                ));
            }
            Ok(())
        }
        Rule::DestinationAllow { addresses } => {
            for d in intent.destinations() {
                if !contains_addr(addresses, d, &intent.chain_id.0) {
                    return Err(format!("destination {d} is not on the allowlist"));
                }
            }
            Ok(())
        }
        Rule::DestinationDeny { addresses } => {
            for d in intent.destinations() {
                if contains_addr(addresses, d, &intent.chain_id.0) {
                    return Err(format!("destination {d} is denylisted"));
                }
            }
            Ok(())
        }
        Rule::ChainAllow { chain_ids } => {
            if chain_ids.contains(&intent.chain_id) {
                Ok(())
            } else {
                Err(format!("chain {} is not allowed", intent.chain_id.0))
            }
        }
        Rule::AssetAllow { assets } => {
            for a in intent.assets() {
                if !assets.contains(a) {
                    return Err(format!("asset {} is not allowed", a.0));
                }
            }
            Ok(())
        }
        Rule::MaxSlippageBps { bps } => match &intent.kind {
            TxIntentKind::Swap {
                max_slippage_bps, ..
            } if max_slippage_bps > bps => {
                Err(format!("slippage {max_slippage_bps} bps exceeds {bps} bps"))
            }
            _ => Ok(()),
        },
        Rule::RequireSimulationPass => match ctx.simulation_ok {
            Some(true) => Ok(()),
            Some(false) => Err("simulation failed".into()),
            None => Err("simulation required but not run".into()),
        },
        Rule::RequireApprovers { .. } => Ok(()),
        Rule::Cooldown { seconds } => match ctx.last_tx_at_ms {
            Some(last) if ctx.now_ms - last < (*seconds as i64) * 1000 => {
                Err(format!("cooldown of {seconds}s has not elapsed"))
            }
            _ => Ok(()),
        },
        Rule::MaxPendingProposals { count } => {
            if ctx.pending_proposals >= *count {
                Err(format!(
                    "{} proposals already pending (max {count})",
                    ctx.pending_proposals
                ))
            } else {
                Ok(())
            }
        }
        Rule::RefuseUntrustedDestinations => {
            if intent.untrusted_destinations.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "destination(s) {} came from untrusted content",
                    intent.untrusted_destinations.join(", ")
                ))
            }
        }
    }
}

/// Evaluate every policy against the intent. Order of `policies` and of rules
/// within them does not affect the outcome.
pub fn evaluate(policies: &[Policy], intent: &TxIntent, ctx: &PolicyContext) -> Decision {
    let mut reasons = Vec::new();
    let mut audit_notes = Vec::new();
    let mut approvers = Vec::new();

    if let Some(group) = &ctx.key_group {
        if let Err(e) = group.validate() {
            reasons.push(format!("key group invalid: {e}"));
        }
    }

    for policy in policies {
        for rule in &policy.rules {
            if let Rule::RequireApprovers {
                device_ids,
                at_least,
            } = rule
            {
                if policy.mode == PolicyMode::Enforce {
                    approvers.push(ApproverRequirement {
                        device_ids: device_ids.clone(),
                        at_least: *at_least,
                    });
                }
            }
            if let Err(reason) = check_rule(rule, intent, ctx) {
                let tagged = format!("[{}] {reason}", policy.name);
                match policy.mode {
                    PolicyMode::Enforce => reasons.push(tagged),
                    PolicyMode::Audit => audit_notes.push(tagged),
                }
            }
        }
    }

    reasons.sort();
    audit_notes.sort();
    if reasons.is_empty() {
        Decision::Allow {
            required_approvers: approvers,
            audit_notes,
        }
    } else {
        Decision::Deny {
            reasons,
            audit_notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{Curve, PartyRef, PartyRole};

    fn intent(to: &str, usd: u64) -> TxIntent {
        TxIntent {
            id: "tx".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId("eip155:1".into()),
            proposer: Proposer::Human {
                device_id: "laptop".into(),
            },
            kind: TxIntentKind::Transfer {
                to: to.into(),
                asset: AssetRef("eip155:1:native".into()),
                amount: Amount("1".into()),
            },
            usd_micros: Some(usd),
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    fn policy(name: &str, mode: PolicyMode, rules: Vec<Rule>) -> Policy {
        Policy {
            id: name.into(),
            name: name.into(),
            mode,
            rules,
        }
    }

    #[test]
    fn allow_with_no_policies() {
        let d = evaluate(&[], &intent("0xA", 1), &PolicyContext::default());
        assert!(d.is_allowed());
    }

    #[test]
    fn solana_address_lists_preserve_base58_case() {
        let mut i = intent("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", 1);
        i.chain_id = ChainId(crate::solana::DEVNET.into());
        let list = vec![policy(
            "allow",
            PolicyMode::Enforce,
            vec![Rule::DestinationAllow {
                addresses: vec!["tokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into()],
            }],
        )];
        assert!(!evaluate(&list, &i, &PolicyContext::default()).is_allowed());
        let list = vec![policy(
            "allow",
            PolicyMode::Enforce,
            vec![Rule::DestinationAllow {
                addresses: i.destinations().iter().map(|d| d.to_string()).collect(),
            }],
        )];
        assert!(evaluate(&list, &i, &PolicyContext::default()).is_allowed());
    }

    #[test]
    fn denylist_beats_allowlist() {
        let p = vec![
            policy(
                "folder",
                PolicyMode::Enforce,
                vec![Rule::DestinationAllow {
                    addresses: vec!["0xA".into()],
                }],
            ),
            policy(
                "wallet",
                PolicyMode::Enforce,
                vec![Rule::DestinationDeny {
                    addresses: vec!["0xa".into()],
                }],
            ),
        ];
        let d = evaluate(&p, &intent("0xA", 1), &PolicyContext::default());
        assert!(!d.is_allowed());
    }

    #[test]
    fn caps_include_reserved_spend_and_take_the_minimum() {
        let p = vec![
            policy(
                "loose",
                PolicyMode::Enforce,
                vec![Rule::SpendCap {
                    window: Window::H24,
                    usd_micros: 1_000_000_000,
                }],
            ),
            policy(
                "tight",
                PolicyMode::Enforce,
                vec![Rule::SpendCap {
                    window: Window::H24,
                    usd_micros: 100_000_000,
                }],
            ),
        ];
        let mut ctx = PolicyContext::default();
        ctx.spent_usd_micros.insert(Window::H24, 90_000_000);
        assert!(evaluate(&p, &intent("0xA", 5_000_000), &ctx).is_allowed());
        assert!(!evaluate(&p, &intent("0xA", 20_000_000), &ctx).is_allowed());
    }

    #[test]
    fn order_independent() {
        let a = policy(
            "a",
            PolicyMode::Enforce,
            vec![Rule::ChainAllow {
                chain_ids: vec![ChainId("eip155:1".into())],
            }],
        );
        let b = policy(
            "b",
            PolicyMode::Enforce,
            vec![Rule::SpendCap {
                window: Window::Tx,
                usd_micros: 10,
            }],
        );
        let i = intent("0xA", 50);
        let ctx = PolicyContext::default();
        assert_eq!(
            evaluate(&[a.clone(), b.clone()], &i, &ctx),
            evaluate(&[b, a], &i, &ctx)
        );
    }

    #[test]
    fn audit_mode_notes_but_allows() {
        let p = vec![policy(
            "shadow",
            PolicyMode::Audit,
            vec![Rule::SpendCap {
                window: Window::Tx,
                usd_micros: 1,
            }],
        )];
        match evaluate(&p, &intent("0xA", 50), &PolicyContext::default()) {
            Decision::Allow { audit_notes, .. } => assert_eq!(audit_notes.len(), 1),
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn d6_rechecked_at_evaluation() {
        let ctx = PolicyContext {
            key_group: Some(KeyGroup {
                id: "g".into(),
                threshold: 1,
                parties: vec![PartyRef {
                    device_id: "agent".into(),
                    role: PartyRole::Agent,
                }],
                curves: vec![Curve::Secp256k1],
                public_keys: vec![],
            }),
            ..Default::default()
        };
        assert!(!evaluate(&[], &intent("0xA", 1), &ctx).is_allowed());
    }

    #[test]
    fn approver_requirements_are_collected() {
        let p = vec![
            policy(
                "a",
                PolicyMode::Enforce,
                vec![Rule::RequireApprovers {
                    device_ids: vec!["phone".into()],
                    at_least: 1,
                }],
            ),
            policy(
                "b",
                PolicyMode::Enforce,
                vec![Rule::RequireApprovers {
                    device_ids: vec!["laptop".into()],
                    at_least: 1,
                }],
            ),
        ];
        match evaluate(&p, &intent("0xA", 1), &PolicyContext::default()) {
            Decision::Allow {
                required_approvers, ..
            } => assert_eq!(required_approvers.len(), 2),
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn audit_approvers_do_not_gate_signing() {
        let policies = vec![policy(
            "observe",
            PolicyMode::Audit,
            vec![Rule::RequireApprovers {
                device_ids: vec!["other".into()],
                at_least: 1,
            }],
        )];
        match evaluate(&policies, &intent("0xA", 1), &PolicyContext::default()) {
            Decision::Allow {
                required_approvers, ..
            } => assert!(required_approvers.is_empty()),
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn untrusted_destinations_refused_when_rule_present() {
        let mut i = intent("0xEvil", 1);
        i.untrusted_destinations.push("0xEvil".into());
        let p = vec![policy(
            "agent",
            PolicyMode::Enforce,
            vec![Rule::RefuseUntrustedDestinations],
        )];
        assert!(!evaluate(&p, &i, &PolicyContext::default()).is_allowed());
        assert!(evaluate(&[], &i, &PolicyContext::default()).is_allowed());
    }
}
