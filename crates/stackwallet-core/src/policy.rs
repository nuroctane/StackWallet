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

    // -----------------------------------------------------------------------
    // Properties over random policy sets (the policy support gate).
    // -----------------------------------------------------------------------

    use crate::tss::harness::XorShift64;

    const ADDRS: [&str; 4] = ["0xA", "0xB", "0xC", "0xD"];
    const CHAINS: [&str; 2] = ["eip155:1", "eip155:11155111"];

    fn pick<'a>(rng: &mut XorShift64, from: &[&'a str]) -> Vec<&'a str> {
        from.iter().copied().filter(|_| rng.below(2) == 0).collect()
    }

    fn random_rule(rng: &mut XorShift64) -> Rule {
        let windows = [Window::Tx, Window::H1, Window::H24, Window::D7, Window::D30];
        match rng.below(10) {
            0 => Rule::SpendCap {
                window: windows[rng.below(windows.len())],
                usd_micros: rng.below(100) as u64 * 1_000_000,
            },
            1 => Rule::DestinationAllow {
                addresses: pick(rng, &ADDRS).into_iter().map(String::from).collect(),
            },
            2 => Rule::DestinationDeny {
                addresses: pick(rng, &ADDRS).into_iter().map(String::from).collect(),
            },
            3 => Rule::ChainAllow {
                chain_ids: pick(rng, &CHAINS)
                    .into_iter()
                    .map(|c| ChainId(c.into()))
                    .collect(),
            },
            4 => Rule::AssetAllow {
                assets: pick(rng, &["eip155:1:native", "eip155:1:erc20:0xT"])
                    .into_iter()
                    .map(|a| AssetRef(a.into()))
                    .collect(),
            },
            5 => Rule::RequireSimulationPass,
            6 => Rule::RequireApprovers {
                device_ids: pick(rng, &["laptop", "phone"])
                    .into_iter()
                    .map(String::from)
                    .collect(),
                at_least: 1 + rng.below(2) as u8,
            },
            7 => Rule::Cooldown {
                seconds: rng.below(7200) as u64,
            },
            8 => Rule::MaxPendingProposals {
                count: rng.below(3) as u32,
            },
            _ => Rule::RefuseUntrustedDestinations,
        }
    }

    fn random_policy(rng: &mut XorShift64, id: usize, mode: Option<PolicyMode>) -> Policy {
        let mode = mode.unwrap_or(if rng.below(3) == 0 {
            PolicyMode::Audit
        } else {
            PolicyMode::Enforce
        });
        let rules = (0..1 + rng.below(4)).map(|_| random_rule(rng)).collect();
        policy(&format!("p{id}"), mode, rules)
    }

    fn random_case(rng: &mut XorShift64) -> (Vec<Policy>, TxIntent, PolicyContext) {
        let policies = (0..rng.below(5))
            .map(|i| random_policy(rng, i, None))
            .collect();
        let mut i = intent(
            ADDRS[rng.below(ADDRS.len())],
            rng.below(50) as u64 * 1_000_000,
        );
        i.chain_id = ChainId(CHAINS[rng.below(CHAINS.len())].into());
        if rng.below(3) == 0 {
            i.usd_micros = None;
        }
        if rng.below(3) == 0 {
            if let TxIntentKind::Transfer { to, .. } = &i.kind {
                i.untrusted_destinations.push(to.clone());
            }
        }
        let mut ctx = PolicyContext {
            now_ms: 10_000_000,
            pending_proposals: rng.below(4) as u32,
            last_tx_at_ms: (rng.below(2) == 0).then(|| 10_000_000 - rng.below(9_000_000) as i64),
            simulation_ok: [None, Some(true), Some(false)][rng.below(3)],
            ..Default::default()
        };
        for w in [Window::H1, Window::H24, Window::D7] {
            if rng.below(2) == 0 {
                ctx.spent_usd_micros
                    .insert(w, rng.below(80) as u64 * 1_000_000);
            }
        }
        (policies, i, ctx)
    }

    /// A verdict with its reasons as sets, which is what order cannot change.
    fn normalized(d: Decision) -> (bool, Vec<String>, Vec<String>, Vec<String>) {
        let (allowed, mut reasons, mut notes, mut approvers) = match d {
            Decision::Allow {
                required_approvers,
                audit_notes,
            } => (
                true,
                vec![],
                audit_notes,
                required_approvers
                    .iter()
                    .map(|a| format!("{:?}/{}", a.device_ids, a.at_least))
                    .collect(),
            ),
            Decision::Deny {
                reasons,
                audit_notes,
            } => (false, reasons, audit_notes, vec![]),
        };
        reasons.sort();
        notes.sort();
        approvers.sort();
        (allowed, reasons, notes, approvers)
    }

    #[test]
    fn verdicts_do_not_depend_on_policy_order() {
        let mut rng = XorShift64::new(0x0DE5);
        for _ in 0..600 {
            let (mut policies, i, ctx) = random_case(&mut rng);
            let before = normalized(evaluate(&policies, &i, &ctx));
            rng.shuffle(&mut policies);
            assert_eq!(
                normalized(evaluate(&policies, &i, &ctx)),
                before,
                "{policies:?}"
            );
        }
    }

    #[test]
    fn adding_an_enforced_policy_never_allows_what_was_denied() {
        let mut rng = XorShift64::new(0xA11);
        for n in 0..600 {
            let (mut policies, i, ctx) = random_case(&mut rng);
            if evaluate(&policies, &i, &ctx).is_allowed() {
                continue;
            }
            policies.push(random_policy(&mut rng, 100 + n, Some(PolicyMode::Enforce)));
            assert!(!evaluate(&policies, &i, &ctx).is_allowed(), "{policies:?}");
        }
    }

    #[test]
    fn an_enforced_denylist_beats_any_allowlist() {
        let mut rng = XorShift64::new(0xDE7);
        for n in 0..300 {
            let (mut policies, i, ctx) = random_case(&mut rng);
            let TxIntentKind::Transfer { to, .. } = &i.kind else {
                unreachable!()
            };
            policies.push(policy(
                &format!("allow{n}"),
                PolicyMode::Enforce,
                vec![Rule::DestinationAllow {
                    addresses: vec![to.clone()],
                }],
            ));
            policies.push(policy(
                &format!("deny{n}"),
                PolicyMode::Enforce,
                vec![Rule::DestinationDeny {
                    addresses: vec![to.clone()],
                }],
            ));
            rng.shuffle(&mut policies);
            assert!(!evaluate(&policies, &i, &ctx).is_allowed());
        }
    }

    #[test]
    fn audit_mode_alone_never_denies() {
        let mut rng = XorShift64::new(0xAD17);
        for n in 0..300 {
            let (_, i, ctx) = random_case(&mut rng);
            let policies: Vec<Policy> = (0..1 + rng.below(4))
                .map(|k| random_policy(&mut rng, n * 10 + k, Some(PolicyMode::Audit)))
                .collect();
            assert!(evaluate(&policies, &i, &ctx).is_allowed(), "{policies:?}");
        }
    }

    #[test]
    fn an_agent_only_threshold_is_denied_whatever_the_policies() {
        // D6 defense in depth: the group is checked again at evaluation time,
        // so no policy set can let an agent sign alone.
        let agent_alone = KeyGroup {
            id: "g".into(),
            threshold: 1,
            parties: vec![
                PartyRef {
                    device_id: "agent".into(),
                    role: PartyRole::Agent,
                },
                PartyRef {
                    device_id: "laptop".into(),
                    role: PartyRole::Human,
                },
            ],
            curves: vec![Curve::Secp256k1],
            public_keys: vec![],
        };
        let mut rng = XorShift64::new(0xD6);
        for _ in 0..300 {
            let (policies, i, mut ctx) = random_case(&mut rng);
            ctx.key_group = Some(agent_alone.clone());
            assert!(!evaluate(&policies, &i, &ctx).is_allowed(), "{policies:?}");
        }
    }
}
