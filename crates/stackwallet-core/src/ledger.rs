//! The transaction ledger: every intent, its unsigned and signed forms, the
//! policy decision, and the hash-chained audit log, sealed in the vault as one
//! record so a state change and its audit row are written together or not at
//! all. The functions here are the only way a transaction moves: each checks
//! the lifecycle graph, appends the audit row, and seals before returning.
//!
//! Signing happens here too. Approval re-runs the policy with a fresh context,
//! re-derives the signer from the vault, signs the digest the core computed
//! from its own serialization, and stores the raw bytes. The client only ever
//! broadcasts what the core produced.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::audit::{Actor, AuditChain, AuditEntry, AuditEvent};
use crate::evm::{self, EvmTx};
use crate::intent::TxIntent;
use crate::lifecycle::TxState;
use crate::model::Curve;
use crate::policy::{self, Decision, Policy, PolicyContext, Window};
use crate::provenance;
use crate::vault::{EncryptedVault, Secret, Vault};
use crate::{CoreError, Result};

pub const LEDGER_LABEL: &str = "tx-ledger";
const MAX_TXS: usize = 20_000;
const MAX_POLICIES: usize = 256;
const MAX_NOTE_CHARS: usize = 500;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "transaction ledger",
        reason: reason.into(),
    }
}

/// Which key signs: a single-key wallet's account at a derivation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signer {
    pub wallet_id: String,
    pub path: String,
    /// The address the UI showed; the core re-derives and must arrive at the same one.
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxRecord {
    pub id: String,
    pub intent: TxIntent,
    pub state: TxState,
    pub signer: Option<Signer>,
    pub unsigned: Option<EvmTx>,
    /// Adapter simulation, kept verbatim for the approval screen.
    pub simulation: Option<serde_json::Value>,
    pub simulation_ok: Option<bool>,
    pub decision: Option<Decision>,
    pub raw_signed_hex: Option<String>,
    pub hash: Option<String>,
    pub error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ledger {
    #[serde(default)]
    pub txs: Vec<TxRecord>,
    #[serde(default)]
    pub audit: Vec<AuditEntry>,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

impl Ledger {
    /// The audit chain must verify, and every transaction's state must be the
    /// last state the chain recorded for it: a record cannot drift from its log.
    pub fn validate(&self) -> Result<()> {
        if self.txs.len() > MAX_TXS || self.policies.len() > MAX_POLICIES {
            return Err(invalid("too many records"));
        }
        AuditChain::from_entries(self.audit.clone())?;
        let mut last: BTreeMap<&str, TxState> = BTreeMap::new();
        for e in &self.audit {
            match &e.event {
                AuditEvent::TxProposed { tx_id, .. } => {
                    last.insert(tx_id, TxState::Draft);
                }
                AuditEvent::TxTransition { tx_id, to, .. } => {
                    last.insert(tx_id, *to);
                }
                _ => {}
            }
        }
        let mut ids = HashSet::new();
        for t in &self.txs {
            if !ids.insert(t.id.as_str()) {
                return Err(invalid(format!("transaction {} appears twice", t.id)));
            }
            if last.get(t.id.as_str()) != Some(&t.state) {
                return Err(invalid(format!(
                    "transaction {} is {:?} but its audit trail disagrees",
                    t.id, t.state
                )));
            }
        }
        let mut pids = HashSet::new();
        for p in &self.policies {
            if !pids.insert(p.id.as_str()) {
                return Err(invalid(format!("policy {} appears twice", p.id)));
            }
        }
        Ok(())
    }

    fn index(&self, id: &str) -> Result<usize> {
        self.txs
            .iter()
            .position(|t| t.id == id)
            .ok_or_else(|| invalid(format!("no transaction {id}")))
    }

    fn chain(&self) -> Result<AuditChain> {
        AuditChain::from_entries(self.audit.clone())
    }

    fn step(
        &mut self,
        i: usize,
        to: TxState,
        note: Option<String>,
        actor: &Actor,
        now_ms: i64,
    ) -> Result<()> {
        let from = self.txs[i].state;
        crate::lifecycle::transition(from, to)?;
        let mut chain = self.chain()?;
        chain.append(
            now_ms,
            actor.clone(),
            AuditEvent::TxTransition {
                tx_id: self.txs[i].id.clone(),
                from,
                to,
                note: note.map(|n| n.chars().take(MAX_NOTE_CHARS).collect()),
            },
        );
        self.audit = chain.entries().to_vec();
        self.txs[i].state = to;
        self.txs[i].updated_at_ms = now_ms;
        Ok(())
    }

    /// Spend reserved or confirmed in each window, pending count, last send.
    pub fn context(
        &self,
        excluding: &str,
        now_ms: i64,
        simulation_ok: Option<bool>,
    ) -> PolicyContext {
        let windows = [
            (Window::H1, 3_600_000i64),
            (Window::H24, 86_400_000),
            (Window::D7, 604_800_000),
            (Window::D30, 2_592_000_000),
        ];
        let mut spent: BTreeMap<Window, u64> = BTreeMap::new();
        let mut pending = 0u32;
        let mut last: Option<i64> = None;
        for t in self.txs.iter().filter(|t| t.id != excluding) {
            if t.state == TxState::Awaiting {
                pending += 1;
            }
            let counts = t.state.reserves_spend() || t.state == TxState::Confirmed;
            if counts {
                last = Some(last.map_or(t.updated_at_ms, |l| l.max(t.updated_at_ms)));
                let usd = t.intent.usd_micros.unwrap_or(0);
                for (w, span) in windows {
                    if now_ms - t.created_at_ms <= span {
                        *spent.entry(w).or_default() += usd;
                    }
                }
            }
        }
        PolicyContext {
            now_ms,
            spent_usd_micros: spent,
            pending_proposals: pending,
            last_tx_at_ms: last,
            simulation_ok,
            key_group: None,
        }
    }
}

pub fn load_ledger(vault: &EncryptedVault) -> Result<Ledger> {
    let Some(handle) = vault.handle_for(LEDGER_LABEL) else {
        return Ok(Ledger::default());
    };
    let ledger = vault.with_secret(&handle, &mut |bytes| {
        serde_json::from_slice::<Ledger>(bytes.expose())
            .map_err(|e| invalid(format!("unreadable: {e}")))
    })??;
    ledger.validate()?;
    Ok(ledger)
}

fn save_ledger(vault: &mut EncryptedVault, next: &Ledger) -> Result<()> {
    next.validate()?;
    let current = load_ledger(vault)?;
    // The log only grows: a save that rewrites or drops a row is refused.
    if !next.audit.starts_with(&current.audit) {
        return Err(invalid("the audit log may only be appended to"));
    }
    let bytes = serde_json::to_vec(next).map_err(|e| invalid(e.to_string()))?;
    vault.put(LEDGER_LABEL, Secret::new(bytes))?;
    Ok(())
}

fn device_actor(device_id: &str) -> Actor {
    Actor::Device {
        device_id: device_id.to_owned(),
    }
}

/// Record a new intent as a draft.
pub fn propose(
    vault: &mut EncryptedVault,
    intent: TxIntent,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    if intent.id.is_empty() || intent.id.len() > 128 {
        return Err(invalid("bad transaction id"));
    }
    evm::eip155_number(&intent.chain_id.0)?;
    let mut ledger = load_ledger(vault)?;
    if ledger.txs.iter().any(|t| t.id == intent.id) {
        return Err(invalid(format!("transaction {} exists", intent.id)));
    }
    let mut chain = ledger.chain()?;
    chain.append(
        now_ms,
        device_actor(device_id),
        AuditEvent::TxProposed {
            tx_id: intent.id.clone(),
            wallet_id: intent.wallet_id.clone(),
            chain_id: intent.chain_id.0.clone(),
        },
    );
    ledger.audit = chain.entries().to_vec();
    let rec = TxRecord {
        id: intent.id.clone(),
        intent,
        state: TxState::Draft,
        signer: None,
        unsigned: None,
        simulation: None,
        simulation_ok: None,
        decision: None,
        raw_signed_hex: None,
        hash: None,
        error: None,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    ledger.txs.push(rec.clone());
    save_ledger(vault, &ledger)?;
    Ok(rec)
}

fn signer_address(vault: &EncryptedVault, signer: &Signer) -> Result<String> {
    let key = provenance::signing_key(vault, &signer.wallet_id, Curve::Secp256k1, &signer.path)?;
    Ok(evm::checksum_address(&evm::address_from_public(
        &key.public,
    )?))
}

/// Attach the adapter's unsigned transaction and simulation (Draft → Simulated).
/// Refused unless the transaction does exactly what the intent says and the
/// signer derives to the address the user saw.
#[allow(clippy::too_many_arguments)]
pub fn attach(
    vault: &mut EncryptedVault,
    tx_id: &str,
    signer: Signer,
    unsigned: EvmTx,
    simulation: serde_json::Value,
    simulation_ok: bool,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    if signer.wallet_id != ledger.txs[i].intent.wallet_id {
        return Err(invalid("signer wallet differs from the intent"));
    }
    evm::check_matches_intent(&unsigned, &ledger.txs[i].intent)?;
    let derived = signer_address(vault, &signer)?;
    if evm::parse_address(&derived)? != evm::parse_address(&signer.address)? {
        return Err(invalid(format!(
            "the key at {} is {derived}, not {}",
            signer.path, signer.address
        )));
    }
    let actor = device_actor(device_id);
    ledger.step(
        i,
        TxState::Simulated,
        (!simulation_ok).then(|| "simulation failed".to_owned()),
        &actor,
        now_ms,
    )?;
    let t = &mut ledger.txs[i];
    t.signer = Some(Signer {
        address: derived,
        ..signer
    });
    t.unsigned = Some(unsigned);
    t.simulation = Some(simulation);
    t.simulation_ok = Some(simulation_ok);
    let out = t.clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Run the policies (Simulated → Evaluated → Denied | Awaiting).
pub fn evaluate(
    vault: &mut EncryptedVault,
    tx_id: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let ctx = ledger.context(tx_id, now_ms, ledger.txs[i].simulation_ok);
    let decision = policy::evaluate(&ledger.policies, &ledger.txs[i].intent, &ctx);
    let actor = device_actor(device_id);
    ledger.step(i, TxState::Evaluated, None, &actor, now_ms)?;
    match &decision {
        Decision::Deny { reasons, .. } => {
            ledger.step(i, TxState::Denied, Some(reasons.join("; ")), &actor, now_ms)?;
        }
        Decision::Allow { .. } => {
            // A human looks at every transaction before it is signed; the queue is that look.
            ledger.step(i, TxState::Awaiting, None, &actor, now_ms)?;
        }
    }
    ledger.txs[i].decision = Some(decision);
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Approve and sign (Awaiting → Signing → Signed, or → Rejected if the policy
/// no longer allows it). Requires the vault passphrase again.
pub fn approve(
    vault: &mut EncryptedVault,
    tx_id: &str,
    passphrase: &Secret,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    vault.verify_passphrase(passphrase)?;
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let actor = device_actor(device_id);
    if ledger.txs[i].state != TxState::Awaiting {
        return Err(invalid(
            "only a transaction awaiting approval can be approved",
        ));
    }
    // Policies can change while a proposal waits; the signing-time answer wins.
    let ctx = ledger.context(tx_id, now_ms, ledger.txs[i].simulation_ok);
    let decision = policy::evaluate(&ledger.policies, &ledger.txs[i].intent, &ctx);
    if let Decision::Deny { reasons, .. } = &decision {
        let note = format!("policy at signing time: {}", reasons.join("; "));
        ledger.step(i, TxState::Rejected, Some(note), &actor, now_ms)?;
        ledger.txs[i].decision = Some(decision);
        let out = ledger.txs[i].clone();
        save_ledger(vault, &ledger)?;
        return Ok(out);
    }
    if let Decision::Allow {
        required_approvers, ..
    } = &decision
    {
        if required_approvers.iter().any(|r| {
            r.at_least > 1 || (r.at_least == 1 && !r.device_ids.iter().any(|d| d == device_id))
        }) {
            return Err(invalid("this policy needs approvals from other devices"));
        }
    }
    ledger.step(i, TxState::Signing, None, &actor, now_ms)?;
    let t = ledger.txs[i].clone();
    let signed = (|| -> Result<(String, String)> {
        let unsigned = t
            .unsigned
            .as_ref()
            .ok_or_else(|| invalid("no unsigned transaction"))?;
        let signer = t.signer.as_ref().ok_or_else(|| invalid("no signer"))?;
        evm::check_matches_intent(unsigned, &t.intent)?;
        let key =
            provenance::signing_key(vault, &signer.wallet_id, Curve::Secp256k1, &signer.path)?;
        let addr = evm::checksum_address(&evm::address_from_public(&key.public)?);
        if addr != signer.address {
            return Err(invalid("signer key changed since the proposal"));
        }
        let (v, r, s) = evm::sign_digest(key.secret(), &unsigned.sighash()?)?;
        let raw = unsigned.encode_signed(v, &r, &s)?;
        Ok((
            format!("0x{}", hex::encode(&raw)),
            format!("0x{}", hex::encode(evm::keccak256(&raw))),
        ))
    })();
    match signed {
        Ok((raw, hash)) => {
            ledger.step(i, TxState::Signed, None, &actor, now_ms)?;
            ledger.txs[i].raw_signed_hex = Some(raw);
            ledger.txs[i].hash = Some(hash);
        }
        Err(e) => {
            ledger.step(i, TxState::Failed, Some(e.to_string()), &actor, now_ms)?;
            ledger.txs[i].error = Some(e.to_string());
        }
    }
    ledger.txs[i].decision = Some(decision);
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

pub fn reject(
    vault: &mut EncryptedVault,
    tx_id: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    ledger.step(
        i,
        TxState::Rejected,
        Some("rejected by the user".into()),
        &device_actor(device_id),
        now_ms,
    )?;
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Network outcomes the client observed: Broadcast, Pending, Confirmed,
/// Failed, Dropped or Replaced. The lifecycle graph decides what is legal.
pub fn report(
    vault: &mut EncryptedVault,
    tx_id: &str,
    to: TxState,
    note: Option<String>,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    if !matches!(
        to,
        TxState::Broadcast
            | TxState::Pending
            | TxState::Confirmed
            | TxState::Failed
            | TxState::Dropped
            | TxState::Replaced
    ) {
        return Err(invalid(format!("{to:?} is not a network outcome")));
    }
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    if ledger.txs[i].raw_signed_hex.is_none() {
        return Err(invalid("nothing was signed for this transaction"));
    }
    ledger.step(i, to, note.clone(), &device_actor(device_id), now_ms)?;
    if to == TxState::Failed {
        ledger.txs[i].error = note;
    }
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Replace the policy set; each added, changed or removed policy is audited.
pub fn set_policies(
    vault: &mut EncryptedVault,
    policies: Vec<Policy>,
    device_id: &str,
    now_ms: i64,
) -> Result<()> {
    let mut ledger = load_ledger(vault)?;
    let before: BTreeMap<String, Policy> = ledger
        .policies
        .iter()
        .map(|p| (p.id.clone(), p.clone()))
        .collect();
    let after: BTreeMap<String, Policy> =
        policies.iter().map(|p| (p.id.clone(), p.clone())).collect();
    let mut chain = ledger.chain()?;
    for id in before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if before.get(id) != after.get(id) {
            chain.append(
                now_ms,
                device_actor(device_id),
                AuditEvent::PolicyChanged {
                    policy_id: id.clone(),
                },
            );
        }
    }
    ledger.audit = chain.entries().to_vec();
    ledger.policies = policies;
    save_ledger(vault, &ledger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer, TxIntentKind};
    use crate::model::{AssetRef, ChainId};
    use crate::policy::{PolicyMode, Rule};
    use crate::vault::KdfParams;

    const PHRASE: &str = "test test test test test test test test test test test junk";
    const PATH: &str = "m/44'/60'/0'/0/0";
    const ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const TO: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    fn vault() -> EncryptedVault {
        let mut v =
            EncryptedVault::create(&Secret::new(b"pw".to_vec()), KdfParams::MINIMUM).unwrap();
        provenance::import_phrase(&mut v, "w", PHRASE, 0).unwrap();
        v
    }

    fn pw() -> Secret {
        Secret::new(b"pw".to_vec())
    }

    fn intent(id: &str, to: &str, amount: &str) -> TxIntent {
        TxIntent {
            id: id.into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId("eip155:11155111".into()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: to.into(),
                asset: AssetRef("eip155:11155111:native".into()),
                amount: Amount(amount.into()),
            },
            usd_micros: Some(5_000_000),
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    fn unsigned(to: &str, value: &str) -> EvmTx {
        EvmTx {
            chain_id: 11155111,
            nonce: 0,
            max_priority_fee_per_gas: "1000000000".into(),
            max_fee_per_gas: "20000000000".into(),
            gas_limit: 21000,
            to: to.into(),
            value: value.into(),
            data_hex: String::new(),
        }
    }

    fn signer() -> Signer {
        Signer {
            wallet_id: "w".into(),
            path: PATH.into(),
            address: ADDR.into(),
        }
    }

    fn to_awaiting(v: &mut EncryptedVault, id: &str) -> TxRecord {
        propose(v, intent(id, TO, "1000"), "d", 1).unwrap();
        attach(
            v,
            id,
            signer(),
            unsigned(TO, "1000"),
            serde_json::json!({"ok": true}),
            true,
            "d",
            2,
        )
        .unwrap();
        evaluate(v, id, "d", 3).unwrap()
    }

    #[test]
    fn full_lifecycle_is_audited_and_signed_by_the_core() {
        let mut v = vault();
        let t = to_awaiting(&mut v, "t1");
        assert_eq!(t.state, TxState::Awaiting);
        assert!(approve(&mut v, "t1", &Secret::new(b"no".to_vec()), "d", 4).is_err());
        let t = approve(&mut v, "t1", &pw(), "d", 4).unwrap();
        assert_eq!(t.state, TxState::Signed);
        let raw = t.raw_signed_hex.unwrap();
        assert!(raw.starts_with("0x02"));
        report(&mut v, "t1", TxState::Broadcast, None, "d", 5).unwrap();
        report(&mut v, "t1", TxState::Pending, None, "d", 6).unwrap();
        let t = report(&mut v, "t1", TxState::Confirmed, None, "d", 7).unwrap();
        assert_eq!(t.state, TxState::Confirmed);
        assert!(
            report(&mut v, "t1", TxState::Pending, None, "d", 8).is_err(),
            "no going back"
        );

        let l = load_ledger(&v).unwrap();
        let states: Vec<_> = l
            .audit
            .iter()
            .filter_map(|e| match &e.event {
                AuditEvent::TxTransition { to, .. } => Some(*to),
                _ => None,
            })
            .collect();
        use TxState::*;
        assert_eq!(
            states,
            vec![Simulated, Evaluated, Awaiting, Signing, Signed, Broadcast, Pending, Confirmed]
        );
    }

    #[test]
    fn a_swapped_destination_or_signer_is_refused() {
        let mut v = vault();
        propose(&mut v, intent("t", TO, "1000"), "d", 1).unwrap();
        let evil = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
        assert!(attach(
            &mut v,
            "t",
            signer(),
            unsigned(evil, "1000"),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        let wrong = Signer {
            address: evil.into(),
            ..signer()
        };
        assert!(attach(
            &mut v,
            "t",
            wrong,
            unsigned(TO, "1000"),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        assert_eq!(load_ledger(&v).unwrap().txs[0].state, TxState::Draft);
    }

    #[test]
    fn policies_deny_and_recheck_at_signing_time() {
        let mut v = vault();
        set_policies(
            &mut v,
            vec![Policy {
                id: "p".into(),
                name: "deny".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::DestinationDeny {
                    addresses: vec![TO.into()],
                }],
            }],
            "d",
            0,
        )
        .unwrap();
        let t = to_awaiting(&mut v, "t1");
        assert_eq!(t.state, TxState::Denied);

        set_policies(&mut v, vec![], "d", 0).unwrap();
        let t = to_awaiting(&mut v, "t2");
        assert_eq!(t.state, TxState::Awaiting);
        set_policies(
            &mut v,
            vec![Policy {
                id: "cap".into(),
                name: "cap".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::SpendCap {
                    window: Window::Tx,
                    usd_micros: 1,
                }],
            }],
            "d",
            9,
        )
        .unwrap();
        let t = approve(&mut v, "t2", &pw(), "d", 10).unwrap();
        assert_eq!(t.state, TxState::Rejected);
        assert!(t.raw_signed_hex.is_none());
    }

    #[test]
    fn the_log_cannot_be_rewritten() {
        let mut v = vault();
        to_awaiting(&mut v, "t1");
        let mut l = load_ledger(&v).unwrap();
        l.txs[0].state = TxState::Signed;
        assert!(save_ledger(&mut v, &l).is_err(), "state without a log row");
        let mut l = load_ledger(&v).unwrap();
        l.audit.pop();
        l.txs[0].state = TxState::Evaluated;
        assert!(save_ledger(&mut v, &l).is_err(), "dropped row");
        reject(&mut v, "t1", "d", 9).unwrap();
        assert_eq!(load_ledger(&v).unwrap().txs[0].state, TxState::Rejected);
    }
}
