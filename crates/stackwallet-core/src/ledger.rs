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
use crate::bitcoin::{self, BitcoinTx};
use crate::cosmos::{self, CosmosTx};
use crate::evm::{self, EvmTx};
use crate::intent::TxIntent;
use crate::lifecycle::TxState;
use crate::model::Curve;
use crate::policy::{self, Decision, Policy, PolicyContext, Window};
use crate::provenance;
use crate::solana::{self, SolanaTx};
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

/// Untagged to keep previously sealed EVM ledgers readable without a migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UnsignedTx {
    Evm(EvmTx),
    Solana(SolanaTx),
    Cosmos(CosmosTx),
    Bitcoin(BitcoinTx),
}

impl From<EvmTx> for UnsignedTx {
    fn from(tx: EvmTx) -> Self {
        Self::Evm(tx)
    }
}
impl From<SolanaTx> for UnsignedTx {
    fn from(tx: SolanaTx) -> Self {
        Self::Solana(tx)
    }
}
impl From<CosmosTx> for UnsignedTx {
    fn from(tx: CosmosTx) -> Self {
        Self::Cosmos(tx)
    }
}
impl UnsignedTx {
    fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        match self {
            Self::Evm(tx) => evm::check_matches_intent(tx, intent),
            Self::Solana(tx) => tx.check_matches_intent(intent),
            Self::Cosmos(tx) => tx.check_matches_intent(intent),
            Self::Bitcoin(tx) => tx.check_matches_intent(intent),
        }
    }
    fn curve(&self) -> Curve {
        match self {
            Self::Evm(_) | Self::Cosmos(_) | Self::Bitcoin(_) => Curve::Secp256k1,
            Self::Solana(_) => Curve::Ed25519,
        }
    }
}
impl From<BitcoinTx> for UnsignedTx {
    fn from(tx: BitcoinTx) -> Self {
        Self::Bitcoin(tx)
    }
}

fn check_bitcoin_reservations(ledger: &Ledger, id: &str, unsigned: &UnsignedTx) -> Result<()> {
    let UnsignedTx::Bitcoin(tx) = unsigned else {
        return Ok(());
    };
    for other in &ledger.txs {
        if other.id == id
            || (other.raw_signed_hex.is_none()
                && matches!(
                    other.state,
                    TxState::Denied | TxState::Rejected | TxState::Failed | TxState::Expired
                ))
        {
            continue;
        }
        if let Some(UnsignedTx::Bitcoin(reserved)) = &other.unsigned {
            if reserved.inputs.iter().any(|a| {
                tx.inputs
                    .iter()
                    .any(|b| a.txid == b.txid && a.vout == b.vout)
            }) {
                return Err(invalid(
                    "Bitcoin input is reserved by another active or signed transfer",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxRecord {
    pub id: String,
    pub intent: TxIntent,
    pub state: TxState,
    pub signer: Option<Signer>,
    pub unsigned: Option<UnsignedTx>,
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
                    // Live signatures and proposals reserve allowance until resolved.
                    // Confirmed spending starts at confirmation, never at draft creation.
                    if t.state.reserves_spend() || now_ms.saturating_sub(t.updated_at_ms) <= span {
                        let total = spent.entry(w).or_default();
                        *total = total.saturating_add(usd);
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
    if intent.chain_id.0.starts_with("solana:") {
        solana::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("cosmos:") {
        cosmos::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("bip122:") {
        bitcoin::check_chain(&intent.chain_id.0)?;
    } else {
        evm::check_chain(&intent.chain_id.0)?;
    }
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

fn signer_address(
    vault: &EncryptedVault,
    signer: &Signer,
    unsigned: &UnsignedTx,
) -> Result<String> {
    // Bitcoin sighashes do not carry a network ID; refuse mainnet coin derivations.
    if matches!(unsigned, UnsignedTx::Bitcoin(_)) && !signer.path.starts_with("m/84'/1'/") {
        return Err(invalid(
            "Signet signing requires a testnet BIP84 derivation path",
        ));
    }
    let key = provenance::signing_key(vault, &signer.wallet_id, unsigned.curve(), &signer.path)?;
    match unsigned {
        UnsignedTx::Solana(_) => Ok(bs58::encode(&key.public).into_string()),
        UnsignedTx::Cosmos(_) => cosmos::address(&key.public),
        UnsignedTx::Bitcoin(_) => bitcoin::address(&key.public),
        UnsignedTx::Evm(_) => Ok(evm::checksum_address(&evm::address_from_public(
            &key.public,
        )?)),
    }
}

/// Attach the adapter's unsigned transaction and simulation (Draft → Simulated).
/// Refused unless the transaction does exactly what the intent says and the
/// signer derives to the address the user saw.
#[allow(clippy::too_many_arguments)]
pub fn attach(
    vault: &mut EncryptedVault,
    tx_id: &str,
    signer: Signer,
    unsigned: impl Into<UnsignedTx>,
    simulation: serde_json::Value,
    simulation_ok: bool,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let unsigned = unsigned.into();
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    if signer.wallet_id != ledger.txs[i].intent.wallet_id {
        return Err(invalid("signer wallet differs from the intent"));
    }
    unsigned.check_matches_intent(&ledger.txs[i].intent)?;
    check_bitcoin_reservations(&ledger, tx_id, &unsigned)?;
    let derived = signer_address(vault, &signer, &unsigned)?;
    let matches = match &unsigned {
        UnsignedTx::Evm(_) => evm::parse_address(&derived)? == evm::parse_address(&signer.address)?,
        UnsignedTx::Solana(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Cosmos(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Bitcoin(tx) => derived == signer.address && tx.from == derived,
    };
    if !matches {
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
    if let Some(unsigned) = &ledger.txs[i].unsigned {
        check_bitcoin_reservations(&ledger, tx_id, unsigned)?;
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
        unsigned.check_matches_intent(&t.intent)?;
        let key =
            provenance::signing_key(vault, &signer.wallet_id, unsigned.curve(), &signer.path)?;
        let addr = signer_address(vault, signer, unsigned)?;
        if addr != signer.address {
            return Err(invalid("signer key changed since the proposal"));
        }
        match unsigned {
            UnsignedTx::Evm(tx) => {
                let (v, r, s) = evm::sign_digest(key.secret(), &tx.sighash()?)?;
                let raw = tx.encode_signed(v, &r, &s)?;
                Ok((
                    format!("0x{}", hex::encode(&raw)),
                    format!("0x{}", hex::encode(evm::keccak256(&raw))),
                ))
            }
            UnsignedTx::Solana(tx) => tx.sign(key.secret()),
            UnsignedTx::Cosmos(tx) => tx.sign(key.secret()),
            UnsignedTx::Bitcoin(tx) => tx.sign(key.secret()),
        }
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

/// Authorize resending the already approved bytes without creating a new signature or releasing spend.
pub fn retry_broadcast(
    vault: &mut EncryptedVault,
    tx_id: &str,
    passphrase: &Secret,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    vault.verify_passphrase(passphrase)?;
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let tx = &ledger.txs[i];
    if !matches!(
        tx.state,
        TxState::Signed | TxState::Broadcast | TxState::Pending
    ) {
        return Err(invalid(
            "only an unresolved signed transaction can be retried",
        ));
    }
    if tx.raw_signed_hex.as_ref().is_none_or(|raw| raw.is_empty()) {
        return Err(invalid("no saved signed transaction bytes"));
    }
    let hash = tx
        .hash
        .clone()
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| invalid("no saved transaction hash"))?;
    tx.unsigned
        .as_ref()
        .ok_or_else(|| invalid("no saved unsigned transaction"))?
        .check_matches_intent(&tx.intent)?;
    let ctx = ledger.context(tx_id, now_ms, tx.simulation_ok);
    match policy::evaluate(&ledger.policies, &tx.intent, &ctx) {
        Decision::Deny { reasons, .. } => {
            return Err(invalid(format!("policy at retry: {}", reasons.join("; "))))
        }
        Decision::Allow {
            required_approvers, ..
        } => {
            if required_approvers.iter().any(|r| {
                r.at_least > 1 || (r.at_least == 1 && !r.device_ids.iter().any(|d| d == device_id))
            }) {
                return Err(invalid("this policy needs approvals from other devices"));
            }
        }
    }
    let mut chain = ledger.chain()?;
    chain.append(
        now_ms,
        device_actor(device_id),
        AuditEvent::TxBroadcastRetry {
            tx_id: tx_id.into(),
            hash,
        },
    );
    ledger.audit = chain.entries().to_vec();
    ledger.txs[i].updated_at_ms = now_ms;
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
            | TxState::Expired
    ) {
        return Err(invalid(format!("{to:?} is not a network outcome")));
    }
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    if to == TxState::Expired
        && !matches!(
            ledger.txs[i].unsigned,
            Some(UnsignedTx::Solana(_) | UnsignedTx::Cosmos(_))
        )
    {
        return Err(invalid(
            "network expiry requires a transaction with a bounded lifetime",
        ));
    }
    if ledger.txs[i].raw_signed_hex.is_none() && to != TxState::Expired {
        return Err(invalid("nothing was signed for this transaction"));
    }
    ledger.step(i, to, note.clone(), &device_actor(device_id), now_ms)?;
    if matches!(to, TxState::Failed | TxState::Expired) {
        ledger.txs[i].error = note;
    }
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Replace the policy set; each added, changed or removed policy is audited.
/// Append one event that belongs to no transaction (a signed message).
pub fn append_audit(
    vault: &mut EncryptedVault,
    now_ms: i64,
    actor: Actor,
    event: AuditEvent,
) -> Result<()> {
    let mut ledger = load_ledger(vault)?;
    let mut chain = ledger.chain()?;
    chain.append(now_ms, actor, event);
    ledger.audit = chain.entries().to_vec();
    save_ledger(vault, &ledger)
}

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
    #[test]
    fn retries_keep_original_bytes_state_reservation_and_verified_audit() {
        let mut v = vault();
        to_awaiting(&mut v, "retry");
        let original = approve(&mut v, "retry", &pw(), "d", 4).unwrap();
        for (step, state) in [
            (5, TxState::Signed),
            (7, TxState::Broadcast),
            (9, TxState::Pending),
        ] {
            if state != TxState::Signed {
                report(&mut v, "retry", state, None, "d", step).unwrap();
            }
            let before = load_ledger(&v).unwrap().audit.len();
            let retried = retry_broadcast(&mut v, "retry", &pw(), "d", step + 1).unwrap();
            assert_eq!(retried.state, state);
            assert!(retried.state.reserves_spend());
            assert_eq!(retried.raw_signed_hex, original.raw_signed_hex);
            assert_eq!(retried.hash, original.hash);
            let ledger = load_ledger(&v).unwrap();
            assert_eq!(ledger.audit.len(), before + 1);
            assert!(
                matches!(&ledger.audit.last().unwrap().event, AuditEvent::TxBroadcastRetry { tx_id, hash }
                if tx_id == "retry" && Some(hash) == original.hash.as_ref())
            );
            ledger.validate().unwrap();
        }
        report(&mut v, "retry", TxState::Confirmed, None, "d", 11).unwrap();
        let before = load_ledger(&v).unwrap();
        assert!(retry_broadcast(&mut v, "retry", &pw(), "d", 12).is_err());
        assert_eq!(load_ledger(&v).unwrap(), before);
    }

    #[test]
    fn retry_requires_passphrase_and_current_policy_without_discarding_signed_spend() {
        let mut v = vault();
        to_awaiting(&mut v, "retry");
        assert!(retry_broadcast(&mut v, "retry", &pw(), "d", 4).is_err());
        approve(&mut v, "retry", &pw(), "d", 5).unwrap();
        let before = load_ledger(&v).unwrap();
        assert!(retry_broadcast(&mut v, "retry", &Secret::new(b"wrong".to_vec()), "d", 6).is_err());
        assert_eq!(load_ledger(&v).unwrap(), before);
        for rule in [
            Rule::DestinationDeny {
                addresses: vec![TO.into()],
            },
            Rule::RequireApprovers {
                device_ids: vec!["other".into()],
                at_least: 1,
            },
        ] {
            set_policies(
                &mut v,
                vec![Policy {
                    id: "retry-policy".into(),
                    name: "retry-policy".into(),
                    mode: PolicyMode::Enforce,
                    rules: vec![rule],
                }],
                "d",
                7,
            )
            .unwrap();
            let before = load_ledger(&v).unwrap();
            assert!(retry_broadcast(&mut v, "retry", &pw(), "d", 8).is_err());
            assert_eq!(load_ledger(&v).unwrap(), before);
            assert!(before.txs[0].state.reserves_spend());
        }
    }

    #[test]
    fn live_reservations_do_not_age_out_and_confirmed_spending_uses_confirmation_time() {
        let mut v = vault();
        let mut tx = to_awaiting(&mut v, "old");
        tx.state = TxState::Signed;
        let later = 7_200_001;
        let mut ledger = Ledger {
            txs: vec![tx],
            ..Ledger::default()
        };
        assert_eq!(
            ledger.context("new", later, None).spent_usd_micros[&Window::H1],
            5_000_000
        );
        ledger.txs[0].state = TxState::Confirmed;
        ledger.txs[0].updated_at_ms = later;
        assert_eq!(
            ledger.context("new", later + 1, None).spent_usd_micros[&Window::H1],
            5_000_000
        );
        assert_eq!(
            ledger
                .context("new", later + 3_600_001, None)
                .spent_usd_micros
                .get(&Window::H1),
            None
        );
    }
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

    #[test]
    fn signing_an_old_proposal_does_not_open_new_spend_allowance() {
        let mut v = vault();
        set_policies(
            &mut v,
            vec![Policy {
                id: "cap".into(),
                name: "cap".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::SpendCap {
                    window: Window::H1,
                    usd_micros: 5_000_000,
                }],
            }],
            "d",
            0,
        )
        .unwrap();
        assert_eq!(to_awaiting(&mut v, "old").state, TxState::Awaiting);
        let later = 7_200_001;
        assert_eq!(
            approve(&mut v, "old", &pw(), "d", later).unwrap().state,
            TxState::Signed
        );
        propose(&mut v, intent("new", TO, "1000"), "d", later + 1).unwrap();
        attach(
            &mut v,
            "new",
            signer(),
            unsigned(TO, "1000"),
            serde_json::json!({"ok": true}),
            true,
            "d",
            later + 2,
        )
        .unwrap();
        assert_eq!(
            evaluate(&mut v, "new", "d", later + 3).unwrap().state,
            TxState::Denied
        );
        load_ledger(&v).unwrap().validate().unwrap();
    }

    #[test]
    fn bitcoin_inputs_are_reserved_and_the_full_lifecycle_is_audited() {
        let mut v = vault();
        let path = "m/84'/1'/0'/0/0";
        let key = provenance::signing_key(&v, "w", Curve::Secp256k1, path).unwrap();
        let unsigned = bitcoin::fixture(&key.public);
        let make_intent = |id: &str| {
            let mut i = intent(id, &unsigned.to, &unsigned.amount);
            i.chain_id = ChainId(bitcoin::SIGNET.into());
            i.kind = TxIntentKind::Transfer {
                to: unsigned.to.clone(),
                asset: AssetRef(format!("{}:native", bitcoin::SIGNET)),
                amount: Amount(unsigned.amount.clone()),
            };
            i
        };
        let signer = Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: unsigned.from.clone(),
        };
        let wrong_path = Signer {
            path: "m/84'/0'/0'/0/0".into(),
            ..signer.clone()
        };
        assert!(signer_address(&v, &wrong_path, &UnsignedTx::Bitcoin(unsigned.clone())).is_err());
        propose(&mut v, make_intent("btc"), "d", 1).unwrap();
        attach(
            &mut v,
            "btc",
            signer.clone(),
            unsigned.clone(),
            serde_json::json!({"ok":false}),
            false,
            "d",
            2,
        )
        .unwrap();
        evaluate(&mut v, "btc", "d", 3).unwrap();
        propose(&mut v, make_intent("conflict"), "d", 4).unwrap();
        assert!(attach(
            &mut v,
            "conflict",
            signer.clone(),
            unsigned.clone(),
            serde_json::json!({}),
            false,
            "d",
            5
        )
        .is_err());
        assert!(approve(&mut v, "btc", &Secret::new(b"wrong".to_vec()), "d", 6).is_err());
        let signed = approve(&mut v, "btc", &pw(), "d", 7).unwrap();
        assert_eq!(signed.state, TxState::Signed);
        report(&mut v, "btc", TxState::Broadcast, None, "d", 8).unwrap();
        report(&mut v, "btc", TxState::Pending, None, "d", 9).unwrap();
        assert!(report(&mut v, "btc", TxState::Expired, None, "d", 10).is_err());
        report(&mut v, "btc", TxState::Confirmed, None, "d", 11).unwrap();
        load_ledger(&v).unwrap().validate().unwrap();
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
    fn evm_mainnets_are_refused_at_proposal() {
        let mut v = vault();
        for chain in ["eip155:1", "eip155:8453", "eip155:137"] {
            let mut i = intent(chain, TO, "1");
            i.chain_id = ChainId(chain.into());
            i.kind = TxIntentKind::Transfer {
                to: TO.into(),
                asset: AssetRef(format!("{chain}:native")),
                amount: Amount("1".into()),
            };
            let err = propose(&mut v, i, "d", 1).unwrap_err();
            assert!(err.to_string().contains("testnets only"), "{chain}: {err}");
        }
        assert!(load_ledger(&v).unwrap().txs.is_empty());
    }

    fn solana_awaiting(v: &mut EncryptedVault, id: &str) -> TxRecord {
        solana_awaiting_version(v, id, solana::MessageVersion::Legacy)
    }

    fn solana_awaiting_version(
        v: &mut EncryptedVault,
        id: &str,
        message_version: solana::MessageVersion,
    ) -> TxRecord {
        let path = "m/44'/501'/0'/0'";
        let key = provenance::signing_key(v, "w", Curve::Ed25519, path).unwrap();
        let from = bs58::encode(hex::decode(key.public_hex()).unwrap()).into_string();
        let to = bs58::encode([8; 32]).into_string();
        let mut i = intent(id, &to, "1000");
        i.chain_id = ChainId(solana::DEVNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", solana::DEVNET)),
            amount: Amount("1000".into()),
        };
        propose(v, i, "d", 1).unwrap();
        attach(
            v,
            id,
            Signer {
                wallet_id: "w".into(),
                path: path.into(),
                address: from.clone(),
            },
            SolanaTx {
                chain_id: solana::DEVNET.into(),
                from,
                to,
                lamports: "1000".into(),
                recent_blockhash: bs58::encode([9; 32]).into_string(),
                last_valid_block_height: 100,
                message_version,
            },
            serde_json::json!({"ok": true}),
            true,
            "d",
            2,
        )
        .unwrap();
        evaluate(v, id, "d", 3).unwrap()
    }

    #[test]
    fn versioned_solana_signing_and_history_are_audited() {
        let mut v = vault();
        solana_awaiting_version(&mut v, "v0", solana::MessageVersion::V0);
        let signed = approve(&mut v, "v0", &pw(), "d", 4).unwrap();
        let raw = hex::decode(signed.raw_signed_hex.unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 217);
        assert_eq!(raw[65], 0x80);
        report(&mut v, "v0", TxState::Broadcast, None, "d", 5).unwrap();
        report(&mut v, "v0", TxState::Pending, None, "d", 6).unwrap();
        let ledger = load_ledger(&v).unwrap();
        ledger.validate().unwrap();
        assert!(matches!(
            ledger.audit.last().unwrap().event,
            AuditEvent::TxTransition {
                to: TxState::Pending,
                ..
            }
        ));
        let bytes = v.to_bytes().unwrap();
        let mut reopened = EncryptedVault::from_bytes(&bytes).unwrap();
        reopened.unlock(&pw()).unwrap();
        assert_eq!(load_ledger(&reopened).unwrap(), ledger);
    }

    #[test]
    fn solana_lifecycle_expiry_and_failure_are_audited() {
        let mut v = vault();
        let t = solana_awaiting(&mut v, "sol");
        assert_eq!(t.state, TxState::Awaiting);
        assert!(approve(&mut v, "sol", &Secret::new(b"wrong".to_vec()), "d", 4).is_err());
        let signed = approve(&mut v, "sol", &pw(), "d", 4).unwrap();
        assert_eq!(signed.state, TxState::Signed);
        let raw = hex::decode(signed.raw_signed_hex.unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 215);
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(&raw[69..101].try_into().unwrap()).unwrap();
        key.verify_strict(
            &raw[65..],
            &ed25519_dalek::Signature::from_slice(&raw[1..65]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            bs58::encode(&raw[1..65]).into_string(),
            signed.hash.unwrap()
        );
        report(&mut v, "sol", TxState::Broadcast, None, "d", 5).unwrap();
        report(&mut v, "sol", TxState::Pending, None, "d", 6).unwrap();
        report(
            &mut v,
            "sol",
            TxState::Failed,
            Some("on-chain failure".into()),
            "d",
            7,
        )
        .unwrap();
        solana_awaiting(&mut v, "expired");
        let expired = report(
            &mut v,
            "expired",
            TxState::Expired,
            Some("blockhash expired".into()),
            "d",
            8,
        )
        .unwrap();
        assert!(expired.raw_signed_hex.is_none());
        assert!(approve(&mut v, "expired", &pw(), "d", 9).is_err());
        let ledger = load_ledger(&v).unwrap();
        ledger.validate().unwrap();
        assert_eq!(
            ledger.audit.last().unwrap().event,
            AuditEvent::TxTransition {
                tx_id: "expired".into(),
                from: TxState::Awaiting,
                to: TxState::Expired,
                note: Some("blockhash expired".into()),
            }
        );
        let bytes = v.to_bytes().unwrap();
        let mut reopened = EncryptedVault::from_bytes(&bytes).unwrap();
        reopened.unlock(&pw()).unwrap();
        assert_eq!(load_ledger(&reopened).unwrap(), ledger);
    }

    #[test]
    fn solana_policy_rechecks_and_legacy_evm_payloads_survive() {
        let mut v = vault();
        let sol = solana_awaiting(&mut v, "sol");
        set_policies(
            &mut v,
            vec![Policy {
                id: "deny-sol".into(),
                name: "Deny Solana".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::ChainAllow {
                    chain_ids: vec![ChainId("eip155:11155111".into())],
                }],
            }],
            "d",
            4,
        )
        .unwrap();
        assert_eq!(
            approve(&mut v, "sol", &pw(), "d", 5).unwrap().state,
            TxState::Rejected
        );
        let legacy = unsigned(TO, "1000");
        let json = serde_json::to_value(&legacy).unwrap();
        let decoded: UnsignedTx = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<TxRecord>(serde_json::to_value(&sol).unwrap()).unwrap(),
            sol
        );
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
    fn cosmos_expiry_is_audited_and_does_not_change_legacy_lifetimes() {
        let mut v = vault();
        to_awaiting(&mut v, "evm");
        assert!(report(&mut v, "evm", TxState::Expired, None, "d", 4).is_err());
        let path = "m/44'/118'/0'/0/0";
        let key = provenance::signing_key(&v, "w", Curve::Secp256k1, path).unwrap();
        let from = cosmos::address(&key.public).unwrap();
        let other =
            provenance::signing_key(&v, "w", Curve::Secp256k1, "m/44'/118'/0'/0/1").unwrap();
        let to = cosmos::address(&other.public).unwrap();
        let unsigned = CosmosTx {
            chain_id: cosmos::TESTNET.into(),
            from: from.clone(),
            to: to.clone(),
            amount: "1000".into(),
            public_key_hex: key.public_hex(),
            account_number: "42".into(),
            sequence: "0".into(),
            gas_limit: 100000,
            fee_amount: "2500".into(),
            timeout_height: 123,
        };
        let mut i = intent("cosmos", &to, "1000");
        i.chain_id = ChainId(cosmos::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to,
            asset: AssetRef(format!("{}:native", cosmos::TESTNET)),
            amount: Amount("1000".into()),
        };
        propose(&mut v, i, "d", 5).unwrap();
        attach(
            &mut v,
            "cosmos",
            Signer {
                wallet_id: "w".into(),
                path: path.into(),
                address: from,
            },
            unsigned,
            serde_json::json!({"ok":true}),
            true,
            "d",
            6,
        )
        .unwrap();
        evaluate(&mut v, "cosmos", "d", 7).unwrap();
        assert_eq!(
            approve(&mut v, "cosmos", &pw(), "d", 8).unwrap().state,
            TxState::Signed
        );
        report(&mut v, "cosmos", TxState::Broadcast, None, "d", 9).unwrap();
        report(&mut v, "cosmos", TxState::Pending, None, "d", 10).unwrap();
        assert_eq!(
            report(
                &mut v,
                "cosmos",
                TxState::Expired,
                Some("timeout".into()),
                "d",
                11
            )
            .unwrap()
            .state,
            TxState::Expired
        );
        assert!(approve(&mut v, "cosmos", &pw(), "d", 12).is_err());
        load_ledger(&v).unwrap().validate().unwrap();
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
