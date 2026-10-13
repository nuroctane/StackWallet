//! Threshold (`tss`) wallets held in the encrypted vault, one FROST share per
//! device. Ed25519 only: secp256k1 ECDSA has no acceptable driver (see
//! `docs/SECURITY.md`), and Taproot needs a Bitcoin spend path that does not
//! exist yet.
//!
//! A share is sealed after DKG and never leaves Rust: the ceremony driver
//! below loads it from the vault itself, so the page only ever moves protocol
//! messages. Before this device's share joins a signing ceremony it checks
//! what it is asked to sign, against its own policies, exactly as it would for
//! a transaction proposed locally.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{Actor, AuditEvent};
use crate::intent::{Amount, Proposer, SignRequest, TxIntent, TxIntentKind};
use crate::ledger;
use crate::model::{AssetRef, ChainId, Curve, KeyGroup, PublicKey};
use crate::policy::{self, Decision};
use crate::solana::{self, SolanaTx};
use crate::tss::frost::{keygen_binding_hex, FrostParty};
use crate::tss::{
    CeremonyKind, CeremonyMessage, CeremonyProgress, CeremonySession, CeremonyState, ShareBlob,
    ThresholdScheme,
};
use crate::vault::{EncryptedVault, Secret, SessionProof, Vault};
use crate::{CoreError, Result};

type Ed25519 = frost_ed25519::Ed25519Sha512;

const PREFIX: &str = "tss:";
/// A proposal may not ask peers to wait longer than this for a ceremony.
pub const MAX_SESSION_MS: i64 = 10 * 60_000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "threshold wallet",
        reason: reason.into(),
    }
}

fn label(wallet_id: &str) -> Result<String> {
    if wallet_id.is_empty() || wallet_id.len() > 128 || wallet_id.chars().any(char::is_control) {
        return Err(invalid("bad wallet id"));
    }
    Ok(format!("{PREFIX}{wallet_id}"))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    group: KeyGroup,
    share: ShareBlob,
}

/// The public half of a threshold wallet on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdAccount {
    pub wallet_id: String,
    pub group: KeyGroup,
    /// This device's party id in the group.
    pub device_id: String,
    /// Ed25519 group key, hex.
    pub public_key_hex: String,
    /// The group key as a Solana address.
    pub solana_address: String,
}

fn account_of(wallet_id: &str, stored: &Stored) -> Result<ThresholdAccount> {
    let key = stored
        .group
        .public_keys
        .iter()
        .find(|k| k.curve == Curve::Ed25519)
        .ok_or_else(|| invalid("group has no Ed25519 key"))?;
    let bytes: [u8; 32] = hex::decode(&key.hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("malformed group key"))?;
    Ok(ThresholdAccount {
        wallet_id: wallet_id.to_owned(),
        group: stored.group.clone(),
        device_id: stored.share.device_id.clone(),
        public_key_hex: key.hex.clone(),
        solana_address: bs58::encode(bytes).into_string(),
    })
}

fn load(vault: &EncryptedVault, wallet_id: &str) -> Result<Option<Stored>> {
    let Some(handle) = vault.handle_for(&label(wallet_id)?) else {
        return Ok(None);
    };
    let stored = vault.with_secret(&handle, &mut |b| {
        serde_json::from_slice::<Stored>(b.expose()).map_err(|_| invalid("unreadable share"))
    })??;
    Ok(Some(stored))
}

pub fn lookup(vault: &EncryptedVault, wallet_id: &str) -> Result<Option<ThresholdAccount>> {
    load(vault, wallet_id)?
        .map(|s| account_of(wallet_id, &s))
        .transpose()
}

/// Every threshold wallet this vault holds a share of.
pub fn list(vault: &EncryptedVault) -> Result<Vec<ThresholdAccount>> {
    let mut out = Vec::new();
    for (_, l) in vault.labels() {
        if let Some(wallet_id) = l.strip_prefix(PREFIX) {
            if let Some(acc) = lookup(vault, wallet_id)? {
                out.push(acc);
            }
        }
    }
    Ok(out)
}

fn by_group(vault: &EncryptedVault, group_id: &str) -> Result<ThresholdAccount> {
    list(vault)?
        .into_iter()
        .find(|a| a.group.id == group_id)
        .ok_or_else(|| invalid(format!("this device holds no share of group {group_id}")))
}

/// The proposal a ceremony starts from. The proposer sends it to every other
/// participant; each checks it before its share does anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Proposal {
    KeyGen {
        group: KeyGroup,
        session: CeremonySession,
    },
    Sign {
        request: SignRequest,
        session: CeremonySession,
    },
}

impl Proposal {
    pub fn session(&self) -> &CeremonySession {
        match self {
            Proposal::KeyGen { session, .. } | Proposal::Sign { session, .. } => session,
        }
    }
}

fn check_session(session: &CeremonySession, device_id: &str, now_ms: i64) -> Result<()> {
    if session.id.is_empty() || session.id.len() > 128 {
        return Err(invalid("bad session id"));
    }
    if session.curve != Curve::Ed25519 {
        return Err(invalid("only Ed25519 threshold wallets are supported"));
    }
    if !session.participants.iter().any(|p| p == device_id) {
        return Err(invalid("this device is not a participant"));
    }
    let mut seen = session.participants.clone();
    seen.sort_unstable();
    seen.dedup();
    if seen.len() != session.participants.len() {
        return Err(invalid("a participant is listed twice"));
    }
    if now_ms > session.expires_at_ms
        || session.expires_at_ms - session.created_at_ms > MAX_SESSION_MS
    {
        return Err(invalid(
            "the ceremony expired or asks for too long a window",
        ));
    }
    Ok(())
}

/// What a co-signer is being asked to sign, decoded by the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignSummary {
    pub wallet_id: String,
    pub chain_id: String,
    pub from: String,
    pub to: String,
    pub lamports: String,
    /// Allow or deny under this device's own policies.
    pub decision: Decision,
}

/// Decode a signing proposal for a co-signer and evaluate it against this
/// device's policies. Only a native Solana Devnet transfer from the group's
/// own address is recognised; anything else is refused unread.
pub fn review_sign(
    vault: &EncryptedVault,
    request: &SignRequest,
    session: &CeremonySession,
    proposer_device_id: &str,
    now_ms: i64,
) -> Result<CosignSummary> {
    let acc = by_group(vault, &request.key_group_id)?;
    check_sign_proposal(&acc, request, session, now_ms)?;
    if !session.participants.iter().any(|p| p == proposer_device_id) {
        return Err(invalid("the proposer is not a participant"));
    }
    let message = hex::decode(&request.payload_hex).map_err(|_| invalid("payload is not hex"))?;
    let tx = SolanaTx::from_message(solana::DEVNET, &message)?;
    if tx.from != acc.solana_address {
        return Err(invalid("the transfer is not from this group's address"));
    }
    let intent = TxIntent {
        id: format!("cosign-{}", request.id),
        wallet_id: acc.wallet_id.clone(),
        account_id: String::new(),
        chain_id: ChainId(solana::DEVNET.into()),
        proposer: Proposer::Human {
            device_id: proposer_device_id.to_owned(),
        },
        kind: TxIntentKind::Transfer {
            to: tx.to.clone(),
            asset: AssetRef(format!("{}:native", solana::DEVNET)),
            amount: Amount(tx.lamports.clone()),
        },
        usd_micros: None,
        untrusted_destinations: vec![],
        created_at_ms: now_ms,
    };
    let book = ledger::load_ledger(vault)?;
    let ctx = book.context("", now_ms, None);
    let decision = policy::evaluate(&book.policies, &intent, &ctx);
    Ok(CosignSummary {
        wallet_id: acc.wallet_id,
        chain_id: solana::DEVNET.into(),
        from: tx.from,
        to: tx.to,
        lamports: tx.lamports,
        decision,
    })
}

fn check_sign_proposal(
    acc: &ThresholdAccount,
    request: &SignRequest,
    session: &CeremonySession,
    now_ms: i64,
) -> Result<()> {
    check_session(session, &acc.device_id, now_ms)?;
    if session.kind != CeremonyKind::Sign || request.curve != Curve::Ed25519 {
        return Err(invalid("not an Ed25519 signing ceremony"));
    }
    if session.key_group_id != acc.group.id || request.key_group_id != acc.group.id {
        return Err(invalid("ceremony is for another key group"));
    }
    let payload = hex::decode(&request.payload_hex).map_err(|_| invalid("payload is not hex"))?;
    let hash = hex::encode(Sha256::digest(&payload));
    if request.payload_hash_hex != hash || session.payload_hash_hex.as_deref() != Some(&hash) {
        return Err(invalid("payload hash does not bind the ceremony"));
    }
    if session.participants.len() < usize::from(acc.group.threshold) {
        return Err(invalid("fewer signers than the threshold"));
    }
    for p in &session.participants {
        if !acc.group.parties.iter().any(|q| &q.device_id == p) {
            return Err(invalid(format!("{p} is not a party of the group")));
        }
    }
    Ok(())
}

/// One device's side of one ceremony. The page feeds it the peers' messages
/// and sends what it returns; the protocol and every check live here.
pub struct Driver {
    party: FrostParty<Ed25519>,
    session: CeremonySession,
    wallet_id: String,
    group: KeyGroup,
}

impl Driver {
    /// Join (or propose) a key generation for `wallet_id`. The group must pass
    /// the D6 check and the session must bind exactly this group.
    pub fn keygen(
        vault: &mut EncryptedVault,
        proof: &SessionProof,
        wallet_id: &str,
        device_id: &str,
        group: &KeyGroup,
        session: &CeremonySession,
        now_ms: i64,
    ) -> Result<(Self, Vec<CeremonyMessage>)> {
        vault.verify_session(proof, true)?;
        if load(vault, wallet_id)?.is_some() {
            return Err(invalid("this wallet already holds a share"));
        }
        group.validate()?;
        if group.curves != [Curve::Ed25519] {
            return Err(invalid("only Ed25519 threshold wallets are supported"));
        }
        check_session(session, device_id, now_ms)?;
        let all: Vec<&str> = group.parties.iter().map(|p| p.device_id.as_str()).collect();
        if session.kind != CeremonyKind::KeyGen
            || session.key_group_id != group.id
            || session.participants.len() != all.len()
            || !session
                .participants
                .iter()
                .all(|p| all.contains(&p.as_str()))
            || session.payload_hash_hex.as_deref()
                != Some(keygen_binding_hex(group, Curve::Ed25519).as_str())
        {
            return Err(invalid("the session does not bind this key group"));
        }
        let mut party = FrostParty::<Ed25519>::new(device_id);
        let out = party.keygen_start(group, session)?;
        ledger::append_audit(
            vault,
            now_ms,
            Actor::Device {
                device_id: device_id.to_owned(),
            },
            AuditEvent::CeremonyStarted {
                session_id: session.id.clone(),
                sign_request_id: None,
            },
        )?;
        Ok((
            Self {
                party,
                session: session.clone(),
                wallet_id: wallet_id.to_owned(),
                group: group.clone(),
            },
            out,
        ))
    }

    /// Join a signing ceremony with this device's sealed share. The caller
    /// has shown the user [`review_sign`] (co-signer) or proposed the
    /// transaction itself through the ledger (initiator).
    pub fn sign(
        vault: &mut EncryptedVault,
        proof: &SessionProof,
        request: &SignRequest,
        session: &CeremonySession,
        proposer_device_id: &str,
        now_ms: i64,
    ) -> Result<(Self, Vec<CeremonyMessage>)> {
        vault.verify_session(proof, false)?;
        let acc = by_group(vault, &request.key_group_id)?;
        check_sign_proposal(&acc, request, session, now_ms)?;
        // The share joins only for a transaction this device's ledger is
        // approving right now, or one its own policies allow as a co-signer.
        let local = ledger::load_ledger(vault)?.txs.into_iter().any(|t| {
            t.id == request.tx_id
                && t.state == crate::lifecycle::TxState::Signing
                && matches!(&t.unsigned, Some(ledger::UnsignedTx::Solana(tx))
                    if tx.message().ok().map(hex::encode).as_deref() == Some(request.payload_hex.as_str()))
        });
        if !local {
            let review = review_sign(vault, request, session, proposer_device_id, now_ms)?;
            if let Decision::Deny { reasons, .. } = review.decision {
                return Err(invalid(format!(
                    "refused by policy: {}",
                    reasons.join("; ")
                )));
            }
        }
        let stored = load(vault, &acc.wallet_id)?.ok_or_else(|| invalid("share disappeared"))?;
        let mut party = FrostParty::<Ed25519>::new(acc.device_id.clone());
        party.import_share(&stored.share)?;
        let out = party.sign_start(request, session)?;
        ledger::append_audit(
            vault,
            now_ms,
            Actor::Device {
                device_id: acc.device_id.clone(),
            },
            AuditEvent::CeremonyStarted {
                session_id: session.id.clone(),
                sign_request_id: Some(request.id.clone()),
            },
        )?;
        Ok((
            Self {
                party,
                session: session.clone(),
                wallet_id: acc.wallet_id,
                group: acc.group,
            },
            out,
        ))
    }

    pub fn session(&self) -> &CeremonySession {
        &self.session
    }

    pub fn state(&self) -> CeremonyState {
        self.party.state()
    }

    pub fn progress(&self) -> Option<CeremonyProgress> {
        self.party.progress()
    }

    /// One peer message in, the replies out. The envelope must be for this
    /// session, bound to its payload, and from a participant.
    pub fn handle(&mut self, msg: CeremonyMessage) -> Result<Vec<CeremonyMessage>> {
        self.session.accepts(&msg)?;
        if msg.from_device_id == self.party.party_id() {
            return Err(invalid("a message claims to be from this device"));
        }
        self.party.handle(&self.session, msg)
    }

    /// Seal the share DKG produced and return the new wallet's account.
    pub fn finish_keygen(
        &self,
        vault: &mut EncryptedVault,
        now_ms: i64,
    ) -> Result<ThresholdAccount> {
        let key = self
            .party
            .keygen_result(&self.session)?
            .ok_or_else(|| invalid("key generation has not finished"))?;
        let share = self.party.export_share()?;
        let mut group = self.group.clone();
        group.public_keys = vec![PublicKey {
            curve: Curve::Ed25519,
            hex: key.hex,
        }];
        let stored = Stored { group, share };
        let bytes = serde_json::to_vec(&stored).map_err(|e| invalid(e.to_string()))?;
        vault.put(&label(&self.wallet_id)?, Secret::new(bytes))?;
        ledger::append_audit(
            vault,
            now_ms,
            Actor::Device {
                device_id: self.party.party_id().to_owned(),
            },
            AuditEvent::CeremonyCompleted {
                session_id: self.session.id.clone(),
            },
        )?;
        account_of(&self.wallet_id, &stored)
    }

    /// The aggregate signature, once every share has contributed.
    pub fn signature_hex(&self) -> Result<Option<String>> {
        Ok(self
            .party
            .sign_result(&self.session)?
            .map(|s| s.signature_hex))
    }

    /// Record how a ceremony ended on this device.
    pub fn audit_end(
        &self,
        vault: &mut EncryptedVault,
        aborted: Option<&str>,
        now_ms: i64,
    ) -> Result<()> {
        let event = match aborted {
            None => AuditEvent::CeremonyCompleted {
                session_id: self.session.id.clone(),
            },
            Some(reason) => AuditEvent::CeremonyAborted {
                session_id: self.session.id.clone(),
                reason: reason
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(200)
                    .collect(),
            },
        };
        ledger::append_audit(
            vault,
            now_ms,
            Actor::Device {
                device_id: self.party.party_id().to_owned(),
            },
            event,
        )
    }
}

/// The session a key generation runs under, built the same way on every side.
pub fn keygen_session(group: &KeyGroup, id: &str, now_ms: i64) -> CeremonySession {
    CeremonySession {
        id: id.to_owned(),
        kind: CeremonyKind::KeyGen,
        key_group_id: group.id.clone(),
        curve: Curve::Ed25519,
        payload_hash_hex: Some(keygen_binding_hex(group, Curve::Ed25519)),
        participants: group.parties.iter().map(|p| p.device_id.clone()).collect(),
        state: CeremonyState::Rounds,
        created_at_ms: now_ms,
        expires_at_ms: now_ms + MAX_SESSION_MS,
    }
}

/// The session a signing ceremony runs under.
pub fn sign_session(
    request: &SignRequest,
    id: &str,
    participants: Vec<String>,
    now_ms: i64,
) -> CeremonySession {
    CeremonySession {
        id: id.to_owned(),
        kind: CeremonyKind::Sign,
        key_group_id: request.key_group_id.clone(),
        curve: Curve::Ed25519,
        payload_hash_hex: Some(request.payload_hash_hex.clone()),
        participants,
        state: CeremonyState::Rounds,
        created_at_ms: now_ms,
        expires_at_ms: now_ms + MAX_SESSION_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::ledger::{self, Signer};
    use crate::lifecycle::TxState;
    use crate::model::{AssetRef, ChainId, PartyRef, PartyRole};
    use crate::vault::KdfParams;

    fn vault() -> EncryptedVault {
        EncryptedVault::create(&Secret::new(b"pw".to_vec()), KdfParams::MINIMUM).unwrap()
    }
    fn proof() -> SessionProof {
        SessionProof::Passphrase(Secret::new(b"pw".to_vec()))
    }
    fn group(roles: [PartyRole; 2], threshold: u8) -> KeyGroup {
        KeyGroup {
            id: "g1".into(),
            threshold,
            parties: vec![
                PartyRef {
                    device_id: "laptop".into(),
                    role: roles[0],
                },
                PartyRef {
                    device_id: "phone".into(),
                    role: roles[1],
                },
            ],
            curves: vec![Curve::Ed25519],
            public_keys: vec![],
        }
    }

    /// Shuttle messages between two drivers until neither has anything to say.
    fn pump(
        a: &mut Driver,
        b: &mut Driver,
        mut out_a: Vec<CeremonyMessage>,
        mut out_b: Vec<CeremonyMessage>,
    ) {
        for _ in 0..64 {
            if out_a.is_empty() && out_b.is_empty() {
                return;
            }
            let to_b = std::mem::take(&mut out_a);
            let to_a = std::mem::take(&mut out_b);
            for m in to_b {
                out_b.extend(b.handle(m).unwrap());
            }
            for m in to_a {
                out_a.extend(a.handle(m).unwrap());
            }
        }
        panic!("ceremony did not settle");
    }

    fn keygen(
        va: &mut EncryptedVault,
        vb: &mut EncryptedVault,
    ) -> (ThresholdAccount, ThresholdAccount) {
        let g = group([PartyRole::Human, PartyRole::Human], 2);
        let s = keygen_session(&g, "kg-1", 10);
        let (mut a, out_a) = Driver::keygen(va, &proof(), "w", "laptop", &g, &s, 11).unwrap();
        let (mut b, out_b) = Driver::keygen(vb, &proof(), "w", "phone", &g, &s, 11).unwrap();
        pump(&mut a, &mut b, out_a, out_b);
        (
            a.finish_keygen(va, 12).unwrap(),
            b.finish_keygen(vb, 12).unwrap(),
        )
    }

    fn propose_transfer(v: &mut EncryptedVault, from: &str, to: &str) {
        let intent = TxIntent {
            id: "t1".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(solana::DEVNET.into()),
            proposer: Proposer::Human {
                device_id: "laptop".into(),
            },
            kind: TxIntentKind::Transfer {
                to: to.into(),
                asset: AssetRef(format!("{}:native", solana::DEVNET)),
                amount: Amount("1000".into()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 20,
        };
        ledger::propose(v, intent, "laptop", 20).unwrap();
        ledger::attach(
            v,
            "t1",
            Signer {
                wallet_id: "w".into(),
                path: "tss".into(),
                address: from.into(),
            },
            SolanaTx {
                chain_id: solana::DEVNET.into(),
                from: from.into(),
                to: to.into(),
                lamports: "1000".into(),
                recent_blockhash: bs58::encode([9; 32]).into_string(),
                last_valid_block_height: 100,
                message_version: solana::MessageVersion::Legacy,
            },
            serde_json::json!({}),
            true,
            "laptop",
            21,
        )
        .unwrap();
        ledger::evaluate(v, "t1", "laptop", 22).unwrap();
    }

    #[test]
    fn two_devices_generate_and_sign_without_either_holding_the_key() {
        let (mut va, mut vb) = (vault(), vault());
        let (acc_a, acc_b) = keygen(&mut va, &mut vb);
        assert_eq!(acc_a.solana_address, acc_b.solana_address);
        assert_eq!(acc_a.device_id, "laptop");
        assert_eq!(acc_b.device_id, "phone");
        assert_eq!(list(&va).unwrap().len(), 1);

        let to = bs58::encode([8; 32]).into_string();
        propose_transfer(&mut va, &acc_a.solana_address, &to);
        let (rec, request) =
            ledger::begin_threshold(&mut va, "t1", &proof(), "laptop", 30).unwrap();
        assert_eq!(rec.state, TxState::Signing);
        let request = request.unwrap();
        let session = sign_session(&request, "sg-1", vec!["laptop".into(), "phone".into()], 30);

        // The co-signer decodes the transfer itself and runs its own policies.
        let summary = review_sign(&vb, &request, &session, "laptop", 31).unwrap();
        assert_eq!(
            (summary.to.as_str(), summary.lamports.as_str()),
            (to.as_str(), "1000")
        );
        assert!(matches!(summary.decision, Decision::Allow { .. }));

        let (mut a, out_a) =
            Driver::sign(&mut va, &proof(), &request, &session, "laptop", 32).unwrap();
        let (mut b, out_b) =
            Driver::sign(&mut vb, &proof(), &request, &session, "laptop", 32).unwrap();
        pump(&mut a, &mut b, out_a, out_b);
        let sig = a.signature_hex().unwrap().unwrap();
        assert_eq!(Some(sig.clone()), b.signature_hex().unwrap());

        let signed = ledger::complete_threshold(&mut va, "t1", &sig, "laptop", 33).unwrap();
        assert_eq!(signed.state, TxState::Signed);
        assert!(signed.raw_signed_hex.unwrap().len() > 2 * 64);
    }

    #[test]
    fn a_forged_signature_fails_the_transaction() {
        let (mut va, mut vb) = (vault(), vault());
        let (acc, _) = keygen(&mut va, &mut vb);
        propose_transfer(
            &mut va,
            &acc.solana_address,
            &bs58::encode([8; 32]).into_string(),
        );
        ledger::begin_threshold(&mut va, "t1", &proof(), "laptop", 30).unwrap();
        let out =
            ledger::complete_threshold(&mut va, "t1", &"11".repeat(64), "laptop", 31).unwrap();
        assert_eq!(out.state, TxState::Failed);
    }

    #[test]
    fn co_signers_refuse_foreign_payloads_and_agent_only_groups() {
        let (mut va, mut vb) = (vault(), vault());
        let (acc, _) = keygen(&mut va, &mut vb);
        // A transfer from some other address must not be co-signed.
        let other = SolanaTx {
            chain_id: solana::DEVNET.into(),
            from: bs58::encode([5; 32]).into_string(),
            to: bs58::encode([8; 32]).into_string(),
            lamports: "1".into(),
            recent_blockhash: bs58::encode([9; 32]).into_string(),
            last_valid_block_height: 1,
            message_version: solana::MessageVersion::Legacy,
        };
        let message = other.message().unwrap();
        let request = SignRequest {
            id: "r".into(),
            tx_id: "x".into(),
            key_group_id: acc.group.id.clone(),
            curve: Curve::Ed25519,
            payload_hash_hex: hex::encode(Sha256::digest(&message)),
            payload_hex: hex::encode(&message),
        };
        let session = sign_session(&request, "sg", vec!["laptop".into(), "phone".into()], 40);
        assert!(review_sign(&vb, &request, &session, "laptop", 41).is_err());
        // Arbitrary bytes are not a transaction this wallet builds.
        let junk = SignRequest {
            payload_hash_hex: hex::encode(Sha256::digest(b"junk")),
            payload_hex: hex::encode(b"junk"),
            ..request.clone()
        };
        let s2 = sign_session(&junk, "sg2", vec!["laptop".into(), "phone".into()], 40);
        assert!(review_sign(&vb, &junk, &s2, "laptop", 41).is_err());
        // A session that binds another payload is refused before the share loads.
        let mut swapped = session.clone();
        swapped.payload_hash_hex = Some("00".repeat(32));
        assert!(Driver::sign(&mut vb, &proof(), &request, &swapped, "laptop", 41).is_err());
        // Expired.
        assert!(Driver::sign(
            &mut vb,
            &proof(),
            &request,
            &session,
            "laptop",
            session.expires_at_ms + 1
        )
        .is_err());

        // The co-signer's own deny list keeps its share out.
        let (mut vc, mut vd) = (vault(), vault());
        let (acc_c, _) = keygen(&mut vc, &mut vd);
        let to = bs58::encode([8; 32]).into_string();
        ledger::set_policies(
            &mut vd,
            vec![crate::policy::Policy {
                id: "p".into(),
                name: "deny".into(),
                mode: crate::policy::PolicyMode::Enforce,
                rules: vec![crate::policy::Rule::DestinationDeny {
                    addresses: vec![to.clone()],
                }],
            }],
            "phone",
            0,
        )
        .unwrap();
        propose_transfer(&mut vc, &acc_c.solana_address, &to);
        let (_, req) = ledger::begin_threshold(&mut vc, "t1", &proof(), "laptop", 30).unwrap();
        let req = req.unwrap();
        let s3 = sign_session(&req, "sg3", vec!["laptop".into(), "phone".into()], 30);
        assert!(Driver::sign(&mut vc, &proof(), &req, &s3, "laptop", 31).is_ok());
        let err = Driver::sign(&mut vd, &proof(), &req, &s3, "laptop", 31)
            .err()
            .unwrap();
        assert!(err.to_string().contains("policy"), "{err}");

        // D6: an agent-only 1-of-2 where the agent could sign alone.
        let g = group([PartyRole::Agent, PartyRole::Human], 1);
        let s = keygen_session(&g, "kg-x", 10);
        let mut v = vault();
        assert!(Driver::keygen(&mut v, &proof(), "w2", "laptop", &g, &s, 11).is_err());
    }
}
