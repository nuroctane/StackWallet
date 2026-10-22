//! Threshold (`tss`) wallets held in the encrypted vault, one FROST share per
//! device. A wallet holds one group key on one FROST curve: Ed25519 signs
//! Solana Devnet transfers, secp256k1-tr signs Bitcoin Signet P2TR key-path
//! spends. secp256k1 ECDSA has no acceptable driver (see `docs/SECURITY.md`).
//!
//! A share is sealed after DKG and never leaves Rust: the ceremony driver
//! below loads it from the vault itself, so the page only ever moves protocol
//! messages. Before this device's share joins a signing ceremony it checks
//! what it is asked to sign, against its own policies, exactly as it would for
//! a transaction proposed locally.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{Actor, AuditEvent};
use crate::bitcoin::{self, BitcoinTx};
use crate::intent::{Amount, Proposer, SignRequest, Signature, TxIntent, TxIntentKind};
use crate::ledger;
use crate::model::{AssetRef, ChainId, Curve, KeyGroup, PublicKey};
use crate::policy::{self, Decision};
use crate::solana::{self, SolanaTx};
use crate::tss::frost::{
    keygen_binding_hex, refresh_binding_hex, Ed25519Sha512, FrostParty, Secp256K1Sha256TR,
};
use crate::tss::{
    CeremonyKind, CeremonyMessage, CeremonyProgress, CeremonySession, CeremonyState, ShareBlob,
    ThresholdScheme,
};
use crate::vault::{EncryptedVault, Secret, SessionProof, Vault};
use crate::{CoreError, Result};

const PREFIX: &str = "tss:";
const CURVES: [Curve; 2] = [Curve::Ed25519, Curve::Secp256k1Tr];
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
    pub curve: Curve,
    /// The 32-byte key the chain sees, hex: the Ed25519 group key, or the
    /// x-only Taproot output key.
    pub public_key_hex: String,
    /// The one chain this wallet signs on.
    pub chain_id: String,
    /// The group key as that chain's address.
    pub address: String,
}

fn account_of(wallet_id: &str, stored: &Stored) -> Result<ThresholdAccount> {
    let key = stored
        .group
        .public_keys
        .iter()
        .find(|k| k.curve == stored.share.curve)
        .ok_or_else(|| invalid("group has no key on its share's curve"))?;
    let bytes = hex::decode(&key.hex).map_err(|_| invalid("malformed group key"))?;
    let (key32, chain_id, address): ([u8; 32], &str, String) = match key.curve {
        Curve::Ed25519 => {
            let k: [u8; 32] = bytes
                .try_into()
                .map_err(|_| invalid("malformed group key"))?;
            (k, solana::DEVNET, bs58::encode(k).into_string())
        }
        Curve::Secp256k1Tr => {
            // frost serializes the group key as compressed SEC1; BIP341 uses
            // its x coordinate.
            let k: [u8; 32] = bytes
                .get(1..33)
                .filter(|_| bytes.len() == 33)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| invalid("malformed group key"))?;
            (k, bitcoin::SIGNET, bitcoin::taproot_address(&k)?)
        }
        Curve::Secp256k1 => return Err(invalid("secp256k1 ECDSA is not a threshold curve here")),
    };
    Ok(ThresholdAccount {
        wallet_id: wallet_id.to_owned(),
        group: stored.group.clone(),
        device_id: stored.share.device_id.clone(),
        curve: key.curve,
        public_key_hex: hex::encode(key32),
        chain_id: chain_id.to_owned(),
        address,
    })
}

/// One device's FROST party on whichever curve its wallet uses.
enum Party {
    Ed(FrostParty<Ed25519Sha512>),
    Tr(FrostParty<Secp256K1Sha256TR>),
}

impl Party {
    fn new(curve: Curve, device_id: &str) -> Result<Self> {
        match curve {
            Curve::Ed25519 => Ok(Self::Ed(FrostParty::new(device_id))),
            Curve::Secp256k1Tr => Ok(Self::Tr(FrostParty::new(device_id))),
            Curve::Secp256k1 => Err(invalid("secp256k1 ECDSA has no threshold driver")),
        }
    }
    fn scheme(&self) -> &dyn ThresholdScheme {
        match self {
            Self::Ed(p) => p,
            Self::Tr(p) => p,
        }
    }
    fn scheme_mut(&mut self) -> &mut dyn ThresholdScheme {
        match self {
            Self::Ed(p) => p,
            Self::Tr(p) => p,
        }
    }
    fn sign_batch_start(
        &mut self,
        request: &SignRequest,
        session: &CeremonySession,
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<CeremonyMessage>> {
        match self {
            Self::Ed(p) => p.sign_batch_start(request, session, messages),
            Self::Tr(p) => p.sign_batch_start(request, session, messages),
        }
    }
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
    Refresh {
        session: CeremonySession,
    },
    /// Compare share generations after a refresh one device did not settle.
    Reconcile {
        session: CeremonySession,
    },
}

impl Proposal {
    pub fn session(&self) -> &CeremonySession {
        match self {
            Proposal::KeyGen { session, .. }
            | Proposal::Sign { session, .. }
            | Proposal::Refresh { session }
            | Proposal::Reconcile { session } => session,
        }
    }
}

const PREVIOUS: &str = "tss-prev:";

fn previous_label(wallet_id: &str) -> Result<String> {
    label(wallet_id).map(|l| format!("{PREVIOUS}{}", &l[PREFIX.len()..]))
}

/// The session a share refresh runs under: every party of the group, bound to
/// the group key that must come out unchanged.
pub fn refresh_session(acc: &ThresholdAccount, id: &str, now_ms: i64) -> Result<CeremonySession> {
    let participants: Vec<String> = acc
        .group
        .parties
        .iter()
        .map(|p| p.device_id.clone())
        .collect();
    Ok(CeremonySession {
        id: id.to_owned(),
        kind: CeremonyKind::Refresh,
        key_group_id: acc.group.id.clone(),
        curve: acc.curve,
        payload_hash_hex: Some(refresh_binding(acc, &participants)?),
        participants,
        state: CeremonyState::Rounds,
        created_at_ms: now_ms,
        expires_at_ms: now_ms + MAX_SESSION_MS,
    })
}

fn refresh_binding(acc: &ThresholdAccount, participants: &[String]) -> Result<String> {
    let key = acc
        .group
        .public_keys
        .iter()
        .find(|k| k.curve == acc.curve)
        .ok_or_else(|| invalid("group has no key on its curve"))?;
    let vk = hex::decode(&key.hex).map_err(|_| invalid("malformed group key"))?;
    Ok(refresh_binding_hex(
        &acc.group.id,
        acc.curve,
        u16::from(acc.group.threshold),
        participants,
        &vk,
    ))
}

/// Whether a refresh finished here but has not been confirmed by every peer:
/// the previous share is still sealed beside the new one.
pub fn refresh_pending(vault: &EncryptedVault, wallet_id: &str) -> Result<bool> {
    Ok(vault.handle_for(&previous_label(wallet_id)?).is_some())
}

/// Which share generation this device holds, as a fingerprint of the group's
/// public key package. The package is public, identical on every party, and
/// changes with each refresh, so two devices compare fingerprints to learn
/// whether they hold matching shares without revealing anything secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareFingerprint {
    pub current: String,
    /// Present while a finished refresh awaits reconciliation.
    pub previous: Option<String>,
}

fn fingerprint_of(stored: &Stored) -> String {
    hex::encode(Sha256::digest(&stored.share.public_key_package))
}

fn load_previous(vault: &EncryptedVault, wallet_id: &str) -> Result<Option<Stored>> {
    let Some(handle) = vault.handle_for(&previous_label(wallet_id)?) else {
        return Ok(None);
    };
    let stored = vault.with_secret(&handle, &mut |b| {
        serde_json::from_slice::<Stored>(b.expose())
            .map_err(|_| invalid("unreadable previous share"))
    })??;
    Ok(Some(stored))
}

pub fn share_fingerprint(vault: &EncryptedVault, wallet_id: &str) -> Result<ShareFingerprint> {
    let current = load(vault, wallet_id)?.ok_or_else(|| invalid("no share of that wallet"))?;
    Ok(ShareFingerprint {
        current: fingerprint_of(&current),
        previous: load_previous(vault, wallet_id)?.map(|p| fingerprint_of(&p)),
    })
}

/// What reconciling with a peer did here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Reconciled {
    /// Nothing was pending; the peer already matches.
    InSync,
    /// The peer holds the refreshed share: the previous one is gone.
    Committed,
    /// The peer never sealed the refresh: the previous share is current again.
    RolledBack,
}

/// Settle a pending refresh against every other party's current fingerprint,
/// received over authenticated ceremony channels. Commit only when all of
/// them hold the new share; roll back only when one still holds the old one
/// (a device reports the new generation only after sealing it, so nobody can
/// have committed then). Anything else is refused, so a lost message can never
/// leave the devices on different generations.
pub fn reconcile_refresh(
    vault: &mut EncryptedVault,
    proof: &SessionProof,
    wallet_id: &str,
    peer_currents: &[String],
    device_id: &str,
    now_ms: i64,
) -> Result<Reconciled> {
    vault.verify_session(proof, false)?;
    let acc = lookup(vault, wallet_id)?.ok_or_else(|| invalid("no share of that wallet"))?;
    if peer_currents.len() + 1 != acc.group.parties.len() {
        return Err(invalid(
            "every other party must report its share generation",
        ));
    }
    let mine = share_fingerprint(vault, wallet_id)?;
    let pending = mine.previous.is_some();
    let known = |f: &String| *f == mine.current || mine.previous.as_ref() == Some(f);
    if !peer_currents.iter().all(known) {
        return Err(invalid(
            "another device holds a share of neither generation; check every device before refreshing or signing",
        ));
    }
    if peer_currents.iter().all(|f| *f == mine.current) {
        if !pending {
            return Ok(Reconciled::InSync);
        }
        commit_refresh(vault, wallet_id, device_id, now_ms)?;
        return Ok(Reconciled::Committed);
    }
    rollback_refresh(vault, wallet_id, device_id, now_ms)?;
    Ok(Reconciled::RolledBack)
}

/// The peer holds the refreshed share: drop the previous one, so a copy of
/// the old vault no longer pairs with anything current.
fn commit_refresh(
    vault: &mut EncryptedVault,
    wallet_id: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<()> {
    let handle = vault
        .handle_for(&previous_label(wallet_id)?)
        .ok_or_else(|| invalid("no refresh is waiting to be committed"))?;
    vault.delete(&handle)?;
    ledger::append_audit(
        vault,
        now_ms,
        Actor::Device {
            device_id: device_id.to_owned(),
        },
        AuditEvent::ShareRefreshCommitted {
            wallet_id: wallet_id.to_owned(),
        },
    )
}

/// The peer never sealed the refresh: put the previous share back, so this
/// device matches the peer that still holds its own.
fn rollback_refresh(
    vault: &mut EncryptedVault,
    wallet_id: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<ThresholdAccount> {
    let prev = previous_label(wallet_id)?;
    let handle = vault
        .handle_for(&prev)
        .ok_or_else(|| invalid("no previous share to restore"))?;
    let bytes = vault.with_secret(&handle, &mut |b| b.expose().to_vec())?;
    let stored: Stored =
        serde_json::from_slice(&bytes).map_err(|_| invalid("unreadable previous share"))?;
    vault.put(&label(wallet_id)?, Secret::new(bytes))?;
    vault.delete(&handle)?;
    ledger::append_audit(
        vault,
        now_ms,
        Actor::Device {
            device_id: device_id.to_owned(),
        },
        AuditEvent::ShareRefreshRolledBack {
            wallet_id: wallet_id.to_owned(),
        },
    )?;
    account_of(wallet_id, &stored)
}

fn check_session(session: &CeremonySession, device_id: &str, now_ms: i64) -> Result<()> {
    if session.id.is_empty() || session.id.len() > 128 {
        return Err(invalid("bad session id"));
    }
    if !CURVES.contains(&session.curve) {
        return Err(invalid(
            "only Ed25519 and Taproot threshold wallets are supported",
        ));
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
    /// In the chain's base unit (lamports, satoshis).
    pub amount: String,
    /// The network fee the transaction pays, where it fixes one (Bitcoin).
    pub fee: Option<String>,
    /// Allow or deny under this device's own policies.
    pub decision: Decision,
}

/// A transfer decoded from a sign request's payload by this device's core.
struct Decoded {
    from: String,
    to: String,
    amount: String,
    fee: Option<String>,
    /// What each share signs: the Solana message, or one sighash per input.
    messages: Vec<Vec<u8>>,
}

/// Rebuild the transaction from the payload the session binds, and the exact
/// messages to sign from it. Only a native Solana Devnet transfer or a Signet
/// P2TR spend from the group's own address is recognised; anything else is
/// refused unread.
fn decode(acc: &ThresholdAccount, request: &SignRequest) -> Result<Decoded> {
    let payload = hex::decode(&request.payload_hex).map_err(|_| invalid("payload is not hex"))?;
    let decoded = match acc.curve {
        Curve::Ed25519 => {
            let tx = SolanaTx::from_message(solana::DEVNET, &payload)?;
            Decoded {
                from: tx.from,
                to: tx.to,
                amount: tx.lamports,
                fee: None,
                messages: vec![payload],
            }
        }
        Curve::Secp256k1Tr => {
            let tx = BitcoinTx::from_payload(&payload)?;
            let messages = tx
                .taproot_sighashes()?
                .into_iter()
                .map(|h| h.to_vec())
                .collect();
            Decoded {
                from: tx.from,
                to: tx.to,
                amount: tx.amount,
                fee: Some(tx.fee),
                messages,
            }
        }
        Curve::Secp256k1 => return Err(invalid("secp256k1 ECDSA is not a threshold curve here")),
    };
    if decoded.from != acc.address {
        return Err(invalid("the transfer is not from this group's address"));
    }
    Ok(decoded)
}

/// Decode a signing proposal for a co-signer and evaluate it against this
/// device's policies.
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
    let tx = decode(&acc, request)?;
    let intent = TxIntent {
        id: format!("cosign-{}", request.id),
        wallet_id: acc.wallet_id.clone(),
        account_id: String::new(),
        chain_id: ChainId(acc.chain_id.clone()),
        proposer: Proposer::Human {
            device_id: proposer_device_id.to_owned(),
        },
        kind: TxIntentKind::Transfer {
            to: tx.to.clone(),
            asset: AssetRef(format!("{}:native", acc.chain_id)),
            amount: Amount(tx.amount.clone()),
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
        chain_id: acc.chain_id,
        from: tx.from,
        to: tx.to,
        amount: tx.amount,
        fee: tx.fee,
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
    if session.kind != CeremonyKind::Sign
        || request.curve != acc.curve
        || session.curve != acc.curve
    {
        return Err(invalid("not a signing ceremony on this wallet's curve"));
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
    party: Party,
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
        let [curve] = group.curves[..] else {
            return Err(invalid("a threshold wallet holds exactly one curve"));
        };
        if !CURVES.contains(&curve) {
            return Err(invalid(
                "only Ed25519 and Taproot threshold wallets are supported",
            ));
        }
        check_session(session, device_id, now_ms)?;
        let all: Vec<&str> = group.parties.iter().map(|p| p.device_id.as_str()).collect();
        if session.kind != CeremonyKind::KeyGen
            || session.curve != curve
            || session.key_group_id != group.id
            || session.participants.len() != all.len()
            || !session
                .participants
                .iter()
                .all(|p| all.contains(&p.as_str()))
            || session.payload_hash_hex.as_deref()
                != Some(keygen_binding_hex(group, curve).as_str())
        {
            return Err(invalid("the session does not bind this key group"));
        }
        let mut party = Party::new(curve, device_id)?;
        let out = party.scheme_mut().keygen_start(group, session)?;
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
        // Until a refresh is settled this device may hold a different
        // generation than its co-signers; signing would only fail later.
        if refresh_pending(vault, &acc.wallet_id)? {
            return Err(invalid(
                "a share refresh on this wallet is not settled; compare shares with the other devices first",
            ));
        }
        // Every share signs what its own core derived from the bound payload.
        let decoded = decode(&acc, request)?;
        // The share joins only for a transaction this device's ledger is
        // approving right now, or one its own policies allow as a co-signer.
        let local = ledger::load_ledger(vault)?.txs.into_iter().any(|t| {
            t.id == request.tx_id
                && t.state == crate::lifecycle::TxState::Signing
                && t.unsigned
                    .as_ref()
                    .and_then(|u| ledger::threshold_payload(u).ok())
                    .map(hex::encode)
                    .as_deref()
                    == Some(request.payload_hex.as_str())
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
        let mut party = Party::new(acc.curve, &acc.device_id)?;
        party.scheme_mut().import_share(&stored.share)?;
        let out = party.sign_batch_start(request, session, decoded.messages)?;
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

    /// Join (or propose) a refresh of this device's share: new share material,
    /// the same group key. Every party must take part, since a share left out
    /// of a refresh no longer combines with the refreshed ones. Needs the
    /// passphrase, like key generation: it rewrites what the vault holds.
    pub fn refresh(
        vault: &mut EncryptedVault,
        proof: &SessionProof,
        session: &CeremonySession,
        now_ms: i64,
    ) -> Result<(Self, Vec<CeremonyMessage>)> {
        vault.verify_session(proof, true)?;
        let acc = by_group(vault, &session.key_group_id)?;
        check_session(session, &acc.device_id, now_ms)?;
        if refresh_pending(vault, &acc.wallet_id)? {
            return Err(invalid(
                "the last refresh is not confirmed yet; commit or roll it back first",
            ));
        }
        let mut all: Vec<&str> = acc
            .group
            .parties
            .iter()
            .map(|p| p.device_id.as_str())
            .collect();
        let mut given: Vec<&str> = session.participants.iter().map(String::as_str).collect();
        all.sort_unstable();
        given.sort_unstable();
        if session.kind != CeremonyKind::Refresh
            || session.curve != acc.curve
            || all != given
            || session.payload_hash_hex.as_deref()
                != Some(refresh_binding(&acc, &session.participants)?.as_str())
        {
            return Err(invalid("the session does not bind a refresh of this group"));
        }
        let stored = load(vault, &acc.wallet_id)?.ok_or_else(|| invalid("share disappeared"))?;
        let mut party = Party::new(acc.curve, &acc.device_id)?;
        party.scheme_mut().import_share(&stored.share)?;
        let out = party.scheme_mut().refresh_start(session)?;
        ledger::append_audit(
            vault,
            now_ms,
            Actor::Device {
                device_id: acc.device_id.clone(),
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
                wallet_id: acc.wallet_id,
                group: acc.group,
            },
            out,
        ))
    }

    /// Seal the refreshed share, keeping the previous one beside it until
    /// [`commit_refresh`]. The group key must come out exactly as it went in.
    pub fn finish_refresh(
        &self,
        vault: &mut EncryptedVault,
        now_ms: i64,
    ) -> Result<ThresholdAccount> {
        if self.session.kind != CeremonyKind::Refresh {
            return Err(invalid("not a refresh ceremony"));
        }
        let scheme = self.party.scheme();
        let key = scheme
            .keygen_result(&self.session)?
            .ok_or_else(|| invalid("the refresh has not finished"))?;
        let old = load(vault, &self.wallet_id)?.ok_or_else(|| invalid("share disappeared"))?;
        if !old.group.public_keys.iter().any(|k| k == &key) {
            return Err(invalid("the refresh changed the group key"));
        }
        let fresh = Stored {
            group: old.group.clone(),
            share: scheme.export_share()?,
        };
        let old_bytes = serde_json::to_vec(&old).map_err(|e| invalid(e.to_string()))?;
        let new_bytes = serde_json::to_vec(&fresh).map_err(|e| invalid(e.to_string()))?;
        // Previous first: a crash between the two writes must never leave the
        // vault with neither share.
        vault.put(&previous_label(&self.wallet_id)?, Secret::new(old_bytes))?;
        vault.put(&label(&self.wallet_id)?, Secret::new(new_bytes))?;
        ledger::append_audit(
            vault,
            now_ms,
            Actor::Device {
                device_id: scheme.party_id().to_owned(),
            },
            AuditEvent::ShareRefreshed {
                wallet_id: self.wallet_id.clone(),
                session_id: self.session.id.clone(),
            },
        )?;
        account_of(&self.wallet_id, &fresh)
    }

    pub fn session(&self) -> &CeremonySession {
        &self.session
    }

    pub fn state(&self) -> CeremonyState {
        self.party.scheme().state()
    }

    pub fn progress(&self) -> Option<CeremonyProgress> {
        self.party.scheme().progress()
    }

    /// One peer message in, the replies out. The envelope must be for this
    /// session, bound to its payload, and from a participant.
    pub fn handle(&mut self, msg: CeremonyMessage) -> Result<Vec<CeremonyMessage>> {
        self.session.accepts(&msg)?;
        if msg.from_device_id == self.party.scheme().party_id() {
            return Err(invalid("a message claims to be from this device"));
        }
        self.party.scheme_mut().handle(&self.session, msg)
    }

    /// Seal the share DKG produced and return the new wallet's account.
    pub fn finish_keygen(
        &self,
        vault: &mut EncryptedVault,
        now_ms: i64,
    ) -> Result<ThresholdAccount> {
        let scheme = self.party.scheme();
        let key = scheme
            .keygen_result(&self.session)?
            .ok_or_else(|| invalid("key generation has not finished"))?;
        let share = scheme.export_share()?;
        let mut group = self.group.clone();
        group.public_keys = vec![PublicKey {
            curve: scheme.curve(),
            hex: key.hex,
        }];
        let stored = Stored { group, share };
        let bytes = serde_json::to_vec(&stored).map_err(|e| invalid(e.to_string()))?;
        vault.put(&label(&self.wallet_id)?, Secret::new(bytes))?;
        ledger::append_audit(
            vault,
            now_ms,
            Actor::Device {
                device_id: scheme.party_id().to_owned(),
            },
            AuditEvent::CeremonyCompleted {
                session_id: self.session.id.clone(),
            },
        )?;
        account_of(&self.wallet_id, &stored)
    }

    /// The aggregate signature, once every share has contributed. A batch
    /// (one Taproot signature per input) comes back concatenated in order.
    pub fn signature_hex(&self) -> Result<Option<String>> {
        Ok(self
            .party
            .scheme()
            .sign_result(&self.session)?
            .map(|s: Signature| s.signature_hex))
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
                device_id: self.party.scheme().party_id().to_owned(),
            },
            event,
        )
    }
}

/// The session a key generation runs under, built the same way on every side.
/// The group names its one curve; [`Driver::keygen`] refuses any other shape.
pub fn keygen_session(group: &KeyGroup, id: &str, now_ms: i64) -> CeremonySession {
    let curve = group.curves.first().copied().unwrap_or(Curve::Ed25519);
    CeremonySession {
        id: id.to_owned(),
        kind: CeremonyKind::KeyGen,
        key_group_id: group.id.clone(),
        curve,
        payload_hash_hex: Some(keygen_binding_hex(group, curve)),
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
        curve: request.curve,
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
        assert_eq!(acc_a.address, acc_b.address);
        assert_eq!(acc_a.device_id, "laptop");
        assert_eq!(acc_b.device_id, "phone");
        assert_eq!(list(&va).unwrap().len(), 1);

        let to = bs58::encode([8; 32]).into_string();
        propose_transfer(&mut va, &acc_a.address, &to);
        let (rec, request) =
            ledger::begin_threshold(&mut va, "t1", &proof(), "laptop", 30).unwrap();
        assert_eq!(rec.state, TxState::Signing);
        let request = request.unwrap();
        let session = sign_session(&request, "sg-1", vec!["laptop".into(), "phone".into()], 30);

        // The co-signer decodes the transfer itself and runs its own policies.
        let summary = review_sign(&vb, &request, &session, "laptop", 31).unwrap();
        assert_eq!(
            (summary.to.as_str(), summary.amount.as_str()),
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
        propose_transfer(&mut va, &acc.address, &bs58::encode([8; 32]).into_string());
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
        propose_transfer(&mut vc, &acc_c.address, &to);
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

    fn taproot_keygen(
        va: &mut EncryptedVault,
        vb: &mut EncryptedVault,
    ) -> (ThresholdAccount, ThresholdAccount) {
        let mut g = group([PartyRole::Human, PartyRole::Human], 2);
        g.curves = vec![Curve::Secp256k1Tr];
        let s = keygen_session(&g, "kg-tr", 10);
        assert_eq!(s.curve, Curve::Secp256k1Tr);
        let (mut a, out_a) = Driver::keygen(va, &proof(), "w", "laptop", &g, &s, 11).unwrap();
        let (mut b, out_b) = Driver::keygen(vb, &proof(), "w", "phone", &g, &s, 11).unwrap();
        pump(&mut a, &mut b, out_a, out_b);
        (
            a.finish_keygen(va, 12).unwrap(),
            b.finish_keygen(vb, 12).unwrap(),
        )
    }

    fn signet_recipient() -> String {
        let key = k256::ecdsa::SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        bitcoin::address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn propose_bitcoin(v: &mut EncryptedVault, from: &str, values: &[u64]) -> BitcoinTx {
        let tx = BitcoinTx {
            replaces: None,
            chain_id: bitcoin::SIGNET.into(),
            from: from.into(),
            to: signet_recipient(),
            amount: "50000".into(),
            fee: "600".into(),
            inputs: bitcoin::funding(from, values),
        };
        let intent = TxIntent {
            id: "b1".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(bitcoin::SIGNET.into()),
            proposer: Proposer::Human {
                device_id: "laptop".into(),
            },
            kind: TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{}:native", bitcoin::SIGNET)),
                amount: Amount(tx.amount.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 20,
        };
        ledger::propose(v, intent, "laptop", 20).unwrap();
        ledger::attach(
            v,
            "b1",
            Signer {
                wallet_id: "w".into(),
                path: "tss".into(),
                address: from.into(),
            },
            tx.clone(),
            serde_json::json!({}),
            true,
            "laptop",
            21,
        )
        .unwrap();
        ledger::evaluate(v, "b1", "laptop", 22).unwrap();
        tx
    }

    #[test]
    fn two_devices_spend_a_taproot_output_with_one_signature_per_input() {
        use ::bitcoin::consensus::deserialize;
        use ::bitcoin::hashes::Hash;
        use ::bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
        use ::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use ::bitcoin::{Transaction, TxOut};

        let (mut va, mut vb) = (vault(), vault());
        let (acc_a, acc_b) = taproot_keygen(&mut va, &mut vb);
        assert_eq!(acc_a.address, acc_b.address);
        assert!(acc_a.address.starts_with("tb1p"), "{}", acc_a.address);
        assert_eq!(acc_a.chain_id, bitcoin::SIGNET);
        assert_eq!(acc_a.public_key_hex.len(), 64);

        let tx = propose_bitcoin(&mut va, &acc_a.address, &[30_000, 40_000]);
        let (rec, request) =
            ledger::begin_threshold(&mut va, "b1", &proof(), "laptop", 30).unwrap();
        assert_eq!(rec.state, TxState::Signing);
        let request = request.unwrap();
        assert_eq!(request.curve, Curve::Secp256k1Tr);
        let session = sign_session(&request, "sg-tr", vec!["laptop".into(), "phone".into()], 30);
        assert_eq!(session.curve, Curve::Secp256k1Tr);

        let summary = review_sign(&vb, &request, &session, "laptop", 31).unwrap();
        assert_eq!(summary.chain_id, bitcoin::SIGNET);
        assert_eq!(
            (summary.amount.as_str(), summary.fee.as_deref()),
            ("50000", Some("600"))
        );
        assert!(matches!(summary.decision, Decision::Allow { .. }));

        let (mut a, out_a) =
            Driver::sign(&mut va, &proof(), &request, &session, "laptop", 32).unwrap();
        let (mut b, out_b) =
            Driver::sign(&mut vb, &proof(), &request, &session, "laptop", 32).unwrap();
        pump(&mut a, &mut b, out_a, out_b);
        let sig = a.signature_hex().unwrap().unwrap();
        assert_eq!(sig.len(), 2 * 64 * 2);
        assert_eq!(Some(sig.clone()), b.signature_hex().unwrap());

        let signed = ledger::complete_threshold(&mut va, "b1", &sig, "laptop", 33).unwrap();
        assert_eq!(signed.state, TxState::Signed, "{:?}", signed.error);

        // Check the broadcast bytes with the bitcoin crate's own BIP341/BIP340
        // code, not through the core path that produced them.
        let raw = hex::decode(&signed.raw_signed_hex.unwrap()[2..]).unwrap();
        let final_tx: Transaction = deserialize(&raw).unwrap();
        assert_eq!(final_tx.compute_txid().to_string(), signed.hash.unwrap());
        let prevouts: Vec<TxOut> = tx
            .inputs
            .iter()
            .map(|i| {
                let prev: Transaction =
                    deserialize(&hex::decode(&i.previous_tx_hex).unwrap()).unwrap();
                prev.output[i.vout as usize].clone()
            })
            .collect();
        let key = XOnlyPublicKey::from_slice(&hex::decode(&acc_a.public_key_hex).unwrap()).unwrap();
        assert_eq!(prevouts[0].script_pubkey.as_bytes()[2..], key.serialize());
        let secp = Secp256k1::verification_only();
        let mut cache = SighashCache::new(&final_tx);
        for (i, input) in final_tx.input.iter().enumerate() {
            let witness: Vec<_> = input.witness.iter().collect();
            assert_eq!(witness.len(), 1);
            let digest = cache
                .taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap();
            secp.verify_schnorr(
                &schnorr::Signature::from_slice(witness[0]).unwrap(),
                &Message::from_digest(digest.to_byte_array()),
                &key,
            )
            .unwrap();
        }
        // Change returns to the group's own P2TR output.
        assert_eq!(final_tx.output.len(), 2);
        assert_eq!(final_tx.output[1].value.to_sat(), 70_000 - 50_000 - 600);
        assert_eq!(final_tx.output[1].script_pubkey, prevouts[0].script_pubkey);
    }

    #[test]
    fn taproot_signatures_in_the_wrong_order_fail_the_transaction() {
        let (mut va, mut vb) = (vault(), vault());
        let (acc, _) = taproot_keygen(&mut va, &mut vb);
        propose_bitcoin(&mut va, &acc.address, &[30_000, 40_000]);
        let (_, request) = ledger::begin_threshold(&mut va, "b1", &proof(), "laptop", 30).unwrap();
        let request = request.unwrap();
        let session = sign_session(&request, "sg", vec!["laptop".into(), "phone".into()], 30);
        let (mut a, out_a) =
            Driver::sign(&mut va, &proof(), &request, &session, "laptop", 32).unwrap();
        let (mut b, out_b) =
            Driver::sign(&mut vb, &proof(), &request, &session, "laptop", 32).unwrap();
        pump(&mut a, &mut b, out_a, out_b);
        let sig = a.signature_hex().unwrap().unwrap();
        let swapped = format!("{}{}", &sig[128..], &sig[..128]);
        let out = ledger::complete_threshold(&mut va, "b1", &swapped, "laptop", 33).unwrap();
        assert_eq!(out.state, TxState::Failed);
        assert!(out.error.unwrap().contains("does not verify"));
    }

    #[test]
    fn taproot_co_signers_refuse_foreign_and_non_canonical_payloads() {
        let (mut va, mut vb) = (vault(), vault());
        let (acc, _) = taproot_keygen(&mut va, &mut vb);
        let tx = propose_bitcoin(&mut va, &acc.address, &[80_000]);
        let request = |payload: Vec<u8>| SignRequest {
            id: "r".into(),
            tx_id: "x".into(),
            key_group_id: acc.group.id.clone(),
            curve: Curve::Secp256k1Tr,
            payload_hash_hex: hex::encode(Sha256::digest(&payload)),
            payload_hex: hex::encode(&payload),
        };
        let review = |req: &SignRequest| {
            let s = sign_session(req, "sg", vec!["laptop".into(), "phone".into()], 40);
            review_sign(&vb, req, &s, "laptop", 41)
        };
        assert!(review(&request(tx.payload().unwrap())).is_ok());
        // Same transfer, pretty-printed: the payload must be the core's bytes.
        let pretty = serde_json::to_vec_pretty(&tx).unwrap();
        assert!(review(&request(pretty)).is_err());
        // A spend from someone else's P2WPKH address.
        let key = k256::ecdsa::SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let other = bitcoin::fixture(key.verifying_key().to_encoded_point(true).as_bytes());
        assert!(review(&request(other.payload().unwrap())).is_err());
        // An Ed25519 request against a Taproot group.
        let mut ed = request(tx.payload().unwrap());
        ed.curve = Curve::Ed25519;
        assert!(review(&ed).is_err());
    }

    #[test]
    fn a_wallet_signs_only_on_its_own_curve() {
        // An Ed25519 wallet cannot be the signer of a Bitcoin spend, even one
        // from a real Taproot group address.
        let (mut va, mut vb) = (vault(), vault());
        keygen(&mut va, &mut vb);
        let (tr, _) = taproot_keygen(&mut vault(), &mut vault());
        let tx = BitcoinTx {
            replaces: None,
            chain_id: bitcoin::SIGNET.into(),
            from: tr.address.clone(),
            to: signet_recipient(),
            amount: "50000".into(),
            fee: "600".into(),
            inputs: bitcoin::funding(&tr.address, &[80_000]),
        };
        let intent = TxIntent {
            id: "b2".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(bitcoin::SIGNET.into()),
            proposer: Proposer::Human {
                device_id: "laptop".into(),
            },
            kind: TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{}:native", bitcoin::SIGNET)),
                amount: Amount(tx.amount.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 20,
        };
        ledger::propose(&mut va, intent, "laptop", 20).unwrap();
        let signer = Signer {
            wallet_id: "w".into(),
            path: "tss".into(),
            address: tr.address.clone(),
        };
        let err = ledger::attach(
            &mut va,
            "b2",
            signer,
            tx,
            serde_json::json!({}),
            true,
            "laptop",
            21,
        )
        .unwrap_err();
        assert!(err.to_string().contains("threshold share"), "{err}");
        // A group listing both curves is refused at key generation.
        let mut g = group([PartyRole::Human, PartyRole::Human], 2);
        g.curves = vec![Curve::Ed25519, Curve::Secp256k1Tr];
        let s = keygen_session(&g, "kg-two", 10);
        assert!(Driver::keygen(&mut vault(), &proof(), "w3", "laptop", &g, &s, 11).is_err());
    }

    /// Both devices refresh their shares of `acc`'s group.
    fn refresh_both(
        va: &mut EncryptedVault,
        vb: &mut EncryptedVault,
        acc: &ThresholdAccount,
        id: &str,
    ) -> (Driver, Driver) {
        let s = refresh_session(acc, id, 50).unwrap();
        let (mut a, out_a) = Driver::refresh(va, &proof(), &s, 51).unwrap();
        let (mut b, out_b) = Driver::refresh(vb, &proof(), &s, 51).unwrap();
        pump(&mut a, &mut b, out_a, out_b);
        (a, b)
    }

    fn share_bytes(v: &EncryptedVault) -> Vec<u8> {
        let h = v.handle_for(&label("w").unwrap()).unwrap();
        v.with_secret(&h, &mut |s| s.expose().to_vec()).unwrap()
    }

    #[test]
    fn a_refresh_rotates_shares_and_keeps_the_group_key_on_both_curves() {
        for taproot in [false, true] {
            let (mut va, mut vb) = (vault(), vault());
            let (acc, _) = if taproot {
                taproot_keygen(&mut va, &mut vb)
            } else {
                keygen(&mut va, &mut vb)
            };
            let before = share_bytes(&va);
            let (a, b) = refresh_both(&mut va, &mut vb, &acc, "rf-1");
            let after_a = a.finish_refresh(&mut va, 52).unwrap();
            let after_b = b.finish_refresh(&mut vb, 52).unwrap();
            assert_eq!(after_a.address, acc.address, "taproot={taproot}");
            assert_eq!(after_b.address, acc.address);
            assert_ne!(share_bytes(&va), before, "the share material changed");
            assert!(refresh_pending(&va, "w").unwrap());
            // Another refresh waits for this one to be confirmed.
            let s = refresh_session(&acc, "rf-2", 53).unwrap();
            assert!(Driver::refresh(&mut va, &proof(), &s, 54).is_err());
            let (fa, fb) = (
                share_fingerprint(&va, "w").unwrap(),
                share_fingerprint(&vb, "w").unwrap(),
            );
            assert_eq!(fa, fb, "both devices hold the same generation");
            assert!(fa.previous.is_some());
            // The phone hears the laptop and commits; the laptop's copy of
            // that acknowledgement is lost, so it is still pending...
            assert_eq!(
                reconcile_refresh(
                    &mut vb,
                    &proof(),
                    "w",
                    std::slice::from_ref(&fa.current),
                    "phone",
                    55
                )
                .unwrap(),
                Reconciled::Committed
            );
            assert!(refresh_pending(&va, "w").unwrap());
            // ...and on the next contact it learns the phone holds the new
            // share, so it commits rather than rolling back.
            let now_b = share_fingerprint(&vb, "w").unwrap();
            assert_eq!(now_b.previous, None);
            assert_eq!(
                reconcile_refresh(
                    &mut va,
                    &proof(),
                    "w",
                    std::slice::from_ref(&now_b.current),
                    "laptop",
                    56
                )
                .unwrap(),
                Reconciled::Committed
            );
            assert!(!refresh_pending(&va, "w").unwrap());
            assert_eq!(
                reconcile_refresh(
                    &mut va,
                    &proof(),
                    "w",
                    std::slice::from_ref(&now_b.current),
                    "laptop",
                    57
                )
                .unwrap(),
                Reconciled::InSync
            );
            assert!(
                reconcile_refresh(&mut va, &proof(), "w", &["00".repeat(32)], "laptop", 57)
                    .is_err()
            );

            // The refreshed shares still sign together.
            if taproot {
                propose_bitcoin(&mut va, &acc.address, &[80_000]);
                let (_, req) =
                    ledger::begin_threshold(&mut va, "b1", &proof(), "laptop", 60).unwrap();
                let req = req.unwrap();
                let s = sign_session(&req, "sg", vec!["laptop".into(), "phone".into()], 60);
                let (mut a, oa) = Driver::sign(&mut va, &proof(), &req, &s, "laptop", 61).unwrap();
                let (mut b, ob) = Driver::sign(&mut vb, &proof(), &req, &s, "laptop", 61).unwrap();
                pump(&mut a, &mut b, oa, ob);
                let sig = a.signature_hex().unwrap().unwrap();
                let done = ledger::complete_threshold(&mut va, "b1", &sig, "laptop", 62).unwrap();
                assert_eq!(done.state, TxState::Signed);
            } else {
                propose_transfer(&mut va, &acc.address, &bs58::encode([8; 32]).into_string());
                let (_, req) =
                    ledger::begin_threshold(&mut va, "t1", &proof(), "laptop", 60).unwrap();
                let req = req.unwrap();
                let s = sign_session(&req, "sg", vec!["laptop".into(), "phone".into()], 60);
                let (mut a, oa) = Driver::sign(&mut va, &proof(), &req, &s, "laptop", 61).unwrap();
                let (mut b, ob) = Driver::sign(&mut vb, &proof(), &req, &s, "laptop", 61).unwrap();
                pump(&mut a, &mut b, oa, ob);
                let sig = a.signature_hex().unwrap().unwrap();
                let done = ledger::complete_threshold(&mut va, "t1", &sig, "laptop", 62).unwrap();
                assert_eq!(done.state, TxState::Signed);
            }
            load_ledger_ok(&va);
        }
    }

    fn load_ledger_ok(v: &EncryptedVault) {
        ledger::load_ledger(v).unwrap().validate().unwrap();
    }

    #[test]
    fn a_half_finished_refresh_rolls_back_to_shares_that_still_sign() {
        let (mut va, mut vb) = (vault(), vault());
        let (acc, _) = keygen(&mut va, &mut vb);
        let before = share_bytes(&va);
        let (a, _b) = refresh_both(&mut va, &mut vb, &acc, "rf-1");
        // Only the laptop seals its refreshed share; the phone never does.
        a.finish_refresh(&mut va, 52).unwrap();
        assert_ne!(share_bytes(&va), before);
        // No signature while the generations may disagree.
        propose_transfer(&mut va, &acc.address, &bs58::encode([8; 32]).into_string());
        let (_, req) = ledger::begin_threshold(&mut va, "t1", &proof(), "laptop", 52).unwrap();
        let req = req.unwrap();
        let s = sign_session(&req, "sg", vec!["laptop".into(), "phone".into()], 52);
        let err = Driver::sign(&mut va, &proof(), &req, &s, "laptop", 52)
            .err()
            .unwrap();
        assert!(err.to_string().contains("refresh"), "{err}");
        let phone = share_fingerprint(&vb, "w").unwrap();
        assert_eq!(phone.previous, None);
        let wrong = SessionProof::Passphrase(Secret::new(b"no".to_vec()));
        assert!(reconcile_refresh(
            &mut va,
            &wrong,
            "w",
            std::slice::from_ref(&phone.current),
            "laptop",
            53
        )
        .is_err());
        assert_eq!(
            reconcile_refresh(
                &mut va,
                &proof(),
                "w",
                std::slice::from_ref(&phone.current),
                "laptop",
                53
            )
            .unwrap(),
            Reconciled::RolledBack
        );
        assert_eq!(lookup(&va, "w").unwrap().unwrap().address, acc.address);
        assert_eq!(share_bytes(&va), before);
        assert!(!refresh_pending(&va, "w").unwrap());

        let (mut a, oa) = Driver::sign(&mut va, &proof(), &req, &s, "laptop", 61).unwrap();
        let (mut b, ob) = Driver::sign(&mut vb, &proof(), &req, &s, "laptop", 61).unwrap();
        pump(&mut a, &mut b, oa, ob);
        assert!(a.signature_hex().unwrap().is_some());
        load_ledger_ok(&va);
    }

    #[test]
    fn a_refresh_must_include_every_party_and_bind_the_group_key() {
        let (mut va, mut vb) = (vault(), vault());
        let (acc, _) = keygen(&mut va, &mut vb);
        let mut s = refresh_session(&acc, "rf", 50).unwrap();
        s.participants.pop();
        assert!(Driver::refresh(&mut va, &proof(), &s, 51).is_err());
        let mut s = refresh_session(&acc, "rf", 50).unwrap();
        s.payload_hash_hex = Some("00".repeat(32));
        assert!(Driver::refresh(&mut va, &proof(), &s, 51).is_err());
        let s = refresh_session(&acc, "rf", 50).unwrap();
        // A PIN may sign, but rewriting the vault needs the passphrase.
        assert!(Driver::refresh(
            &mut va,
            &SessionProof::Passphrase(Secret::new(b"no".to_vec())),
            &s,
            51
        )
        .is_err());
        assert!(Driver::refresh(&mut va, &proof(), &s, s.expires_at_ms + 1).is_err());
    }

    /// Route every message to its addressee (or to every other party) until
    /// nobody has anything left to say.
    fn pump_all(drivers: &mut [&mut Driver], mut outbox: Vec<CeremonyMessage>) {
        for _ in 0..64 {
            if outbox.is_empty() {
                return;
            }
            let mut next = Vec::new();
            for m in std::mem::take(&mut outbox) {
                for d in drivers.iter_mut() {
                    let me = d.party.scheme().party_id().to_owned();
                    let wanted = match &m.to_device_id {
                        Some(to) => *to == me,
                        None => m.from_device_id != me,
                    };
                    if wanted {
                        next.extend(d.handle(m.clone()).unwrap());
                    }
                }
            }
            outbox = next;
        }
        panic!("ceremony did not settle");
    }

    #[test]
    fn two_of_three_signs_with_any_pair_and_refreshes_with_everyone() {
        let ids = ["laptop", "phone", "desk"];
        let g = KeyGroup {
            id: "g3".into(),
            threshold: 2,
            parties: ids
                .iter()
                .map(|d| PartyRef {
                    device_id: (*d).into(),
                    role: PartyRole::Human,
                })
                .collect(),
            curves: vec![Curve::Secp256k1Tr],
            public_keys: vec![],
        };
        let mut vaults = [vault(), vault(), vault()];
        let s = keygen_session(&g, "kg3", 10);
        let mut outs = Vec::new();
        let mut drivers: Vec<Driver> = vaults
            .iter_mut()
            .zip(ids)
            .map(|(v, id)| {
                let (d, out) = Driver::keygen(v, &proof(), "w", id, &g, &s, 11).unwrap();
                outs.extend(out);
                d
            })
            .collect();
        pump_all(&mut drivers.iter_mut().collect::<Vec<_>>(), outs);
        let accs: Vec<_> = drivers
            .iter()
            .zip(vaults.iter_mut())
            .map(|(d, v)| d.finish_keygen(v, 12).unwrap())
            .collect();
        assert!(accs.iter().all(|a| a.address == accs[0].address));

        // Laptop and desk sign; the phone is not involved at all.
        let [va, vb, vc] = &mut vaults;
        propose_bitcoin(va, &accs[0].address, &[80_000]);
        let (_, req) = ledger::begin_threshold(va, "b1", &proof(), "laptop", 30).unwrap();
        let req = req.unwrap();
        let s = sign_session(&req, "sg", vec!["laptop".into(), "desk".into()], 30);
        let (mut a, oa) = Driver::sign(va, &proof(), &req, &s, "laptop", 31).unwrap();
        let (mut c, oc) = Driver::sign(vc, &proof(), &req, &s, "laptop", 31).unwrap();
        pump(&mut a, &mut c, oa, oc);
        let sig = a.signature_hex().unwrap().unwrap();
        assert_eq!(
            ledger::complete_threshold(va, "b1", &sig, "laptop", 32)
                .unwrap()
                .state,
            TxState::Signed
        );
        // One share is not enough.
        let lone = sign_session(&req, "sg1", vec!["phone".into()], 30);
        assert!(Driver::sign(vb, &proof(), &req, &lone, "phone", 31).is_err());

        // A refresh needs all three; afterwards each device commits only once
        // both others report the new generation.
        let rs = refresh_session(&accs[0], "rf3", 40).unwrap();
        let mut outs = Vec::new();
        let mut drivers: Vec<Driver> = vaults
            .iter_mut()
            .map(|v| {
                let (d, out) = Driver::refresh(v, &proof(), &rs, 41).unwrap();
                outs.extend(out);
                d
            })
            .collect();
        pump_all(&mut drivers.iter_mut().collect::<Vec<_>>(), outs);
        for (d, v) in drivers.iter().zip(vaults.iter_mut()) {
            d.finish_refresh(v, 42).unwrap();
        }
        let fps: Vec<String> = vaults
            .iter()
            .map(|v| share_fingerprint(v, "w").unwrap().current)
            .collect();
        assert!(fps.iter().all(|f| *f == fps[0]));
        // Hearing from only one other party is not enough to commit.
        assert!(reconcile_refresh(
            &mut vaults[0],
            &proof(),
            "w",
            &[fps[1].clone()],
            "laptop",
            43
        )
        .is_err());
        for (i, v) in vaults.iter_mut().enumerate() {
            let others: Vec<String> = fps
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, f)| f.clone())
                .collect();
            assert_eq!(
                reconcile_refresh(v, &proof(), "w", &others, ids[i], 44).unwrap(),
                Reconciled::Committed
            );
        }
    }
}
