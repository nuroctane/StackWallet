//! Threshold signing. Phase 1 wires CGGMP21 (secp256k1 ECDSA) and FROST
//! (Ed25519, secp256k1-tr) behind the traits below. Phase 0 defines the
//! ceremony shape so transport, policy and the UI can be built against it.

use serde::{Deserialize, Serialize};

use crate::intent::{SignRequest, Signature};
use crate::model::{Curve, KeyGroup, PublicKey};
use crate::{CoreError, Result};

/// One protocol message between parties. `session_id` and `payload_hash_hex`
/// are echoed on every message so a receiver can refuse anything that is not
/// about the exact payload it agreed to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CeremonyMessage {
    pub session_id: String,
    pub payload_hash_hex: String,
    pub from_device_id: String,
    pub to_device_id: Option<String>,
    pub round: u8,
    pub body_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CeremonyKind {
    KeyGen,
    Refresh,
    Reshare,
    Sign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CeremonyState {
    Proposed,
    Collecting,
    Rounds,
    Complete,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CeremonySession {
    pub id: String,
    pub kind: CeremonyKind,
    pub key_group_id: String,
    pub curve: Curve,
    pub payload_hash_hex: Option<String>,
    pub participants: Vec<String>,
    pub state: CeremonyState,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl CeremonySession {
    /// Transport calls this before handing a message to the protocol driver.
    pub fn accepts(&self, msg: &CeremonyMessage) -> Result<()> {
        if msg.session_id != self.id {
            return Err(CoreError::Invalid {
                what: "ceremony message",
                reason: "wrong session".into(),
            });
        }
        if let Some(expected) = &self.payload_hash_hex {
            if &msg.payload_hash_hex != expected {
                return Err(CoreError::Invalid {
                    what: "ceremony message",
                    reason: "payload hash does not match the agreed sign request".into(),
                });
            }
        }
        if !self.participants.iter().any(|p| p == &msg.from_device_id) {
            return Err(CoreError::Invalid {
                what: "ceremony message",
                reason: "sender is not a participant".into(),
            });
        }
        Ok(())
    }
}

/// A protocol driver for one curve. Implementations are thin wrappers around
/// audited libraries; no protocol logic lives in this crate.
pub trait ThresholdScheme {
    fn curve(&self) -> Curve;
    fn keygen_start(
        &mut self,
        group: &KeyGroup,
        session: &CeremonySession,
    ) -> Result<Vec<CeremonyMessage>>;
    fn sign_start(
        &mut self,
        request: &SignRequest,
        session: &CeremonySession,
    ) -> Result<Vec<CeremonyMessage>>;
    fn handle(
        &mut self,
        session: &CeremonySession,
        msg: CeremonyMessage,
    ) -> Result<Vec<CeremonyMessage>>;
    fn keygen_result(&self, session: &CeremonySession) -> Result<Option<PublicKey>>;
    fn sign_result(&self, session: &CeremonySession) -> Result<Option<Signature>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> CeremonySession {
        CeremonySession {
            id: "s1".into(),
            kind: CeremonyKind::Sign,
            key_group_id: "g".into(),
            curve: Curve::Ed25519,
            payload_hash_hex: Some("aa".repeat(32)),
            participants: vec!["laptop".into(), "phone".into()],
            state: CeremonyState::Rounds,
            created_at_ms: 0,
            expires_at_ms: 60_000,
        }
    }

    fn msg(session_id: &str, hash: &str, from: &str) -> CeremonyMessage {
        CeremonyMessage {
            session_id: session_id.into(),
            payload_hash_hex: hash.into(),
            from_device_id: from.into(),
            to_device_id: None,
            round: 1,
            body_hex: String::new(),
        }
    }

    #[test]
    fn rejects_payload_substitution() {
        let s = session();
        assert!(s.accepts(&msg("s1", &"aa".repeat(32), "phone")).is_ok());
        assert!(s.accepts(&msg("s1", &"bb".repeat(32), "phone")).is_err());
        assert!(s.accepts(&msg("s2", &"aa".repeat(32), "phone")).is_err());
        assert!(s.accepts(&msg("s1", &"aa".repeat(32), "stranger")).is_err());
    }
}
