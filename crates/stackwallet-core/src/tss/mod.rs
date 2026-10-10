//! Threshold signing. FROST (Ed25519, secp256k1-Taproot) is driven by
//! [`frost::FrostParty`]. secp256k1 ECDSA has no driver yet: the only
//! maintained CGGMP implementation is pre-release, which `docs/SECURITY.md`
//! rules out for a signing scheme, so callers get an explicit refusal for
//! that curve. This module owns the ceremony shape that transport, policy and
//! the UI are built against; the protocol maths lives entirely in the audited
//! upstream crates.
//!
//! Every message a party emits carries the session id and the hash of the
//! payload it agreed to sign, and every message a party accepts is checked
//! against both before the protocol driver ever sees its body. A peer that
//! swaps the payload mid-ceremony is refused and the local ceremony aborts.

pub mod frost;
pub mod harness;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Where a party is inside the current ceremony, for diagnostics and the UI.
/// `missing` lists the devices whose message for `round` has not arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CeremonyProgress {
    pub kind: CeremonyKind,
    pub state: CeremonyState,
    pub round: u8,
    pub missing: Vec<String>,
}

/// A party's long-lived key material, opaque to everything except the scheme
/// that produced it. The vault stores and encrypts it as bytes; the
/// `key_package` half is secret and is wiped when the blob is dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ShareBlob {
    #[zeroize(skip)]
    pub curve: Curve,
    pub key_group_id: String,
    pub device_id: String,
    #[serde(with = "hex_bytes")]
    pub key_package: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub public_key_package: Vec<u8>,
}

impl core::fmt::Debug for ShareBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareBlob")
            .field("curve", &self.curve)
            .field("key_group_id", &self.key_group_id)
            .field("device_id", &self.device_id)
            .field("key_package", &"<redacted>")
            .field("public_key_package_len", &self.public_key_package.len())
            .finish()
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// A protocol driver for one party on one curve. Implementations are thin
/// wrappers around audited libraries; no protocol logic lives in this crate.
///
/// A driver runs one ceremony at a time. `*_start` begins it and returns the
/// first messages to send; `handle` consumes a peer message and returns
/// whatever must be sent in reply (possibly nothing). Results are available
/// once `state()` reports [`CeremonyState::Complete`].
pub trait ThresholdScheme {
    fn curve(&self) -> Curve;
    fn party_id(&self) -> &str;
    fn state(&self) -> CeremonyState;
    fn progress(&self) -> Option<CeremonyProgress>;
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
    fn refresh_start(&mut self, session: &CeremonySession) -> Result<Vec<CeremonyMessage>>;
    fn handle(
        &mut self,
        session: &CeremonySession,
        msg: CeremonyMessage,
    ) -> Result<Vec<CeremonyMessage>>;
    fn keygen_result(&self, session: &CeremonySession) -> Result<Option<PublicKey>>;
    fn sign_result(&self, session: &CeremonySession) -> Result<Option<Signature>>;
    fn export_share(&self) -> Result<ShareBlob>;
    fn import_share(&mut self, blob: &ShareBlob) -> Result<()>;
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

    #[test]
    fn share_blob_round_trips_as_hex_and_redacts_debug() {
        let blob = ShareBlob {
            curve: Curve::Ed25519,
            key_group_id: "g".into(),
            device_id: "laptop".into(),
            key_package: vec![1, 2, 3],
            public_key_package: vec![4, 5],
        };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(json.contains("\"keyPackage\":\"010203\""));
        let back: ShareBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
        let dbg = format!("{blob:?}");
        assert!(dbg.contains("<redacted>") && !dbg.contains("[1, 2, 3]"));
    }
}
