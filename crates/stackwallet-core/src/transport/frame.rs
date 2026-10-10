//! Application frames carried inside Noise transport messages.
//!
//! Every frame is JSON (the same serde shapes the TS side validates with Zod)
//! and is encrypted by the session, so this layer never sees plaintext on the
//! wire. The carrier only moves `u16`-length-prefixed ciphertexts, which keeps
//! each one inside the 65535-byte Noise message limit.

use serde::{Deserialize, Serialize};

use crate::identity::SignedCeremonyMessage;
use crate::store::DeviceKind;
use crate::{CoreError, Result};

/// Largest plaintext a single frame may carry: the Noise limit less the AEAD
/// tag. Larger ceremony bodies are rejected rather than chunked; no FROST
/// round in Phase 1 approaches this.
pub const MAX_FRAME_LEN: usize = 65535 - 16;

/// First frame each side sends after the handshake completes. Binds the
/// channel to the device record the peer already holds: a mismatch between
/// the handshake static and the pinned `identity_pub_hex` tears the session
/// down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    pub device_id: String,
    pub device_name: String,
    pub kind: DeviceKind,
    pub identity_pub_hex: String,
    /// Ed25519 signature over the Noise handshake hash and the sender's own
    /// Noise static, proving the holder of the identity key is the same party
    /// that holds the Noise static (and cannot be reflected back by the peer).
    pub handshake_sig_hex: String,
    /// How this device can be reached; only consulted at pairing, when the
    /// peer has no record yet.
    #[serde(default)]
    pub endpoints: Vec<String>,
}

impl Hello {
    /// Shape checks that need no key material: the id must be the one derived
    /// from the identity key, and the name must fit the directory column.
    pub fn validate(&self) -> Result<()> {
        let invalid = |reason: &str| CoreError::Invalid {
            what: "hello",
            reason: reason.to_owned(),
        };
        if crate::identity::device_id_from_public_hex(&self.identity_pub_hex)? != self.device_id {
            return Err(invalid("device id does not match identity key"));
        }
        if self.device_name.trim().is_empty() || self.device_name.len() > 64 {
            return Err(invalid("device name must be 1-64 bytes"));
        }
        if self.endpoints.len() > 16 || self.endpoints.iter().any(|e| e.len() > 256) {
            return Err(invalid("too many or too long endpoints"));
        }
        Ok(())
    }

    pub fn handshake_sig(&self) -> Result<[u8; crate::identity::SIGNATURE_LEN]> {
        hex::decode(&self.handshake_sig_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| CoreError::Invalid {
                what: "hello",
                reason: "handshake signature must be 64 hex-encoded bytes".into(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Frame {
    Hello(Hello),
    Ceremony(SignedCeremonyMessage),
    /// Relayed WebRTC signalling for a browser peer; opaque to the relay.
    Signal {
        to_device_id: String,
        from_device_id: String,
        sdp_or_ice_json: String,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Bye {
        reason: String,
    },
}

impl Frame {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|e| CoreError::Store(e.to_string()))?;
        if bytes.len() > MAX_FRAME_LEN {
            return Err(CoreError::Invalid {
                what: "frame",
                reason: format!("{} bytes exceeds {MAX_FRAME_LEN}", bytes.len()),
            });
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| CoreError::Invalid {
            what: "frame",
            reason: "malformed".into(),
        })
    }
}
