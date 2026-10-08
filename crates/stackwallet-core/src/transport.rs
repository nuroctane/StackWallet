//! Device-to-device channel. Phase 2 implements pairing (QR + one-time PSK,
//! Noise IK), LAN discovery (mDNS) and WebRTC data channels. Phase 0 defines
//! the records transport persists and the surface the ceremony layer uses.

use serde::{Deserialize, Serialize};

use crate::tss::CeremonyMessage;
use crate::{CoreError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Desktop,
    Browser,
    Cli,
    Mobile,
}

/// A paired device. The identity key is pinned at pairing and never prompted
/// for again: an unknown identity is refused, not "trust on first use".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub name: String,
    pub kind: DeviceKind,
    /// Ed25519 identity public key, hex.
    pub identity_pub_hex: String,
    pub endpoints: Vec<String>,
    pub paired_at_ms: i64,
    pub last_seen_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

/// Contents of the pairing QR. The one-time code is the Noise PSK for the
/// first handshake only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOffer {
    pub device_id: String,
    pub identity_pub_hex: String,
    pub endpoints: Vec<String>,
    pub one_time_code: String,
    pub expires_at_ms: i64,
}

pub trait Transport {
    fn local_device(&self) -> &Device;
    fn peers(&self) -> Vec<Device>;
    fn send(&mut self, msg: CeremonyMessage) -> Result<()>;
    fn poll(&mut self) -> Result<Vec<CeremonyMessage>>;
}

/// Placeholder until Phase 2.
#[derive(Debug)]
pub struct UnimplementedTransport {
    local: Device,
}

impl UnimplementedTransport {
    pub fn new(local: Device) -> Self {
        Self { local }
    }
}

impl Transport for UnimplementedTransport {
    fn local_device(&self) -> &Device {
        &self.local
    }
    fn peers(&self) -> Vec<Device> {
        vec![]
    }
    fn send(&mut self, _msg: CeremonyMessage) -> Result<()> {
        Err(CoreError::NotYet {
            phase: "Phase 2",
            what: "transport send",
        })
    }
    fn poll(&mut self) -> Result<Vec<CeremonyMessage>> {
        Err(CoreError::NotYet {
            phase: "Phase 2",
            what: "transport poll",
        })
    }
}
