//! Device-to-device channel.
//!
//! The core is sans-IO here: it owns pairing, the Noise handshake, the session
//! cipher state and framing, and hands opaque byte buffers to whatever carries
//! them (TCP on desktop and CLI, a WebRTC data channel in the browser). Every
//! carrier therefore gets the same authentication, replay protection and
//! binding to device identity, and the browser build needs no sockets.
//!
//! Trust model (`docs/SECURITY.md` §3): a peer is known only if its Ed25519
//! identity key and X25519 Noise static key were pinned at pairing. Pairing
//! happens exactly once per peer under a one-time code that acts as the Noise
//! PSK; every later connection is Noise `IK` against the pinned static, and a
//! handshake from an unpinned static is refused before any application byte
//! is read. Unknown devices are refused, not trusted on first use.

use serde::{Deserialize, Serialize};

use crate::identity::SignedCeremonyMessage;
use crate::Result;

pub use crate::store::{Device, DeviceKind};

pub mod frame;
pub mod noise;
pub mod pairing;
pub mod session;

pub use frame::{Frame, Hello, MAX_FRAME_LEN};
pub use noise::{
    HandshakeRole, NoiseHandshake, NoiseTransport, NOISE_PATTERN_IK, NOISE_PATTERN_PAIRING,
};
pub use pairing::{PairingOffer, ONE_TIME_CODE_LEN, PAIRING_OFFER_PREFIX};
pub use session::{hello_binding, Session, SessionEvent, SessionState, StaticLookup, HELLO_DOMAIN};

/// Version byte on every pairing offer and handshake prologue. Bump when the
/// wire format changes incompatibly; peers on different versions refuse each
/// other instead of guessing.
pub const TRANSPORT_VERSION: u8 = 1;

/// Service type advertised on the LAN. Instances carry the device id as the
/// instance name and `identity`/`noise` TXT records holding the public keys,
/// so discovery alone can never introduce an unpinned device.
pub const MDNS_SERVICE_TYPE: &str = "_stackwallet._tcp.local.";

/// What the ceremony layer needs from a carrier: deliver signed messages to
/// paired devices and surface the ones that arrived. Implementations verify
/// the envelope signature and the channel binding before returning a message.
pub trait Transport {
    fn local_device(&self) -> &Device;
    fn peers(&self) -> Vec<Device>;
    fn send(&mut self, msg: SignedCeremonyMessage) -> Result<()>;
    fn poll(&mut self) -> Result<Vec<SignedCeremonyMessage>>;
}

/// How a peer can be reached. Strings in `Device::endpoints` are the
/// serialised form so the store never needs to know the carrier set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Endpoint {
    /// `host:port`, reachable directly on the LAN.
    Tcp { addr: String },
    /// A browser peer that needs a WebRTC offer relayed over an existing
    /// channel to a desktop on the same LAN.
    WebRtc { via_device_id: String },
}

impl Endpoint {
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(addr) = s.strip_prefix("tcp://") {
            return Some(Self::Tcp {
                addr: addr.to_owned(),
            });
        }
        if let Some(via) = s.strip_prefix("webrtc-via://") {
            return Some(Self::WebRtc {
                via_device_id: via.to_owned(),
            });
        }
        None
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp { addr } => write!(f, "tcp://{addr}"),
            Self::WebRtc { via_device_id } => write!(f, "webrtc-via://{via_device_id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_roundtrip() {
        for s in ["tcp://192.168.1.2:4000", "webrtc-via://abcd"] {
            assert_eq!(Endpoint::parse(s).unwrap().to_string(), s);
        }
        assert!(Endpoint::parse("http://x").is_none());
    }
}
