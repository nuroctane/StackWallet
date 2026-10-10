//! One authenticated channel to one peer, as a sans-IO state machine.
//!
//! The carrier feeds `Session::handle_incoming` every wire message it receives
//! (one Noise handshake message or one transport ciphertext, already stripped
//! of the carrier's length prefix) and drains `Session::take_outgoing` after
//! each call; `Session::send` queues an application frame. The session
//! refuses to carry frames until the Noise handshake has finished *and* both
//! sides exchanged a valid `Hello` whose identity matches the pinned device
//! record (or, during pairing, whose identity is then pinned).
//!
//! Protocol violations never surface as `Err`: they close the session and
//! come back as `SessionEvent::Closed`, so a carrier that forgets to check a
//! `Result` still cannot keep talking to a peer that failed authentication.
//! `Err` is reserved for caller mistakes (sending before open, feeding a
//! closed session).

use zeroize::Zeroizing;

use crate::identity::{self, DeviceIdentity, SignedCeremonyMessage};
use crate::store::Device;
use crate::transport::frame::{Frame, Hello};
use crate::transport::noise::{HandshakeRole, NoiseHandshake, NoiseTransport};
use crate::transport::pairing::{decode_32, PairingOffer};
use crate::{CoreError, Result};

/// Domain separator for the `Hello` signature so an identity signature over a
/// handshake hash can never double as a ceremony signature or vice versa.
pub const HELLO_DOMAIN: &[u8] = b"stackwallet/v1/noise-hello";

/// Resolves the Noise static an `IK` initiator transmitted in its first
/// message to the pinned device record. `None` refuses the connection.
pub type StaticLookup = Box<dyn Fn(&[u8; 32]) -> Option<Device> + Send>;

/// Bytes each side signs with its identity key inside `Hello`. Including the
/// signer's own Noise static means a peer cannot reflect our Hello back at us
/// (its static differs), and the verifier checks against the static the
/// handshake actually authenticated rather than anything the Hello claims.
pub fn hello_binding(handshake_hash: &[u8], signer_noise_static: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_DOMAIN.len() + handshake_hash.len() + 32);
    out.extend_from_slice(HELLO_DOMAIN);
    out.extend_from_slice(handshake_hash);
    out.extend_from_slice(signer_noise_static);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    /// Noise done, our `Hello` queued, waiting for the peer's.
    AwaitingHello,
    Open,
    Closed,
}

/// What the carrier or ceremony layer should act on after feeding input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Channel is authenticated; `peer` is the verified device record with a
    /// fresh `last_seen_at_ms`.
    Opened {
        peer: Device,
    },
    /// Pairing completed; the caller must persist `peer` before trusting it
    /// for anything else.
    Paired {
        peer: Device,
    },
    /// An authenticated application frame. `Ping` is answered internally and
    /// never surfaced; `Hello` and `Bye` become state changes instead. A
    /// `Ceremony` frame here was authored by the session peer and its
    /// envelope signature has been verified against the pinned identity.
    Frame(Frame),
    /// A ceremony envelope the peer forwarded on behalf of another device.
    /// The channel authenticates the peer as the relay, not the author: the
    /// session has no device table, so the caller must verify the envelope
    /// against its own pinned record for `from_device_id` (refusing unknown
    /// or revoked devices) before the ceremony layer sees it.
    Relayed(SignedCeremonyMessage),
    Closed {
        reason: String,
    },
}

/// Who we expect on the other end, decided before the handshake starts.
enum Expect {
    /// Scanner side of pairing: the issuer exactly as the offer described it.
    Offer(Device),
    /// Issuer side of pairing: whoever completes the PSK handshake, pinned
    /// from its `Hello` and the static the handshake transmitted.
    AnyUnderPsk,
    /// A record already in the device table.
    Pinned(Device),
    /// `IK` responder: resolved once the first message reveals the static.
    Lookup(StaticLookup),
}

enum Phase {
    Handshaking(Box<NoiseHandshake>),
    AwaitingHello(NoiseTransport),
    Open(NoiseTransport),
    Closed,
}

pub struct Session {
    identity: DeviceIdentity,
    local: Device,
    phase: Phase,
    expect: Expect,
    pairing: bool,
    peer: Option<Device>,
    outgoing: Vec<Vec<u8>>,
    now_ms: i64,
}

impl Session {
    /// Start a pairing session from the issuer's side (QR shown here).
    /// `now_ms` stamps the record pinned when the scanner's `Hello` arrives.
    pub fn pair_as_issuer(
        identity: &DeviceIdentity,
        local: &Device,
        offer: &PairingOffer,
        now_ms: i64,
    ) -> Result<Self> {
        offer.validate()?;
        check_local(identity, local)?;
        check_fresh(offer, now_ms)?;
        if offer.identity_pub_hex != identity.public_hex()
            || offer.noise_static_hex != identity.noise_static_public_hex()
        {
            return Err(invalid(
                "pairing offer",
                "offer was not issued by this device",
            ));
        }
        let code = Zeroizing::new(offer.one_time_code());
        let hs = NoiseHandshake::pairing(
            HandshakeRole::Responder,
            &identity.noise_static(),
            None,
            &code,
        )?;
        Self::new(identity, local, hs, Expect::AnyUnderPsk, true, now_ms)
    }

    /// Start a pairing session from the scanning side.
    pub fn pair_as_scanner(
        identity: &DeviceIdentity,
        local: &Device,
        offer: &PairingOffer,
        now_ms: i64,
    ) -> Result<Self> {
        offer.validate()?;
        check_local(identity, local)?;
        check_fresh(offer, now_ms)?;
        if offer.identity_pub_hex == identity.public_hex() {
            return Err(invalid("pairing offer", "cannot pair a device with itself"));
        }
        let code = Zeroizing::new(offer.one_time_code());
        let hs = NoiseHandshake::pairing(
            HandshakeRole::Initiator,
            &identity.noise_static(),
            Some(&offer.noise_static()),
            &code,
        )?;
        let expected = Device {
            id: offer.device_id.clone(),
            name: offer.device_name.clone(),
            kind: offer.kind,
            identity_pub_hex: offer.identity_pub_hex.clone(),
            noise_static_hex: offer.noise_static_hex.clone(),
            endpoints: offer.endpoints.clone(),
            paired_at_ms: now_ms,
            last_seen_at_ms: Some(now_ms),
            revoked_at_ms: None,
        };
        Self::new(identity, local, hs, Expect::Offer(expected), true, now_ms)
    }

    /// Open an `IK` session to an already paired peer. The initiator passes
    /// the pinned record; the responder passes `peer: None` and a lookup that
    /// resolves the initiator's static to its pinned record. Unknown and
    /// revoked statics are refused before the handshake completes.
    pub fn connect(
        identity: &DeviceIdentity,
        local: &Device,
        role: HandshakeRole,
        peer: Option<&Device>,
        lookup_by_static: Option<StaticLookup>,
        now_ms: i64,
    ) -> Result<Self> {
        check_local(identity, local)?;
        let (hs, expect) = match role {
            HandshakeRole::Initiator => {
                let peer = peer.ok_or_else(|| {
                    invalid("session", "IK initiator needs the peer's pinned record")
                })?;
                if peer.revoked_at_ms.is_some() {
                    return Err(invalid("session", "revoked device"));
                }
                let remote = decode_32(&peer.noise_static_hex)
                    .ok_or_else(|| invalid("session", "peer has no pinned noise static"))?;
                let hs = NoiseHandshake::session(role, &identity.noise_static(), Some(&remote))?;
                (hs, Expect::Pinned(peer.clone()))
            }
            HandshakeRole::Responder => {
                let lookup = lookup_by_static.ok_or_else(|| {
                    invalid(
                        "session",
                        "IK responder needs a lookup for the peer's static",
                    )
                })?;
                let hs = NoiseHandshake::session(role, &identity.noise_static(), None)?;
                (hs, Expect::Lookup(lookup))
            }
        };
        Self::new(identity, local, hs, expect, false, now_ms)
    }

    fn new(
        identity: &DeviceIdentity,
        local: &Device,
        mut hs: NoiseHandshake,
        expect: Expect,
        pairing: bool,
        now_ms: i64,
    ) -> Result<Self> {
        let mut outgoing = Vec::new();
        if hs.is_my_turn() {
            outgoing.push(hs.write_message(&[])?);
        }
        Ok(Self {
            // The handshake hash is only known after the last handshake
            // message, so the signer has to outlive the constructor.
            identity: DeviceIdentity::from_secret(&identity.to_secret())?,
            local: local.clone(),
            phase: Phase::Handshaking(Box::new(hs)),
            expect,
            pairing,
            peer: None,
            outgoing,
            now_ms,
        })
    }

    pub fn state(&self) -> SessionState {
        match self.phase {
            Phase::Handshaking(_) => SessionState::Handshaking,
            Phase::AwaitingHello(_) => SessionState::AwaitingHello,
            Phase::Open(_) => SessionState::Open,
            Phase::Closed => SessionState::Closed,
        }
    }

    pub fn is_pairing(&self) -> bool {
        self.pairing
    }

    /// The verified peer. `Some` only from `Open` on, and kept after close so
    /// the carrier can still say which device the session was with.
    pub fn peer(&self) -> Option<&Device> {
        self.peer.as_ref()
    }

    /// Feed one wire message from the carrier.
    pub fn handle_incoming(&mut self, bytes: &[u8]) -> Result<Vec<SessionEvent>> {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Closed => Err(invalid("session", "closed")),
            Phase::Handshaking(hs) => Ok(self.handshake_step(*hs, bytes)),
            Phase::AwaitingHello(mut transport) => {
                let frame = match decrypt_frame(&mut transport, bytes) {
                    Ok(frame) => frame,
                    Err(reason) => return Ok(self.fail(Some(&mut transport), reason)),
                };
                let Frame::Hello(hello) = frame else {
                    return Ok(self.fail(Some(&mut transport), "frame before hello"));
                };
                match self.verify_hello(&transport, hello) {
                    Ok(peer) => {
                        self.peer = Some(peer.clone());
                        self.phase = Phase::Open(transport);
                        Ok(vec![if self.pairing {
                            SessionEvent::Paired { peer }
                        } else {
                            SessionEvent::Opened { peer }
                        }])
                    }
                    Err(reason) => Ok(self.fail(Some(&mut transport), &reason)),
                }
            }
            Phase::Open(mut transport) => {
                let frame = match decrypt_frame(&mut transport, bytes) {
                    Ok(frame) => frame,
                    Err(reason) => return Ok(self.fail(Some(&mut transport), reason)),
                };
                Ok(self.dispatch(transport, frame))
            }
        }
    }

    /// Queue an application frame; only valid once `Open`. `Bye` is routed
    /// through `close`; `Hello` is the session's own business.
    pub fn send(&mut self, frame: Frame) -> Result<()> {
        match frame {
            Frame::Hello(_) => Err(invalid("frame", "hello is sent by the session itself")),
            Frame::Bye { reason } => {
                self.close(&reason);
                Ok(())
            }
            other => {
                let Phase::Open(transport) = &mut self.phase else {
                    return Err(invalid("session", "not open"));
                };
                let ciphertext = transport.encrypt(&other.to_bytes()?)?;
                self.outgoing.push(ciphertext);
                Ok(())
            }
        }
    }

    /// Wire messages the carrier must deliver, in order.
    pub fn take_outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outgoing)
    }

    /// Tell the peer we are leaving (when the channel can carry it) and stop
    /// accepting input. Idempotent.
    pub fn close(&mut self, reason: &str) {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::AwaitingHello(mut t) | Phase::Open(mut t) => self.queue_bye(&mut t, reason),
            Phase::Handshaking(_) | Phase::Closed => {}
        }
    }

    fn handshake_step(&mut self, mut hs: NoiseHandshake, bytes: &[u8]) -> Vec<SessionEvent> {
        if hs.read_message(bytes).is_err() {
            return self.fail(None, "handshake failed");
        }
        // The responder learns the initiator's static from the first message
        // and must refuse unknown or revoked devices before replying, so an
        // unpinned peer never gets a second message to work with.
        if let Expect::Lookup(lookup) = &self.expect {
            let Some(remote) = hs.remote_static() else {
                return self.fail(None, "handshake did not carry a static");
            };
            let Some(device) = lookup(&remote) else {
                return self.fail(None, "unknown device");
            };
            if device.revoked_at_ms.is_some() {
                return self.fail(None, "revoked device");
            }
            if decode_32(&device.noise_static_hex) != Some(remote) {
                return self.fail(None, "lookup returned a device with a different static");
            }
            self.expect = Expect::Pinned(device);
        }
        if !hs.is_finished() && hs.is_my_turn() {
            match hs.write_message(&[]) {
                Ok(msg) => self.outgoing.push(msg),
                Err(_) => return self.fail(None, "handshake failed"),
            }
        }
        if !hs.is_finished() {
            self.phase = Phase::Handshaking(Box::new(hs));
            return Vec::new();
        }
        let mut transport = match hs.into_transport() {
            Ok(t) => t,
            Err(_) => return self.fail(None, "handshake failed"),
        };
        let hello = Frame::Hello(self.local_hello(&transport));
        match hello.to_bytes().and_then(|bytes| transport.encrypt(&bytes)) {
            Ok(ciphertext) => self.outgoing.push(ciphertext),
            Err(_) => return self.fail(None, "could not send hello"),
        }
        self.phase = Phase::AwaitingHello(transport);
        Vec::new()
    }

    fn local_hello(&self, transport: &NoiseTransport) -> Hello {
        let binding = hello_binding(
            transport.handshake_hash(),
            &self.identity.noise_static_public(),
        );
        Hello {
            device_id: self.local.id.clone(),
            device_name: self.local.name.clone(),
            kind: self.local.kind,
            identity_pub_hex: self.identity.public_hex(),
            handshake_sig_hex: hex::encode(self.identity.sign(&binding)),
            endpoints: self.local.endpoints.clone(),
        }
    }

    /// Check the peer's `Hello` against the handshake and against what we
    /// expected, returning the record to treat as the peer from now on.
    fn verify_hello(
        &self,
        transport: &NoiseTransport,
        hello: Hello,
    ) -> std::result::Result<Device, String> {
        hello
            .validate()
            .map_err(|e| format!("hello rejected: {e}"))?;
        if hello.identity_pub_hex == self.identity.public_hex() {
            return Err("peer presented our own identity".into());
        }
        let remote = transport
            .remote_static()
            .ok_or_else(|| "handshake did not carry a static".to_owned())?;
        let sig = hello
            .handshake_sig()
            .map_err(|e| format!("hello rejected: {e}"))?;
        identity::verify(
            &hello.identity_pub_hex,
            &hello_binding(transport.handshake_hash(), &remote),
            &sig,
        )
        .map_err(|_| "hello signature does not bind identity to handshake".to_owned())?;

        match &self.expect {
            Expect::Offer(expected) | Expect::Pinned(expected) => {
                if expected.identity_pub_hex != hello.identity_pub_hex
                    || expected.id != hello.device_id
                {
                    return Err("hello identity does not match pinned device".into());
                }
                if decode_32(&expected.noise_static_hex) != Some(remote) {
                    return Err("noise static does not match pinned device".into());
                }
                let mut peer = expected.clone();
                peer.last_seen_at_ms = Some(self.now_ms);
                Ok(peer)
            }
            Expect::AnyUnderPsk => Ok(Device {
                id: hello.device_id,
                name: hello.device_name,
                kind: hello.kind,
                identity_pub_hex: hello.identity_pub_hex,
                noise_static_hex: hex::encode(remote),
                endpoints: hello.endpoints,
                paired_at_ms: self.now_ms,
                last_seen_at_ms: Some(self.now_ms),
                revoked_at_ms: None,
            }),
            Expect::Lookup(_) => Err("peer was never resolved".into()),
        }
    }

    fn dispatch(&mut self, mut transport: NoiseTransport, frame: Frame) -> Vec<SessionEvent> {
        match frame {
            Frame::Hello(_) => self.fail(Some(&mut transport), "duplicate hello"),
            Frame::Bye { reason } => {
                self.phase = Phase::Closed;
                vec![SessionEvent::Closed {
                    reason: format!("peer closed: {reason}"),
                }]
            }
            Frame::Ping { nonce } => {
                let pong = Frame::Pong { nonce };
                match pong.to_bytes().and_then(|bytes| transport.encrypt(&bytes)) {
                    Ok(ciphertext) => self.outgoing.push(ciphertext),
                    Err(_) => return self.fail(Some(&mut transport), "could not answer ping"),
                }
                self.phase = Phase::Open(transport);
                Vec::new()
            }
            Frame::Ceremony(signed) => {
                let Some(peer) = &self.peer else {
                    return self.fail(Some(&mut transport), "ceremony frame without a peer");
                };
                if signed.msg.from_device_id != peer.id {
                    // Forwarded for a third device; the relay cannot vouch for
                    // the author, so the caller verifies against its own table.
                    self.phase = Phase::Open(transport);
                    return vec![SessionEvent::Relayed(signed)];
                }
                if signed.verify(&peer.identity_pub_hex).is_err() {
                    return self.fail(
                        Some(&mut transport),
                        "ceremony message not signed by the peer",
                    );
                }
                self.phase = Phase::Open(transport);
                vec![SessionEvent::Frame(Frame::Ceremony(signed))]
            }
            other @ (Frame::Signal { .. } | Frame::Pong { .. }) => {
                self.phase = Phase::Open(transport);
                vec![SessionEvent::Frame(other)]
            }
        }
    }

    /// Protocol violation: tear down, keep the reason local, and tell the peer
    /// only that it was refused so an attacker probing with statics or
    /// signatures learns nothing from the wording.
    fn fail(&mut self, transport: Option<&mut NoiseTransport>, reason: &str) -> Vec<SessionEvent> {
        if let Some(t) = transport {
            self.queue_bye(t, "refused");
        }
        self.phase = Phase::Closed;
        vec![SessionEvent::Closed {
            reason: reason.to_owned(),
        }]
    }

    fn queue_bye(&mut self, transport: &mut NoiseTransport, reason: &str) {
        let bye = Frame::Bye {
            reason: reason.to_owned(),
        };
        if let Ok(ciphertext) = bye.to_bytes().and_then(|bytes| transport.encrypt(&bytes)) {
            self.outgoing.push(ciphertext);
        }
    }
}

fn decrypt_frame(
    transport: &mut NoiseTransport,
    bytes: &[u8],
) -> std::result::Result<Frame, &'static str> {
    let plaintext = transport.decrypt(bytes).map_err(|_| "decrypt failed")?;
    Frame::from_bytes(&plaintext).map_err(|_| "malformed frame")
}

fn invalid(what: &'static str, reason: &str) -> CoreError {
    CoreError::Invalid {
        what,
        reason: reason.to_owned(),
    }
}

/// The record we announce in `Hello` must be the one our identity signs for,
/// otherwise every honest peer would refuse us.
fn check_local(identity: &DeviceIdentity, local: &Device) -> Result<()> {
    if local.id != identity.device_id() || local.identity_pub_hex != identity.public_hex() {
        return Err(invalid(
            "session",
            "local device record does not match the identity",
        ));
    }
    Ok(())
}

fn check_fresh(offer: &PairingOffer, now_ms: i64) -> Result<()> {
    if offer.is_expired(now_ms) {
        return Err(invalid("pairing offer", "expired"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_binding_separates_domain_hash_and_static() {
        let hash = [7u8; 32];
        let a = hello_binding(&hash, &[1u8; 32]);
        let b = hello_binding(&hash, &[2u8; 32]);
        assert_ne!(a, b);
        assert!(a.starts_with(HELLO_DOMAIN));
        assert_eq!(a.len(), HELLO_DOMAIN.len() + 64);
    }
}
