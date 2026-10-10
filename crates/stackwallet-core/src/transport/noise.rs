//! Noise handshake and transport state over `snow`, sans-IO.
//!
//! Two patterns:
//! * pairing: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` keyed with the one-time
//!   code from the QR. The scanner initiates against the issuer's static read
//!   from the QR; the PSK proves the initiator saw the QR, and `IK` transmits
//!   the initiator's static so the issuer can pin it in turn.
//! * session: `Noise_IK_25519_ChaChaPoly_BLAKE2s` against the pinned static of
//!   a paired device. The initiator proves knowledge of the responder's static
//!   in its first message, so an unpinned peer is refused before any payload.
//!
//! Prologue is `TRANSPORT_VERSION || "stackwallet"`, so peers on different
//! wire versions fail the handshake instead of misparsing frames.

use zeroize::Zeroizing;

use crate::{CoreError, Result};

pub const NOISE_PATTERN_PAIRING: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_PATTERN_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Prologue every handshake is bound to.
pub fn prologue() -> Vec<u8> {
    let mut p = vec![super::TRANSPORT_VERSION];
    p.extend_from_slice(b"stackwallet");
    p
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// In-progress handshake. Drive it with `write_message`/`read_message` until
/// `is_finished`, then `into_transport`.
pub struct NoiseHandshake {
    inner: snow::HandshakeState,
    role: HandshakeRole,
}

impl NoiseHandshake {
    /// Pairing handshake (`IKpsk2`) under a one-time code. `local_static` is
    /// this device's X25519 static from `DeviceIdentity::noise_static`; the
    /// scanner (initiator) passes the issuer's static from the offer.
    pub fn pairing(
        role: HandshakeRole,
        local_static: &Zeroizing<x25519_dalek::StaticSecret>,
        issuer_static: Option<&[u8; 32]>,
        one_time_code: &[u8; 32],
    ) -> Result<Self> {
        let prologue = prologue();
        let local_key = Zeroizing::new(local_static.to_bytes());
        let mut builder = snow::Builder::new(parse(NOISE_PATTERN_PAIRING)?)
            .prologue(&prologue)
            .and_then(|b| b.local_private_key(local_key.as_ref()))
            .and_then(|b| b.psk(2, one_time_code))
            .map_err(|_| CoreError::Crypto("noise build"))?;
        match (role, issuer_static) {
            (HandshakeRole::Initiator, Some(rs)) => {
                builder = builder
                    .remote_public_key(rs)
                    .map_err(|_| CoreError::Crypto("noise build"))?
            }
            (HandshakeRole::Initiator, None) => {
                return Err(CoreError::Invalid {
                    what: "noise handshake",
                    reason: "pairing initiator needs the issuer's static from the offer".into(),
                })
            }
            (HandshakeRole::Responder, _) => {}
        }
        let inner = match role {
            HandshakeRole::Initiator => builder.build_initiator(),
            HandshakeRole::Responder => builder.build_responder(),
        }
        .map_err(|_| CoreError::Crypto("noise build"))?;
        Ok(Self { inner, role })
    }

    /// Session handshake (`IK`). The initiator must pass the responder's
    /// pinned static; the responder checks the initiator's static against its
    /// device table after the first message via `remote_static`.
    pub fn session(
        role: HandshakeRole,
        local_static: &Zeroizing<x25519_dalek::StaticSecret>,
        remote_static: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let prologue = prologue();
        let local_key = Zeroizing::new(local_static.to_bytes());
        let mut builder = snow::Builder::new(parse(NOISE_PATTERN_IK)?)
            .prologue(&prologue)
            .and_then(|b| b.local_private_key(local_key.as_ref()))
            .map_err(|_| CoreError::Crypto("noise build"))?;
        match (role, remote_static) {
            (HandshakeRole::Initiator, Some(rs)) => {
                builder = builder
                    .remote_public_key(rs)
                    .map_err(|_| CoreError::Crypto("noise build"))?
            }
            (HandshakeRole::Initiator, None) => {
                return Err(CoreError::Invalid {
                    what: "noise handshake",
                    reason: "IK initiator needs the peer's pinned static".into(),
                })
            }
            (HandshakeRole::Responder, _) => {}
        }
        let inner = match role {
            HandshakeRole::Initiator => builder.build_initiator(),
            HandshakeRole::Responder => builder.build_responder(),
        }
        .map_err(|_| CoreError::Crypto("noise build"))?;
        Ok(Self { inner, role })
    }

    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    pub fn is_my_turn(&self) -> bool {
        self.inner.is_my_turn()
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    /// Produce the next handshake message carrying `payload`.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; payload.len() + 128];
        let n = self
            .inner
            .write_message(payload, &mut out)
            .map_err(|_| CoreError::Crypto("noise write"))?;
        out.truncate(n);
        Ok(out)
    }

    /// Consume the peer's next handshake message, returning its payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; message.len()];
        let n = self
            .inner
            .read_message(message, &mut out)
            .map_err(|_| CoreError::Crypto("noise read"))?;
        out.truncate(n);
        Ok(out)
    }

    /// The peer's static once the pattern has transmitted it.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.inner
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
    }

    /// Handshake hash `h`; both sides sign it with their identity key in
    /// `Hello` to bind the Noise static to the pinned Ed25519 identity.
    pub fn handshake_hash(&self) -> Vec<u8> {
        self.inner.get_handshake_hash().to_vec()
    }

    pub fn into_transport(self) -> Result<NoiseTransport> {
        if !self.is_finished() {
            return Err(CoreError::Crypto("noise handshake incomplete"));
        }
        let handshake_hash = self.handshake_hash();
        let remote_static = self.remote_static();
        let inner = self
            .inner
            .into_transport_mode()
            .map_err(|_| CoreError::Crypto("noise transport"))?;
        Ok(NoiseTransport {
            inner,
            handshake_hash,
            remote_static,
        })
    }
}

/// Post-handshake cipher state. Nonces are strictly increasing per direction,
/// so a replayed or reordered ciphertext fails to decrypt.
pub struct NoiseTransport {
    inner: snow::TransportState,
    handshake_hash: Vec<u8>,
    remote_static: Option<[u8; 32]>,
}

impl NoiseTransport {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; plaintext.len() + 16];
        let n = self
            .inner
            .write_message(plaintext, &mut out)
            .map_err(|_| CoreError::Crypto("noise encrypt"))?;
        out.truncate(n);
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; ciphertext.len()];
        let n = self
            .inner
            .read_message(ciphertext, &mut out)
            .map_err(|_| CoreError::Crypto("noise decrypt"))?;
        out.truncate(n);
        Ok(out)
    }

    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.remote_static
    }
}

fn parse(pattern: &str) -> Result<snow::params::NoiseParams> {
    pattern
        .parse()
        .map_err(|_| CoreError::Crypto("noise params"))
}
